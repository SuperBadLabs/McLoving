#!/usr/bin/env python3
"""Mutation tests for the pre-execution container inspection gate."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('jenkins', Path(__file__).with_name('run-jenkins.py'))
J = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(J)


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.mounts = {'/opt/jcomp/input': Path('/tmp/private/input')}
        self.inspect = [{'Image': J.IMAGE_ID, 'Config': {'User': '1000:1000',
            'Entrypoint': ['/usr/bin/tini'], 'Cmd': J.WATCHDOG},
            'EffectiveCaps': [], 'Mounts': [{'Destination': '/opt/jcomp/input',
                'Source': '/tmp/private/input', 'Type': 'bind', 'RW': False}],
            'HostConfig': {'NetworkMode': 'none', 'PortBindings': {},
                'ReadonlyRootfs': True, 'Privileged': False,
                'SecurityOpt': ['no-new-privileges'], 'PidMode': 'private', 'IpcMode': 'private',
                'CapAdd': [], 'Devices': [], 'Memory': 4 * 1024 ** 3, 'PidsLimit': 1024,
                'MemorySwap':4 * 1024 ** 3, 'NanoCpus': 4 * 10 ** 9,
                'LogConfig': {'Type':'k8s-file', 'Size':'16MB'},
                'Ulimits':[{'Name':'RLIMIT_NOFILE','Soft':1024,'Hard':1024}],
                'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=2g,mode=1777',
                          '/var/jenkins_home': 'rw,noexec,nosuid,nodev,size=2g,mode=1777',
                          '/var/jenkins_home/plugins': 'rw,noexec,nosuid,nodev,size=512m,mode=1777'}}}]

    def test_expected_boundary(self):
        J.verify_boundary(self.inspect, self.mounts)

    def test_host_boundary_mutations(self):
        changes = {'NetworkMode': 'host', 'PortBindings': {'8080/tcp': [{}]},
            'ReadonlyRootfs': False, 'Privileged': True, 'SecurityOpt': [],
            'PidMode': 'host', 'IpcMode': 'host', 'CapAdd': ['CAP_SYS_ADMIN'],
            'Devices': ['/dev/kvm'], 'Memory': 0, 'PidsLimit': -1, 'NanoCpus': 0,
            'MemorySwap': -1, 'LogConfig':{'Type':'journald','Size':'16MB'}, 'Ulimits':[],
            'Tmpfs': {'/tmp': 'rw', '/var/jenkins_home': 'rw', '/host': 'rw'}}
        for field, value in changes.items():
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.inspect)
                mutated[0]['HostConfig'][field] = value
                with self.assertRaises(AssertionError):
                    J.verify_boundary(mutated, self.mounts)

    def test_unexpected_writable_or_host_mount(self):
        for field, value in [('Source', '/home/service'), ('Type', 'volume'), ('RW', True),
                             ('Destination', '/var/jenkins_home')]:
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.inspect)
                mutated[0]['Mounts'][0][field] = value
                with self.assertRaises(AssertionError):
                    J.verify_boundary(mutated, self.mounts)

    def test_extra_mount(self):
        self.inspect[0]['Mounts'].append({'Destination': '/socket', 'Source': '/run/podman.sock',
                                         'Type': 'bind', 'RW': True})
        with self.assertRaises(AssertionError):
            J.verify_boundary(self.inspect, self.mounts)

    def test_tmpfs_and_watchdog_mutations(self):
        for value in ['rw,noexec,nosuid,nodev,size=512m,mode=1777',
                      'rw,exec,nosuid,nodev,size=512m,mode=1777',
                      'rw,noexec,nosuid,nodev,size=512m,mode=777']:
            mutated = copy.deepcopy(self.inspect)
            mutated[0]['HostConfig']['Tmpfs']['/tmp'] = value
            with self.assertRaises(AssertionError):
                J.verify_boundary(mutated, self.mounts)
        self.inspect[0]['Config']['Cmd'] = ['/usr/local/bin/jenkins.sh']
        with self.assertRaises(AssertionError):
            J.verify_boundary(self.inspect, self.mounts)

    def test_wrong_image_user_capability(self):
        for field, value in [('Image', 'f' * 64), ('Config', {'User': '0:0'}),
                             ('EffectiveCaps', ['CAP_SYS_ADMIN'])]:
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.inspect)
                mutated[0][field] = value
                with self.assertRaises(AssertionError):
                    J.verify_boundary(mutated, self.mounts)

    def test_private_home_mode_and_ownership_mutations(self):
        prefix = 'rw,noexec,nosuid,nodev,size=2g,'
        for options in ['mode=700', 'mode=777', 'mode=1777,uid=1000',
                        'mode=1777,gid=1000', 'mode=1777,uid=0,gid=0']:
            with self.subTest(options=options):
                mutated = copy.deepcopy(self.inspect)
                mutated[0]['HostConfig']['Tmpfs']['/var/jenkins_home'] = prefix + options
                with self.assertRaises(AssertionError):
                    J.verify_boundary(mutated, self.mounts)

    def test_failed_launch_retains_exact_command_and_streams(self):
        command = ['podman', 'run', '--network=none', 'sha256:' + J.IMAGE_ID]
        for error in [subprocess.CalledProcessError(125, command, b'partial-id', b'mount error\n'),
                      subprocess.TimeoutExpired(command, 30, b'partial-id', b'partial error\n')]:
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                with patch.object(J, 'run', side_effect=error):
                    with self.assertRaises(type(error)) as observed:
                        J.launch(command, output)
                self.assertIs(observed.exception, error)
                self.assertEqual(json.loads((output / 'launch.json').read_text()), command)
                self.assertEqual((output / 'launch-failed.stdout').read_bytes(), error.stdout)
                self.assertEqual((output / 'launch-failed.stderr').read_bytes(), error.stderr)

    def test_private_plugin_tmpfs_mutations(self):
        for value in [None, 'rw,noexec,nosuid,nodev,size=2g,mode=1777',
                      'rw,noexec,nosuid,nodev,size=512m,mode=777',
                      'rw,exec,nosuid,nodev,size=512m,mode=1777']:
            with self.subTest(value=value):
                mutated = copy.deepcopy(self.inspect)
                tmpfs = mutated[0]['HostConfig']['Tmpfs']
                if value is None:
                    del tmpfs['/var/jenkins_home/plugins']
                else:
                    tmpfs['/var/jenkins_home/plugins'] = value
                with self.assertRaises(AssertionError):
                    J.verify_boundary(mutated, self.mounts)


if __name__ == '__main__':
    unittest.main()
