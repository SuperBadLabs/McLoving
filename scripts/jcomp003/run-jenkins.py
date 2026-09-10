#!/usr/bin/env python3
"""Run fixed positive sources on a pinned, network-none disposable Jenkins.

Requires a fresh output directory and the exact historical public plugin files.
This driver records observations; verify-paired.py decides semantic parity.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

if not __debug__:
    raise RuntimeError('Jenkins campaign requires assertion checks; Python optimization is forbidden')

ROOT = Path(__file__).resolve().parents[2]
IMAGE = 'docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02'
IMAGE_ID = '3b072c3e47bfa9a97dc733fc414da2005c99180f111ac0842327bd963509a1c1'
MANIFEST_SHA = '654898829f31872d471db88830414b23a9453e021bec281f05ac1aa4175de727'
PLUGIN_MANIFEST_SHA = 'e33fa87646e6e360e7614373cc0057ba2e92ff18b9a9ea9419dea796dcb950b0'
PROFILE_SHA = 'feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271'
WATCHDOG = ['--', '/usr/bin/timeout', '--signal=TERM', '--kill-after=10s',
            '540s', '/usr/local/bin/jenkins.sh']


def run(args, **kwargs):
    kwargs.setdefault('timeout', 30)
    return subprocess.run(args, check=True, capture_output=True, **kwargs).stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def launch(command, output):
    (output / 'launch.json').write_text(json.dumps(command, indent=2) + '\n')
    try:
        return run(command)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        (output / 'launch-failed.stdout').write_bytes(error.stdout or b'')
        (output / 'launch-failed.stderr').write_bytes(error.stderr or b'')
        raise


def verify_tmpfs(value, size, mode):
    options = dict(part.split('=', 1) if '=' in part else (part, None) for part in value.split(','))
    assert set(options) <= {'rw', 'noexec', 'nosuid', 'nodev', 'size', 'mode',
                            'rprivate', 'tmpcopyup'}
    assert {'rw', 'noexec', 'nosuid', 'nodev'} <= set(options)
    observed_size = options['size'].lower()
    multipliers = {'k':1024, 'm':1024 ** 2, 'g':1024 ** 3}
    count = (int(observed_size[:-1]) * multipliers[observed_size[-1]]
             if observed_size[-1] in multipliers else int(observed_size))
    assert count == size and int(options['mode'], 8) == mode


def verify_boundary(inspect, expected_mounts):
    assert len(inspect) == 1
    observed = inspect[0]
    config = observed['HostConfig']
    assert observed['Image'].removeprefix('sha256:') == IMAGE_ID
    assert config['NetworkMode'] == 'none' and not config['PortBindings']
    assert config['ReadonlyRootfs'] is True and config['Privileged'] is False
    assert 'no-new-privileges' in config['SecurityOpt']
    assert config['PidMode'] == 'private' and config['IpcMode'] == 'private'
    assert not config['CapAdd'] and not config['Devices']
    assert observed['EffectiveCaps'] in ([], None)
    assert observed['Config']['User'] == '1000:1000'
    assert config['Memory'] == 4 * 1024 ** 3 and config['PidsLimit'] == 1024
    assert config['MemorySwap'] == 4 * 1024 ** 3
    assert config['NanoCpus'] == 4 * 10 ** 9
    assert set(config['Tmpfs']) == {'/tmp', '/var/jenkins_home', '/var/jenkins_home/plugins'}
    verify_tmpfs(config['Tmpfs']['/tmp'], 2 * 1024 ** 3, 0o1777)
    verify_tmpfs(config['Tmpfs']['/var/jenkins_home'], 2 * 1024 ** 3, 0o1777)
    verify_tmpfs(config['Tmpfs']['/var/jenkins_home/plugins'], 512 * 1024 ** 2, 0o1777)
    assert config['LogConfig']['Type'] == 'k8s-file'
    assert config['LogConfig']['Size'] in ('16MB', '16mb', '16m', '16777216')
    assert any(limit['Name'] == 'RLIMIT_NOFILE' and limit['Soft'] == 1024 and
               limit['Hard'] == 1024 for limit in config['Ulimits'])
    assert observed['Config']['Entrypoint'] in ('/usr/bin/tini', ['/usr/bin/tini'])
    assert observed['Config']['Cmd'] == WATCHDOG
    assert len(observed['Mounts']) == len(expected_mounts)
    mounts = {mount['Destination']: mount for mount in observed['Mounts']}
    assert set(mounts) == set(expected_mounts)
    for destination, source in expected_mounts.items():
        mount = mounts[destination]
        assert mount['Source'] == str(source) and mount['Type'] == 'bind' and mount['RW'] is False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plugins', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    output = args.output.resolve()
    name = 'mcloving-jcomp003-jenkins-' + uuid.uuid4().hex[:12]
    launch_attempted = False
    with tempfile.TemporaryDirectory(prefix='mcloving-jcomp003-jenkins-input-') as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o755)
        inputs = scratch / 'input'
        inputs.mkdir()
        inputs.chmod(0o755)
        plugins = scratch / 'plugins'
        plugins.mkdir()
        plugins.chmod(0o755)
        manifest_bytes = (ROOT / 'compat/jenkins-worker/fixtures/sequential-v1/manifest.json').read_bytes()
        assert sha(manifest_bytes) == MANIFEST_SHA
        (inputs / 'manifest.json').write_bytes(manifest_bytes)
        manifest = json.loads(manifest_bytes)
        profile_bytes = (ROOT / 'compat/jenkins-worker/profile-v1.properties').read_bytes()
        assert sha(profile_bytes) == PROFILE_SHA
        (inputs / 'profile-v1.properties').write_bytes(profile_bytes)
        (output / 'profile-v1.properties').write_bytes(profile_bytes)
        for fixture in manifest['fixtures']:
            if fixture['expected']['compilation'] == 'supported':
                source = (ROOT / fixture['source_path']).read_bytes()
                assert sha(source) == fixture['source_sha256']
                (inputs / (fixture['id'] + '.Jenkinsfile')).write_bytes(source)
        plugin_manifest = (ROOT / 'migration/mario-jenkins-oracle-228/corpus-v1/differential-v1/jenkins/PLUGIN_SHA256SUMS').read_bytes()
        assert sha(plugin_manifest) == PLUGIN_MANIFEST_SHA
        (inputs / 'PLUGIN_SHA256SUMS').write_bytes(plugin_manifest)
        for staged_input in inputs.iterdir():
            staged_input.chmod(0o444)
        mounts = []
        expected_mounts = {
            '/opt/jcomp/input': inputs,
            '/opt/jcomp/observe-shell': scratch / 'observe-shell',
            '/var/jenkins_home/init.groovy.d/jcomp003.groovy': scratch / 'jenkins-init.groovy',
        }
        for line in plugin_manifest.decode().splitlines():
            digest, relative = line.split()
            leaf = Path(relative).name
            assert relative == 'plugins/' + leaf and leaf.endswith('.jpi')
            source = args.plugins / leaf
            assert source.is_file() and not source.is_symlink()
            content = source.read_bytes()
            assert sha(content) == digest
            destination = plugins / leaf
            destination.write_bytes(content)
            destination.chmod(0o444)
            mounts += ['--volume', f'{destination}:/var/jenkins_home/plugins/{leaf}:ro']
            expected_mounts['/var/jenkins_home/plugins/' + leaf] = destination
        assert len(mounts) == 180
        (output / 'PLUGIN_SHA256SUMS').write_bytes(plugin_manifest)
        for filename in ('observe-shell', 'jenkins-init.groovy'):
            shutil.copyfile(ROOT / 'scripts/jcomp003' / filename, scratch / filename)
            (scratch / filename).chmod(0o555 if filename == 'observe-shell' else 0o444)
            shutil.copyfile(scratch / filename, output / filename)
        inspect = json.loads(run(['podman', 'image', 'inspect', IMAGE]))
        assert inspect[0]['Id'].removeprefix('sha256:') == IMAGE_ID
        (output / 'image-inspect.json').write_text(json.dumps(inspect, indent=2) + '\n')
        command = ['podman', 'run', '--detach', '--name', name, '--pull=never',
                   '--network=none', '--pid=private', '--ipc=private', '--image-volume=ignore',
                   '--http-proxy=false', '--read-only', '--cap-drop=all',
                   '--security-opt=no-new-privileges', '--user=1000:1000',
                   '--cpus=4', '--memory=4g', '--memory-swap=4g', '--pids-limit=1024',
                   '--ulimit=nofile=1024:1024', '--log-driver=k8s-file', '--log-opt=max-size=16mb',
                   '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=2g,mode=1777',
                   # Podman rejects tmpfs uid/gid options. This private, sticky
                   # home permits UID 1000 writes without a root bootstrap.
                   '--tmpfs=/var/jenkins_home:rw,noexec,nosuid,nodev,size=2g,mode=1777',
                   # File bind mounts otherwise create a root-owned 0755 parent
                   # where Jenkins cannot unpack the read-only pinned archives.
                   '--tmpfs=/var/jenkins_home/plugins:rw,noexec,nosuid,nodev,size=512m,mode=1777',
                   '--env=JAVA_OPTS=-Djenkins.install.runSetupWizard=false -Xmx2g',
                   '--volume', f'{inputs}:/opt/jcomp/input:ro',
                   '--volume', f'{scratch / "observe-shell"}:/opt/jcomp/observe-shell:ro',
                   '--volume', f'{scratch / "jenkins-init.groovy"}:/var/jenkins_home/init.groovy.d/jcomp003.groovy:ro',
                   *mounts, '--entrypoint=/usr/bin/tini', 'sha256:' + IMAGE_ID, *WATCHDOG]
        try:
            launch_attempted = True
            container = launch(command, output).decode().strip()
            (output / 'container-id.txt').write_text(container + '\n')
            container_inspect = run(['podman', 'inspect', name])
            (output / 'container-inspect.json').write_bytes(container_inspect)
            verify_boundary(json.loads(container_inspect), expected_mounts)
            (output / 'shell-identity.txt').write_bytes(run(['podman', 'exec', name, 'bash', '-c',
                'set -eu; readlink -f /bin/sh; sha256sum /bin/sh /usr/share/jenkins/jenkins.war; java -version 2>&1']))
            # The init observer waits for this marker. No fixture may run until
            # actual container inspection has confirmed the disposable boundary.
            run(['podman', 'exec', name, 'touch', '/tmp/jcomp-boundary-approved'])
            deadline = time.monotonic() + 420
            while time.monotonic() < deadline:
                probe = subprocess.run(['podman', 'exec', name, 'sh', '-c',
                    'test -f /tmp/jcomp-observations/complete.json || test -f /tmp/jcomp-observations/failure.txt'],
                    capture_output=True, timeout=10)
                if probe.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError('bounded Jenkins campaign did not complete')
            run(['podman', 'cp', name + ':/tmp/jcomp-observations', str(output / 'observations')])
            if (output / 'observations/failure.txt').exists():
                raise RuntimeError((output / 'observations/failure.txt').read_text())
            assert (output / 'observations/complete.json').is_file()
        finally:
            if launch_attempted:
                # A failed log capture must never suppress container removal.
                try:
                    logs = subprocess.run(['podman', 'logs', name], capture_output=True, timeout=30)
                    (output / 'jenkins.log').write_bytes(logs.stdout)
                    (output / 'jenkins-log-stderr.txt').write_bytes(logs.stderr)
                finally:
                    removal = subprocess.run(['podman', 'rm', '--force', '--ignore', name],
                                             capture_output=True, timeout=30)
                    (output / 'cleanup.txt').write_bytes(removal.stdout + removal.stderr)
                    assert removal.returncode == 0
                    exists = subprocess.run(['podman', 'container', 'exists', name],
                                            capture_output=True, timeout=10)
                    assert exists.returncode == 1
                    (output / 'cleanup-verified.json').write_text(json.dumps({'container':name, 'removed':True,
                        'home_and_workspace_tmpfs_removed':True, 'production_authority':False}) + '\n')
    artifacts = {str(path.relative_to(output)): sha(path.read_bytes())
                 for path in sorted(output.rglob('*')) if path.is_file()}
    (output / 'artifacts.json').write_text(json.dumps(artifacts, indent=2) + '\n')


if __name__ == '__main__':
    main()
