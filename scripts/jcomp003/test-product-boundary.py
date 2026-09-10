#!/usr/bin/env python3
"""Mutation controls for the independent product pre-execution inspection gate."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('boundary', Path(__file__).with_name('verify-product-boundary.py'))
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)


class ProductBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.scratch = Path('/tmp/product-fixture-test')
        host = {'Privileged':False, 'PortBindings':{}, 'PublishAllPorts':False,
            'PidMode':'private', 'IpcMode':'private', 'CapAdd':[], 'Devices':[],
            'LogConfig':{'Type':'k8s-file','Size':'8MB'},
            'Ulimits':[{'Name':'RLIMIT_NOFILE','Soft':1024,'Hard':1024}]}
        db_host = dict(host, Memory=1024 ** 3, MemorySwap=1024 ** 3, NanoCpus=2 * 10 ** 9,
            PidsLimit=256, NetworkMode='none', Tmpfs={'/var/lib/postgresql/data':'rw,size=512m'},
            ReadonlyRootfs=False)
        runner_host = dict(host, Memory=2 * 1024 ** 3, MemorySwap=2 * 1024 ** 3, NanoCpus=4 * 10 ** 9,
            PidsLimit=512, NetworkMode='container:' + 'f' * 64, Tmpfs={'/tmp':'rw,size=512m,mode=1777'},
            ReadonlyRootfs=True, SecurityOpt=['no-new-privileges'])
        self.database = [{'Id':'f' * 64, 'Image':B.POSTGRES_ID, 'ImageName':B.POSTGRES_REFERENCE,
            'HostConfig':db_host, 'Mounts':[], 'EffectiveCaps':sorted(B.DEFAULT_PG_CAPABILITIES),
            'Config':{'User':'', 'Env':['POSTGRES_HOST_AUTH_METHOD=trust'],
                'Entrypoint':['/bin/sh'], 'Cmd':B.DB_WATCHDOG}}]
        mounts = [{'Destination':dest, 'Source':str(self.scratch / name), 'Type':'bind','RW':False}
                  for dest, name in [('/tmp/jcomp003-target/debug','binaries'),
                    ('/opt/jcomp/tracer','tracer'),('/opt/jcomp/input.json','input.json')]]
        self.runner = [{'Image':B.RUNTIME_ID,'HostConfig':runner_host,'EffectiveCaps':None,
            'Mounts':mounts,'Config':{'User':'1000:1000','Entrypoint':['/usr/bin/timeout'],
                'Cmd':['-k','5','240','/bin/bash','-c',B.RUNNER_BODY], 'Env':[
                    'MCLOVING_TEST_DATABASE_URL=postgres://mcloving@127.0.0.1:5432/mcloving',
                    'JCOMP_INPUT=/opt/jcomp/input.json','JCOMP_OUTPUT=/tmp/observations',
                    'JCOMP_STRACE=/opt/jcomp/tracer/observe-exec',
                    'MCLOVING_CONTROLLER_BINARY=/tmp/jcomp003-target/debug/mcloving-controller']}}]

    def reject(self):
        with self.assertRaises(ValueError):
            B.verify(self.runner,self.database,self.scratch)

    def test_expected(self):
        self.assertIn('product-boundary-ok',B.verify(self.runner,self.database,self.scratch))

    def test_namespace_and_resource_mutations(self):
        mutations = {'NetworkMode':'host','PidMode':'host','IpcMode':'host','Memory':0,
            'MemorySwap':-1,'NanoCpus':0,'PidsLimit':-1,'Privileged':True,'Devices':['/dev/kvm'],
            'PortBindings':{'5432/tcp':[{}]},'PublishAllPorts':True,'CapAdd':['CAP_SYS_ADMIN'],
            'LogConfig':{'Type':'journald','Size':'8MB'},'Ulimits':[]}
        for target in (self.runner,self.database):
            original = copy.deepcopy(target[0]['HostConfig'])
            for field,value in mutations.items():
                with self.subTest(target='runner' if target is self.runner else 'database',field=field):
                    target[0]['HostConfig'] = dict(original, **{field:value})
                    self.reject()
            target[0]['HostConfig'] = original

    def test_unrelated_database_network(self):
        self.runner[0]['HostConfig']['NetworkMode'] = 'container:' + 'a' * 64
        self.reject()

    def test_private_database_cannot_mount_host(self):
        self.database[0]['Mounts'] = [{'Source':'/srv/postgres','Destination':'/var/lib/postgresql/data'}]
        self.reject()

    def test_runner_wrong_mount_source(self):
        self.runner[0]['Mounts'][0]['Source'] = '/home/production'
        self.reject()

    def test_runner_writable_mount(self):
        self.runner[0]['Mounts'][1]['RW'] = True
        self.reject()

    def test_extra_mount(self):
        self.runner[0]['Mounts'].append({'Source':'/run/podman.sock','Destination':'/socket'})
        self.reject()

    def test_missing_watchdogs(self):
        for target in (self.runner,self.database):
            original = target[0]['Config']['Entrypoint']
            target[0]['Config']['Entrypoint'] = ['/bin/sh'] if target is self.runner else ['/bin/postgres']
            self.reject()
            target[0]['Config']['Entrypoint'] = original

    def test_bypassed_release_gate(self):
        self.runner[0]['Config']['Cmd'] = ['-k','5','240','/bin/bash','-c','exec jcomp003_paired']
        self.reject()

    def test_proxy_inheritance(self):
        self.runner[0]['Config']['Env'].append('HTTPS_PROXY=http://production:3128')
        self.reject()

    def test_production_database_endpoint(self):
        self.runner[0]['Config']['Env'][0] = 'MCLOVING_TEST_DATABASE_URL=postgres://production/mcloving'
        self.reject()

    def test_wrong_image(self):
        self.database[0]['Image'] = 'a' * 64
        self.reject()

    def test_overlarge_tmpfs(self):
        self.runner[0]['HostConfig']['Tmpfs']['/tmp'] = 'rw,size=5g,mode=1777'
        self.reject()

    def test_additional_database_capability(self):
        self.database[0]['EffectiveCaps'].append('CAP_SYS_ADMIN')
        self.reject()


if __name__ == '__main__':
    unittest.main()
