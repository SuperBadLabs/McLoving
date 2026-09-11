"""Actual private entries reject a fixture parent before trusting capsule content."""
import fcntl
import json
import os
import subprocess
import sys
import time

PREFIX = 'MCLOVING_SOURCE_CONTAINMENT'
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
if sys.argv[1] == '--inner':
    mode = os.environ[PREFIX]
    image = int(os.environ[PREFIX + '_IMAGE_FD'])
    if mode == 'init':
        assert os.getpid() == 1
        os.execve(f'/proc/self/fd/{image}', ['source-forged-init'], os.environ)
    assert os.getpid() == 1
    parent = os.pidfd_open(1)
    os.environ[PREFIX + '_PARENT_PIDFD'] = str(parent)
    inherited = [int(os.environ[PREFIX + suffix]) for suffix in
                 ['_IMAGE_FD', '_PARENT_PIDFD', '_RUNTIME_FD', '_READY_FD', '_GATE_FD']]
    child = subprocess.run([f'/proc/self/fd/{image}'], env=os.environ,
                           pass_fds=tuple(set(inherited)), timeout=5)
    sys.exit(child.returncode)

binary, mode, variant = sys.argv[1:]
def sealed(data, seal=True):
    fd = os.memfd_create('source-forged-lineage-fixture', os.MFD_ALLOW_SEALING)
    assert os.write(fd, data) == len(data)
    assert os.fstat(fd).st_size == len(data)
    if seal:
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
    return fd

with open(binary, 'rb') as source:
    image = sealed(source.read())
capsule = sealed(b'{"fixture":"substituted capsule"}', variant != 'unsealed-capsule')
if variant == 'runtime-image-alias':
    capsule = image
parent = os.pidfd_open(os.getpid())
ready_read, ready_write = os.pipe()
gate_read, gate_write = os.pipe()
env = {PREFIX: mode, PREFIX+'_IMAGE_FD': str(image), PREFIX+'_PARENT_PIDFD': str(parent),
       PREFIX+'_RUNTIME_FD': str(capsule), PREFIX+'_READY_FD': str(ready_write),
       PREFIX+'_GATE_FD': str(gate_read), PREFIX+'_DEADLINE_MONOTONIC_NS': str(time.monotonic_ns()+5_000_000_000),
       'MCLOVING_SOURCE_ACQUIRER_CONFIG': '/nonexistent-forged-lineage-config',
       'MCLOVING_SOURCE_ACQUIRER_EXPECTED_CONFIG_SHA256': ('1' if variant == 'config-mismatch' else '0')*64}
command = ['aa-exec','-p','mcloving-source-acquirer','--','unshare','--user','--map-root-user','--pid','--fork']
if mode == 'worker':
    command += ['--mount-proc']
command += ['python3', os.path.abspath(__file__), '--inner']
child = subprocess.Popen(command, env=env, pass_fds=tuple(set((image,capsule,parent,ready_write,gate_read))),
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
os.close(ready_write)
stdout,stderr = child.communicate(timeout=8)
phase = os.read(ready_read,32)
print(json.dumps({'mode':mode,'variant':variant,'status':child.returncode,'phase_bytes':len(phase),
                  'stdout_bytes':len(stdout),'stderr_bytes':len(stderr)}))
