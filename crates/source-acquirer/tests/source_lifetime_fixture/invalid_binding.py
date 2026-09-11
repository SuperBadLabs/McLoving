"""Adversarial caller of the private source launch protocol, fixture-only."""
import fcntl
import json
import os
import subprocess
import sys
import time

binary, case = sys.argv[1:]
prefix = "MCLOVING_SOURCE_CONTAINMENT"
seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE

def image(seal=True):
    fd = os.memfd_create("source-invalid-binding-fixture", os.MFD_ALLOW_SEALING)
    with open(binary, "rb") as source:
        data = source.read()
        assert os.write(fd, data) == len(data)
        assert os.fstat(fd).st_size == len(data)
    if seal:
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
    return fd

running = image()
selected = running
parent = os.pidfd_open(os.getpid())
ready_read, ready_write = os.pipe()
gate_read, gate_write = os.pipe()
owned_child = None
args = []
deadline = time.monotonic_ns() + 5_000_000_000
if case == "unsealed-image":
    running = selected = image(False)
elif case == "different-sealed-inode":
    selected = image()
elif case == "wrong-live-parent":
    owned_child = subprocess.Popen(["sleep", "30"])
    parent = os.pidfd_open(owned_child.pid)
elif case == "dead-parent-pidfd":
    owned_child = subprocess.Popen(["sleep", "30"])
    parent = os.pidfd_open(owned_child.pid)
    owned_child.kill()
    owned_child.wait()
elif case == "aliased-control-fds":
    gate_read = ready_write
elif case == "ordinary-file-parent":
    parent = image()
elif case == "expired-deadline":
    deadline = 1
elif case == "extra-argument":
    args = ["not-a-supported-command"]
else:
    raise ValueError(case)

env = {
    prefix: "outer",
    prefix + "_IMAGE_FD": str(selected),
    prefix + "_PARENT_PIDFD": str(parent),
    prefix + "_READY_FD": str(ready_write),
    prefix + "_GATE_FD": str(gate_read),
    prefix + "_DEADLINE_MONOTONIC_NS": str(deadline),
    "MCLOVING_SOURCE_ACQUIRER_CONFIG": "/source-fixture-must-not-open-config",
    "MCLOVING_SOURCE_ACQUIRER_EXPECTED_CONFIG_SHA256": "0" * 64,
}
try:
    child = subprocess.Popen(["aa-exec", "-p", "unconfined", "--", f"/proc/self/fd/{running}", *args],
                             env=env, pass_fds=tuple(set((running, selected, parent, ready_write, gate_read))),
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.close(ready_write)
    stdout, stderr = child.communicate(timeout=8)
    phase = os.read(ready_read, 32)
    print(json.dumps({"case": case, "status": child.returncode,
                      "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
                      "phase_bytes": len(phase)}))
finally:
    if owned_child is not None and owned_child.poll() is None:
        owned_child.kill()
        owned_child.wait()
