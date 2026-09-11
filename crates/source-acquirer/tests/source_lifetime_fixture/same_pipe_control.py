"""Owned-file inotify observer; no privileged operations or policy changes."""
import base64
import ctypes
import json
import os
import subprocess
import sys
import time

libc = ctypes.CDLL(None, use_errno=True)
watch_fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
if watch_fd < 0:
    raise OSError(ctypes.get_errno(), "inotify_init1")
IN_ACCESS = 0x00000001
IN_OPEN = 0x00000020
for path in sys.argv[2:5]:
    if libc.inotify_add_watch(watch_fd, os.fsencode(path), IN_OPEN | IN_ACCESS) < 0:
        raise OSError(ctypes.get_errno(), "inotify_add_watch")

def drain():
    total = 0
    while True:
        try:
            batch = os.read(watch_fd, 65536)
        except BlockingIOError:
            return total
        if not batch:
            return total
        total += len(batch)

# Verify that this exact watch sees an actual open/read before testing refusal.
with open(sys.argv[2], "rb") as control:
    control.read(1)
positive_control = drain()
if positive_control == 0:
    raise RuntimeError("owned credential watch did not observe positive control")
fd = int(sys.argv[1])
parent = os.pidfd_open(os.getpid())
gate_read, ready_write = os.pipe()
assert gate_read != ready_write
assert (os.fstat(gate_read).st_dev, os.fstat(gate_read).st_ino) == (os.fstat(ready_write).st_dev, os.fstat(ready_write).st_ino)
prefix = "MCLOVING_SOURCE_CONTAINMENT"
env = dict(os.environ)
env.update({prefix: "outer", prefix + "_IMAGE_FD": str(fd),
            prefix + "_PARENT_PIDFD": str(parent), prefix + "_READY_FD": str(ready_write),
            prefix + "_GATE_FD": str(gate_read),
            prefix + "_DEADLINE_MONOTONIC_NS": str(time.monotonic_ns() + 5_000_000_000)})
# No caller ACK or request is ever written. Valid configuration and actual
# private files make an authority-open observation independent of bad input.
result = subprocess.run(["aa-exec", "-p", "unconfined", "--", f"/proc/self/fd/{fd}"],
                        input=b"", capture_output=True, env=env,
                        pass_fds=(fd, parent, gate_read, ready_write), timeout=8)
observed = drain()
os.close(ready_write)
os.set_blocking(gate_read, False)
remaining = os.read(gate_read, 65536)
os.close(watch_fd)
print(json.dumps({"status": result.returncode, "stdout_base64": base64.b64encode(result.stdout).decode("ascii"),
                  "stderr_base64": base64.b64encode(result.stderr).decode("ascii"), "private_access_event_bytes": observed,
                  "positive_control_event_bytes": positive_control, "distinct_fd_numbers": True,
                  "same_pipe_identity": True, "caller_ack_bytes": 0, "remaining_phase_bytes": len(remaining)}))
