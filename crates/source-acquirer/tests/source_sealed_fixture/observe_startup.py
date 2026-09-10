"""Owned-file inotify observer; no privileged operations or policy changes."""
import ctypes
import json
import os
import subprocess
import sys

libc = ctypes.CDLL(None, use_errno=True)
watch_fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
if watch_fd < 0:
    raise OSError(ctypes.get_errno(), "inotify_init1")
for path in sys.argv[2:5]:
    if libc.inotify_add_watch(watch_fd, os.fsencode(path), 0x20 | 0x1) < 0:
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
result = subprocess.run([f"/proc/self/fd/{fd}"], input=b"{}\n", capture_output=True,
                        pass_fds=(fd,), timeout=10)
observed = drain()
os.close(watch_fd)
print(json.dumps({"status": result.returncode, "stdout": result.stdout.decode(),
                  "stderr": result.stderr.decode(), "private_access_event_bytes": observed,
                  "positive_control_event_bytes": positive_control}))
