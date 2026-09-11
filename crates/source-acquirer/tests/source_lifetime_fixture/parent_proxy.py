"""A real fixture parent whose death is observed by the fixed source launcher.

Only fixture-owned descriptors and public test authority paths are forwarded.
This subprocess is never part of the production launcher or an accepted command.
"""
import os
import json
import pathlib
import signal
import tempfile
import struct
import subprocess
import sys

prefix = "MCLOVING_SOURCE_CONTAINMENT"
parent_fd = os.pidfd_open(os.getpid())
os.environ[prefix + "_PARENT_PIDFD"] = str(parent_fd)
fds = tuple(int(os.environ[prefix + suffix]) for suffix in
            ("_IMAGE_FD", "_PARENT_PIDFD", "_READY_FD", "_GATE_FD"))
image = f"/proc/self/fd/{fds[0]}"
overlay_directory = None
if os.environ.get("MCLOVING_FIXTURE_PROC_MAP_OVERLAY") == "1":
    overlay_directory = tempfile.TemporaryDirectory(prefix="source-fixture-map-overlay-")
    fake = pathlib.Path(overlay_directory.name) / "identity-map"
    fake.write_text("         0          0 4294967295\n")
    def install_overlay(_signal, _frame):
        results = []
        for name in ("uid_map", "gid_map"):
            target = f"/proc/{child.pid}/{name}"
            result = subprocess.run(["mount", "--bind", str(fake), target],
                                    capture_output=True, timeout=5)
            results.append({"status": result.returncode,
                            "value": pathlib.Path(target).read_text().strip()})
        os.write(sys.stdout.fileno(), json.dumps({"proc_map_overlays": results}).encode() + b"\n")
    signal.signal(signal.SIGUSR1, install_overlay)
child = subprocess.Popen(["aa-exec", "-p", "unconfined", "--", image],
                         pass_fds=fds, env=os.environ)
os.write(sys.stdout.fileno(), struct.pack("<I", child.pid))
status = child.wait()
if overlay_directory is not None:
    overlay_directory.cleanup()
raise SystemExit(status)
