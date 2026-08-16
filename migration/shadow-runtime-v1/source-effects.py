#!/usr/bin/env python3
"""Capture bounded live side effects around the SHADOW-001 Jenkins probe."""

import base64
import ctypes
import http.cookiejar
import json
import os
import pathlib
import select
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request


CONTAINER = "jenkins-oracle-228"
HOME = pathlib.Path("/home/srikanth/jenkins-oracle-228/home")
JOB = "corpus-052-cinqict_jenkinsdev"
JOB_ROOT = HOME / "jobs" / JOB
PASSWORD = pathlib.Path("/home/srikanth/jenkins-oracle-228/runner/admin-password")
BASE_URL = "http://100.127.170.90:18080"

IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_ISDIR = 0x40000000
WATCH_MASK = (
    IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)
EVENT = struct.Struct("iIII")


class HomeMutationMonitor:
    def __init__(self) -> None:
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.inotify_init1.argtypes = [ctypes.c_int]
        self.libc.inotify_init1.restype = ctypes.c_int
        self.libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.libc.inotify_add_watch.restype = ctypes.c_int
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self.paths: dict[int, pathlib.Path] = {}
        self.control_mutations = 0
        self.unclassified_mutations = 0
        self.running = True
        for root, directories, _ in os.walk(HOME, followlinks=False):
            self.add_watch(pathlib.Path(root))
            directories[:] = [
                name for name in directories if not (pathlib.Path(root) / name).is_symlink()
            ]
        self.thread = threading.Thread(target=self.read_events, daemon=True)
        self.thread.start()

    def add_watch(self, path: pathlib.Path) -> None:
        wd = self.libc.inotify_add_watch(self.fd, os.fsencode(path), WATCH_MASK)
        if wd < 0:
            raise OSError(ctypes.get_errno(), f"cannot monitor Jenkins home directory: {path}")
        self.paths[wd] = path

    @staticmethod
    def is_probe_control_path(path: pathlib.Path) -> bool:
        if path == JOB_ROOT:
            return True
        return path.parent == JOB_ROOT and (
            path.name == "config.xml"
            or (path.name.startswith("config.xml-atomic") and path.name.endswith("tmp"))
            or path.name == "scm-polling.log"
        )

    def read_events(self) -> None:
        while self.running:
            readable, _, _ = select.select([self.fd], [], [], 0.1)
            if not readable:
                continue
            try:
                payload = os.read(self.fd, 1 << 20)
            except BlockingIOError:
                continue
            offset = 0
            while offset < len(payload):
                wd, mask, _, length = EVENT.unpack_from(payload, offset)
                offset += EVENT.size
                raw_name = payload[offset : offset + length].split(b"\0", 1)[0]
                offset += length
                parent = self.paths.get(wd)
                if parent is None:
                    continue
                path = parent / os.fsdecode(raw_name) if raw_name else parent
                if mask & IN_ISDIR and mask & (IN_CREATE | IN_MOVED_TO):
                    try:
                        self.add_watch(path)
                    except FileNotFoundError:
                        pass
                if self.is_probe_control_path(path):
                    self.control_mutations += 1
                else:
                    self.unclassified_mutations += 1

    def stop(self) -> None:
        time.sleep(0.25)
        self.running = False
        self.thread.join(timeout=2)
        os.close(self.fd)


def start_network_monitor(capture: pathlib.Path) -> subprocess.Popen[str]:
    inspected = subprocess.run(
        ["podman", "inspect", "--format", "{{.State.Pid}}", CONTAINER],
        check=True,
        capture_output=True,
        text=True,
    )
    pid = inspected.stdout.strip()
    if not pid.isdigit():
        raise RuntimeError("Jenkins container PID is unavailable")
    process = subprocess.Popen(
        [
            "podman",
            "unshare",
            "nsenter",
            "-t",
            pid,
            "-n",
            "tcpdump",
            "-Q",
            "out",
            "-i",
            "any",
            "-U",
            "-n",
            "-w",
            str(capture),
            "(ip or ip6) and not (tcp src port 8080)",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    assert process.stderr is not None
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        readable, _, _ = select.select([process.stderr], [], [], 0.1)
        if readable and "listening on" in process.stderr.readline():
            return process
        if process.poll() is not None:
            raise RuntimeError("network monitor exited before capture")
    os.killpg(process.pid, signal.SIGTERM)
    process.wait(timeout=5)
    raise RuntimeError("network monitor did not become ready")


def stop_network_monitor(process: subprocess.Popen[str], capture: pathlib.Path) -> int:
    os.killpg(process.pid, signal.SIGINT)
    process.communicate(timeout=10)
    if not capture.is_file():
        raise RuntimeError("network monitor did not publish a packet capture")
    decoded = subprocess.run(
        ["tcpdump", "-n", "-r", str(capture)],
        check=True,
        capture_output=True,
        text=True,
    )
    return sum(1 for line in decoded.stdout.splitlines() if line.strip())


def execute_probe(groovy: str) -> str:
    password = PASSWORD.read_text(encoding="utf-8").strip()
    authorization = "Basic " + base64.b64encode(
        ("oracle-admin:" + password).encode()
    ).decode()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    crumb = json.load(
        opener.open(
            urllib.request.Request(
                BASE_URL + "/crumbIssuer/api/json",
                headers={"Authorization": authorization},
            ),
            timeout=15,
        )
    )
    payload = urllib.parse.urlencode({"script": groovy}).encode()
    response = opener.open(
        urllib.request.Request(
            BASE_URL + "/scriptText",
            data=payload,
            headers={
                "Authorization": authorization,
                "Content-Type": "application/x-www-form-urlencoded",
                crumb["crumbRequestField"]: crumb["crumb"],
            },
        ),
        timeout=30,
    ).read().decode("utf-8", "replace")
    markers = [line for line in response.splitlines() if line.startswith("SHADOW001_SOURCE=")]
    if len(markers) != 1:
        raise RuntimeError("bounded Jenkins source marker denominator mismatch")
    return markers[0]


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: source-effects.py SOURCE_PROBE_GROOVY")
    groovy = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    home_monitor = HomeMutationMonitor()
    network_process: subprocess.Popen[str] | None = None
    with tempfile.TemporaryDirectory(prefix="mcloving-shadow001-effects.") as temporary:
        capture = pathlib.Path(temporary) / "network.pcap"
        try:
            network_process = start_network_monitor(capture)
            marker = execute_probe(groovy)
            network_requests = stop_network_monitor(network_process, capture)
            network_process = None
        finally:
            if network_process is not None and network_process.poll() is None:
                os.killpg(network_process.pid, signal.SIGTERM)
                network_process.wait(timeout=10)
            home_monitor.stop()
    effects = {
        "schema": "mcloving.shadow001.source-effects/v1",
        "network_request_attempts": network_requests,
        "unclassified_home_mutations": home_monitor.unclassified_mutations,
        "probe_control_mutations": home_monitor.control_mutations,
    }
    print(marker)
    print("SHADOW001_SOURCE_EFFECTS=" + json.dumps(effects, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
