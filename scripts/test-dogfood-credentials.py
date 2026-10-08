#!/usr/bin/env python3
"""Exercise real dogfood scripts with isolated toy credentials and command spies."""
from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
import time

DOGFOOD = Path(__file__).resolve().parent / "dogfood"
TOKEN = "PUBLIC-TOY-API-TOKEN"
ARTIFACT_TOKEN = "PUBLIC-TOY-ARTIFACT-TOKEN"
GITHUB_TOKEN = "PUBLIC-TOY-GITHUB-TOKEN"
KEY = "PUBLIC-TOY-hook-key-π"
COMMIT = "a" * 40
BUILD = "00000000-0000-0000-0000-000000000001"

# These programs never perform deployment, container, privilege or network
# actions. Every credential is public synthetic test data. The actual scripts
# execute unmodified; spies replace only their external command dependencies.
SPY = r'''
import hashlib, hmac, json, os, pathlib, stat, subprocess, sys, time
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
directory = pathlib.Path(os.environ["FIXTURE"])
scenario = json.loads((directory / "scenario.json").read_text())
entry = {"command": name, "argv": args,
         "proc_cmdline": pathlib.Path("/proc/self/cmdline").read_bytes().decode().split("\0")[:-1]}
if scenario.get("block") == "quiesce" and name == "python3" and args[1:2] == ["run"]:
    text = pathlib.Path("/proc/self/stat").read_text()
    fields = text[text.rindex(")") + 2:].split()
    entry["birth"] = dict(pid=os.getpid(), uid=os.getuid(), ppid=int(fields[1]),
                          pgrp=os.getpgrp(), session=os.getsid(0), start_ticks=int(fields[19]))
    entry["requested_public_mode"] = os.environ["MCLOVING_DOGFOOD_PUBLIC_HOOK"]
owner_path = directory / 'state' / 'hook-owner.json'
if owner_path.exists():
    entry['sender_phase'] = json.loads(owner_path.read_text())['phase']
old_pids = directory / 'old-runtime-pids.json'
if old_pids.exists():
    entry['old_runtime_states'] = {}
    for role, pid in json.loads(old_pids.read_text()).items():
        try:
            text = pathlib.Path('/proc', str(pid), 'stat').read_text()
            entry['old_runtime_states'][role] = text[text.rindex(')') + 2:].split()[0]
        except FileNotFoundError:
            entry['old_runtime_states'][role] = 'absent'
def option(flag):
    return args[args.index(flag)+1] if flag in args else None
if name == "curl":
    headers = [args[n+1] for n, arg in enumerate(args[:-1]) if arg in ("-H", "--header")]
    expanded_headers = []
    for header in headers:
        if header.startswith("@"):
            path = pathlib.Path(header[1:])
            entry["header_file"] = str(path)
            entry["header_mode"] = stat.S_IMODE(path.stat().st_mode)
            entry["header_owner"] = path.stat().st_uid
            entry["header_content"] = path.read_text()
            expanded_headers.extend(path.read_text().splitlines())
        else:
            expanded_headers.append(header)
    headers = expanded_headers
    url = next(arg for arg in args if arg.startswith("http"))
    if option("--data-binary"):
        body = pathlib.Path(option("--data-binary")[1:]).read_bytes()
        entry["payload_hex"] = body.hex()
        entry["signature"] = next(header.split(": ", 1)[1] for header in headers if header.startswith("X-Hub-Signature-256: "))
        expected = "sha256=" + hmac.new(scenario["key"].encode(), body, hashlib.sha256).hexdigest()
        assert entry["signature"] == expected
        assert json.loads(body)["after"] == scenario["commit"]
        answer = {"status":"admitted", "admission":{"build_id":scenario["build"]}}
        code = "202"
    elif url.endswith("/webhook"):
        answer = {"path":"/hooks/toy", "provider":"github", "secret":scenario["key"]}
        code = "200"
    elif option("-X") == "PUT":
        request = json.loads(option("--data"))
        generation = 4 if scenario.get("existing") == "200" else 1
        answer = dict(request, generation=generation); code = "200"
        (directory / "current-trigger.json").write_text(json.dumps(answer))
    elif (directory / "current-trigger.json").exists():
        answer = json.loads((directory / "current-trigger.json").read_text()); code = "200"
    else:
        code = scenario.get("existing", "404")
        answer = {"generation":3, "configuration":{"repository_identity":"other/repository"}}
    entry["url"] = url
    failure = scenario.get("failure")
    if (failure == "initial" and url.endswith("/triggers/trigger")) or (failure == "put" and option("-X") == "PUT") or (failure == "webhook" and url.endswith("/webhook")) or (failure == "bridge" and option("--data-binary")):
        entry["injected_failure"] = True
    elif option("-o"):
        pathlib.Path(option("-o")).write_text(json.dumps(answer))
        print(code, end="")
    else:
        print(json.dumps(answer))
elif name == "gh":
    if args[:2] == ["auth", "token"]:
        print(scenario["github_token"])
    elif "--input" in args:
        if option("--input") == "-":
            entry["request"] = json.load(sys.stdin)
            entry["request_file"] = "-"
            entry["request_mode"] = None
        else:
            path = pathlib.Path(option("--input"))
            entry["request_file"] = str(path)
            entry["request_mode"] = stat.S_IMODE(path.stat().st_mode)
            entry["request_owner"] = path.stat().st_uid
            entry["request"] = json.loads(path.read_text())
        if scenario.get("failure") == "registration" or (scenario.get('failure') == 'early-disable' and entry.get('sender_phase') == 'pending-quiesce'):
            entry["injected_failure"] = True
        else:
            hook_store = directory / "owned-hook.json"
            method = option("-X")
            previous = json.loads(hook_store.read_text()) if hook_store.exists() else {"id":73,"name":"web"}
            previous.update(json.loads(json.dumps(entry["request"])))
            previous["config"].pop("secret", None)
            hook_store.write_text(json.dumps(previous))
            print(json.dumps(previous))
    elif any("/events?" in arg for arg in args):
        print(json.dumps(scenario.get("events", [{"id":"1001", "type":"PushEvent", "payload":{"ref":"refs/heads/main", "head":scenario["commit"]}, "created_at":"2026-01-01T00:00:00Z"}])))
    elif any("/commits/" in arg for arg in args):
        print(json.dumps({"sha":scenario["commit"], "message":"toy push", "timestamp":"2026-01-01T00:00:00Z", "files":["toy.txt"]}))
    elif any("/branches/" in arg for arg in args):
        print(scenario["commit"])
    elif any("/hooks?" in arg for arg in args):
        hook_store = directory / "owned-hook.json"
        print(json.dumps([[json.loads(hook_store.read_text())]] if hook_store.exists() else [[]]))
    elif any("/hooks/" in arg for arg in args):
        if scenario.get('failure') == 'early-readback' and entry.get('sender_phase') == 'pending-quiesce':
            entry['injected_failure'] = True
        else:
            print((directory / "owned-hook.json").read_text())
    elif "repos/example/repository" in args:
        print(json.dumps({"id":711,"full_name":"example/repository","permissions":{"admin":True}}))
    else:
        raise AssertionError(args)
elif name == "render_source_binding":
    intent = json.loads(pathlib.Path(args[0]).read_text())
    private = pathlib.Path(intent["private_dir"])
    private.mkdir(exist_ok=True)
    output = pathlib.Path(intent['output_root'])
    assert not output.exists(), 'prior sealed output was not removed before renderer'
    output.mkdir(mode=0o700)
    (private / "agent-source-bindings.json").write_text("{}")
    print("mapping_digest=sha256:" + "1" * 64)
elif name == "mcloving-cli":
    if "audit" in args and scenario.get("handoff_failure"):
        sys.exit(1)
    if "pipelines" in args:
        print('{"items":[]}')
    elif "apply" in args:
        print('{"revision":1,"schema_minor":9}')
    else:
        print('{}')
elif name in ("python3", "jq", "openssl", "env"):
    # Record argv before delegation, catching keys supplied to jq --argjson,
    # openssl -hmac, or a Python signer argument in the uncorrected scripts.
    actual = scenario["actual"][name]
    if name == "env" and "dogfood-controller" in args and scenario.get("handoff_failure"):
        identity_file = pathlib.Path(args[args.index("dogfood-controller")+1])
        if scenario["handoff_failure"] == "missing":
            identity_file.unlink()
        else:
            identity_file.write_text("api_token=\nartifact_token=\n")
    with (directory / "commands.jsonl").open("a") as output:
        output.write(json.dumps(entry) + "\n")
    os.execv(actual, [actual, *args])
with (directory / "commands.jsonl").open("a") as output:
    output.write(json.dumps(entry) + "\n")
quiesce_block = (scenario.get("block") == "quiesce" and name == "gh" and
    option("-X") == "PATCH" and "repos/example/repository/hooks/73" in args and
    entry.get("sender_phase") == "pending-quiesce" and
    entry.get("request") == {"active": False} and entry.get("request_file"))
if ((scenario.get("block") == "api" and name == "curl" and entry.get("header_file")) or
    (scenario.get("block") == "bridge" and name == "curl" and entry.get("payload_hex")) or
    (scenario.get("block") == "registration" and name == "gh" and entry.get("request_file")) or
    quiesce_block):
    if quiesce_block:
        # Publish an entire actual request ACK only after the real helper's
        # durable pending-quiesce and the toy owned hook's inactive effect.
        ready = directory / ".quiesce-ready.pending"
        with ready.open("x") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(entry, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(ready, directory / "blocked.json")
    else:
        (directory / "blocked.json").write_text(json.dumps(entry))
    while True:
        time.sleep(1)
if entry.get("injected_failure"):
    sys.exit(23)
'''


class CredentialTests(unittest.TestCase):
    def fixture(self, root: Path, **scenario: str) -> tuple[Path, dict[str, str]]:
        commands = root / "commands"
        state = root / "state"
        commands.mkdir()
        state.mkdir(mode=0o700)
        (root / "scenario.json").write_text(json.dumps({
            "key": KEY, "token": TOKEN, "github_token": GITHUB_TOKEN, "commit": COMMIT, "build": BUILD,
            "actual": {name: shutil.which(name) for name in ("python3", "jq", "openssl", "env")},
            **scenario,
        }))
        for name in ("gh", "curl", "python3", "jq", "openssl", "cargo", "sudo",
                     "podman", "mountpoint", "aa-exec", "sleep", "env"):
            command = commands / name
            command.write_text(f"#!{sys.executable}\n" + SPY)
            command.chmod(0o700)
        env = dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}", FIXTURE=str(root),
                   MCLOVING_DOGFOOD_REPOSITORY="example/repository", MCLOVING_URL="http://fixture.invalid")
        return state, env

    def seed_bridge(self, state: Path) -> None:
        import importlib.util
        specification = importlib.util.spec_from_file_location("credential_lifecycle", DOGFOOD / "hook-lifecycle.py")
        assert specification and specification.loader
        lifecycle = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(lifecycle)
        lifecycle.begin(state)
        context = dict(repository="example/repository", organization="organization", project="project", pipeline="pipeline",
                       trigger="trigger", generation=1, source_generation="dogfood-1", route_url="http://fixture.invalid/hooks/toy", trigger_created=True)
        lifecycle.write_private(state / "sender-context.json", context)
        receipt = lifecycle.owner(state)
        receipt.update(context, repository_id=711, mode="bridge", previous_mode="none", phase="bridge-ready")
        lifecycle.write_private(state / "hook-owner.json", receipt)
        (state / "transition.lock").touch(mode=0o600)

    def entries(self, root: Path) -> list[dict]:
        return [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]

    def assert_private_arguments(self, entries: list[dict], output: str, error: str) -> None:
        for credential in (TOKEN, ARTIFACT_TOKEN, GITHUB_TOKEN, KEY):
            self.assertNotIn(credential, output + error)
            for entry in entries:
                self.assertNotIn(credential, " ".join(entry["argv"]))
                self.assertNotIn(credential, " ".join(entry["proc_cmdline"]))

    def test_bridge_signs_exact_payload_without_key_arguments(self) -> None:
        with TemporaryDirectory(prefix="mcloving-bridge-test-") as temporary:
            root = Path(temporary)
            state, environment = self.fixture(root)
            self.seed_bridge(state)
            (state / "hook.json").write_text(json.dumps({"path":"/hooks/toy", "secret":KEY}))
            (state / "hook.json").chmod(0o600)
            result = subprocess.run(["bash", str(DOGFOOD / "bridge.sh"), str(state), "once"],
                                    env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            entries = self.entries(root)
            self.assert_private_arguments(entries, result.stdout, result.stderr)
            deliveries = [entry for entry in entries if entry["command"] == "curl"]
            self.assertEqual(len(deliveries), 1)
            payload = bytes.fromhex(deliveries[0]["payload_hex"])
            self.assertEqual(json.loads(payload)["commits"][0]["modified"], ["toy.txt"])
            self.assertEqual(deliveries[0]["signature"], "sha256=" + hmac.new(KEY.encode(), payload, hashlib.sha256).hexdigest())
            for entry in entries:
                self.assertNotIn(deliveries[0]["signature"], " ".join(entry["argv"]))
                self.assertNotIn(deliveries[0]["signature"], " ".join(entry["proc_cmdline"]))
            self.assertNotIn(deliveries[0]["signature"], result.stdout + result.stderr)
            self.assertEqual(deliveries[0].get("header_mode"), 0o600)
            self.assertEqual(deliveries[0]["header_owner"], os.getuid())
            self.assertFalse(Path(deliveries[0]["header_file"]).exists())
            self.assertEqual(list(state.glob(".delivery-auth.*")), [])
            self.assertEqual((state / "last-delivered-event.example__repository.main").read_text(), "1001\n")

    def test_repeated_commit_distinct_push_ids_and_history_gap_refusal(self) -> None:
        with TemporaryDirectory(prefix="mcloving-bridge-identities-") as temporary:
            root = Path(temporary); state, environment = self.fixture(root)
            self.seed_bridge(state)
            (state / "hook.json").write_text(json.dumps({"path":"/hooks/toy","secret":KEY}))
            (state / "hook.json").chmod(0o600)
            command=["bash",str(DOGFOOD / "bridge.sh"),str(state),"once"]
            first=subprocess.run(command,env=environment,capture_output=True,text=True,timeout=30)
            self.assertEqual(first.returncode,0,first.stderr)
            scenario=json.loads((root / "scenario.json").read_text())
            def push(event):
                return {"id":event,"type":"PushEvent","payload":{"ref":"refs/heads/main","head":COMMIT},"created_at":"2026-01-01T00:00:00Z"}
            scenario["events"]=[push("1002"),push("1001")]
            (root / "scenario.json").write_text(json.dumps(scenario))
            second=subprocess.run(command,env=environment,capture_output=True,text=True,timeout=30)
            self.assertEqual(second.returncode,0,second.stderr)
            deliveries=[e for e in self.entries(root) if e["command"]=="curl"]
            self.assertEqual(len(deliveries),2)
            self.assertIn("X-GitHub-Delivery: 1001",deliveries[0]["argv"])
            self.assertIn("X-GitHub-Delivery: 1002",deliveries[1]["argv"])
            self.assertEqual(json.loads(bytes.fromhex(deliveries[0]["payload_hex"]))["after"],COMMIT)
            self.assertEqual(json.loads(bytes.fromhex(deliveries[1]["payload_hex"]))["after"],COMMIT)
            self.assertEqual((state / "last-delivered-event.example__repository.main").read_text(),"1002\n")
            scenario["events"]=[push("1003")]
            (root / "scenario.json").write_text(json.dumps(scenario))
            gap=subprocess.run(command,env=environment,capture_output=True,text=True,timeout=30)
            self.assertEqual(gap.returncode,0,gap.stderr)
            self.assertIn("history unresolved",gap.stderr)
            self.assertEqual(len([e for e in self.entries(root) if e["command"]=="curl"]),2)
            self.assertEqual((state / "last-delivered-event.example__repository.main").read_text(),"1002\n")

    def test_signer_rfc4231_vector(self) -> None:
        with TemporaryDirectory(prefix="mcloving-signature-test-") as temporary:
            root = Path(temporary)
            hook, payload = root / "hook.json", root / "payload"
            hook.write_text(json.dumps({"secret":"\x0b" * 20}))
            payload.write_bytes(b"Hi There")
            result = subprocess.run([sys.executable, str(DOGFOOD / "sign-hook.py"), str(hook), str(payload)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "sha256=b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

    def test_signer_key_is_absent_from_live_process_arguments(self) -> None:
        with TemporaryDirectory(prefix="mcloving-signer-proc-test-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            hook, payload = root / "hook.json", root / "payload.fifo"
            hook.write_text(json.dumps({"secret":"Jefe"}))
            hook.chmod(0o600)
            os.mkfifo(payload, 0o600)
            process = subprocess.Popen([sys.executable, str(DOGFOOD / "sign-hook.py"), str(hook), str(payload)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            writer = None
            try:
                # Opening a FIFO writer succeeds only after the actual signer
                # has loaded the key and opened its payload reader.
                for _ in range(300):
                    self.assertIsNone(process.poll())
                    try:
                        writer = os.open(payload, os.O_WRONLY | os.O_NONBLOCK)
                        break
                    except OSError as error:
                        if error.errno != errno.ENXIO:
                            raise
                        time.sleep(0.01)
                self.assertIsNotNone(writer, "signer did not open the payload FIFO")
                cmdline = Path(f"/proc/{process.pid}/cmdline").read_bytes()
                self.assertNotIn(b"Jefe", cmdline)
                self.assertIn(str(hook).encode(), cmdline)
                self.assertEqual(hook.stat().st_mode & 0o777, 0o600)
                os.write(writer, b"what do ya want for nothing?")
                os.close(writer)
                writer = None
                output, error = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, error)
                self.assertEqual(output.strip(), "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
            finally:
                if writer is not None:
                    os.close(writer)
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=10)

    def test_bridge_private_header_cleanup_after_transport_or_signer_failure(self) -> None:
        for failure in ("bridge", "signer", "missing", "malformed"):
            with self.subTest(failure=failure), TemporaryDirectory(prefix="mcloving-bridge-failure-") as temporary:
                root = Path(temporary)
                state, environment = self.fixture(root, failure=failure)
                self.seed_bridge(state)
                hook = {"path":"/hooks/toy", "secret":17 if failure == "signer" else KEY}
                if failure == "missing":
                    del hook["secret"]
                (state / "hook.json").write_text("{ malformed" if failure == "malformed" else json.dumps(hook))
                (state / "hook.json").chmod(0o600)
                result = subprocess.run(["bash", str(DOGFOOD / "bridge.sh"), str(state), "once"],
                                        env=environment, capture_output=True, text=True, timeout=30)
                if failure == "malformed":
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(list(state.glob(".delivery-auth.*")), [])
                self.assertFalse((state / "last-delivered-event.example__repository.main").exists())
                self.assertFalse((state / "deliveries.example__repository.main.tsv").exists())
                if failure != "bridge":
                    if failure == "signer":
                        self.assertIn("hook secret must be a string", result.stderr)
                    self.assertFalse(any(entry["command"] == "curl" for entry in self.entries(root)))
                self.assert_private_arguments(self.entries(root), result.stdout, result.stderr)

    def finish_overlap_request(self, process: subprocess.Popen) -> None:
        # Failure cleanup for this exact owned invocation. The real supervisor
        # starts its deployment child in a separate session: killing only the
        # supervisor's group cannot close that child's inherited pipes.
        import select
        faults, held = [], []
        def attempt(label, action):
            try:
                return action()
            except ProcessLookupError:
                return None
            except Exception as error:
                faults.append(label + ':' + type(error).__name__)
                return None
        def birth(pid):
            base = Path('/proc') / str(pid)
            if base.stat().st_uid != os.getuid():
                raise RuntimeError('cleanup_owner_changed')
            text = (base / 'stat').read_text()
            fields = text[text.rindex(')') + 2:].split()
            return (int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19]))
        def retain(pid, expected):
            fd = os.pidfd_open(pid)
            held.append(fd)
            if birth(pid) != expected:
                raise RuntimeError('cleanup_birth_changed')
            return fd
        def retain_children():
            parent = birth(process.pid)
            if parent[:3] != (os.getpid(), process.pid, process.pid):
                raise RuntimeError('cleanup_parent_custody_changed')
            with (Path('/proc') / str(process.pid) / 'task' / str(process.pid) / 'children').open() as source:
                raw = source.read(257)
            if len(raw) > 256 or len(raw.split()) > 8:
                raise RuntimeError('cleanup_children_bound')
            for value in raw.split():
                if not value.isdecimal():
                    raise RuntimeError('cleanup_child_identity')
                pid = int(value)
                observed = birth(pid)
                # Only the actual direct child in its own session is eligible;
                # no scan, guessed group or foreign process is terminated.
                if observed[:3] != (process.pid, pid, pid):
                    raise RuntimeError('cleanup_child_session_changed')
                fd = retain(pid, observed)
                children.append((pid, observed, fd))
            if birth(process.pid) != parent:
                raise RuntimeError('cleanup_parent_birth_changed')
        children = []
        if attempt('poll', process.poll) is None:
            attempt('retain_children', retain_children)
            attempt('term', process.terminate)
            attempt('cooperative_capture', lambda: process.communicate(timeout=3))
            # Retained child custody survives supervisor death/reap. Check it
            # independently: reparenting changes PPID, not the held identity.
            for pid, observed, fd in children:
                def kill_child(pid=pid, observed=observed, fd=fd):
                    if not select.select([fd], [], [], 0)[0]:
                        if birth(pid)[1:] != observed[1:]:
                            raise RuntimeError('cleanup_child_birth_changed')
                        os.killpg(pid, signal.SIGKILL)
                attempt('kill_child', kill_child)
            if attempt('poll_after_term', process.poll) is None:
                attempt('kill_parent', process.kill)
            # Always attempt terminal/reap independently of capture failure.
            attempt('terminal_wait', lambda: process.wait(timeout=5))
            attempt('final_capture', lambda: process.communicate(timeout=5))
            for _, _, fd in children:
                def child_terminal(fd=fd):
                    if not select.select([fd], [], [], 2)[0]:
                        raise RuntimeError('cleanup_child_terminal_unearned')
                attempt('child_terminal', child_terminal)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                attempt('close_stream', stream.close)
        for fd in held:
            attempt('close_pidfd', lambda fd=fd: os.close(fd))
        if process.returncode is None:
            faults.append('terminal_unearned')
        if faults:
            # Refusal remains failure even if a later cleanup attempt works.
            # Do not mask an already failing assertion with another exception.
            if sys.exc_info()[0] is None:
                raise RuntimeError('overlap_cleanup_refused:' + ','.join(faults))
            print('overlap_cleanup_refused:' + ','.join(faults), file=sys.stderr)

    def interrupt_request(self, command: list[str], environment: dict[str, str], root: Path, signum: int, *, expected_quiesce: bool = False, competing_bridge: bool = False) -> subprocess.CompletedProcess:
        if competing_bridge:
            self.assertTrue(expected_quiesce)
        process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            for _ in range(1000):
                if (root / "blocked.json").exists():
                    break
                self.assertIsNone(process.poll(), "script exited before entering the blocked credential request")
                time.sleep(0.01)
            self.assertTrue((root / "blocked.json").exists(), "request never blocked")
            blocked = json.loads((root / "blocked.json").read_text())
            self.assertTrue(Path(blocked.get("header_file", blocked.get("request_file"))).exists())
            if expected_quiesce:
                request = Path(blocked["request_file"])
                self.assertEqual(request.parent, root / "state")
                self.assertTrue(request.name.startswith(".hook-request."))
                self.assertEqual(request.lstat().st_mode & 0o777, 0o600)
                self.assertEqual(request.lstat().st_uid, os.getuid())
                self.assertFalse(request.is_symlink())
                self.assertEqual(blocked["command"], "gh")
                self.assertEqual(blocked["argv"], ["api", "-X", "PATCH",
                    "repos/example/repository/hooks/73", "--input", str(request)])
                self.assertEqual(blocked["request"], {"active": False})
                self.assertEqual(json.loads(request.read_text()), {"active": False})
                self.assertEqual(blocked["sender_phase"], "pending-quiesce")
                receipt = json.loads((root / "state" / "hook-owner.json").read_text())
                self.assertEqual(receipt["phase"], "pending-quiesce")
                self.assertEqual(receipt["hook_id"], 73)
                self.assertIs(receipt["hook_quiesced"], False)
                self.assertEqual(receipt["hook_url"], "https://fixture.invalid/hooks/toy")
                self.assertEqual(set(blocked["old_runtime_states"]), {"controller", "agent"})
                self.assertTrue(all(s not in {"absent", "Z", "X"}
                    for s in blocked["old_runtime_states"].values()))
                self.assertIs(json.loads((root / "owned-hook.json").read_text())["active"], False)
                if competing_bridge:
                    # Two real script/supervisor invocations share this one
                    # freshly owned state. No mocked Child or lock result.
                    import fcntl
                    state = root / "state"
                    def live_birth(pid):
                        base = Path("/proc") / str(pid)
                        self.assertEqual(base.stat().st_uid, os.getuid())
                        text = (base / "stat").read_text()
                        fields = text[text.rindex(")") + 2:].split()
                        self.assertNotIn(fields[0], {"Z", "X"})
                        return dict(pid=pid, uid=os.getuid(), ppid=int(fields[1]),
                                    pgrp=int(fields[2]), session=int(fields[3]), start_ticks=int(fields[19]))
                    self.assertIsNone(process.poll())
                    first_birth = live_birth(process.pid)
                    self.assertEqual(first_birth["ppid"], os.getpid())
                    self.assertEqual((first_birth["pgrp"], first_birth["session"]), (process.pid, process.pid))
                    old_pids = json.loads((root / "old-runtime-pids.json").read_text())
                    self.assertEqual(set(old_pids), {"controller", "agent"})
                    old_births = {role: live_birth(pid) for role, pid in old_pids.items()}
                    # These exist before quiesce; hook.json is generated only
                    # later, after the old-runtime fence and API setup.
                    names = ("hook-owner.json", "sender-context.json", "identities.env", "pki/ca.pem",
                             "controller.pid", "agent.pid", "controller-process.json", "agent-process.json")
                    self.assertFalse((state / "hook.json").exists())
                    before_state = {name: (state / name).read_bytes() for name in names}
                    before_hook = (root / "owned-hook.json").read_bytes()
                    before_ready = (root / "blocked.json").read_bytes()
                    before_request = request.read_bytes()
                    request_info = request.lstat()
                    before_names = sorted(path.name for path in state.iterdir())
                    before_calls = self.entries(root)
                    run_argv = [str(Path(command[1]).parent / "hook-lifecycle.py"), "run", str(state)]
                    first_runs = [entry for entry in before_calls if entry["command"] == "python3" and entry["argv"] == run_argv]
                    self.assertEqual(len(first_runs), 1)
                    self.assertEqual(first_runs[0]["birth"], first_birth)
                    self.assertEqual(first_runs[0]["requested_public_mode"], "1")
                    probe = os.open(state / "transition.lock", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
                    try:
                        lock_info = os.fstat(probe)
                        self.assertEqual(lock_info.st_uid, os.getuid())
                        self.assertEqual(lock_info.st_mode & 0o777, 0o600)
                        self.assertEqual(lock_info.st_nlink, 1)
                        matches = []
                        for ordinal, path in enumerate((Path("/proc") / str(process.pid) / "fd").iterdir()):
                            self.assertLess(ordinal, 64)
                            try:
                                info = path.stat()
                                if (info.st_dev, info.st_ino) == (lock_info.st_dev, lock_info.st_ino):
                                    matches.append(path.name)
                            except FileNotFoundError:
                                pass
                        self.assertEqual(len(matches), 1)
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        second_environment = dict(environment, MCLOVING_DOGFOOD_PUBLIC_HOOK="0")
                        second = subprocess.Popen(command, env=second_environment, stdout=subprocess.PIPE,
                                                  stderr=subprocess.PIPE, text=True, start_new_session=True)
                        try:
                            second_output, second_error = second.communicate(timeout=10)
                            self.assertEqual(second.returncode, 1, second_error)
                            self.assertIn("state_or_dependency_unavailable", second_error)
                            self.assertEqual(second_output, "")
                            after_calls = self.entries(root)
                            self.assertEqual(after_calls[:len(before_calls)], before_calls)
                            extra = after_calls[len(before_calls):]
                            self.assertEqual(len(extra), 1)
                            self.assertEqual(extra[0]["command"], "python3")
                            self.assertEqual(extra[0]["argv"], run_argv)
                            self.assertEqual(extra[0]["requested_public_mode"], "0")
                            birth = extra[0]["birth"]
                            self.assertEqual(birth["pid"], second.pid)
                            self.assertEqual((birth["uid"], birth["ppid"]), (os.getuid(), os.getpid()))
                            self.assertEqual((birth["pgrp"], birth["session"]), (second.pid, second.pid))
                            self.assertGreater(birth["start_ticks"], 0)
                            self.assertNotEqual(second.pid, process.pid)
                            self.assert_private_arguments(extra, second_output, second_error)
                        finally:
                            self.finish_overlap_request(second)
                        self.assertIsNone(process.poll())
                        self.assertEqual(live_birth(process.pid), first_birth)
                        self.assertEqual({role: live_birth(pid) for role, pid in old_pids.items()}, old_births)
                        self.assertEqual({name: (state / name).read_bytes() for name in names}, before_state)
                        self.assertEqual((root / "owned-hook.json").read_bytes(), before_hook)
                        self.assertEqual((root / "blocked.json").read_bytes(), before_ready)
                        self.assertEqual(request.read_bytes(), before_request)
                        after_request = request.lstat()
                        self.assertEqual((after_request.st_dev, after_request.st_ino, after_request.st_mode,
                                          after_request.st_uid, after_request.st_nlink, after_request.st_size),
                                         (request_info.st_dev, request_info.st_ino, request_info.st_mode,
                                          request_info.st_uid, request_info.st_nlink, request_info.st_size))
                        self.assertEqual(sorted(path.name for path in state.iterdir()), before_names)
                        self.assertFalse((state / "bridge.pid").exists())
                        self.assertFalse((state / "bridge-process.json").exists())
                        self.assertFalse((state / "hook.json").exists())
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(probe)
            os.killpg(process.pid, signum)
            output, error = process.communicate(timeout=10)
            return subprocess.CompletedProcess(command, process.returncode, output, error)
        finally:
            if competing_bridge:
                self.finish_overlap_request(process)
            elif process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=10)

    def test_bridge_private_header_cleanup_on_interrupt_and_terminate(self) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum), TemporaryDirectory(prefix="mcloving-bridge-signal-") as temporary:
                root = Path(temporary)
                state, environment = self.fixture(root, block="bridge")
                self.seed_bridge(state)
                (state / "hook.json").write_text(json.dumps({"path":"/hooks/toy", "secret":KEY}))
                (state / "hook.json").chmod(0o600)
                result = self.interrupt_request(["bash", str(DOGFOOD / "bridge.sh"), str(state), "once"], environment, root, signum)
                self.assertEqual(result.returncode, 128 + signum, result.stderr)
                self.assertEqual(list(state.glob(".delivery-auth.*")), [])
                self.assertFalse((state / "last-delivered-event.example__repository.main").exists())

    def run_deployment(self, hook_id: str = "", failure: str = "", existing: str = "404", interrupt: int | None = None, handoff_failure: str = "", signal_stage: str = "api", sealed_output: bool = False, overlap: bool = False) -> None:
        with TemporaryDirectory(prefix="mcloving-deploy-test-") as temporary:
            root = Path(temporary)
            state, environment = self.fixture(root, hook_id=hook_id, failure=failure, existing=existing,
                                              block=signal_stage if interrupt else "", handoff_failure=handoff_failure)
            scripts = root / "scripts" / "dogfood"
            scripts.mkdir(parents=True)
            for name in ("heman-up.sh", "bridge.sh", "sign-hook.py", "hook-lifecycle.py"):
                shutil.copyfile(DOGFOOD / name, scripts / name)
            (root / "tools").mkdir()
            (root / "tools" / "versions.env").write_text("MCLOVING_POSTGRES_IMAGE=public-toy-image\n")
            (root / ".mcloving").mkdir()
            (root / ".mcloving" / "pipeline.yaml").write_text("version: 1\n")
            binaries = root / "target" / "debug"
            (binaries / "examples").mkdir(parents=True)
            for name in ("mcloving-cli", "mcloving-identity-admin"):
                path = binaries / name
                path.write_text(f"#!{sys.executable}\n" + SPY)
                path.chmod(0o700)
            for name in ("mcloving-controller", "mcloving-agent"):
                path = binaries / name
                path.write_text(f"#!{sys.executable}\nimport json, os, pathlib, sys, time\n"
                                f"pathlib.Path({str(root / (name + '-environment.json'))!r}).write_text(json.dumps({{'argv':sys.argv, 'api_token':os.getenv('MCLOVING_API_TOKEN'), 'artifact_token':os.getenv('MCLOVING_ARTIFACT_AGENT_TOKEN'), 'parent_sentinel':os.getenv('PARENT_SECRET_SENTINEL')}}))\ntime.sleep(60)\n")
                path.chmod(0o700)
            render = binaries / "examples" / "render_source_binding"
            render.write_text(f"#!{sys.executable}\n" + SPY)
            render.chmod(0o700)
            (state / "pki").mkdir()
            (state / "pki" / "ca.pem").write_text("PUBLIC TOY CERTIFICATE")
            (state / "identities.env").write_text(
                "organization_id=organization\nproject_id=project\npipeline_id=pipeline\n"
                f"trigger_id=trigger\napi_token={TOKEN}\nartifact_token={ARTIFACT_TOKEN}\nagent_id=toy-agent\n")
            (state / "identities.env").chmod(0o600)
            if hook_id:
                import importlib.util
                specification = importlib.util.spec_from_file_location("retained_credential_lifecycle", scripts / "hook-lifecycle.py")
                assert specification and specification.loader
                lifecycle = importlib.util.module_from_spec(specification); specification.loader.exec_module(lifecycle)
                lifecycle.begin(state)
                receipt = lifecycle.owner(state)
                receipt.update(repository_id=711, repository="example/repository", organization="organization", project="project", pipeline="pipeline",
                               trigger="trigger", generation=3, source_generation="dogfood-3", route_url="https://fixture.invalid/hooks/toy",
                               hook_url="https://fixture.invalid/hooks/toy", hook_id=int(hook_id), mode="public", previous_mode="public", phase="public-ready")
                lifecycle.write_private(state / "hook-owner.json", receipt)
                lifecycle.write_private(state / 'sender-context.json', {key:receipt[key] for key in
                    ('repository','organization','project','pipeline','trigger','generation','source_generation','route_url','trigger_created')})
                (root / "owned-hook.json").write_text(json.dumps({"id":int(hook_id),"name":"web","active":True,"events":["push"],
                    "config":{"url":"https://fixture.invalid/hooks/toy","content_type":"json","insecure_ssl":"0"}}))
            environment.update(MCLOVING_DOGFOOD_PUBLIC_HOOK="1",
                               MCLOVING_DOGFOOD_PUBLIC_BASE_URL="https://fixture.invalid",
                               MCLOVING_DOGFOOD_TRANSPORT_ROOT=str(root / "transport"),
                               PARENT_SECRET_SENTINEL="PUBLIC-TOY-PARENT-SECRET")
            old_children = []
            def reap_old_fixture_children():
                for child in old_children:
                    if child.poll() is None: child.terminate()
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=5)
            # Also cover setup/assertion failures before the command's finally.
            self.addCleanup(reap_old_fixture_children)
            if hook_id:
                # Genuine local toy runtime processes establish stop ordering;
                # no product binary, hook, provider or native deployment runs.
                pids = {}
                for role in ('controller', 'agent'):
                    binary = binaries / ('mcloving-' + role)
                    child = subprocess.Popen([str(binary)], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    old_children.append(child)
                    (state / (role + '.pid')).write_text(str(child.pid))
                    lifecycle.record_pid(state, role, child.pid, str(binary))
                    pids[role] = child.pid
                (root / 'old-runtime-pids.json').write_text(json.dumps(pids))
            foreign = root / 'unrelated-readonly-tree'
            if sealed_output:
                foreign.mkdir(mode=0o700)
                (foreign / 'kept').write_text('unrelated preserved fixture')
                (foreign / 'kept').chmod(0o400); foreign.chmod(0o500)
                tree = state / 'source-output' / 'acquisition' / 'tree' / 'nested'
                tree.mkdir(parents=True, mode=0o700)
                (tree / 'file').write_text('actual readonly prior output')
                (tree / 'file').chmod(0o400)
                (tree / 'unrelated-link').symlink_to(foreign, target_is_directory=True)
                for path in (tree, tree.parent, tree.parent.parent, tree.parent.parent.parent): path.chmod(0o500)
            command = ["bash", str(scripts / "heman-up.sh"), str(state)]
            try:
                result = self.interrupt_request(command, environment, root, interrupt,
                    expected_quiesce=signal_stage == "quiesce", competing_bridge=overlap) if interrupt else subprocess.run(
                    command, env=environment, capture_output=True, text=True, timeout=30)
            finally:
                old_status_before_fixture_cleanup = [child.poll() for child in old_children]
                for role in ("controller", "agent"):
                    pid_path = state / (role + ".pid")
                    if pid_path.exists():
                        try:
                            held = os.pidfd_open(int(pid_path.read_text().strip()))
                            try: signal.pidfd_send_signal(held, signal.SIGTERM)
                            finally: os.close(held)
                        except ProcessLookupError:
                            pass
                reap_old_fixture_children()
            if signal_stage == "quiesce":
                # Check the cancelled early branch before downstream-success
                # assertions that require controller/API work it must prevent.
                self.assertIn(interrupt, (signal.SIGINT, signal.SIGTERM))
                self.assertEqual(hook_id, "73")
                self.assertEqual(result.returncode, 128 + interrupt, result.stderr)
                self.assertEqual(old_status_before_fixture_cleanup, [None, None])
                entries = self.entries(root)
                self.assert_private_arguments(entries, result.stdout, result.stderr)
                self.assertFalse(any(e["command"] in {"cargo", "podman", "sudo", "curl", "env",
                    "mcloving-cli", "mcloving-identity-admin", "render_source_binding"} for e in entries))
                self.assertFalse(any(e["command"] == "python3" and e["argv"][1:2] == ["stop"] for e in entries))
                requests = [e for e in entries if "request" in e]
                self.assertEqual(len(requests), 1)
                self.assertEqual(requests[0]["request"], {"active": False})
                self.assertEqual(requests[0]["sender_phase"], "pending-quiesce")
                self.assertEqual(requests[0]["request_mode"], 0o600)
                self.assertEqual(requests[0]["request_owner"], os.getuid())
                self.assertFalse(Path(requests[0]["request_file"]).exists())
                self.assertFalse(any(e["command"] == "gh" and "POST" in e["argv"] for e in entries))
                self.assertEqual(list(state.glob(".hook-request.*")), [])
                self.assertEqual(list(state.glob(".api-auth.*")), [])
                self.assertEqual(list(state.glob("deliveries.*.tsv")), [])
                self.assertEqual(list(state.glob("last-delivered-event.*")), [])
                receipt = lifecycle.owner(state)
                self.assertEqual(receipt["hook_id"], 73)
                self.assertEqual(receipt["phase"], "pending-quiesce")
                self.assertIs(receipt["hook_quiesced"], False)
                self.assertIs(json.loads((root / "owned-hook.json").read_text())["active"], False)
                before = (state / "hook-owner.json").read_bytes()
                from unittest.mock import patch
                with patch.dict(os.environ, environment, clear=True):
                    with self.assertRaisesRegex(lifecycle.Refused, "uncertain_previous_transition"):
                        lifecycle.begin(state)
                self.assertEqual((state / "hook-owner.json").read_bytes(), before)
                # The real supervisor must release its one held lock after
                # terminal cancellation, without weakening the uncertain phase.
                import fcntl
                held = os.open(state / "transition.lock", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(held)
                return
            if failure in {'early-disable', 'early-readback'}:
                self.assertEqual(result.returncode, 23, result.stderr)
                entries = self.entries(root)
                self.assert_private_arguments(entries, result.stdout, result.stderr)
                self.assertEqual(old_status_before_fixture_cleanup, [None, None])
                self.assertFalse(any(e['command'] in {'cargo','podman','sudo','curl'} for e in entries))
                self.assertFalse(any(e['command']=='python3' and e['argv'][1:2]==['stop'] for e in entries))
                self.assertEqual(json.loads((state/'hook-owner.json').read_text())['phase'], 'pending-quiesce')
                self.assertEqual(list(state.glob('.hook-request.*')), [])
                return
            if handoff_failure:
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse((root / "mcloving-controller-environment.json").exists())
                self.assertFalse(any(entry["command"] == "curl" for entry in self.entries(root)))
                controller_error = (state / "controller.log").read_text()
                self.assertIn("No such file" if handoff_failure == "missing" else "missing API token", controller_error)
                return
            self.assertEqual(result.returncode, 128 + interrupt if interrupt else 23 if failure else 0, result.stderr)
            entries = self.entries(root)
            self.assert_private_arguments(entries, result.stdout, result.stderr)
            captured = root / "mcloving-controller-environment.json"
            for _ in range(100):
                if captured.exists():
                    break
                time.sleep(0.01)
            controller = json.loads(captured.read_text())
            self.assertEqual(controller["api_token"], TOKEN)
            self.assertEqual(controller["artifact_token"], ARTIFACT_TOKEN)
            self.assertIsNone(controller["parent_sentinel"])
            self.assertNotIn(TOKEN, " ".join(controller["argv"]))
            requests = [entry for entry in entries if "header_file" in entry]
            self.assertGreaterEqual(len(requests), 1)
            for request in requests:
                self.assertEqual(request["header_mode"], 0o600)
                self.assertEqual(request["header_owner"], os.getuid())
                self.assertEqual(request["header_content"], f"Authorization: Bearer {TOKEN}\n")
                self.assertFalse(Path(request["header_file"]).exists())
            self.assertEqual(list(state.glob(".api-auth.*")), [])
            self.assertEqual(list(state.glob(".hook-request.*")), [])
            registrations = [entry for entry in entries if "request" in entry]
            if hook_id and not interrupt:
                quiesce = next(e for e in registrations if e.get('sender_phase') == 'pending-quiesce')
                self.assertEqual(quiesce['request'], {'active':False})
                self.assertTrue(all(s not in {'absent','Z','X'} for s in quiesce['old_runtime_states'].values()))
                fence_index = next(i for i,e in enumerate(entries) if e['command']=='gh' and
                    e.get('sender_phase')=='pending-quiesce' and 'request' not in e and
                    'repos/example/repository/hooks/73' in e['argv'])
                effects = [i for i,e in enumerate(entries) if e['command'] in {'cargo','podman','sudo','curl','env'} or
                           (e['command']=='python3' and e['argv'][1:2]==['stop'])]
                self.assertTrue(effects); self.assertTrue(all(i > fence_index for i in effects))
                self.assertEqual(quiesce['request_mode'],0o600)
                self.assertEqual(quiesce['request_owner'],os.getuid())
                self.assertFalse(Path(quiesce['request_file']).exists())
                registrations = [e for e in registrations if e is not quiesce]
            if sealed_output:
                self.assertFalse((state/'source-output/acquisition').exists())
                self.assertEqual(foreign.stat().st_mode & 0o777,0o500)
                self.assertEqual((foreign/'kept').stat().st_mode & 0o777,0o400)
                self.assertEqual((foreign/'kept').read_text(),'unrelated preserved fixture')
            trigger_puts = [entry for entry in entries if entry["command"] == "curl" and "PUT" in entry["argv"]]
            if not failure or failure == "registration":
                self.assertEqual(len(trigger_puts), 1)
                put_headers = trigger_puts[0]["argv"]
                self.assertIn('If-Match: "3"' if existing == "200" else 'If-Match: "0"', put_headers)
                trigger_body = json.loads(put_headers[put_headers.index("--data") + 1])
                self.assertEqual(trigger_body["source_generation"], "dogfood-4" if existing == "200" else "dogfood-1")
                self.assertEqual(trigger_body["configuration"]["repository_identity"], "example/repository")
            if not failure or failure == "registration":
                expected_count = 1 if failure == "registration" else 2
                self.assertEqual(len(registrations), expected_count)
                registration = registrations[0]
                for request in registrations:
                    self.assertEqual(request["request_mode"], 0o600)
                    self.assertEqual(request["request_owner"], os.getuid())
                    self.assertFalse(Path(request["request_file"]).exists())
                expected = {"active":False, "events":["push"], "config":{
                    "url":"https://fixture.invalid/hooks/toy", "content_type":"json", "secret":KEY, "insecure_ssl":"0"}}
                if not hook_id: expected["name"] = "web"
                self.assertEqual(registration["request"], expected)
                self.assertIn("PATCH" if hook_id else "POST", registration["argv"])
                if not failure:
                    self.assertEqual(registrations[1]["request"], {"active":True})
                    self.assertIn("PATCH", registrations[1]["argv"])
                    self.assertIn("repos/example/repository/hooks/73", registrations[1]["argv"])
                    receipt = json.loads((state / "hook-owner.json").read_text())
                    self.assertEqual(receipt["hook_id"],73)
                    self.assertEqual(receipt["phase"],"public-ready")

    def test_public_hook_post_credentials(self) -> None:
        self.run_deployment()

    def test_public_hook_patch_credentials(self) -> None:
        self.run_deployment(hook_id="73", existing="200")

    def test_private_request_cleanup_on_failures(self) -> None:
        for failure in ("initial", "put", "webhook", "registration"):
            with self.subTest(failure=failure):
                self.run_deployment(failure=failure)

    def test_private_controller_handoff_refuses_missing_or_empty_identity(self) -> None:
        for failure in ("missing", "empty"):
            with self.subTest(failure=failure):
                self.run_deployment(handoff_failure=failure)

    def test_private_request_cleanup_on_interrupt_and_terminate(self) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum):
                self.run_deployment(failure="signal", interrupt=signum)
    def test_private_hook_request_cleanup_on_interrupt_and_terminate(self) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum):
                self.run_deployment(failure="signal", interrupt=signum, signal_stage="registration")

    def test_owned_public_quiescence_precedes_all_runtime_deployment_effects(self) -> None:
        self.run_deployment(hook_id='73',existing='200')

    def test_owned_public_quiescence_failure_preserves_old_runtime(self) -> None:
        for failure in ('early-disable','early-readback'):
            with self.subTest(failure=failure): self.run_deployment(hook_id='73',existing='200',failure=failure)

    def test_same_mode_restart_removes_actual_sealed_readonly_output_only(self) -> None:
        self.run_deployment(hook_id='73',existing='200',sealed_output=True)

    def test_retained_public_quiesce_request_cleanup_on_interrupt(self) -> None:
        self.run_deployment(hook_id="73", existing="200", interrupt=signal.SIGINT,
                            signal_stage="quiesce")

    def test_retained_public_quiesce_request_cleanup_on_terminate(self) -> None:
        self.run_deployment(hook_id="73", existing="200", interrupt=signal.SIGTERM,
                            signal_stage="quiesce")

    def test_overlapping_bridge_deployment_refused_before_effects(self) -> None:
        self.run_deployment(hook_id="73", existing="200", interrupt=signal.SIGTERM,
                            signal_stage="quiesce", overlap=True)



if __name__ == "__main__":
    unittest.main()
