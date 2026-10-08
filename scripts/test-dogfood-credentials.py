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
if ((scenario.get("block") == "api" and name == "curl" and entry.get("header_file")) or
    (scenario.get("block") == "bridge" and name == "curl" and entry.get("payload_hex")) or
    (scenario.get("block") == "registration" and name == "gh" and entry.get("request_file"))):
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

    def interrupt_request(self, command: list[str], environment: dict[str, str], root: Path, signum: int) -> subprocess.CompletedProcess:
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
            os.killpg(process.pid, signum)
            output, error = process.communicate(timeout=10)
            return subprocess.CompletedProcess(command, process.returncode, output, error)
        finally:
            if process.poll() is None:
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

    def run_deployment(self, hook_id: str = "", failure: str = "", existing: str = "404", interrupt: int | None = None, handoff_failure: str = "", signal_stage: str = "api", sealed_output: bool = False) -> None:
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
                result = self.interrupt_request(command, environment, root, interrupt) if interrupt else subprocess.run(
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



if __name__ == "__main__":
    unittest.main()
