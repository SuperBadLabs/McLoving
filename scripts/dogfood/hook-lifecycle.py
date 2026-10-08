#!/usr/bin/env python3
"""Owner-private dogfood sender lifecycle. No credential/payload diagnostics.

The supervisor owns a CLOEXEC flock for the entire heman deployment. A create
intent is durable before the inactive POST; its returned ID is durable before
activation. Uncertain effects are never resolved by a second POST or URL search.
Cross-mode delivery identity reconciliation is not supplied by today's public
controller API: that transition remains explicitly blocked, after old sender
termination/disable, rather than pretending a SHA is a delivery identity.
"""
from __future__ import annotations

import fcntl
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid

HERE = pathlib.Path(__file__).resolve().parent
PROTOCOL = 'mcloving.dogfood-hook-owner/v2'
READY = {'public-ready', 'bridge-ready'}
MAX_JSON = 4 * 1024 * 1024


class Refused(Exception):
    pass


def fail(code: str) -> None:
    raise Refused(code)


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail('duplicate_field')
        value[key] = item
    return value


def decode(data: bytes):
    if len(data) > MAX_JSON:
        fail('oversize_metadata')
    return json.loads(data, object_pairs_hook=unique)


def private_dir(path: pathlib.Path) -> pathlib.Path:
    # Do not chmod an attacker-selected/symlinked existing directory.
    path = pathlib.Path(os.path.abspath(path))
    for part in [path, *path.parents]:
        if part.is_symlink():
            fail('symlink_state')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        fail('state_owner_mode')
    return path


def read_private(path: pathlib.Path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            fail('metadata_owner_mode')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            data = source.read(MAX_JSON + 1)
        after = os.fstat(fd)
        if any(getattr(after, field) != getattr(info, field) for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')):
            fail('metadata_changed')
        return decode(data)
    finally:
        os.close(fd)


def write_private(path: pathlib.Path, value) -> None:
    directory = private_dir(path.parent)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def process(pid: int) -> dict:
    base = pathlib.Path('/proc') / str(pid)
    if base.stat().st_uid != os.getuid():
        fail('process_owner_changed')
    text = (base / 'stat').read_text()
    fields = text[text.rindex(')') + 2:].split()
    argv = (base / 'cmdline').read_bytes().split(b'\0')
    return {'pid': pid, 'start_ticks': int(fields[19]), 'parent': int(fields[1]), 'state': fields[0],
            'image': str((base / 'exe').resolve(strict=True)),
            'argv': [a.decode() for a in argv if a]}


def held_lock(state: pathlib.Path) -> None:
    """Authenticate the actual supervisor/child relationship, not an env flag."""
    child = process(os.getppid())
    supervisor = process(child['parent'])
    script = str(HERE / 'heman-up.sh')
    if child['argv'][-3:] != [script, str(state), '--under-transition-lock']:
        fail('not_deployment_child')
    expected = [str(HERE / 'hook-lifecycle.py'), 'run', str(state)]
    if supervisor['argv'][1:] != expected or supervisor['image'] != str(pathlib.Path(sys.executable).resolve()):
        fail('not_lock_supervisor')
    info = (state / 'transition.lock').stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        fail('lock_owner_mode')
    matches = []
    for fd in (pathlib.Path('/proc') / str(supervisor['pid']) / 'fd').iterdir():
        try:
            observed = fd.stat()
            if (observed.st_dev, observed.st_ino) == (info.st_dev, info.st_ino):
                matches.append(fd)
        except FileNotFoundError:
            continue
    if len(matches) != 1:
        fail('supervisor_lock_custody')
    probe = os.open(state / 'transition.lock', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        fail('transition_lock_not_held')
    finally:
        os.close(probe)


def supervise(state: pathlib.Path) -> int:
    fd = os.open(state / 'transition.lock', os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            fail('lock_owner_mode')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        child = subprocess.Popen(['/bin/bash', str(HERE / 'heman-up.sh'), str(state), '--under-transition-lock'],
                                 close_fds=True, start_new_session=True)
        def forward(signum, _frame):
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                pass
        old = {s: signal.signal(s, forward) for s in (signal.SIGINT, signal.SIGTERM)}
        try:
            code = child.wait()
        finally:
            for s, handler in old.items():
                signal.signal(s, handler)
        return 128 - code if code < 0 else code
    finally:
        os.close(fd)


def owner(state: pathlib.Path) -> dict:
    value = read_private(state / 'hook-owner.json')
    fields = {'protocol', 'owner_uid', 'state_device', 'state_inode', 'deployment_id', 'operation_id', 'phase',
              'mode', 'previous_mode', 'repository_id', 'repository', 'organization', 'project', 'pipeline',
              'trigger', 'generation', 'source_generation', 'route_url', 'hook_id', 'hook_url', 'trigger_created',
              'pending_input', 'hook_quiesced'}
    if not isinstance(value, dict) or set(value) != fields or value['protocol'] != PROTOCOL:
        fail('invalid_owner_receipt')
    for field in ('owner_uid', 'state_device', 'state_inode'):
        if type(value[field]) is not int or value[field] < 0:
            fail('invalid_owner_identity')
    if value['repository_id'] is not None and (type(value['repository_id']) is not int or value['repository_id'] <= 0):
        fail('invalid_repository_identity')
    info = state.stat()
    if (value['owner_uid'], value['state_device'], value['state_inode']) != (os.getuid(), info.st_dev, info.st_ino):
        fail('foreign_owner_receipt')
    for field in ('deployment_id', 'operation_id'):
        if str(uuid.UUID(value[field])) != value[field]:
            fail('invalid_operation_identity')
    if value['hook_id'] is not None and (type(value['hook_id']) is not int or value['hook_id'] <= 0):
        fail('invalid_retained_hook_id')
    if value['mode'] not in {'none', 'public', 'bridge'} or value['previous_mode'] not in {'none', 'public', 'bridge'}:
        fail('invalid_sender_mode')
    if type(value['hook_quiesced']) is not bool:
        fail('invalid_quiescence_observation')
    return value


def begin(state: pathlib.Path) -> None:
    repository = os.environ.get('MCLOVING_DOGFOOD_REPOSITORY', 'SuperBadLabs/McLoving')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or os.environ.get('MCLOVING_DOGFOOD_PUBLIC_HOOK', '0') not in {'0', '1'}:
        fail('invalid_configured_sender')
    if (state / 'hook-owner.json').exists():
        receipt = owner(state)
        if receipt['repository'] != repository:
            fail('retained_hook_repository_changed')
        if receipt['phase'] not in READY:
            fail('uncertain_previous_transition')
        receipt['previous_mode'] = receipt['mode']
        receipt['phase'] = 'deploying'
        receipt['operation_id'] = str(uuid.uuid4())
        receipt['hook_quiesced'] = False
    else:
        if any((state / name).exists() for name in ('hook.json', 'bridge.pid', 'webhook.key')) or list(state.glob('deliveries.*.tsv')) or list(state.glob('last-delivered-event.*')):
            fail('unrecorded_sender_history')
        info = state.stat()
        receipt = dict.fromkeys({'repository_id', 'repository', 'organization', 'project', 'pipeline', 'trigger',
                                 'generation', 'source_generation', 'route_url', 'hook_id', 'hook_url'})
        receipt.update(protocol=PROTOCOL, owner_uid=os.getuid(), state_device=info.st_dev, state_inode=info.st_ino,
                       deployment_id=str(uuid.uuid4()), operation_id=str(uuid.uuid4()), phase='deploying',
                       mode='none', previous_mode='none', trigger_created=False, pending_input=None, hook_quiesced=False)
    write_private(state / 'hook-owner.json', receipt)


def phase(state: pathlib.Path, receipt: dict, value: str) -> None:
    receipt['phase'] = value
    write_private(state / 'hook-owner.json', receipt)


def repository_api(repository: str) -> dict:
    if not isinstance(repository, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        fail('invalid_repository')
    value = gh('GET', f'repos/{repository}')
    if not isinstance(value, dict) or value.get('full_name') != repository or type(value.get('id')) is not int or value['id'] <= 0 or value.get('permissions', {}).get('admin') is not True:
        fail('repository_admin_readback')
    return value


def gh(method: str, endpoint: str, body: dict | None = None, state: pathlib.Path | None = None):
    args = ['gh', 'api', '-X', method, endpoint]
    temporary = None
    try:
        if body is not None:
            if state is None:
                fail('missing_request_custody')
            fd, temporary = tempfile.mkstemp(prefix='.hook-request.', dir=state)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as output:
                json.dump(body, output)
            args += ['--input', temporary]
        return captured_api(args)
    finally:
        if temporary is not None:
            pathlib.Path(temporary).unlink(missing_ok=True)


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def captured_api(args: list[str]):
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
    try:
        output, _ = child.communicate(timeout=60)
    except BaseException:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill(); child.wait()
        raise
    if child.returncode:
        raise ExternalFailure(child.returncode)
    return decode(output)


class ExternalFailure(Exception):
    def __init__(self, code):
        self.code = code


def hooks(repository: str) -> list:
    # gh owns Link pagination; --slurp retains page boundaries, not a jq search.
    pages = captured_api(['gh', 'api', f'repos/{repository}/hooks?per_page=100', '--paginate', '--slurp'])
    if not isinstance(pages, list) or not 1 <= len(pages) <= 64 or any(not isinstance(p, list) or len(p) > 100 for p in pages):
        fail('incomplete_repository_hook_inventory')
    entries = [item for page in pages for item in page]
    ids = []
    for item in entries:
        if not isinstance(item, dict) or type(item.get('id')) is not int or item['id'] <= 0 or not isinstance(item.get('config'), dict):
            fail('malformed_repository_hook_inventory')
        ids.append(item['id'])
    if len(set(ids)) != len(ids):
        fail('duplicate_hook_inventory')
    return entries


def verify_hook(value, hook_id: int | None, url: str, active: bool) -> int:
    if not isinstance(value, dict) or type(value.get('id')) is not int or value['id'] <= 0:
        fail('malformed_hook_response')
    if hook_id is not None and value['id'] != hook_id:
        fail('wrong_hook_id')
    config = value.get('config')
    if value.get('name') != 'web' or value.get('active') is not active or value.get('events') != ['push'] or not isinstance(config, dict) or config.get('url') != url or config.get('content_type') != 'json' or str(config.get('insecure_ssl')) != '0':
        fail('hook_configuration_readback')
    return value['id']


def quiesce(state: pathlib.Path) -> None:
    """Fence the exact old owned public sender before touching its runtime.

    This observes GitHub inactive state, not exhausted retries/in-flight work.
    Any uncertain API or durable-write effect prevents deployment continuation.
    """
    receipt = owner(state)
    if receipt['phase'] != 'deploying' or receipt['hook_quiesced']:
        fail('quiescence_not_prepared')
    if receipt['previous_mode'] != 'public':
        return
    if receipt['hook_id'] is None or not isinstance(receipt['hook_url'], str):
        fail('missing_owned_public_hook')
    context = read_private(state / 'sender-context.json')
    fields = {'repository', 'organization', 'project', 'pipeline', 'trigger', 'generation', 'source_generation', 'route_url', 'trigger_created'}
    if not isinstance(context, dict) or set(context) != fields or any(context[k] != receipt[k] for k in fields):
        fail('old_sender_binding_changed')
    if os.environ.get('MCLOVING_DOGFOOD_REPOSITORY', 'SuperBadLabs/McLoving') != receipt['repository']:
        fail('old_sender_repository_changed')
    repo = repository_api(receipt['repository'])
    if repo['id'] != receipt['repository_id']:
        fail('old_repository_identity_changed')
    inventory = hooks(receipt['repository'])
    owned = [h for h in inventory if h['id'] == receipt['hook_id']]
    if len(owned) != 1 or any(h['id'] != receipt['hook_id'] and h['config'].get('url') == receipt['hook_url'] for h in inventory):
        fail('old_hook_inventory_changed')
    verify_hook(owned[0], receipt['hook_id'], receipt['hook_url'], True)
    endpoint = f"repos/{receipt['repository']}/hooks/{receipt['hook_id']}"
    verify_hook(gh('GET', endpoint), receipt['hook_id'], receipt['hook_url'], True)
    phase(state, receipt, 'pending-quiesce')
    verify_hook(gh('PATCH', endpoint, {'active': False}, state), receipt['hook_id'], receipt['hook_url'], False)
    verify_hook(gh('GET', endpoint), receipt['hook_id'], receipt['hook_url'], False)
    receipt['hook_quiesced'] = True
    phase(state, receipt, 'deploying')


def writable_output(state: pathlib.Path) -> None:
    """Restore owner write access only on retained owned output directories.

    Files/hardlinks/symlink targets are never chmodded. Directory descriptors
    keep traversal relative to this private state; foreign/device/type drift
    refuses removal. Concurrent mutation by the owner is still a trust residual.
    """
    receipt = owner(state)
    if receipt['phase'] != 'deploying' or (receipt['previous_mode'] == 'public' and not receipt['hook_quiesced']):
        fail('output_reclaim_not_prepared')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        root = os.open(state / 'source-output', flags)
    except FileNotFoundError:
        return
    pending = []
    device = state.stat().st_dev
    deadline = time.monotonic() + 60
    count = 0
    def enter(descriptor):
        try:
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid() or info.st_dev != device or not stat.S_ISDIR(info.st_mode):
                fail('foreign_output_directory')
            os.fchmod(descriptor, stat.S_IMODE(info.st_mode) | stat.S_IWUSR)
            pending.append((descriptor, iter(os.listdir(descriptor))))
        except BaseException:
            os.close(descriptor)
            raise
    try:
        enter(root)
        while pending:
            active, entries = pending[-1]
            try:
                name = next(entries)
            except StopIteration:
                os.close(active)
                pending.pop()
                continue
            count += 1
            if count > 20_000 * 4096 + 4096 or time.monotonic() >= deadline:
                fail('output_reclaim_budget_exceeded')
            entry = os.stat(name, dir_fd=active, follow_symlinks=False)
            if entry.st_uid != os.getuid() or entry.st_dev != device:
                fail('foreign_output_entry')
            if stat.S_ISDIR(entry.st_mode):
                child = os.open(name, flags, dir_fd=active)
                actual = os.fstat(child)
                if (actual.st_dev, actual.st_ino) != (entry.st_dev, entry.st_ino):
                    os.close(child)
                    fail('output_directory_changed')
                enter(child)
            elif not (stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode)):
                fail('unexpected_output_entry')
    finally:
        for descriptor, _entries in pending:
            os.close(descriptor)


def reconcile(state: pathlib.Path, mode: str) -> None:
    if mode not in {'public', 'bridge'}:
        fail('invalid_target_mode')
    receipt = owner(state)
    if receipt['phase'] != 'deploying':
        fail('transition_not_prepared')
    if receipt['previous_mode'] == 'public' and not receipt['hook_quiesced']:
        fail('old_public_sender_not_quiesced')
    context = read_private(state / 'sender-context.json')
    fields = {'repository', 'organization', 'project', 'pipeline', 'trigger', 'generation', 'source_generation', 'route_url', 'trigger_created'}
    if not isinstance(context, dict) or set(context) != fields or type(context['generation']) is not int or context['generation'] < 1 or type(context['trigger_created']) is not bool:
        fail('invalid_trigger_context')
    for key in ('organization', 'project', 'pipeline', 'trigger', 'source_generation'):
        if not isinstance(context[key], str) or not context[key] or len(context[key]) > 128:
            fail('invalid_trigger_binding')
    if not isinstance(context['route_url'], str) or any(ord(c) < 33 for c in context['route_url']):
        fail('invalid_route_url')
    url = urllib.parse.urlsplit(context['route_url'])
    if url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password or url.query or url.fragment or not url.path.startswith('/') or (mode == 'public' and url.scheme != 'https'):
        fail('invalid_route_url')
    repo = repository_api(context['repository'])
    if receipt['repository_id'] is not None and any(receipt[key] != value for key, value in (
            ('repository_id', repo['id']), ('repository', context['repository']), ('organization', context['organization']),
            ('project', context['project']), ('pipeline', context['pipeline']), ('trigger', context['trigger']))):
        fail('retained_hook_binding_changed')
    receipt.update(context)
    receipt['repository_id'] = repo['id']
    write_private(state / 'hook-owner.json', receipt)
    inventory = hooks(context['repository'])
    owned_id = receipt['hook_id']
    matching = [h for h in inventory if h['config'].get('url') in {receipt['hook_url'], context['route_url']}]
    if any(h['id'] != owned_id for h in matching):
        fail('unowned_hook_on_configured_route')
    if owned_id is not None:
        retained = gh('GET', f"repos/{context['repository']}/hooks/{owned_id}")
        verify_hook(retained, owned_id, receipt['hook_url'], receipt['previous_mode'] == 'public' and not receipt['hook_quiesced'])
        if len([h for h in inventory if h['id'] == owned_id]) != 1:
            fail('retained_hook_missing_from_repository')
    elif receipt['previous_mode'] != 'none' and receipt['previous_mode'] != 'bridge':
        fail('unrecorded_public_hook')
    if receipt['previous_mode'] == 'none' and not context['trigger_created']:
        fail('unrecorded_existing_trigger_history')
    if mode == 'bridge' and owned_id is not None:
        phase(state, receipt, 'pending-disable')
        answer = gh('PATCH', f"repos/{context['repository']}/hooks/{owned_id}", {'active': False}, state)
        verify_hook(answer, owned_id, receipt['hook_url'], False)
        verify_hook(gh('GET', f"repos/{context['repository']}/hooks/{owned_id}"), owned_id, receipt['hook_url'], False)
        phase(state, receipt, 'disabled')
    if receipt['previous_mode'] not in {'none', mode}:
        # Actual available APIs cannot produce the controller admission join.
        # Neither an operator assertion nor a caller-supplied "complete" flag
        # may turn this unavailable fact into permission to send.
        receipt['pending_input'] = {
            'producer': 'pending-installer-input: exact configured ingress fence plus complete GitHub delivery/PushEvent/controller admission/build identity export',
            'missing_public_api': 'complete controller trigger-delivery/admission/build history and payload-bound public-GUID-to-PushEvent association',
            'repository_id': repo['id'], 'repository': context['repository'], 'branch': 'main',
            'trigger': context['trigger'], 'generation': context['generation'], 'source_generation': context['source_generation'],
            'deployment_id': receipt['deployment_id'], 'operation_id': receipt['operation_id'],
            'old_mode': receipt['previous_mode'], 'new_mode': mode,
            'guarantee': 'UNAVAILABLE; no skip, replay, SHA-only or in-flight success claim'}
        phase(state, receipt, 'blocked-handoff')
        fail('cross_mode_handoff_requires_real_producer')
    if mode == 'public':
        descriptor = read_private(state / 'hook.json')
        if descriptor.get('provider') != 'github' or not isinstance(descriptor.get('secret'), str) or not descriptor['secret']:
            fail('invalid_private_hook_descriptor')
        body = {'active': False, 'events': ['push'], 'config': {'url': context['route_url'], 'content_type': 'json', 'insecure_ssl': '0', 'secret': descriptor['secret']}}
        if owned_id is None:
            phase(state, receipt, 'pending-create')
            answer = gh('POST', f"repos/{context['repository']}/hooks", body | {'name': 'web'}, state)
            owned_id = verify_hook(answer, None, context['route_url'], False)
            receipt['hook_id'] = owned_id
            receipt['hook_url'] = context['route_url']
            # ID is durable before any activation effect.
            phase(state, receipt, 'created-inactive')
        else:
            phase(state, receipt, 'pending-update')
            verify_hook(gh('PATCH', f"repos/{context['repository']}/hooks/{owned_id}", body, state), owned_id, context['route_url'], False)
            receipt['hook_url'] = context['route_url']
            phase(state, receipt, 'updated-inactive')
        verify_hook(gh('GET', f"repos/{context['repository']}/hooks/{owned_id}"), owned_id, context['route_url'], False)
        phase(state, receipt, 'pending-activate')
        verify_hook(gh('PATCH', f"repos/{context['repository']}/hooks/{owned_id}", {'active': True}, state), owned_id, context['route_url'], True)
        verify_hook(gh('GET', f"repos/{context['repository']}/hooks/{owned_id}"), owned_id, context['route_url'], True)
    receipt['mode'] = mode
    receipt['pending_input'] = None
    phase(state, receipt, mode + '-ready')


def record_pid(state: pathlib.Path, role: str, pid: int, expected: str) -> None:
    if role not in {'bridge', 'controller', 'agent'} or pid < 1:
        fail('invalid_process_role')
    held = os.pidfd_open(pid, 0)
    try:
        deadline = time.monotonic() + 10
        while True:
            actual = process(pid)
            source = pathlib.Path(expected)
            with source.open('rb') as program:
                prefix = program.read(256).split(b'\n', 1)[0]
            script_image = None
            if prefix.startswith(b'#!'):
                words = prefix[2:].decode().split()
                if len(words) == 1:
                    script_image = str(pathlib.Path(words[0]).resolve(strict=True))
            if role == 'bridge':
                script_image = str(pathlib.Path('/bin/bash').resolve())
            valid = actual['image'] == expected or (script_image == actual['image'] and len(actual['argv']) > 1 and actual['argv'][1] == expected)
            if valid:
                again = process(pid)
                if any(actual[k] != again[k] for k in ('pid', 'start_ticks', 'image', 'argv', 'parent')):
                    fail('process_changed')
                break
            if time.monotonic() >= deadline:
                fail('process_image_mismatch')
            time.sleep(0.02)
        write_private(state / (role + '-process.json'), {'protocol': 'mcloving.dogfood-process/v1', 'role': role,
                      'expected': expected, 'pid': pid, 'start_ticks': actual['start_ticks'], 'image': actual['image'],
                      'argv': actual['argv']})
    finally:
        os.close(held)


def stop(state: pathlib.Path, role: str, expected: str) -> None:
    path = state / (role + '-process.json')
    legacy = state / (role + '.pid')
    if not path.exists():
        if legacy.exists():
            raw = legacy.read_text().strip()
            if not raw.isdecimal() or int(raw) < 1:
                fail('unrecorded_process')
            if (pathlib.Path('/proc') / raw).exists():
                fail('unrecorded_live_process')
            # A dead legacy bridge still has unresolved sender history.
            if role == 'bridge':
                fail('unrecorded_bridge_history')
            legacy.unlink()
        return
    recorded = read_private(path)
    if set(recorded) != {'protocol', 'role', 'expected', 'pid', 'start_ticks', 'image', 'argv'} or recorded['protocol'] != 'mcloving.dogfood-process/v1' or recorded['role'] != role or recorded['expected'] != expected:
        fail('invalid_process_receipt')
    if type(recorded['pid']) is not int or recorded['pid'] < 1 or type(recorded['start_ticks']) is not int or recorded['start_ticks'] < 1 or not isinstance(recorded['image'], str) or not isinstance(recorded['argv'], list) or not recorded['argv'] or any(not isinstance(a, str) for a in recorded['argv']):
        fail('invalid_process_identity')
    pid = recorded['pid']
    try:
        held = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        path.unlink()
        legacy.unlink(missing_ok=True)
        return
    try:
        import select
        poll = select.poll()
        poll.register(held, select.POLLIN)
        if poll.poll(0):
            path.unlink(); legacy.unlink(missing_ok=True); return
        actual = process(pid)
        if any(actual[k] != recorded[k] for k in ('pid', 'start_ticks', 'image', 'argv')):
            fail('pid_reused_or_image_changed')
        signal.pidfd_send_signal(held, signal.SIGTERM)
        if not poll.poll(10000):
            fail('sender_stop_unconfirmed')
        path.unlink()
        legacy.unlink(missing_ok=True)
    finally:
        os.close(held)


def bridge_guard(state: pathlib.Path) -> None:
    receipt = owner(state)
    if receipt['phase'] != 'bridge-ready' or receipt['mode'] != 'bridge' or receipt['previous_mode'] not in {'none', 'bridge'}:
        fail('bridge_not_authorized')
    context = read_private(state / 'sender-context.json')
    if receipt['repository'] != os.environ.get('MCLOVING_DOGFOOD_REPOSITORY') or os.environ.get('MCLOVING_DOGFOOD_BRANCH', 'main') != 'main' or any(receipt[k] != context[k] for k in context):
        fail('bridge_binding_changed')
    descriptor = read_private(state / 'hook.json')
    if not isinstance(descriptor, dict) or not isinstance(descriptor.get('path'), str) or os.environ.get('MCLOVING_URL', '').rstrip('/') + descriptor['path'] != receipt['route_url']:
        fail('bridge_route_changed')
    # Serialize every actual delivery against deployment transition effects.
    # lock must stay held across caller's signer/curl/ledger/watermark command.


def owned_delivery_guard(state: pathlib.Path, args: list[str]) -> None:
    parent = process(os.getppid())
    supervisor = process(parent['parent'])
    if parent['argv'] != ['/bin/bash', str(HERE / 'bridge.sh'), str(state), '--owned-delivery', *args] or supervisor['argv'][1:] != [str(HERE / 'hook-lifecycle.py'), 'bridge-send', str(state), *args] or supervisor['image'] != str(pathlib.Path(sys.executable).resolve()):
        fail('not_owned_delivery')
    info = (state / 'transition.lock').stat(follow_symlinks=False)
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
        fail('lock_owner_mode')
    matches = []
    for fd in (pathlib.Path('/proc') / str(supervisor['pid']) / 'fd').iterdir():
        try:
            observed = fd.stat()
            if (observed.st_dev, observed.st_ino) == (info.st_dev, info.st_ino): matches.append(fd)
        except FileNotFoundError:
            continue
    if len(matches) != 1:
        fail('delivery_lock_custody')
    probe = os.open(state / 'transition.lock', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        try: fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            bridge_guard(state); return
        fail('delivery_lock_not_held')
    finally: os.close(probe)


def bridge_send(state: pathlib.Path, args: list[str]) -> int:
    fd = os.open(state / 'transition.lock', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        bridge_guard(state)
        if len(args) != 3 or not args[0].isdecimal() or not re.fullmatch(r'[0-9a-f]{40}', args[1]) or not re.fullmatch(r'[0-9TZ:.+-]+', args[2]):
            fail('invalid_bridge_event_identity')
        # Reenter the actual script for one delivery under this held lock.
        child = subprocess.Popen(['/bin/bash', str(HERE / 'bridge.sh'), str(state), '--owned-delivery', *args], close_fds=True)
        try:
            return child.wait()
        except BaseException:
            child.terminate()
            child.wait(timeout=10)
            raise
    finally:
        os.close(fd)


def main() -> int:
    try:
        args = sys.argv[1:]
        if len(args) < 2:
            fail('invalid_arguments')
        action, state_raw, *rest = args
        state = private_dir(pathlib.Path(state_raw))
        if action == 'run' and not rest:
            return supervise(state)
        if action == 'bridge-guard' and not rest:
            bridge_guard(state)
            return 0
        def interrupted(signum, _frame):
            raise Interrupted(signum)
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, interrupted)
        if action == 'bridge-send':
            return bridge_send(state, rest)
        if action == 'owned-delivery-guard':
            owned_delivery_guard(state, rest)
            return 0
        held_lock(state)
        if action == 'assert-lock' and not rest:
            return 0
        if action == 'begin' and not rest:
            begin(state)
        elif action == 'quiesce' and not rest:
            quiesce(state)
        elif action == 'writable-output' and not rest:
            writable_output(state)
        elif action == 'reconcile' and len(rest) == 1:
            reconcile(state, rest[0])
        elif action in {'record-pid', 'stop'} and len(rest) == (3 if action == 'record-pid' else 2):
            role = rest[0]
            if action == 'record-pid':
                record_pid(state, role, int(rest[1]), rest[2])
            else:
                stop(state, role, rest[1])
        else:
            fail('invalid_arguments')
        return 0
    except Interrupted as error:
        return 128 + error.signum
    except ExternalFailure as error:
        print('dogfood-lifecycle: external_api_failed', file=sys.stderr)
        return error.code if 0 < error.code < 126 else 1
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Codes only. Never stringify an API response, private payload or path.
        code = str(error) if isinstance(error, Refused) else 'state_or_dependency_unavailable'
        print('dogfood-lifecycle: ' + code, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
