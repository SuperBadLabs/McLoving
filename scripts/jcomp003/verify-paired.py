#!/usr/bin/env python3
"""Fail closed on the fixed JCOMP-001 population's paired measured observations.

No semantic line is discarded. Jenkins per-shell combined logs must be an exact
sequence-preserving merge of product stdout and independently attributed xtrace.
The fixed manifest is the authority for output, order, outcomes, scripts and files.
"""
import argparse
import base64
import hashlib
import importlib.util
import tarfile
import tomllib
import json
from pathlib import Path
import re

if not __debug__:
    raise RuntimeError('verification requires assertions; Python optimization forbidden')
ROOT = Path(__file__).resolve().parents[2]
MANIFEST_SHA = '654898829f31872d471db88830414b23a9453e021bec281f05ac1aa4175de727'
XTRACE_SHA = 'cc1ca1b493acf318f4c98d57d6d4d969e60b57d6daae5da9ebea4d59861f0572'
IDENTITY_ONLY_PRODUCT_ARTIFACTS = frozenset({
    'tracer/strace', 'tracer/lib/libunwind-ptrace.so.0',
    'tracer/lib/libunwind-x86_64.so.8', 'tracer/lib/libunwind.so.8',
    'tracer/lib/liblzma.so.5',
})


def sha(value):
    return hashlib.sha256(value).hexdigest()


def unique(items):
    result = {}
    for key, value in items:
        assert key not in result, f'duplicate JSON key {key}'
        result[key] = value
    return result


def read_json(path):
    assert path.is_file() and not path.is_symlink()
    assert path.stat().st_size <= 8 * 1024 * 1024
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def verify_inventory(root, retained_product_identities=False):
    assert root.is_dir() and not root.is_symlink()
    assert all(not path.is_symlink() for path in root.rglob('*')), 'symlink in evidence inventory'
    artifacts = read_json(root / 'artifacts.json')
    identity_only = IDENTITY_ONLY_PRODUCT_ARTIFACTS if retained_product_identities else frozenset()
    assert identity_only <= set(artifacts), 'fixed observer identity inventory incomplete'
    assert all(not (root / name).exists() for name in identity_only), 'retained identity-only mode requires exact absent binary set'
    expected_directories = {str(parent) for name in set(artifacts) - identity_only for parent in Path(name).parents if str(parent) != '.'}
    actual_directories = {str(path.relative_to(root)) for path in root.rglob('*') if path.is_dir()}
    assert actual_directories == expected_directories, 'unexpected empty or missing evidence directory'
    actual = {str(path.relative_to(root)) for path in root.rglob('*') if path.is_file()}
    assert actual == (set(artifacts) - identity_only) | {'artifacts.json'}, 'evidence inventory changed'
    for relative, digest in artifacts.items():
        assert not Path(relative).is_absolute() and '..' not in Path(relative).parts
        assert re.fullmatch(r'[0-9a-f]{64}', digest)
        if relative in identity_only:
            continue
        path = root / relative
        assert not path.is_symlink() and sha(path.read_bytes()) == digest, relative
    return sha((root / 'artifacts.json').read_bytes())


def source_archive_tree(path, required_bytes=None):
    """Reconstruct Git's tree ID from archived bytes, independent of tar comments."""
    root = {}
    members = set()
    required_bytes = {} if required_bytes is None else dict(required_bytes)
    with tarfile.open(path, 'r:') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            parts = Path(name).parts
            assert parts and not Path(name).is_absolute() and all(part not in ('.', '..', '.git') for part in parts)
            if member.isdir():
                continue
            assert name not in members
            members.add(name)
            tree = root
            for part in parts[:-1]:
                tree = tree.setdefault(part, {})
                assert isinstance(tree, dict)
            assert parts[-1] not in tree
            if member.issym():
                content = member.linkname.encode()
                mode = b'120000'
            else:
                assert member.isfile(), 'unsupported source archive entry'
                content = archive.extractfile(member).read()
                assert len(content) == member.size
                mode = b'100755' if member.mode & 0o111 else b'100644'
            if name in required_bytes:
                assert content == required_bytes.pop(name), 'producer/policy bytes differ from frozen source: ' + name
            blob = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).digest()
            tree[parts[-1]] = (mode, blob)
    assert not required_bytes, 'required producer/policy missing from source archive'
    def digest(tree):
        encoded = b''
        for name, value in sorted(tree.items(), key=lambda item:(item[0] + ('/' if isinstance(item[1], dict) else '')).encode()):
            mode, oid = (b'40000', digest(value)) if isinstance(value, dict) else value
            encoded += mode + b' ' + name.encode() + b'\0' + oid
        return hashlib.sha1(b'tree ' + str(len(encoded)).encode() + b'\0' + encoded).digest()
    return digest(root).hex()


def module(filename):
    spec = importlib.util.spec_from_file_location(filename.replace('-', '_'), ROOT / 'scripts/jcomp003' / filename)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def verify_retained_boundaries(jenkins_root, product_root):
    jenkins = module('run-jenkins.py')
    product = module('verify-product-boundary.py')
    ji = read_json(jenkins_root / 'container-inspect.json')
    mounts = {mount['Destination']:mount['Source'] for mount in ji[0]['Mounts']}
    scratch = Path(mounts['/opt/jcomp/input']).parent
    assert scratch.parent == Path('/tmp') and re.fullmatch(r'mcloving-jcomp003-jenkins-input-[A-Za-z0-9_-]+', scratch.name)
    expected = {'/opt/jcomp/input':scratch / 'input',
        '/opt/jcomp/observe-shell':scratch / 'observe-shell',
        '/var/jenkins_home/init.groovy.d/jcomp003.groovy':scratch / 'jenkins-init.groovy'}
    plugins = {}
    plugin_manifest = (jenkins_root / 'PLUGIN_SHA256SUMS').read_bytes()
    assert sha(plugin_manifest) == jenkins.PLUGIN_MANIFEST_SHA
    for line in plugin_manifest.decode().splitlines():
        digest, name = line.split()
        leaf = Path(name).name
        assert name == 'plugins/' + leaf and leaf not in plugins
        plugins[leaf] = digest
        expected['/var/jenkins_home/plugins/' + leaf] = scratch / 'plugins' / leaf
    assert len(plugins) == 90
    jenkins.verify_boundary(ji, expected)
    launch = read_json(jenkins_root / 'launch.json')
    launch_mounts = {launch[index + 1] for index, flag in enumerate(launch) if flag == '--volume'}
    assert launch_mounts == {str(source) + ':' + target + ':ro' for target, source in expected.items()}
    assert '--network=none' in launch and '--http-proxy=false' in launch
    profile_bytes = (jenkins_root / 'profile-v1.properties').read_bytes()
    assert sha(profile_bytes) == jenkins.PROFILE_SHA
    profile = dict(line.split('=', 1) for line in profile_bytes.decode().splitlines())
    runtime = read_json(jenkins_root / 'observations/runtime.json')
    for actual, key in [('jenkins','jenkins.core.version'), ('java','java.runtime.version'),
        ('java_vendor','java.vendor'), ('groovy','groovy.version'),
        ('core_jar_sha256','jenkins.core.jar.sha256'), ('groovy_jar_sha256','groovy.jar.sha256'),
        ('war_sha256','jenkins.war.sha256')]:
        assert runtime[actual] == profile[key], 'Jenkins runtime/profile drift'
    assert runtime['plugin_files'] == plugins
    assert len(runtime['plugins']) == 90 and all(plugin['active'] for plugin in runtime['plugins'])
    assert runtime['step_sentinel_initially_absent'] is True
    pi = read_json(product_root / 'runner-inspect.json')
    db = read_json(product_root / 'database-inspect.json')
    source = next(mount['Source'] for mount in pi[0]['Mounts'] if mount['Destination'] == '/opt/jcomp/input.json')
    scratch = Path(source).parent
    assert scratch.parent == Path('/tmp') and re.fullmatch(r'mcloving-jcomp003-product\.[A-Za-z0-9]+', scratch.name)
    product.verify(pi, db, scratch)
    return {'jenkins_image':jenkins.IMAGE_ID, 'product_image':product.RUNTIME_ID,
            'postgres_image':product.POSTGRES_ID, 'profile_sha256':jenkins.PROFILE_SHA}


def merged_exact(combined, stdout, stderr):
    """Recognize a merge without dropping/reordering any byte or stream line."""
    combined_lines = combined.splitlines(keepends=True)
    stdout_lines = stdout.splitlines(keepends=True)
    stderr_lines = stderr.splitlines(keepends=True)
    positions = {(0, 0)}
    for line in combined_lines:
        following = set()
        for out, err in positions:
            if out < len(stdout_lines) and stdout_lines[out] == line:
                following.add((out + 1, err))
            if err < len(stderr_lines) and stderr_lines[err] == line:
                following.add((out, err + 1))
        positions = following
        if not positions:
            return False
    return (len(stdout_lines), len(stderr_lines)) in positions


def decode_trace_string(value):
    assert re.fullmatch(r'(?:\\x[0-9a-f]{2})*', value), 'tracer must hex-encode complete bytes'
    return bytes.fromhex(value.replace('\\x', ''))


def trace_shells(path):
    """Join strace's split syscall records by PID, retain chronological exec order."""
    pending = {}
    shells = []
    exit_codes = {}
    for line in path.read_text().splitlines():
        match = re.match(r'^([0-9]+)\s+([0-9]+\.[0-9]+)\s+(.*)$', line)
        assert match, f'unrecognized independent trace record: {line[:160]}'
        pid, timestamp, body = match.groups()
        if '<unfinished ...>' in body:
            assert pid not in pending
            pending[pid] = (timestamp, body.replace(' <unfinished ...>', ''))
            continue
        if body.startswith('<... '):
            assert pid in pending
            timestamp, initial = pending.pop(pid)
            body = initial + body.split('resumed>', 1)[1].lstrip()
        exit_match = re.match(r'^exit_group\(([0-9]+)\)', body)
        if exit_match:
            exit_codes[pid] = int(exit_match.group(1))
            continue
        exec_match = re.match(r'^execve\("((?:\\x[0-9a-f]{2})*)", \[(.*?)\], .*\)\s+= 0$', body)
        if not exec_match:
            # Signal/failed PATH probes remain raw evidence; only successful exec
            # records establish process arguments. Unknown successful exec is fatal.
            assert not ('execve(' in body and re.search(r'= 0$', body)), body
            continue
        executable, argv_text = exec_match.groups()
        executable = decode_trace_string(executable)
        argv_matches = re.findall(r'"((?:\\x[0-9a-f]{2})*)"', argv_text)
        assert ', '.join('"' + value + '"' for value in argv_matches) == argv_text
        argv = [decode_trace_string(value) for value in argv_matches]
        if executable == b'/bin/sh':
            shells.append({'pid':pid, 'timestamp':timestamp, 'argv':argv})
    assert not pending, 'incomplete syscall observations'
    for shell in shells:
        assert shell['pid'] in exit_codes, 'shell has no observed exit_group'
        shell['exit_code'] = exit_codes[shell['pid']]
    return shells


def product_logs(record, attempt_id, attempt=None):
    rows = [row for row in record['logs'] if row['attempt_id'] == attempt_id]
    assert len(rows) == 1
    streams = {'stdout': [], 'stderr': []}
    sequences = {'stdout': [], 'stderr': []}
    last_cursor = -1
    for ordinal, chunk in enumerate(rows[0]['chunks']):
        assert set(chunk) == {'fence', 'sequence', 'stream', 'content', 'digest', 'cursor_id'}
        stream, sequence, content = chunk['stream'], chunk['sequence'], chunk['content']
        assert stream in streams and type(sequence) is int and sequence == ordinal
        assert type(chunk['cursor_id']) is int and chunk['cursor_id'] > last_cursor
        last_cursor = chunk['cursor_id']
        assert isinstance(content, list) and all(type(byte) is int and 0 <= byte <= 255 for byte in content)
        assert sha(bytes(content)) == chunk['digest']
        if attempt is not None:
            assert chunk['fence'] == attempt['accounting']['fence']
        sequences[stream].append(sequence)
        streams[stream].append(bytes(content))
    if attempt is not None:
        references = {reference['stream']:reference for reference in attempt['logs']}
        assert len(references) == len(attempt['logs'])
        assert set(references) == {stream for stream, values in sequences.items() if values}
        for stream, reference in references.items():
            values = sequences[stream]
            assert reference['attempt_id'] == attempt_id
            assert reference['fence'] == attempt['accounting']['fence']
            assert reference['first_sequence'] == values[0] and reference['last_sequence'] == values[-1]
            assert reference['chunk_count'] == len(values)
    return {stream:b''.join(chunks) for stream, chunks in streams.items()}


def expected_files(fixture):
    return {entry['path']:(entry['bytes'], entry['sha256']) for entry in fixture['expected']['workspace_files']}


def ancestor_directories(files):
    result = set()
    for name in files:
        result.update(str(parent) for parent in Path(name).parents if str(parent) != '.')
    return result


def verify_workspace(fixture, jenkins, product):
    files = expected_files(fixture)
    dirs = ancestor_directories(files)
    observed = {}
    observed_dirs = set()
    for entry in jenkins['workspace']:
        if entry['kind'] == 'directory':
            assert entry['path'] not in observed_dirs
            observed_dirs.add(entry['path'])
        else:
            assert entry['kind'] == 'file', 'unexpected symlink/special workspace entry'
            assert entry['path'] not in observed
            content = base64.b64decode(entry['contents_base64'], validate=True)
            assert len(content) == entry['size_bytes'] and sha(content) == entry['sha256']
            observed[entry['path']] = (len(content), sha(content))
    assert observed == files and observed_dirs == dirs
    receipt = product['result']['workspace_receipt']
    assert receipt['version'] == 1
    observed = {}
    observed_dirs = set()
    for entry in receipt['entries']:
        if entry['kind'] == 'directory':
            assert entry['path'] not in observed_dirs
            observed_dirs.add(entry['path'])
        else:
            assert entry['kind'] == 'file' and entry['executable'] is False
            assert entry['path'] not in observed
            observed[entry['path']] = (entry['size_bytes'], bytes(entry['digest']).hex())
    assert observed == files and observed_dirs == dirs
    assert jenkins['control_entries'] == [], 'unexpected retained Jenkins control material'
    assert jenkins['workspace_cleanup'] and jenkins['control_cleanup']
    assert product['checkpoint_raw_bytes_removed'] and product['attempt_workspace_cleanup']
    assert product['result']['workspace_closed']


def ancestor(nodes, candidate, descendant):
    frontier = list(nodes[descendant]['parents'])
    seen = set()
    while frontier:
        node = frontier.pop()
        if node == candidate:
            return True
        assert node in nodes
        if node not in seen:
            seen.add(node)
            frontier.extend(nodes[node]['parents'])
    return False


def verify_console_text(fixture, observed, shell_nodes, directory):
    """Exact fixed Jenkins protocol grammar around verified per-shell bytes."""
    raw = (directory / (fixture['id'] + '.console-text')).read_bytes()
    assert sha(raw) == observed['console_text_sha256']
    # The source-bound observer explicitly supplies UserIdCause(null); the
    # pinned Jenkins implementation prints this exact synthetic cause header.
    header = b'Started by user unknown or anonymous\n'
    assert raw.startswith(header), 'unexpected scheduling cause header'
    raw = raw[len(header):]
    expected = b'[Pipeline] Start of Pipeline\n[Pipeline] node\n'
    expected += ('Running on Jenkins in ' + observed['workspace_path'] + '\n').encode()
    expected += b'[Pipeline] {\n'
    index = 0
    for stage in fixture['expected']['stages']:
        expected += ('[Pipeline] stage\n[Pipeline] { (' + stage['name'] + ')\n').encode()
        if stage['outcome'] == 'skipped':
            expected += ('Stage "' + stage['name'] + '" skipped due to earlier failure(s)\n[Pipeline] getContext\n').encode()
        else:
            for step in stage['steps']:
                if step['outcome'] == 'skipped':
                    continue
                expected += b'[Pipeline] sh\n' + base64.b64decode(shell_nodes[index]['log_base64'], validate=True)
                index += 1
        expected += b'[Pipeline] }\n[Pipeline] // stage\n'
    expected += b'[Pipeline] }\n[Pipeline] // node\n[Pipeline] End of Pipeline\n'
    if fixture['expected']['build_outcome'] == 'failed':
        failures = [step['exit_code'] for stage in fixture['expected']['stages'] for step in stage['steps'] if step['outcome'] == 'failed']
        assert len(failures) == 1
        expected += f'ERROR: script returned exit code {failures[0]}\nFinished: FAILURE\n'.encode()
    else:
        expected += b'Finished: SUCCESS\n'
    assert raw == expected, 'unexplained whole-console bytes outside attributed shell logs'


def verify_case(fixture, jenkins_root, product_root, observed_shells, expected_traces):
    identifier = fixture['id']
    j = read_json(jenkins_root / 'observations' / f'{identifier}.json')
    p = read_json(product_root / 'observations' / f'{identifier}.json')
    assert j['fixture'] == p['fixture'] == identifier
    assert j['source_sha256'] == p['source_sha256'] == fixture['source_sha256']
    expected = fixture['expected']
    assert j['result'] == {'succeeded':'SUCCESS', 'failed':'FAILURE'}[expected['build_outcome']]
    assert p['result']['status'] == expected['build_outcome']
    assert sha((jenkins_root / 'observations' / f'{identifier}.console').read_bytes()) == j['console_sha256']
    nodes = {node['id']:node for node in j['nodes']}
    assert len(nodes) == len(j['nodes'])
    stages = [node for node in j['nodes'] if node['function_name'] == 'stage'
              and node['type'].endswith('StepStartNode') and node['arguments'].get('name') is not None]
    shell_nodes = [node for node in j['nodes'] if node['function_name'] == 'sh'
                   and node['arguments'].get('script') is not None]
    # The retained scanner walks from graph heads backwards. Reverse that exact
    # traversal, then independently require ancestry between every adjacent step.
    stages.reverse()
    shell_nodes.reverse()
    assert [stage['arguments']['name'] for stage in stages] == [stage['name'] for stage in expected['stages']]
    for stage, expected_stage in zip(stages, expected['stages']):
        ends = [node for node in j['nodes'] if node.get('block_start_id') == stage['id']]
        assert len(ends) == 1, 'stage has no unique observed block end'
        if expected_stage['outcome'] == 'skipped':
            assert stage['tags'].get('STAGE_STATUS') == 'SKIPPED_FOR_FAILURE'
            assert not any(ancestor(nodes, stage['id'], node['id']) and ancestor(nodes, node['id'], ends[0]['id']) for node in shell_nodes)
        elif expected_stage['outcome'] == 'failed':
            assert ends[0]['error'] is not None
        else:
            assert ends[0]['error'] is None
            assert not stage['tags'].get('STAGE_STATUS', '').startswith('SKIPPED')
    for previous, following in zip(shell_nodes, shell_nodes[1:]):
        assert ancestor(nodes, previous['id'], following['id']), 'shell order lacks graph ancestry'
        assert previous['start_ms'] <= following['start_ms']
    executed = [(stage_index, step_index, step) for stage_index, stage in enumerate(expected['stages'])
                for step_index, step in enumerate(stage['steps']) if step['outcome'] != 'skipped']
    assert len(shell_nodes) == len(executed) == len(j['shells']) == len(observed_shells)
    wrapper_records = []
    for name in j['shells']:
        assert re.fullmatch(r'shell\.[A-Za-z0-9]+', name)
        root = jenkins_root / 'observations' / name
        wrapper_records.append((int((root / 'start-ns.txt').read_text()), root))
    wrapper_records.sort(key=lambda record:record[0])
    assert len({start for start, _ in wrapper_records}) == len(wrapper_records)
    assert len(p['result']['stages']) == len(expected['stages'])
    execution_index = 0
    previous_completed = None
    step_receipts = []
    for stage_index, (actual_stage, expected_stage) in enumerate(zip(p['result']['stages'], expected['stages'])):
        assert actual_stage['stage_name'] == expected_stage['name']
        assert actual_stage['stage_ordinal'] == stage_index + 1
        assert actual_stage['status'] == expected_stage['outcome']
        assert len(actual_stage['steps']) == len(expected_stage['steps'])
        for step_index, (actual_step, expected_step) in enumerate(zip(actual_stage['steps'], expected_stage['steps'])):
            assert actual_step['status'] == expected_step['outcome']
            assert actual_step['layout']['stage_ordinal'] == stage_index + 1
            assert actual_step['layout']['step_ordinal'] == step_index + 1
            assert len(actual_step['attempts']) == 1
            attempt = actual_step['attempts'][0]['accounting']
            streams = product_logs(p, attempt['attempt_id'], actual_step['attempts'][0])
            assert streams['stdout'] == expected_step['stdout_utf8'].encode()
            if expected_step['outcome'] == 'skipped':
                assert streams == {'stdout':b'', 'stderr':b''}
                assert attempt.get('terminal_summary') is None or attempt['terminal_summary'].get('exit_code') is None
                continue
            node = shell_nodes[execution_index]
            _, wrapper = wrapper_records[execution_index]
            traced = observed_shells[execution_index]
            script = expected_step['script_utf8'].encode()
            assert node['arguments']['script'].encode() == script
            assert ancestor(nodes, stages[stage_index]['id'], node['id'])
            assert (wrapper / 'script').read_bytes() == script
            argv = (wrapper / 'argv.nul').read_bytes().split(b'\0')
            assert argv[-1] == b'' and len(argv) == 4 and argv[:2] == [b'/bin/sh', b'-xe']
            assert argv[2].startswith(j['workspace_path'].encode() + b'@tmp/')
            assert re.fullmatch(re.escape(j['workspace_path'].encode()) + rb'@tmp/durable-[a-z0-9]+/script\.sh(?:\.copy)?', argv[2])
            assert (wrapper / 'cwd.txt').read_text() == j['workspace_path'] + '\n'
            assert (wrapper / 'interpreter.sha256').read_text() == 'a6f559e00b69a4aa4d8cb607be18d9386c5aee55c509e2c075549dcf00e00fc7  /bin/sh\n'
            assert int((wrapper / 'end-ns.txt').read_text()) >= int((wrapper / 'start-ns.txt').read_text())
            assert traced['argv'] == [b'/bin/sh', b'-xe', b'-c', script]
            exit_code = expected_step['exit_code']
            assert int((wrapper / 'exit-code.txt').read_text()) == traced['exit_code'] == exit_code
            assert attempt['terminal_summary']['exit_code'] == exit_code
            assert (node['error'] is None) == (exit_code == 0)
            expected_trace = expected_traces[identifier, stage_index + 1, step_index + 1]
            assert sha(script) == expected_trace['script_sha256']
            assert streams['stderr'] == expected_trace['xtrace_utf8'].encode(), 'xtrace differs from frozen script-attributed expectation'
            combined = base64.b64decode(node['log_base64'], validate=True)
            assert merged_exact(combined, streams['stdout'], streams['stderr']), 'unexplained combined shell log bytes'
            if previous_completed is not None:
                assert attempt['started_at_unix_ms'] >= previous_completed
            previous_completed = attempt['completed_at_unix_ms']
            step_receipts.append({'stage':expected_stage['name'], 'step':step_index + 1,
                'script_sha256':sha(script), 'stdout_sha256':sha(streams['stdout']),
                'xtrace_sha256':sha(streams['stderr']), 'jenkins_node':node['id'],
                'product_attempt':attempt['attempt_id'], 'product_process_id':traced['pid'],
                'exit_code':exit_code, 'outcome':expected_step['outcome']})
            execution_index += 1
    assert execution_index == len(executed)
    verify_console_text(fixture, j, shell_nodes, jenkins_root / 'observations')
    verify_workspace(fixture, j, p)
    return {'fixture':identifier, 'source_sha256':fixture['source_sha256'], 'result':expected['build_outcome'],
            'product_build_id':p['result']['build_id'], 'product_pipeline_id':p['result']['pipeline_id'],
            'product_workspace_namespace':p['result']['workspace_namespace'], 'jenkins_wrapper_records':j['shells'],
            'executed_steps':step_receipts, 'workspace_files':expected['workspace_files'],
            'unexplained_differences':0}


def verify_global_joins(cases, complete, observations):
    wrappers = [name for case in cases for name in case['jenkins_wrapper_records']]
    actual_wrappers = {path.name for path in observations.iterdir() if path.name.startswith('shell.')}
    assert len(wrappers) == len(set(wrappers)) == 19, 'wrapper records duplicated or missing'
    assert set(wrappers) == actual_wrappers, 'unreferenced extra shell observation'
    build_ids = [case['product_build_id'] for case in cases]
    namespaces = [case['product_workspace_namespace'] for case in cases]
    pipeline_ids = [case['product_pipeline_id'] for case in cases]
    assert len(build_ids) == len(set(build_ids)) == 11
    assert len(namespaces) == len(set(namespaces)) == 11 and all(namespaces)
    assert len(pipeline_ids) == len(set(pipeline_ids)) == 11
    attempts = [step['product_attempt'] for case in cases for step in case['executed_steps']]
    assert len(attempts) == len(set(attempts)) == 19
    records = {record['fixture']:record for record in complete['records']}
    assert len(records) == len(complete['records']) == 23
    for case in cases:
        assert records[case['fixture']]['build_id'] == case['product_build_id']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('jenkins', type=Path)
    parser.add_argument('product', type=Path)
    parser.add_argument('report', type=Path)
    parser.add_argument('--jenkins-inventory-sha256', required=True)
    parser.add_argument('--product-inventory-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--source-tree', required=True)
    parser.add_argument('--compiler-campaign-sha256', required=True)
    parser.add_argument('--prepared-input-sha256', required=True)
    parser.add_argument('--worker-sha256', required=True)
    parser.add_argument('--admission-sha256', required=True)
    parser.add_argument('--retained-identity-only', action='store_true',
        help='fixed five observer binaries are recorded identities only; hydrated archive and every semantic artifact remain mandatory')
    args = parser.parse_args()
    jenkins_inventory = verify_inventory(args.jenkins)
    product_inventory = verify_inventory(args.product, args.retained_identity_only)
    assert jenkins_inventory == args.jenkins_inventory_sha256
    assert product_inventory == args.product_inventory_sha256
    assert (args.product / 'source-commit.txt').read_text().strip() == args.source_commit
    assert (args.product / 'source-tree.txt').read_text().strip() == args.source_tree
    source_bytes = {str(path.relative_to(ROOT)):path.read_bytes() for path in (ROOT / 'scripts/jcomp003').iterdir() if path.is_file()}
    for name in ('tools/versions.env', 'rust-toolchain.toml'):
        source_bytes[name] = (ROOT / name).read_bytes()
    source_bytes['bins/agent/tests/jcomp003_paired.rs'] = (ROOT / 'bins/agent/tests/jcomp003_paired.rs').read_bytes()
    for name in ('observe-shell', 'jenkins-init.groovy'):
        retained = (args.jenkins / name).read_bytes()
        assert retained == source_bytes['scripts/jcomp003/' + name], 'retained Jenkins producer differs from reviewed source'
    assert source_archive_tree(args.product / 'source.tar', source_bytes) == args.source_tree
    identities = verify_retained_boundaries(args.jenkins, args.product)
    images = read_json(args.product / 'images.json')
    assert len(images) == 3
    versions = dict(line.split('=', 1) for line in (ROOT / 'tools/versions.env').read_text().splitlines() if line.startswith('MCLOVING_'))
    rust_reference = versions['MCLOVING_RUST_IMAGE'].strip('"')
    assert rust_reference in images[0]['RepoDigests']
    assert images[0]['Id'].removeprefix('sha256:') == 'a0635962c16d5f26400703edd4317175cf9531f3285d632613f9da227f9c71d1'
    rust_version = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    build_log = (args.product / 'build.log').read_text()
    assert re.search(r'^rustc ' + re.escape(rust_version) + r' \([^\n]+\)$', build_log, re.M)
    identities.update(rust_builder_image=images[0]['Id'], rust_builder_reference=rust_reference, rust_version=rust_version)
    runtime_log = (args.product / 'runtime.log').read_text()
    for role in ('controller', 'agent'):
        assert f'{role}-build-provenance source_head={args.source_commit} source_tree={args.source_tree}\n' in runtime_log
    binaries = {name:digest for digest, name in (line.split() for line in (args.product / 'binaries.sha256').read_text().splitlines())}
    assert set(binaries) == {'mcloving-controller', 'mcloving-agent', 'jcomp003_paired'}
    assert f'jcomp003-observer-build-provenance source_head={args.source_commit} source_tree={args.source_tree}\n' in runtime_log
    assert f'jcomp003-observer-binary {binaries["jcomp003_paired"]}\n' in runtime_log
    for role in ('controller', 'agent'):
        assert f'sequential-executed-binary {role} {binaries["mcloving-" + role]}\n' in runtime_log
    manifest_bytes = (ROOT / 'compat/jenkins-worker/fixtures/sequential-v1/manifest.json').read_bytes()
    assert sha(manifest_bytes) == MANIFEST_SHA
    manifest = json.loads(manifest_bytes)
    positive = [fixture for fixture in manifest['fixtures'] if fixture['expected']['compilation'] == 'supported']
    negative = [fixture for fixture in manifest['fixtures'] if fixture['expected']['compilation'] != 'supported']
    assert len(positive) == 11 and len(negative) == 12
    jcomplete = read_json(args.jenkins / 'observations/complete.json')
    pcomplete = read_json(args.product / 'observations/complete.json')
    assert [record['fixture'] for record in jcomplete['results']] == [fixture['id'] for fixture in positive]
    assert jcomplete['queue'] == 0 and jcomplete['production_authority'] is False
    assert [record['fixture'] for record in pcomplete['records']] == [fixture['id'] for fixture in manifest['fixtures']]
    assert pcomplete['positive_builds'] == 11 and pcomplete['negative_inputs'] == 12
    assert pcomplete['observed_database_builds'] == 11 and pcomplete['observed_database_nodes'] == 23
    assert pcomplete['distinct_workspace_namespaces'] == 11 and pcomplete['production_authority'] is False
    input_bytes = (args.product / 'input.json').read_bytes()
    assert sha(input_bytes) == pcomplete['input_sha256'] == args.prepared_input_sha256
    inputs = json.loads(input_bytes, object_pairs_hook=unique)
    assert inputs['compiler_campaign_sha256'] == args.compiler_campaign_sha256
    assert inputs['manifest_sha256'] == MANIFEST_SHA
    assert [fixture['id'] for fixture in inputs['fixtures']] == [fixture['id'] for fixture in manifest['fixtures']]
    expected_by_id = {fixture['id']:fixture for fixture in manifest['fixtures']}
    for fixture in inputs['fixtures']:
        expected_fixture = expected_by_id[fixture['id']]
        assert fixture['source_sha256'] == expected_fixture['source_sha256']
        assert fixture['receipt']['worker_image_sha256'] == args.worker_sha256
        assert fixture['receipt']['admission_binary_sha256'] == args.admission_sha256
        if fixture['receipt']['status'] == 'admitted':
            assert sha(fixture['pipeline_yaml'].encode()) == fixture['receipt']['pipeline_yaml_sha256']
            assert sha(fixture['disabled_definition_yaml'].encode()) == fixture['receipt']['definition_yaml_sha256']
            assert fixture['receipt']['state'] == 'disabled' and fixture['receipt']['execution_authority'] == 'false'
        else:
            assert 'pipeline_yaml' not in fixture and 'disabled_definition_yaml' not in fixture
            assert fixture['receipt']['status'] == expected_fixture['expected']['compilation']
            assert fixture['receipt']['code'] == expected_fixture['expected']['diagnostic']
    trace_bytes = (ROOT / 'scripts/jcomp003/xtrace-expectations-v1.json').read_bytes()
    assert sha(trace_bytes) == XTRACE_SHA
    trace_expectations = json.loads(trace_bytes, object_pairs_hook=unique)
    assert trace_expectations['manifest_sha256'] == MANIFEST_SHA
    expected_traces = {(r['fixture'], r['stage_ordinal'], r['step_ordinal']):r for r in trace_expectations['records']}
    assert len(expected_traces) == len(trace_expectations['records']) == 23
    for record in expected_traces.values():
        assert sha(record['xtrace_utf8'].encode()) == record['xtrace_sha256']
    assert f"{trace_expectations['shell_sha256']}  /bin/sh\n" in runtime_log
    assert f"{trace_expectations['shell_sha256']}  /bin/sh\n" in (args.jenkins / 'shell-identity.txt').read_text()
    traced = trace_shells(args.product / 'observations/execve.trace')
    assert len(traced) == 19, 'workload shell invocation denominator changed'
    offset = 0
    cases = []
    for fixture in positive:
        count = sum(step['outcome'] != 'skipped' for stage in fixture['expected']['stages'] for step in stage['steps'])
        cases.append(verify_case(fixture, args.jenkins, args.product, traced[offset:offset + count], expected_traces))
        offset += count
    assert offset == len(traced)
    verify_global_joins(cases, pcomplete, args.jenkins / 'observations')
    precords = {record['fixture']:record for record in pcomplete['records']}
    assert len(precords) == 23
    for fixture in negative:
        record = precords[fixture['id']]
        assert record['compilation'] == fixture['expected']['compilation']
        assert record['scheduled_work'] == 0
        assert record['scheduler_nodes_before'] == record['scheduler_nodes_after']
    assert read_json(args.jenkins / 'cleanup-verified.json')['removed'] is True
    assert (args.product / 'cleanup-verified.txt').read_text() == 'product-containers-removed=true\nworkspaces-and-database-tmpfs-removed=true\n'
    report = {'schema':'mcloving.jenkins.sequential-differential/2', 'manifest_sha256':MANIFEST_SHA,
        'jenkins_inventory_sha256':jenkins_inventory, 'product_inventory_sha256':product_inventory,
        'product_source_commit':args.source_commit, 'product_source_tree':args.source_tree,
        'runtime_identities':identities, 'xtrace_expectations_sha256':XTRACE_SHA,
        'product_binary_sha256':binaries, 'compiler_campaign_sha256':args.compiler_campaign_sha256,
        'prepared_input_sha256':args.prepared_input_sha256,
        'compiler_worker_image_sha256':args.worker_sha256, 'admission_binary_sha256':args.admission_sha256,
        'authored_positive_fixtures':10, 'historical_regressions':1, 'authored_negative_inputs':12,
        'observed_workload_shell_invocations_per_runtime':19, 'unexplained_differences':0, 'cases':cases,
        'negative_claim':'independently denied compilation, no executable, unchanged observed scheduler population',
        'production_authority':False, 'original_corpus_runtime_parity_claim':False,
        'artifact_verification_mode':('retained-with-fixed-observer-binary-identities' if args.retained_identity_only else 'full-artifact-bytes'),
        'identity_only_artifacts':({name:read_json(args.product / 'artifacts.json')[name] for name in sorted(IDENTITY_ONLY_PRODUCT_ARTIFACTS)} if args.retained_identity_only else {})}
    with args.report.open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print('retained measured observations verified; runtime was not rerun' if args.retained_identity_only else 'paired observations verified: 10 authored + C052, 19 workload shell invocations per runtime, 12 compile denials; no production authority')


if __name__ == '__main__':
    main()
