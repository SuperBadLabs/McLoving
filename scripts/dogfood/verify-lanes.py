#!/usr/bin/env python3
"""Closed Foundation/dogfood command comparison (DOGFOOD-001).

No shell is executed. The finite setup catalog binds reviewed complex blocks
byte-for-byte; simple commands are parsed as argv, never substring matches.
Unlisted YAML, shell grammar, context, action or setup changes fail closed.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import pathlib
import re
import shlex
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIRRORED = {name + '.sh': name for name in (
    'rust-lint', 'rust-tests', 'dependencies', 'secrets', 'architecture', 'controller-postgres')}


class Drift(ValueError):
    pass


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def clean(text: str) -> str:
    return '\n'.join(line.rstrip() for line in text.splitlines()
                     if line.strip() and not line.lstrip().startswith('#')) + '\n'


def unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Drift('duplicate metadata key')
        result[key] = value
    return result


def scalar(raw: str) -> str:
    # Only actual scalar shapes. Comments in quoted values are not removed.
    raw = raw.strip()
    if raw.startswith(('"', "'")):
        values = shlex.split(raw, comments=True)
        if len(values) != 1:
            raise Drift('unsupported quoted YAML scalar')
        return values[0]
    raw = raw.split(' #', 1)[0].rstrip()
    if not raw or raw.startswith(('[', '{', '&', '*', '!', '|', '>')):
        raise Drift('unsupported YAML scalar')
    return raw


@dataclass(frozen=True)
class Step:
    raw: str
    fields: dict
    env: dict
    run: str | None


@dataclass(frozen=True)
class CatalogRecords:
    """Internal reviewed records; never deserialized from a lane comment."""
    records: tuple[str, ...]


def logical_lines(text: str) -> list[str]:
    """Finite Bash comment/escaped-newline lexer, without shell execution.

    A comment's trailing backslash is not a continuation. Quoted hashes and
    hashes within a word are literal; only an unquoted word-start hash starts
    a comment. Unsupported multiline quotes fail in the downstream argv lexer.
    """
    result = []
    pending = ''
    for raw in text.splitlines():
        if not pending and (not raw.strip() or raw.lstrip().startswith('#')):
            result.append(raw.strip())
            continue
        line = pending + raw
        quote = None
        escaped = False
        word = False
        comment = None
        for at, char in enumerate(line):
            if escaped:
                escaped = False
                word = True
                continue
            if quote == "'":
                if char == "'": quote = None
                continue
            if char == '\\':
                escaped = True
                word = True
                continue
            if quote == '"':
                if char == '"': quote = None
                continue
            if char in {'"', "'"}:
                quote = char
                word = True
            elif char == '#' and not word:
                comment = at
                break
            elif char.isspace() or char in ';|&()<>':
                word = False
            else:
                word = True
        if comment is not None:
            result.append(line[:comment].strip())
            pending = ''
        elif escaped and quote != "'":
            # Remove precisely the escaped physical newline, with no invented
            # space: foo\\\nbar is foobar, while reviewed argv lines carry space.
            pending = line[:-1]
        else:
            result.append(line.strip())
            pending = ''
    if pending:
        raise Drift('unterminated shell continuation')
    return result


def parse_step(raw: str) -> Step:
    lines = raw.splitlines()
    if not lines or not lines[0].startswith('      - name: '):
        raise Drift('every step must have a unique, explicit name')
    fields = {'name': scalar(lines[0][14:])}
    env: dict[str, str] = {}
    run = None
    i = 1
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith('#'):
            i += 1
            continue
        match = re.fullmatch(r'        ([a-z][a-z-]*):(?: (.*))?', line)
        if not match or match[1] in fields:
            raise Drift('unsupported or duplicate step field')
        key, value = match[1], match[2]
        if key not in {'run', 'uses', 'with', 'env', 'shell', 'working-directory', 'name'}:
            raise Drift('unsupported conditional/dynamic step')
        fields[key] = value
        i += 1
        if key in {'env', 'with'}:
            values = {}
            while i < len(lines) and (not lines[i].strip() or lines[i].startswith('          ')):
                nested = lines[i]
                if nested.strip() and not nested.lstrip().startswith('#'):
                    item = re.fullmatch(r'          ([A-Za-z_][A-Za-z_0-9-]*): (.*)', nested)
                    if not item or item[1] in values:
                        raise Drift('unsupported or duplicate nested metadata')
                    values[item[1]] = scalar(item[2])
                i += 1
            fields[key] = values
            if key == 'env':
                env = values
        elif key == 'run':
            if value in {'|', '|-', '>', '>-'}:
                block = []
                while i < len(lines) and (not lines[i].strip() or lines[i].startswith('          ')):
                    block.append(lines[i][10:])
                    i += 1
                if value.startswith('>'):
                    while block and not block[-1].strip():
                        block.pop()
                    # Fold only the actual equal-indent, single-paragraph form.
                    if any(not p.strip() or p.startswith(' ') for p in block):
                        raise Drift('unsupported YAML folding')
                    run = ' '.join(block) + '\n'
                else:
                    run = '\n'.join(block) + '\n'
            else:
                run = scalar(value or '') + '\n'
        else:
            fields[key] = scalar(value or '')
    if ('uses' in fields) == (run is not None):
        raise Drift('exactly one run or uses is required')
    if run is not None and 'with' in fields:
        raise Drift('run step cannot carry action inputs')
    return Step(raw, fields, env, run)


def parse_jobs(text: str) -> dict[str, tuple[str, list[Step]]]:
    lines = text.splitlines(keepends=True)
    if lines.count('jobs:\n') != 1:
        raise Drift('exactly one jobs mapping required')
    result = {}
    i = lines.index('jobs:\n') + 1
    while i < len(lines):
        if not lines[i].strip() or lines[i].lstrip().startswith('#'):
            i += 1
            continue
        job = re.fullmatch(r'  ([a-z][a-z0-9-]*):\n', lines[i])
        if not job:
            raise Drift('unsupported job mapping')
        name = job[1]
        if name in result:
            raise Drift('duplicate job')
        end = i + 1
        while end < len(lines) and not re.match(r'^  [a-z][a-z0-9-]*:', lines[end]):
            end += 1
        block = lines[i + 1:end]
        if name not in MIRRORED.values():
            # Other protected jobs are outside this six-lane contract.
            i = end
            continue
        if block.count('    steps:\n') != 1:
            raise Drift('exactly one steps mapping required')
        at = block.index('    steps:\n')
        header = ''.join(block[:at])
        rawsteps = ''.join(block[at + 1:])
        starts = [m.start() for m in re.finditer(r'^      - ', rawsteps, re.M)]
        if not starts or rawsteps[:starts[0]].strip():
            raise Drift('unsupported steps mapping')
        starts.append(len(rawsteps))
        steps = [parse_step(rawsteps[a:b]) for a, b in zip(starts, starts[1:])]
        if len({s.fields['name'] for s in steps}) != len(steps):
            raise Drift('duplicate step name')
        result[name] = (header, steps)
        i = end
    if set(result) != set(MIRRORED.values()):
        raise Drift('missing mirrored job')
    return result


def expanded(value: str, pins: dict[str, str]) -> str:
    for old in ('${{ github.workspace }}', '${dogfood_repo}'):
        value = value.replace(old, '<checkout>')
    value = value.replace('${port}', '<database-port>')
    if value == 'postgres://mcloving@127.0.0.1:5432/mcloving':
        value = 'postgres://mcloving@127.0.0.1:<database-port>/mcloving'
    for key, pin in pins.items():
        value = value.replace('${' + key + '}', pin)
    if '$' in value:
        raise Drift('unbound environment expansion')
    return value


def record(command: str, cwd: str, env: dict[str, str], pins: dict[str, str]) -> str:
    # ADR inventory is a separately bounded assertion, not a general pipeline.
    adr = 'test "$(find docs/adr -maxdepth 1 -name \'[0-9][0-9][0-9][0-9]-*.md\' | wc -l)" -eq 16'
    if command == adr:
        argv = ['assert-adr-inventory', 'docs/adr', '[0-9][0-9][0-9][0-9]-*.md', '16']
    else:
        if any(token in command for token in (';', '&&', '||', '|', '`', '$(', '<', '\n')):
            raise Drift('unsupported shell operator/substitution')
        lexer = shlex.shlex(command, posix=True, punctuation_chars='><&;|()')
        lexer.whitespace_split = True
        # logical_lines already identified real comments. Word-internal and
        # quoted hashes must survive argv parsing unchanged.
        lexer.commenters = ''
        argv = list(lexer)
        env = dict(env)
        while argv and re.match(r'^[A-Za-z_][A-Za-z_0-9]*=', argv[0]):
            key, value = argv.pop(0).split('=', 1)
            env[key] = expanded(value, pins)
        if argv[-2:] == ['>', '/dev/null']:
            argv = argv[:-2]  # metadata's checked output sink, retained below.
            sink = '/dev/null'
        else:
            sink = None
        if any(a in {'>', '>>', '&', '(', ')', '<'} for a in argv):
            raise Drift('unsupported redirection/control flow')
        argv = [expanded(a, pins) for a in argv]
        if not argv or argv[0] not in {'cargo', 'bash', 'python3', '/usr/bin/python3', 'test', 'timeout', './test-plugin-directory.sh', '../../scripts/test-jenkins-sequential-contract.sh', '../../scripts/test-jenkins-sequential-compiler.sh'}:
            raise Drift('unsupported executable')
    wrapped = None
    if argv[:2] == ['bash', 'scripts/run-verified-rust-test.sh']:
        if len(argv) < 6 or not re.fullmatch(r'[1-9][0-9]*', argv[2]) or not re.fullmatch(r'[a-z][a-z0-9-]*', argv[3]):
            raise Drift('invalid verified-test metadata')
        wrapped = {'expected': int(argv[2]), 'label': argv[3], 'require_postgres': argv[4] == '--require-postgres'}
        argv = argv[5:] if wrapped['require_postgres'] else argv[4:]
    rust = None
    if argv[0] == 'cargo':
        if len(argv) < 3 or argv[1] != '+1.97.1':
            raise Drift('Cargo toolchain must be explicit and pinned')
        rust = {'operation': argv[2], 'packages': [], 'targets': [], 'features': [], 'test_flags': []}
        tail = argv[3:]
        if '--' in tail:
            pos = tail.index('--')
            rust['test_flags'] = tail[pos + 1:]
            tail = tail[:pos]
        for n, arg in enumerate(tail):
            if arg in {'-p', '--package', '--test', '--features'}:
                if n + 1 == len(tail):
                    raise Drift('missing Cargo option value')
                key = {'-p': 'packages', '--package': 'packages', '--test': 'targets', '--features': 'features'}[arg]
                rust[key].append(tail[n + 1])
        if wrapped and (rust['operation'] != 'test' or not rust['packages'] or len(rust['targets']) != 1 or '--locked' not in tail):
            raise Drift('wrapped command must be a locked, targeted Cargo test')
    if wrapped and rust is None:
        raise Drift('unsupported wrapped executable')
    if wrapped and wrapped['require_postgres'] and not env.get('MCLOVING_TEST_DATABASE_URL'):
        raise Drift('PostgreSQL wrapper has no database environment')
    return json.dumps({'argv': argv, 'cwd': cwd, 'env': sorted(env.items()), 'wrapper': wrapped, 'rust': rust,
                       'sink': None if command == adr else sink, 'failure': 'bash-errexit/simple-command'}, sort_keys=True)


def simple(text: str, cwd: str, env: dict[str, str], pins: dict[str, str]) -> list[str]:
    result = []
    for command in logical_lines(text):
        if not command or command.startswith('#'):
            continue
        result.append(record(command, cwd, env, pins))
    return result


def compare(left: list[str], right: list[str]) -> None:
    missing, added = Counter(left) - Counter(right), Counter(right) - Counter(left)
    if missing or added:
        raise Drift(f'command/context multiset changed: missing={sum(missing.values())}, added={sum(added.values())}')
    if left != right:
        raise Drift('verification order changed')


def check(root: pathlib.Path) -> int:
    policy = json.loads((root / 'scripts/dogfood/lane-contracts.json').read_text(), object_pairs_hook=unique)
    if set(policy) != {'protocol', 'inputs', 'workflow_header_sha256', 'jobs', 'workflow_blocks', 'lane_blocks', 'exceptions'} or policy['protocol'] != 'mcloving.dogfood-lane-contracts/v1':
        raise Drift('invalid closed lane contract')
    pins = {'RUST_TOOLCHAIN': '1.97.1'}
    for path, sha in policy['inputs'].items():
        raw = (root / path).read_text()
        if digest(raw) != sha:
            raise Drift('shared setup/tool/policy source changed: ' + path)
        if path.endswith('versions.env'):
            for match in re.finditer(r'^([A-Z_]+)="([^"]+)"$', raw, re.M):
                if match[1] in pins:
                    raise Drift('duplicate tool pin')
                pins[match[1]] = match[2]
    workflow = (root / '.github/workflows/foundation.yml').read_text()
    if workflow.count('\njobs:\n') != 1 or digest(clean(workflow.split('\njobs:\n', 1)[0])) != policy['workflow_header_sha256']:
        raise Drift('workflow execution/default/global context changed')
    jobs = parse_jobs(workflow)
    used_workflow = Counter()
    used_lanes = Counter()
    total = 0
    for script, job in MIRRORED.items():
        header, steps = jobs[job]
        bound = policy['jobs'][job]
        if digest(clean(header)) != bound['header_sha256']:
            raise Drift('job execution/service/default context changed: ' + job)
        base = {k: expanded(v, pins) for k, v in bound['env'].items()}
        expected = []
        for step in steps:
            h = digest(clean(step.raw))
            if h in policy['workflow_blocks']:
                entry = policy['workflow_blocks'][h]
                if job not in entry['jobs']:
                    raise Drift('setup action/block moved between jobs')
                used_workflow[h] += 1
                expected.extend(entry['records'])
                continue
            if step.run is None or set(step.fields) - {'name', 'run', 'env', 'working-directory', 'shell'}:
                raise Drift('unreviewed action or step metadata')
            if step.fields.get('shell', 'bash') != 'bash':
                raise Drift('unsupported shell')
            env = base | {k: expanded(v, pins) for k, v in step.env.items()}
            cwd = step.fields.get('working-directory', '.')
            if '$' in cwd or cwd.startswith('/') or '..' in cwd.split('/'):
                raise Drift('unsupported working directory')
            expected.extend(simple(step.run, cwd, env, pins))
        lane = (root / 'scripts/dogfood' / script).read_text()
        if any(line.lstrip().startswith('# canonical-record') for line in lane.splitlines()):
            raise Drift('source-authored canonical record is not executable verification')
        # Each complex block is exact, occurrence-bound and explicitly classified.
        # Any changed command inside a block invalidates its source binding.
        ranges = []
        for key, block in policy['lane_blocks'].items():
            if block['script'] != script:
                continue
            begin, end = f'# dogfood-contract-begin {key}\n', f'# dogfood-contract-end {key}\n'
            if lane.count(begin) != 1 or lane.count(end) != 1:
                raise Drift('missing/duplicate bounded lane setup block')
            a, b = lane.index(begin), lane.index(end) + len(end)
            body = lane[a + len(begin):b - len(end)]
            if digest(clean(body)) != block['sha256']:
                raise Drift('bounded lane setup/verification changed: ' + key)
            used_lanes[key] += 1
            ranges.append((a, b, CatalogRecords(tuple(block['records']))))
        items = []
        previous = 0
        for a, b, canonical in sorted(ranges, key=lambda item: item[0]):
            if a < previous:
                raise Drift('overlapping bounded lane blocks')
            items.extend(logical_lines(lane[previous:a]))
            items.append(canonical)
            previous = b
        items.extend(logical_lines(lane[previous:]))
        actual = []
        env = dict(base)
        cwd = '.'
        scope_env = None
        meaningful_lines = [line.strip() for line in lane.splitlines() if line.strip() and not line.lstrip().startswith('#')]
        if script == 'architecture.sh' and (not meaningful_lines or meaningful_lines[-1] != 'python3 scripts/dogfood/verify-lanes.py'):
            raise Drift('lane self-check must be the final architecture command')
        for line in items:
            if isinstance(line, CatalogRecords):
                actual.extend(line.records)
                continue
            text = line.strip()
            if not text or text.startswith('#'):
                continue
            if text.startswith('export '):
                values = shlex.split(text[7:])
                for item in values:
                    if not re.match(r'^[A-Za-z_][A-Za-z_0-9]*=', item):
                        raise Drift('unsupported export')
                    key, value = item.split('=', 1)
                    env[key] = expanded(value, pins)
                continue
            if text.startswith('unset '):
                for key in shlex.split(text[6:]):
                    if key not in env:
                        raise Drift('unbound unset')
                    del env[key]
                continue
            if text == '(':
                if cwd != '.' or scope_env is not None:
                    raise Drift('nested working directory')
                scope_env = dict(env)
                continue
            if text == 'cd compat/jenkins-worker':
                if scope_env is None or cwd != '.':
                    raise Drift('working directory must use the closed subshell scope')
                cwd = 'compat/jenkins-worker'
                continue
            if text == ')':
                if cwd != 'compat/jenkins-worker' or scope_env is None:
                    raise Drift('unmatched working-directory scope')
                env = scope_env
                scope_env = None
                cwd = '.'
                continue
            if text == 'python3 scripts/dogfood/verify-lanes.py' and script == 'architecture.sh':
                # A named, required lane-only self-check; cannot disappear.
                used_lanes['architecture-self-check'] += 1
                continue
            actual.extend(simple(text, cwd, env, pins))
        if cwd != '.' or scope_env is not None:
            raise Drift('unclosed working directory')
        compare(expected, actual)
        total += len(expected)
    expected_workflow = Counter({h: b['count'] for h, b in policy['workflow_blocks'].items()})
    expected_lanes = Counter({key: 1 for key in policy['lane_blocks']})
    expected_lanes['architecture-self-check'] = 1
    if used_workflow != expected_workflow or used_lanes != expected_lanes:
        raise Drift('finite setup or exception inventory changed')
    return total


def main() -> int:
    try:
        count = check(ROOT)
    except (Drift, OSError, ValueError, KeyError, TypeError) as error:
        print('dogfood-lanes-drift: ' + str(error), file=sys.stderr)
        return 1
    print(f'dogfood-lanes: six bidirectional ordered command/context inventories ({count} records)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
