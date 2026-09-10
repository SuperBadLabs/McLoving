#!/usr/bin/env python3
"""Capture/recheck compile-only outcomes for the unchanged 228-source population.

No Jenkinsfile or shell script is evaluated. Only the existing contained compiler
launcher runs. A failed independent admission remains unverified, never a denial
count. Retained verification checks bindings; --admission-bin additionally
replays independent Rust admission without launching a worker or workload.
"""
import argparse
from collections import Counter
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'migration/mario-jenkins-oracle-228/corpus-v1'
PINS = {
    'corpus-index.tsv': '5ecfefafc33b61d5c304a2dc6fbd60ca819882c3294605d92248f86215d51137',
    'SOURCE_SHA256SUMS': '3f95c70e04ef72dc107e7bb6f031679cfc56e5cf44e12948b89c98baacd7db06',
    'typed-redactions.tsv': 'f76fd92c95f93b5b8b0b9c2e1dad6322e9afcbb263d5d022186d127960abe223',
    'jenkins-source-normalization.tsv': 'ea69f40a53da5f177678d989677d112ef13da768f4c8ff8bd01c93eb2b28ac45',
}
CONTRACT = '264436c57b3aa82810f7041515c924b38a5a5e4be1f60fb6987151d1e8336a41'
PROFILE = 'feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271'
STATUSES = ('admitted', 'unsupported', 'rejected', 'unverified')
COMPILER_PATHS = ('compat/jenkins-worker', 'crates/jenkins-compiler-admission',
                  'crates/pipeline-ir', 'Cargo.toml', 'Cargo.lock')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(content):
    return hashlib.sha256(content).hexdigest()


def is_digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def read(path, bound=1048576):
    require(not path.is_symlink() and path.is_file(), f'not a regular file: {path}')
    with path.open('rb') as stream:
        content = stream.read(bound + 1)
    require(len(content) <= bound, f'input exceeds bound: {path}')
    return content


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def population():
    contents = {name: read(CORPUS / name) for name in PINS}
    require(all(sha(contents[name]) == pin for name, pin in PINS.items()),
            'historical population pin changed')
    rows = list(csv.DictReader(io.StringIO(contents['corpus-index.tsv'].decode()), delimiter='\t'))
    require(len(rows) == 228 and len({row['file'] for row in rows}) == 228,
            'original source population changed')
    require({p.name for p in (CORPUS / 'sources').iterdir()} == {r['file'] for r in rows},
            'original source membership changed')
    manifest = dict(line.split('  ', 1)[::-1] for line in
                    contents['SOURCE_SHA256SUMS'].decode('ascii').splitlines())
    for row in rows:
        source = read(CORPUS / 'sources' / row['file'], 262144)
        require(sha(source) == row['repository_source_sha256'] == manifest['sources/' + row['file']],
                'retained source bytes changed')
        if row['redacted'] == 'false':
            require(sha(source) == row['source_sha256'] and len(source) == int(row['bytes']),
                    'original source bytes changed')
    return rows


def identity(number):
    return f'jcomp003-corpus-{number:03d}'


def context(row, number):
    fields = {
        'document-id': identity(number),
        'origin': 'repository:migration/mario-jenkins-oracle-228/corpus-v1/sources/' + row['file'],
        'origin-kind': 'corpus-reference',
        'schema': 'mcloving.jenkins.source-document/1',
        'source-sha256': row['repository_source_sha256'],
    }
    return ('{' + ', '.join(':' + key + ' ' +
        (':' + value if key == 'origin-kind' else json.dumps(value, ensure_ascii=True))
        for key, value in sorted(fields.items())) + '}\n').encode('ascii')


def parse_receipt(content):
    require(content.endswith(b'\n') and b'\r' not in content, 'receipt framing changed')
    fields = {}
    for line in content.decode('ascii').splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in fields, 'invalid receipt field')
        fields[key] = value
    return fields


def check_receipt(content, row, number, image, admission):
    fields = parse_receipt(content)
    status = fields.get('status')
    require(status in STATUSES[:3], 'unknown verified classification')
    bindings = {
        'status': status, 'worker_image_sha256': image,
        'admission_binary_sha256': admission,
        'launch_source_sha256': row['repository_source_sha256'],
        'launch_context_sha256': sha(context(row, number)),
    }
    varying = set()
    if status == 'admitted':
        bindings.update(state='disabled', execution_authority='false',
            source_sha256=row['repository_source_sha256'], context_sha256=sha(context(row, number)),
            contract_sha256=CONTRACT, target_profile_sha256=PROFILE,
            protocol='mcloving.jenkins.compiler/2', compiler='mcloving-jenkins-compiler-worker/2',
            request_id=identity(number), document_id=identity(number))
        varying = {'stages', 'steps', 'pipeline_yaml_sha256', 'definition_yaml_sha256',
                   'semantic_ir_sha256', 'canonical_ir_sha256'}
        for key in varying - {'stages', 'steps'}:
            require(is_digest(fields.get(key)), 'invalid lowering digest')
        require(fields.get('stages', '').isdigit() and fields.get('steps', '').isdigit(),
                'invalid stage/step counts')
        require(1 <= int(fields['stages']) <= 32 and
                int(fields['stages']) <= int(fields['steps']) <= 64, 'stage/step bounds changed')
    else:
        require(re.fullmatch('E_[A-Z0-9_]+', fields.get('code', '')) is not None,
                'missing diagnostic code')
        varying = {'code'}
    require(set(fields) == set(bindings) | varying, 'receipt field set changed')
    require(all(fields[key] == value for key, value in bindings.items()), 'receipt binding changed')
    return status, fields.get('code'), fields


def summary(records):
    counts = Counter(record['status'] for record in records)
    reasons = Counter((record['status'], record['code']) for record in records)
    return {
        'population': 228,
        'exact_original_representations': 226,
        'retained_redacted_representations': 2,
        'counts': {status: counts[status] for status in STATUSES},
        'reasons': [{'status': status, 'code': code, 'count': count}
                    for (status, code), count in sorted(reasons.items(), key=lambda item: str(item[0]))],
        'classification_complete': counts['unverified'] == 0,
        'workload_executions': 0,
        'execution_equivalence_claim': False,
        'production_eligibility_claim': False,
    }


def launch(command, environment):
    process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=30)
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        # Terminate the complete launcher process group, then allow its cleanup
        # before escalating. This is unverified evidence even if output exists.
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=5)
        return 124, stdout, b'E_CAMPAIGN_TIMEOUT\n' + stderr


def capture(args):
    rows = population()
    require(is_digest(args.image_sha256), 'invalid image digest')
    admission = args.admission_bin.resolve(strict=True)
    admission_hash = sha(read(admission, 268435456))
    baseline = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    require(re.fullmatch('[0-9a-f]{40}', baseline) is not None, 'invalid implementation head')
    require(not subprocess.check_output(['git', 'status', '--porcelain', '--', *COMPILER_PATHS],
                                        cwd=ROOT), 'compiler inputs must be clean before capture')
    source_archive = subprocess.check_output(['git', 'archive', baseline, '--', *COMPILER_PATHS],
                                            cwd=ROOT)
    source_archive_hash = sha(source_archive)
    environment = dict(os.environ, MCLOVING_JENKINS_WORKER_IMAGE=args.image,
        MCLOVING_JENKINS_SEQUENTIAL_WORKER_IMAGE_SHA256=args.image_sha256,
        MCLOVING_JENKINS_ADMISSION_BIN=str(admission))
    args.output.mkdir(parents=True, exist_ok=False)
    records = []
    with tempfile.TemporaryDirectory(prefix='jcomp003-corpus-') as temporary:
        private = Path(temporary)
        for number, row in enumerate(rows, 1):
            stem = f'{number:03d}'
            source = read(CORPUS / 'sources' / row['file'], 262144)
            source_path, context_path = private / 'source', private / 'context'
            source_path.write_bytes(source)
            context_path.write_bytes(context(row, number))
            # The sealed launcher owns its own bounded input snapshots and
            # five-second container deadline, including cleanup on failure.
            launcher_exit, stdout, stderr = launch([str(ROOT / 'compat/jenkins-worker/run-worker.sh'),
                'compile-sequential', str(source_path), identity(number), str(context_path)],
                environment)
            require(len(stdout) <= 65536 and len(stderr) <= 65536,
                    'launcher output exceeds evidence bound')
            status, code = 'unverified', 'E_LAUNCHER_UNVERIFIED'
            if launcher_exit == 0:
                status, code, _ = check_receipt(stderr, row, number,
                                               args.image_sha256, admission_hash)
            else:
                # This names a trusted-side failure, not a source rejection.
                matches = re.findall(rb'\bE_[A-Z0-9_]+\b', stderr)
                if matches:
                    code = matches[0].decode('ascii')
            (args.output / (stem + '.stdout')).write_bytes(stdout)
            (args.output / (stem + '.stderr')).write_bytes(stderr)
            record = {'number': number, 'historical': row, 'context_sha256': sha(context(row, number)),
                'status': status, 'code': code, 'launcher_exit': launcher_exit,
                'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)}
            records.append(record)
            print(f'{stem} {row["file"]}: {status} {code or ""}', flush=True)
            if code == 'E_CAMPAIGN_TIMEOUT':
                (args.output / 'incomplete.json').write_text(json.dumps({
                    'schema': 'mcloving.jenkins.sequential-corpus-incomplete/1',
                    'reason': 'outer timeout; explicit container cleanup inspection required',
                    'implementation_head': baseline, 'records': records,
                    'worker_image_sha256': args.image_sha256,
                    'admission_binary_sha256': admission_hash}, indent=2) + '\n')
                raise ValueError('outer timeout: incomplete capture retained; inspect cleanup before another campaign')
    campaign = {
        'schema': 'mcloving.jenkins.sequential-corpus/1', 'implementation_head': baseline,
        'compiler_source_archive_sha256': source_archive_hash,
        'source_representation': 'unchanged repository source bytes; no Jenkins XML normalization',
        'population_pins': PINS, 'contract_sha256': CONTRACT, 'profile_sha256': PROFILE,
        'worker_image_sha256': args.image_sha256, 'admission_binary_sha256': admission_hash,
        'tool_sha256': sha(read(Path(__file__))), 'summary': summary(records), 'records': records,
    }
    content = (json.dumps(campaign, indent=2) + '\n').encode()
    (args.output / 'campaign.json').write_bytes(content)
    print(json.dumps(campaign['summary'], sort_keys=True))
    print('campaign_sha256=' + sha(content))


def verify(directory, expected_sha256, admission_bin=None):
    require(is_digest(expected_sha256), 'a reviewed external campaign digest is required')
    rows = population()
    require(not directory.is_symlink() and directory.is_dir(), 'invalid evidence directory')
    inventory = {'campaign.json'} | {f'{number:03d}.{suffix}' for number in range(1, 229)
                                    for suffix in ('stdout', 'stderr')}
    require({p.name for p in directory.iterdir()} == inventory, 'fixed 457-file inventory changed')
    content = read(directory / 'campaign.json', 1048576)
    campaign = json.loads(content, object_pairs_hook=pairs)
    require(set(campaign) == {'schema', 'implementation_head', 'source_representation',
        'compiler_source_archive_sha256', 'population_pins', 'contract_sha256', 'profile_sha256', 'worker_image_sha256',
        'admission_binary_sha256', 'tool_sha256', 'summary', 'records'}, 'campaign fields changed')
    require(campaign['schema'] == 'mcloving.jenkins.sequential-corpus/1' and
        campaign['population_pins'] == PINS and campaign['contract_sha256'] == CONTRACT and
        campaign['profile_sha256'] == PROFILE, 'campaign contract changed')
    require(campaign['source_representation'] ==
        'unchanged repository source bytes; no Jenkins XML normalization', 'source representation changed')
    require(type(campaign['implementation_head']) is str and
        re.fullmatch('[0-9a-f]{40}', campaign['implementation_head']), 'invalid implementation head')
    for key in ('worker_image_sha256', 'admission_binary_sha256', 'tool_sha256',
                'compiler_source_archive_sha256'):
        require(is_digest(campaign[key]), 'invalid implementation digest')
    if admission_bin is not None:
        admission_bin = admission_bin.resolve(strict=True)
        require(sha(read(admission_bin, 268435456)) == campaign['admission_binary_sha256'],
                'replay requires the recorded admission executable')
    records = campaign['records']
    require(type(records) is list and len(records) == 228, 'record population changed')
    with tempfile.TemporaryDirectory(prefix='jcomp003-corpus-replay-') as temporary:
        private = Path(temporary)
        for number, (row, record) in enumerate(zip(rows, records), 1):
            require(type(record) is dict and set(record) == {'number', 'historical', 'context_sha256',
                'status', 'code', 'launcher_exit', 'stdout_sha256', 'stderr_sha256'}, 'record fields changed')
            require(type(record['number']) is int and record['number'] == number and
                record['historical'] == row, 'historical identity/order changed')
            require(record['context_sha256'] == sha(context(row, number)), 'context binding changed')
            stdout = read(directory / f'{number:03d}.stdout', 65536)
            stderr = read(directory / f'{number:03d}.stderr', 65536)
            require(sha(stdout) == record['stdout_sha256'] and sha(stderr) == record['stderr_sha256'],
                    'raw artifact digest changed')
            require(type(record['launcher_exit']) is int, 'invalid launcher exit')
            if record['launcher_exit'] != 0:
                require(record['status'] == 'unverified', 'failed admission borrowed a classification')
                matches = re.findall(rb'\bE_[A-Z0-9_]+\b', stderr)
                code = matches[0].decode('ascii') if matches else 'E_LAUNCHER_UNVERIFIED'
                require(record['code'] == code, 'unverified diagnostic changed')
                continue
            status, code, fields = check_receipt(stderr, row, number,
                campaign['worker_image_sha256'], campaign['admission_binary_sha256'])
            require(record['status'] == status and record['code'] == code, 'classification changed')
            require(stdout.endswith(b'\n') and stdout.count(b'\n') == 1, 'response framing changed')
            if admission_bin is not None:
                source_path, context_path, response_path = (private / name for name in
                                                            ('source', 'context', 'response'))
                source_path.write_bytes(read(CORPUS / 'sources' / row['file'], 262144))
                context_path.write_bytes(context(row, number))
                response_path.write_bytes(stdout)
                replay = subprocess.run([str(admission_bin), 'validate-sequential', str(response_path),
                    str(source_path), str(context_path), identity(number)], capture_output=True, timeout=10)
                expected = {k: v for k, v in fields.items() if k not in {
                    'worker_image_sha256', 'admission_binary_sha256',
                    'launch_source_sha256', 'launch_context_sha256'}}
                require(replay.returncode == 0 and not replay.stderr and
                    parse_receipt(replay.stdout) == expected, 'independent Rust replay failed')
    require(json.dumps(campaign['summary'], sort_keys=True) ==
            json.dumps(summary(records), sort_keys=True), 'summary or claim changed')
    require(sha(content) == expected_sha256, 'reviewed campaign digest changed')
    return campaign['summary']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    live = sub.add_parser('capture')
    live.add_argument('--image', required=True)
    live.add_argument('--image-sha256', required=True)
    live.add_argument('--admission-bin', type=Path, required=True)
    live.add_argument('--output', type=Path, required=True)
    retained = sub.add_parser('verify')
    retained.add_argument('directory', type=Path)
    retained.add_argument('--campaign-sha256', required=True)
    retained.add_argument('--admission-bin', type=Path)
    args = parser.parse_args()
    if args.operation == 'capture':
        capture(args)
    else:
        print(json.dumps(verify(args.directory, args.campaign_sha256, args.admission_bin), sort_keys=True))
        print('verification=retained-bindings' if args.admission_bin is None else
              'verification=retained-bindings-and-independent-rust-replay')


if __name__ == '__main__':
    main()
