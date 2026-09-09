#!/usr/bin/env python3
"""Compile the fixed preregistered population twice; never execute its scripts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'compat/jenkins-worker/fixtures/sequential-v1'
MANIFEST_SHA256 = '654898829f31872d471db88830414b23a9453e021bec281f05ac1aa4175de727'
CONTRACT_SHA256 = 'ae47b3f3cc58d6a66cec6d73832a189417864df74110c83bf1f656840c5d5dfe'
PROFILE_SHA256 = 'feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271'
RETAINED_CAMPAIGN_SHA256 = '1851ed7e7cec098049995abf898a009bae4f25bb42582a8108ed3010be9014e7'
RETAINED_IMAGE_SHA256 = '0b687a72f8cd99a1c8401796714e5f9867f2288d7aff80bf1fdd22e2ac417232'
RETAINED_ADMISSION_SHA256 = '01f40fa860b18cef0b3821092f1fffbde37124db911d6e9f31482ac24bcc2ca6'


def digest(content):
    return hashlib.sha256(content).hexdigest()


def receipt(content):
    result = {}
    for line in content.decode('ascii').splitlines():
        key, separator, value = line.partition('=')
        if not separator or key in result:
            raise ValueError('invalid or duplicate trusted receipt field')
        result[key] = value
    return result


def canonical_context(fixture, source):
    identifier = fixture['id']
    historical = identifier == 'C052'
    context = {'document-id': f'jcomp-{identifier.lower()}',
               'origin': ('repository:' + fixture['source_path'] if historical else
                          'project-authored:JCOMP-001/' + identifier),
               'origin-kind': 'corpus-reference' if historical else 'authored-document',
               'schema': 'mcloving.jenkins.source-document/1',
               'source-sha256': digest(source)}
    context_bytes = ('{' + ', '.join(':' + key + ' ' +
        (':' + value if key == 'origin-kind' else json.dumps(value, ensure_ascii=True))
        for key, value in sorted(context.items())) + '}\n').encode('ascii')
    return context_bytes


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def read_retained(path, limit):
    require(not path.is_symlink() and path.is_file(), 'retained input is not a regular file')
    with path.open('rb') as source:
        content = source.read(limit + 1)
    require(len(content) <= limit, 'retained input exceeds bound')
    return content


def verify_retained(directory):
    """Check preserved observations, not replay worker code or claim new execution."""
    directory = Path(directory)
    require(not directory.is_symlink() and directory.is_dir(), 'invalid retained directory')
    manifest_bytes = (BASE / 'manifest.json').read_bytes()
    require(digest(manifest_bytes) == MANIFEST_SHA256, 'preregistered manifest changed')
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_pairs)
    require(digest((ROOT / manifest['contract_path']).read_bytes()) == CONTRACT_SHA256,
            'contract content changed')
    require(digest((ROOT / manifest['profile']['path']).read_bytes()) == PROFILE_SHA256,
            'profile content changed')
    fixtures = {fixture['id']: fixture for fixture in manifest['fixtures']}
    identifiers = [fixture['id'] for fixture in manifest['fixtures']]
    inventory = {'campaign.json'} | {f'{identifier}-run-{run}{suffix}'
        for identifier in identifiers for run in (1, 2) for suffix in ('.edn', '.receipt')}
    require(len(inventory) == 93 and {path.name for path in directory.iterdir()} == inventory,
            'retained inventory must contain exactly the fixed 93 files')
    campaign_bytes = read_retained(directory / 'campaign.json', 131072)
    campaign = json.loads(campaign_bytes, object_pairs_hook=unique_pairs)
    require(set(campaign) == {'schema', 'fixtures', 'isolated_runs', 'worker_image_sha256',
        'admission_binary_sha256', 'manifest_sha256', 'execution_authority', 'records'},
        'campaign field set changed')
    require(campaign['schema'] == 'mcloving.jenkins.sequential-contained/1' and
        type(campaign['fixtures']) is int and campaign['fixtures'] == 23 and
        type(campaign['isolated_runs']) is int and campaign['isolated_runs'] == 46 and
        campaign['execution_authority'] is False, 'campaign population or authority claim changed')
    require(campaign['manifest_sha256'] == MANIFEST_SHA256 and
        campaign['worker_image_sha256'] == RETAINED_IMAGE_SHA256 and
        campaign['admission_binary_sha256'] == RETAINED_ADMISSION_SHA256,
        'campaign implementation or manifest pin changed')
    records = campaign['records']
    require(type(records) is list and len(records) == 46, 'record population changed')
    expected_pairs = [(identifier, run) for identifier in identifiers for run in (1, 2)]
    seen = set()
    previous = {}
    for index, record in enumerate(records):
        require(type(record) is dict and set(record) == {'fixture', 'run', 'status',
            'response_sha256', 'receipt_sha256', 'source_sha256', 'context_sha256'},
            'record field set changed')
        require(type(record['fixture']) is str and type(record['run']) is int,
                'record identity type changed')
        pair = (record['fixture'], record['run'])
        require(pair not in seen, 'duplicate fixture/run record')
        require(pair == expected_pairs[index], 'fixed fixture/run record ordering changed')
        seen.add(pair)
        identifier, run = pair
        fixture = fixtures[identifier]
        source = (ROOT / fixture['source_path']).read_bytes()
        require(digest(source) == fixture['source_sha256'], 'fixture source changed')
        context_bytes = canonical_context(fixture, source)
        require(record['source_sha256'] == digest(source), 'record source binding changed')
        require(record['context_sha256'] == digest(context_bytes), 'record context binding changed')
        stem = f'{identifier}-run-{run}'
        response = read_retained(directory / (stem + '.edn'), 65536)
        receipt_bytes = read_retained(directory / (stem + '.receipt'), 16384)
        require(digest(response) == record['response_sha256'] and
            digest(receipt_bytes) == record['receipt_sha256'], 'retained artifact digest mismatch')
        require(response.endswith(b'\n') and response.count(b'\n') == 1,
                'retained response framing changed')
        require(receipt_bytes.endswith(b'\n') and b'\r' not in receipt_bytes,
                'retained receipt framing changed')
        observed = receipt(receipt_bytes)
        expected = fixture['expected']
        status = 'admitted' if expected['compilation'] == 'supported' else expected['compilation']
        require(record['status'] == status, 'record classification changed')
        bindings = {'status': status, 'worker_image_sha256': RETAINED_IMAGE_SHA256,
            'admission_binary_sha256': RETAINED_ADMISSION_SHA256,
            'launch_source_sha256': digest(source), 'launch_context_sha256': digest(context_bytes)}
        digest_keys = set()
        if status == 'admitted':
            bindings.update(state='disabled', execution_authority='false',
                contract_sha256=CONTRACT_SHA256, target_profile_sha256=PROFILE_SHA256,
                source_sha256=digest(source), context_sha256=digest(context_bytes),
                protocol='mcloving.jenkins.compiler/2', compiler='mcloving-jenkins-compiler-worker/2',
                request_id='jcomp-' + identifier.lower(), document_id='jcomp-' + identifier.lower(),
                stages=str(len(expected['stages'])),
                steps=str(sum(len(stage['steps']) for stage in expected['stages'])))
            digest_keys = {'pipeline_yaml_sha256', 'definition_yaml_sha256',
                           'semantic_ir_sha256', 'canonical_ir_sha256'}
        else:
            bindings['code'] = expected['diagnostic']
        require(set(observed) == set(bindings) | digest_keys, 'retained receipt field set changed')
        require(all(observed[key] == value for key, value in bindings.items()),
                'retained receipt binding or authority claim changed')
        require(all(len(observed[key]) == 64 and all(c in '0123456789abcdef' for c in observed[key])
                    for key in digest_keys), 'retained artifact digest format changed')
        if identifier in previous:
            require(previous[identifier] == (response, receipt_bytes), 'repeated-run identity changed')
        previous[identifier] = (response, receipt_bytes)
    # Freeze the observed campaign after structural/semantic checks: coordinated
    # artifact + index edits cannot manufacture a replacement historical receipt.
    require(digest(campaign_bytes) == RETAINED_CAMPAIGN_SHA256, 'reviewed campaign bytes changed')
    return 'retained-sequential-ok files=93 fixtures=23 isolated_runs=46 execution_authority=false'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-retained', type=Path)
    parser.add_argument('--image')
    parser.add_argument('--image-sha256')
    parser.add_argument('--admission-bin', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.verify_retained is not None:
        if any(value is not None for value in [args.image, args.image_sha256, args.admission_bin, args.output]):
            parser.error('offline verification does not accept live compiler options')
        print(verify_retained(args.verify_retained))
        return
    if any(value is None for value in [args.image, args.image_sha256, args.admission_bin, args.output]):
        parser.error('live compilation requires image, image-sha256, admission-bin and output')
    if len(args.image_sha256) != 64 or any(c not in '0123456789abcdef' for c in args.image_sha256):
        raise ValueError('invalid immutable image pin')
    manifest_bytes = (BASE / 'manifest.json').read_bytes()
    if digest(manifest_bytes) != MANIFEST_SHA256:
        raise ValueError('preregistered manifest changed')
    subprocess.run(['python3', '-B', str(BASE / 'validate.py')], check=True)
    manifest = json.loads(manifest_bytes)
    fixtures = manifest['fixtures']
    expected_ids = {f'S{i:02}' for i in range(1, 11)} | {f'N{i:02}' for i in range(1, 13)} | {'C052'}
    if len(fixtures) != 23 or {f['id'] for f in fixtures} != expected_ids:
        raise ValueError('fixed fixture denominator changed')
    admission = args.admission_bin.resolve(strict=True)
    admission_sha256 = digest(admission.read_bytes())
    args.output.mkdir(parents=True, exist_ok=False)
    records = []
    environment = dict(os.environ, MCLOVING_JENKINS_WORKER_IMAGE=args.image,
                       MCLOVING_JENKINS_SEQUENTIAL_WORKER_IMAGE_SHA256=args.image_sha256,
                       MCLOVING_JENKINS_ADMISSION_BIN=str(admission))
    with tempfile.TemporaryDirectory(prefix='mcloving-sequential-campaign-') as temporary:
        private = Path(temporary)
        for fixture in fixtures:
            identifier = fixture['id']
            source = (ROOT / fixture['source_path']).read_bytes()
            if digest(source) != fixture['source_sha256']:
                raise ValueError(f'{identifier}: source digest mismatch')
            context_bytes = canonical_context(fixture, source)
            source_path, context_path = private / (identifier + '.source'), private / (identifier + '.context')
            source_path.write_bytes(source)
            context_path.write_bytes(context_bytes)
            source_path.chmod(0o400)
            context_path.chmod(0o400)
            previous = None
            for run in (1, 2):
                result = subprocess.run([str(ROOT / 'compat/jenkins-worker/run-worker.sh'),
                    'compile-sequential', str(source_path), 'jcomp-' + identifier.lower(),
                    str(context_path)], env=environment, capture_output=True, timeout=20)
                if result.returncode:
                    stem = f'{identifier}-run-{run}-unverified'
                    (args.output / (stem + '.stdout')).write_bytes(result.stdout)
                    (args.output / (stem + '.stderr')).write_bytes(result.stderr)
                    (args.output / (stem + '.json')).write_text(json.dumps({
                        'fixture': identifier, 'run': run, 'launcher_exit': result.returncode,
                        'verified': False, 'worker_image_sha256': args.image_sha256,
                        'admission_binary_sha256': admission_sha256}, indent=2) + '\n')
                    raise ValueError(f'{identifier} run {run}: unverified compilation; launcher exit {result.returncode}; diagnostics {result.stderr[:1024]!r}')
                observed = receipt(result.stderr)
                expected = fixture['expected']
                status = 'admitted' if expected['compilation'] == 'supported' else expected['compilation']
                bindings = {'status': status, 'worker_image_sha256': args.image_sha256,
                            'admission_binary_sha256': admission_sha256,
                            'launch_source_sha256': digest(source),
                            'launch_context_sha256': digest(context_bytes)}
                if status == 'admitted':
                    bindings.update(state='disabled', execution_authority='false',
                        contract_sha256=CONTRACT_SHA256, source_sha256=digest(source),
                        context_sha256=digest(context_bytes),
                        protocol='mcloving.jenkins.compiler/2',
                        compiler='mcloving-jenkins-compiler-worker/2',
                        target_profile_sha256=manifest['profile']['sha256'],
                        request_id='jcomp-' + identifier.lower(),
                        document_id='jcomp-' + identifier.lower(),
                        stages=str(len(expected['stages'])),
                        steps=str(sum(len(s['steps']) for s in expected['stages'])))
                else:
                    bindings['code'] = expected['diagnostic']
                digest_keys = {'pipeline_yaml_sha256', 'definition_yaml_sha256',
                               'semantic_ir_sha256', 'canonical_ir_sha256'} if status == 'admitted' else set()
                if set(observed) != set(bindings) | digest_keys:
                    raise ValueError(f'{identifier}: missing or unexpected receipt fields')
                if any(len(observed[key]) != 64 or any(c not in '0123456789abcdef' for c in observed[key])
                       for key in digest_keys):
                    raise ValueError(f'{identifier}: invalid admitted artifact digest')
                if any(observed.get(key) != value for key, value in bindings.items()):
                    raise ValueError(f'{identifier}: trusted admission receipt disagrees with preregistration')
                pair = (result.stdout, result.stderr)
                if previous is not None and previous != pair:
                    raise ValueError(f'{identifier}: isolated compiler or trusted receipt is nondeterministic')
                previous = pair
                stem = f'{identifier}-run-{run}'
                (args.output / (stem + '.edn')).write_bytes(result.stdout)
                (args.output / (stem + '.receipt')).write_bytes(result.stderr)
                records.append({'fixture': identifier, 'run': run, 'status': status,
                    'response_sha256': digest(result.stdout), 'receipt_sha256': digest(result.stderr),
                    'source_sha256': digest(source), 'context_sha256': digest(context_bytes)})
            print(f'{identifier}: {status}; two identical isolated compile-only responses', flush=True)
    evidence = {'schema': 'mcloving.jenkins.sequential-contained/1', 'fixtures': 23,
                'isolated_runs': 46, 'worker_image_sha256': args.image_sha256,
                'admission_binary_sha256': admission_sha256, 'manifest_sha256': MANIFEST_SHA256,
                'execution_authority': False, 'records': records}
    (args.output / 'campaign.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print('23 fixtures, 46 isolated compilations verified; no execution or corpus admission claim')


if __name__ == '__main__':
    main()
