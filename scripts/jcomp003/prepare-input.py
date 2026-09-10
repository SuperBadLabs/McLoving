#!/usr/bin/env python3
"""Bind fresh trusted compiler receipts to exact YAML bytes for contained submission.

This extraction grants no compiler authority: each extracted byte string must match
its independent Rust admission digest. Original EDN and disabled documents remain.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile

if not __debug__:
    raise RuntimeError('verification requires assertions; Python optimization forbidden')

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('fixed_compiler', ROOT / 'scripts/test-jenkins-sequential-contained.py')
fixed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixed)


def sha(content):
    return hashlib.sha256(content).hexdigest()


def extract(response, key, expected_digest):
    # Only canonical EDN strings are selected, and the authority is the trusted
    # admission digest, not this small transport extractor's structural reading.
    matches = re.findall(r':' + re.escape(key) + r' ("(?:[^"\\]|\\.)*")', response)
    if len(matches) != 1:
        raise ValueError(f'exactly one {key} string required')
    value = json.loads(matches[0])
    if sha(value.encode()) != expected_digest:
        raise ValueError(f'{key} differs from independently admitted bytes')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('compiler_evidence', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--admission-bin', required=True, type=Path)
    parser.add_argument('--admission-sha256', required=True)
    parser.add_argument('--worker-sha256', required=True)
    parser.add_argument('--campaign-sha256', required=True)
    args = parser.parse_args()
    manifest_bytes = (fixed.BASE / 'manifest.json').read_bytes()
    assert sha(manifest_bytes) == fixed.MANIFEST_SHA256
    manifest = json.loads(manifest_bytes, object_pairs_hook=fixed.unique_pairs)
    campaign_bytes = (args.compiler_evidence / 'campaign.json').read_bytes()
    assert sha(campaign_bytes) == args.campaign_sha256
    assert sha(args.admission_bin.read_bytes()) == args.admission_sha256
    campaign = json.loads(campaign_bytes, object_pairs_hook=fixed.unique_pairs)
    assert campaign['admission_binary_sha256'] == args.admission_sha256
    assert campaign['worker_image_sha256'] == args.worker_sha256
    assert campaign['fixtures'] == 23 and campaign['isolated_runs'] == 46
    assert campaign['execution_authority'] is False
    assert campaign['manifest_sha256'] == sha(manifest_bytes)
    records = {(record['fixture'], record['run']): record for record in campaign['records']}
    assert len(records) == len(campaign['records']) == 46
    expected_pairs = [(fixture['id'], run) for fixture in manifest['fixtures'] for run in (1, 2)]
    assert [(record['fixture'], record['run']) for record in campaign['records']] == expected_pairs
    results = []
    for fixture in manifest['fixtures']:
        identifier = fixture['id']
        source = (ROOT / fixture['source_path']).read_bytes()
        assert sha(source) == fixture['source_sha256']
        context = fixed.canonical_context(fixture, source)
        previous = None
        for run in (1, 2):
            response = (args.compiler_evidence / f'{identifier}-run-{run}.edn').read_bytes()
            receipt_bytes = (args.compiler_evidence / f'{identifier}-run-{run}.receipt').read_bytes()
            record = records[identifier, run]
            assert sha(response) == record['response_sha256']
            assert sha(receipt_bytes) == record['receipt_sha256']
            assert sha(source) == record['source_sha256']
            receipt = fixed.receipt(receipt_bytes)
            assert receipt['launch_source_sha256'] == sha(source)
            assert receipt['worker_image_sha256'] == campaign['worker_image_sha256']
            assert receipt['admission_binary_sha256'] == campaign['admission_binary_sha256']
            assert record['context_sha256'] == sha(context)
            assert receipt['launch_context_sha256'] == sha(context)
            with tempfile.TemporaryDirectory(prefix='jcomp003-readmission-') as temporary:
                private = Path(temporary)
                (private / 'source').write_bytes(source)
                (private / 'context').write_bytes(context)
                (private / 'response').write_bytes(response)
                observed = subprocess.run([str(args.admission_bin.resolve()), 'validate-sequential',
                    str(private / 'response'), str(private / 'source'), str(private / 'context'),
                    'jcomp-' + identifier.lower()], check=True, capture_output=True, timeout=10)
                assert observed.stderr == b''
                readmitted = fixed.receipt(observed.stdout)
                launch_keys = {'launch_source_sha256', 'launch_context_sha256',
                               'worker_image_sha256', 'admission_binary_sha256'}
                assert readmitted == {key:value for key,value in receipt.items() if key not in launch_keys}
            assert previous is None or (response, receipt_bytes) == previous
            previous = (response, receipt_bytes)
        result = {'id':identifier, 'source_sha256':sha(source), 'response_sha256':sha(response),
                  'receipt':receipt}
        if fixture['expected']['compilation'] == 'supported':
            assert receipt['status'] == 'admitted' and receipt['state'] == 'disabled'
            assert receipt['execution_authority'] == 'false'
            result['pipeline_yaml'] = extract(response.decode(), 'pipeline-yaml', receipt['pipeline_yaml_sha256'])
            result['disabled_definition_yaml'] = extract(response.decode(), 'definition-yaml', receipt['definition_yaml_sha256'])
        else:
            assert receipt['status'] == fixture['expected']['compilation']
            assert receipt['code'] == fixture['expected']['diagnostic']
        results.append(result)
    payload = {'schema':'mcloving.jcomp003.contained-input/1', 'manifest_sha256':sha(manifest_bytes),
               'compiler_campaign_sha256':sha(campaign_bytes), 'fixtures':results}
    with args.output.open('x') as output:
        json.dump(payload, output, indent=2)
        output.write('\n')


if __name__ == '__main__':
    main()
