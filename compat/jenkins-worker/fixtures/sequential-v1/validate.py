#!/usr/bin/env python3
"""Read-only JCOMP-001 preregistration integrity; never execute fixture source."""
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

ASCII_FOLD = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
BASE = PurePosixPath('compat/jenkins-worker/fixtures/sequential-v1')
PROFILE = 'compat/jenkins-worker/profile-v1.properties'
PROFILE_SHA256 = 'feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271'
HISTORICAL = 'migration/mario-jenkins-oracle-228/corpus-v1/sources/cinqict_jenkinsdev.Jenkinsfile'
HISTORICAL_SHA256 = '666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(root, relative, limit):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == relative,
            'noncanonical relative path')
    current = root
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), 'symlink in fixture path')
    require(current.is_file(), 'missing regular input: ' + relative)
    with current.open('rb') as source:
        content = source.read(limit + 1)
    require(len(content) <= limit, 'oversized contract input')
    return content


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def verify(root):
    manifest = json.loads(read(root, str(BASE / 'manifest.json'), 262144), object_pairs_hook=pairs)
    require(manifest['schema'] == 'mcloving.jenkins.sequential-contract/1', 'schema changed')
    require(manifest['status'] == 'preregistered-expectations-not-execution-evidence', 'not expectations')
    require(manifest['authority'] == {'production': False, 'imported_job_enabled': False,
                                    'execution_evidence': False}, 'authority or evidence claim')
    require(manifest['denominators'] == {'authored_supported': 10, 'authored_negative': 12,
                                       'historical_regression': 1, 'original_corpus_sources': 228},
            'denominator changed')
    require(manifest['limits'] == {'source_utf8_bytes': 16384, 'stages': 32, 'steps_total': 64,
                                  'stage_name_utf8_bytes': 96, 'shell_literal_utf8_bytes': 4096,
                                  'shell_literals_total_utf8_bytes': 4096, 'response_bytes': 65536},
            'contract limits changed')
    profile = manifest['profile']
    require(profile == {'path': PROFILE, 'sha256': PROFILE_SHA256, 'jenkins_core': '2.568.1',
                        'plugin_files': 90, 'plugin_manifest_sha256':
                        'e33fa87646e6e360e7614373cc0057ba2e92ff18b9a9ea9419dea796dcb950b0'},
            'profile reference changed')
    require(hashlib.sha256(read(root, PROFILE, 16384)).hexdigest() == PROFILE_SHA256, 'profile bytes changed')
    require(manifest['contract_path'] == 'docs/architecture/JENKINS_SEQUENTIAL_DECLARATIVE_V1.md',
            'contract reference changed')
    read(root, manifest['contract_path'], 65536)
    expected_ids = {f'S{i:02}' for i in range(1, 11)} | {f'N{i:02}' for i in range(1, 13)} | {'C052'}
    fixtures = manifest['fixtures']
    require(len(fixtures) == len(expected_ids) and {f['id'] for f in fixtures} == expected_ids,
            'missing or duplicate fixture ID')
    paths = set()
    for fixture in fixtures:
        identifier = fixture['id']
        supported = identifier.startswith('S') or identifier == 'C052'
        population = ('historical-regression' if identifier == 'C052' else
                      'authored-supported' if supported else 'authored-negative')
        require(fixture['population'] == population, 'borrowed population')
        path = fixture['source_path']
        require(path not in paths, 'source path reused')
        paths.add(path)
        require(path == (HISTORICAL if identifier == 'C052' else str(BASE / (identifier + '.Jenkinsfile'))),
                'source identity changed')
        content = read(root, path, 32768)
        content.decode('utf-8', errors='strict')
        require(hashlib.sha256(content).hexdigest() == fixture['source_sha256'] and
                len(content) == fixture['source_bytes'], 'source bytes changed: ' + identifier)
        if identifier == 'C052':
            require(fixture['source_sha256'] == HISTORICAL_SHA256, 'historical source replaced')
            require(fixture['provenance'] == {'origin': 'cinqict/jenkinsdev',
                    'commit': 'd20369f19c12899e2f3bc5c8fbce7e7b81752fb7', 'license': 'MIT',
                    'attribution': 'migration/mario-jenkins-oracle-228/corpus-v1/corpus-index.tsv'},
                    'historical attribution changed')
        else:
            require(fixture['provenance'] == {'origin': 'project-authored-for-JCOMP-001',
                    'license': 'project-authored-no-third-party-source; no new license grant'},
                    'authored provenance changed')
        expected = fixture['expected']
        if not supported:
            require(expected['compilation'] in ('unsupported', 'rejected') and
                    expected['diagnostic'].startswith('E_') and expected['scheduled_work'] == 0,
                    'negative fixture grants work')
            require(set(expected) == {'compilation', 'diagnostic', 'scheduled_work'},
                    'negative fixture has execution expectations')
            continue
        require(expected['compilation'] == 'supported' and expected['diagnostic'] is None,
                'supported fixture disposition')
        require(len(content) <= manifest['limits']['source_utf8_bytes'], 'supported source over bound')
        require(not content.startswith(b'\xef\xbb\xbf') and b'\r' not in content and b'\0' not in content,
                'supported source violates LF/no-BOM/no-NUL contract')
        stages = expected['stages']
        require(0 < len(stages) <= 32, 'stage bound')
        names = [s['name'] for s in stages]
        normalized = [re.sub(r'[^a-z0-9._-]+', '-', name.translate(ASCII_FOLD)).strip('-')
                      for name in names]
        require(all(0 < len(name) <= 96 for name in normalized) and
                len(set(normalized)) == len(normalized),
                'blank or duplicate normalized stage identity')
        failed = False
        scripts = []
        for stage in stages:
            require(0 < len(stage['name'].encode()) <= 96 and stage['steps'], 'stage name or empty steps')
            outcomes = []
            for step in stage['steps']:
                scripts.append(step['script_utf8'].encode())
                require(0 < len(scripts[-1]) <= 4096 and not scripts[-1].startswith(b'#!') and
                        b'\0' not in scripts[-1], 'shell bound/shebang/NUL')
                outcome = step['outcome']
                if failed:
                    require(outcome == 'skipped' and step['exit_code'] is None and step['stdout_utf8'] == '',
                            'work after failed step')
                else:
                    require(type(step['exit_code']) is int and 0 <= step['exit_code'] <= 255,
                            'invalid executed exit code')
                    require(outcome == ('succeeded' if step['exit_code'] == 0 else 'failed'),
                            'exit/outcome disagreement')
                    failed = outcome == 'failed'
                outcomes.append(outcome)
            stage_outcome = 'failed' if 'failed' in outcomes else 'skipped' if set(outcomes) == {'skipped'} else 'succeeded'
            require(stage['outcome'] == stage_outcome, 'stage outcome mismatch')
        require(len(scripts) <= 64 and sum(map(len, scripts)) <= 4096, 'aggregate shell bound')
        require(expected['build_outcome'] == ('failed' if failed else 'succeeded'), 'build outcome mismatch')
        workspace = expected['workspace_files']
        names = [f['path'] for f in workspace]
        require(names == sorted(set(names)), 'duplicate or unsorted workspace files')
        for entry in workspace:
            name = PurePosixPath(entry['path'])
            require(not name.is_absolute() and '..' not in name.parts and str(name) == entry['path'],
                    'workspace path escape')
            require(type(entry['bytes']) is int and entry['bytes'] >= 0 and
                    len(entry['sha256']) == 64 and all(c in '0123456789abcdef' for c in entry['sha256']),
                    'invalid workspace digest/size')
    actual = {str(BASE / p.name) for p in (root / BASE).glob('*.Jenkinsfile')}
    require(actual == paths - {HISTORICAL}, 'missing or extra authored source')
    return '23 preregistered fixtures verified: 10 supported, 12 negative, 1 historical; no execution claim'


if __name__ == '__main__':
    print(verify(Path(__file__).resolve().parents[4]))
