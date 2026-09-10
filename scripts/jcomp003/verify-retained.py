#!/usr/bin/env python3
"""Hydrate frozen source and verify retained observations; never rerun workloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

if not __debug__:
    raise RuntimeError('verification requires assertions')
OMITTED = {'tracer/strace', 'tracer/lib/libunwind-ptrace.so.0',
           'tracer/lib/libunwind-x86_64.so.8', 'tracer/lib/libunwind.so.8',
           'tracer/lib/liblzma.so.5'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unique(items):
    result = {}
    for key, value in items:
        assert key not in result, 'duplicate JSON key'
        result[key] = value
    return result


def read(path):
    assert path.is_file() and not path.is_symlink()
    assert path.stat().st_size <= 8 * 1024 * 1024
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def relative(name):
    assert isinstance(name, str) and name and '\\' not in name
    path = Path(name)
    assert not path.is_absolute() and all(p not in ('.', '..') for p in path.parts)
    assert str(path) == name
    return path


def inventory(root, expected):
    assert root.is_dir() and not root.is_symlink()
    for name, digest in expected.items():
        relative(name)
        assert re.fullmatch('[0-9a-f]{64}', digest)
    entries = list(root.rglob('*'))
    assert all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in entries)
    assert {str(p.relative_to(root)) for p in entries if p.is_file()} == set(expected) | {'RETENTION.json'}
    directories = {str(p) for name in expected for p in Path(name).parents if str(p) != '.'}
    assert {str(p.relative_to(root)) for p in entries if p.is_dir()} == directories
    for name, digest in expected.items():
        assert sha(root / name) == digest, name


def git(repo, *args, output=None):
    env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
    result = subprocess.run(['git', '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always',
                             '-c', 'core.hooksPath=/dev/null', '-C', str(repo), *args],
                            stdout=output or subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, timeout=120, check=True)
    return None if output else result.stdout.decode().strip()


def hydrate(source, repository, bundle, target):
    for key in ('base_commit', 'commit', 'tree'):
        assert re.fullmatch('[0-9a-f]{40}', source[key])
    assert sha(bundle) == source['bundle_sha256']
    git(repository, 'merge-base', '--is-ancestor', source['base_commit'], 'HEAD')
    bare = target / 'objects.git'
    git(target, 'init', '--bare', str(bare))
    git(bare, 'fetch', '--depth=1', '--no-tags', repository.resolve().as_uri(), source['base_commit'])
    git(bare, 'bundle', 'verify', str(bundle.resolve()))
    heads = git(bare, 'bundle', 'list-heads', str(bundle.resolve())).splitlines()
    assert len(heads) == 1 and heads[0].split()[0] == source['commit']
    git(bare, 'bundle', 'unbundle', str(bundle.resolve()))
    assert git(bare, 'rev-parse', source['commit'] + '^{tree}') == source['tree']
    git(bare, 'merge-base', '--is-ancestor', source['base_commit'], source['commit'])
    archive = target / 'source.tar'
    with archive.open('xb') as stream:
        git(bare, 'archive', '--format=tar', source['commit'], output=stream)
    assert sha(archive) == source['archive_sha256']
    return archive



def validate_schema(receipt):
    assert set(receipt) == {'schema', 'source', 'pins', 'omissions', 'files'}
    assert receipt['schema'] == 'mcloving.jcomp003.retention/1'
    assert set(receipt['source']) == {'base_commit', 'commit', 'tree', 'archive_sha256', 'bundle_sha256'}
    assert set(receipt['pins']) == {'report_sha256', 'jenkins_inventory_sha256', 'product_inventory_sha256',
                                  'compiler_campaign_sha256', 'prepared_input_sha256', 'worker_sha256', 'admission_sha256'}
    for digest in [*receipt['pins'].values(), receipt['source']['archive_sha256'], receipt['source']['bundle_sha256'], *receipt['omissions'].values()]:
        assert re.fullmatch('[0-9a-f]{64}', digest)


def retained_root(path):
    assert path.is_dir() and not path.is_symlink(), 'retained root must be a physical directory'
    return path.resolve(strict=True)


def compare_reports(recomputed, published, original):
    recomputed = dict(recomputed)
    published = dict(published)
    assert recomputed.pop('artifact_verification_mode') == 'retained-with-fixed-observer-binary-identities'
    assert recomputed.pop('identity_only_artifacts') == {name:original[name] for name in OMITTED}
    assert published.pop('artifact_verification_mode') == 'full-artifact-bytes'
    assert published.pop('identity_only_artifacts') == {}
    assert recomputed == published, 'retained report differs from recomputed observations'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('retained', type=Path)
    parser.add_argument('--retention-sha256', required=True)
    parser.add_argument('--base-commit', required=True)
    parser.add_argument('--repository', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    root = retained_root(args.retained)
    assert sha(root / 'RETENTION.json') == args.retention_sha256
    receipt = read(root / 'RETENTION.json')
    validate_schema(receipt)
    assert receipt['source']['base_commit'] == args.base_commit
    inventory(root, receipt['files'])
    assert set(receipt['omissions']) == {'product/' + name for name in OMITTED}
    original = read(root / 'product/artifacts.json')
    assert all(receipt['omissions']['product/' + name] == original[name] for name in OMITTED)
    assert all(not (root / 'product' / name).exists() for name in OMITTED)
    assert not (root / 'product/source.tar').exists()
    assert original['source.tar'] == receipt['source']['archive_sha256']
    pins = receipt['pins']
    assert sha(root / 'report.json') == pins['report_sha256']
    with tempfile.TemporaryDirectory(prefix='jcomp003-retained-') as scratch:
        temp = Path(scratch)
        archive = hydrate(receipt['source'], args.repository, root / 'source.bundle', temp)
        shutil.copytree(root / 'product', temp / 'product')
        shutil.copyfile(archive, temp / 'product/source.tar')
        command = ['python3', '-I', str(args.repository / 'scripts/jcomp003/verify-paired.py'),
                   str(root / 'jenkins'), str(temp / 'product'), str(temp / 'report.json'),
                   '--source-commit', receipt['source']['commit'], '--source-tree', receipt['source']['tree']]
        for key in ('jenkins_inventory_sha256', 'product_inventory_sha256', 'compiler_campaign_sha256',
                    'prepared_input_sha256', 'worker_sha256', 'admission_sha256'):
            command.extend(['--' + key.replace('_', '-'), pins[key]])
        command.append('--retained-identity-only')
        subprocess.run(command, check=True, timeout=180)
        compare_reports(read(temp / 'report.json'), read(root / 'report.json'), original)
    print('Retained observations verified; source archive hydrated; five tracer binaries identity-only; no workload or admission rerun.')


if __name__ == '__main__':
    main()
