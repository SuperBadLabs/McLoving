#!/usr/bin/env python3
"""Synthetic mutation checks, not campaign or workload execution evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('retained', Path(__file__).with_name('verify-retained.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RetentionTests(unittest.TestCase):
    def test_schema_unknown_authority(self):
        source = dict(base_commit='b' * 40, commit='c' * 40, tree='d' * 40, archive_sha256='a' * 64, bundle_sha256='b' * 64)
        pins = {name:'a' * 64 for name in ('report_sha256', 'jenkins_inventory_sha256', 'product_inventory_sha256', 'compiler_campaign_sha256', 'prepared_input_sha256', 'worker_sha256', 'admission_sha256')}
        receipt = dict(schema='mcloving.jcomp003.retention/1', source=source, pins=pins, omissions={}, files={})
        m.validate_schema(receipt)
        for scope in ('root', 'source', 'pins'):
            changed = copy.deepcopy(receipt)
            (changed if scope == 'root' else changed[scope])['unknown_authority'] = True
            with self.subTest(scope=scope), self.assertRaises(AssertionError): m.validate_schema(changed)

    def test_root_symlink(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch); (root / 'real').mkdir(); (root / 'alias').symlink_to(root / 'real')
            self.assertEqual(m.retained_root(root / 'real'), root / 'real')
            with self.assertRaises(AssertionError): m.retained_root(root / 'alias')

    def test_paths(self):
        for value in ('../escape', '/absolute', 'a/../b', './a', 'a//b', 'a\\b', ''):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                m.relative(value)

    def test_duplicate_keys(self):
        with self.assertRaises(AssertionError):
            json.loads('{"key":1,"key":2}', object_pairs_hook=m.unique)

    def test_inventory_mutations(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / 'RETENTION.json').write_text('{}')
            (root / 'a').write_bytes(b'original')
            files = {'a':m.sha(root / 'a')}
            m.inventory(root, files)
            (root / 'a').write_bytes(b'changed')
            with self.assertRaises(AssertionError): m.inventory(root, files)
            (root / 'a').write_bytes(b'original')
            (root / 'unexpected').mkdir()
            with self.assertRaises(AssertionError): m.inventory(root, files)
            (root / 'unexpected').rmdir()
            (root / 'extra').write_bytes(b'extra')
            with self.assertRaises(AssertionError): m.inventory(root, files)
            (root / 'extra').unlink()
            (root / 'alias').symlink_to(root / 'a')
            with self.assertRaises(AssertionError): m.inventory(root, files)
            (root / 'alias').unlink()
            (root / 'a').unlink()
            with self.assertRaises(AssertionError): m.inventory(root, files)

    def test_report_only_declared_mode_changes(self):
        identities = {name:'a' * 64 for name in m.OMITTED}
        full = dict(artifact_verification_mode='full-artifact-bytes', identity_only_artifacts={}, observed=19)
        retained = dict(artifact_verification_mode='retained-with-fixed-observer-binary-identities', identity_only_artifacts=identities, observed=19)
        m.compare_reports(retained, full, identities)
        for key, value in [('observed', 18), ('artifact_verification_mode', 'full-artifact-bytes'), ('identity_only_artifacts', {}), ('unexpected', True)]:
            changed = dict(retained); changed[key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                m.compare_reports(changed, full, identities)

    def test_hydrate_and_mutations(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch); repo = root / 'repository'; repo.mkdir()
            m.git(repo, 'init')
            m.git(repo, 'config', 'user.name', 'Synthetic test')
            m.git(repo, 'config', 'user.email', 'synthetic@example.invalid')
            (repo / 'source').write_text('base\n')
            m.git(repo, 'add', 'source'); m.git(repo, 'commit', '-m', 'synthetic base')
            base = m.git(repo, 'rev-parse', 'HEAD')
            (repo / 'source').write_text('candidate\n')
            m.git(repo, 'commit', '-am', 'synthetic candidate')
            commit = m.git(repo, 'rev-parse', 'HEAD'); tree = m.git(repo, 'rev-parse', 'HEAD^{tree}')
            bundle = root / 'source.bundle'
            m.git(repo, 'bundle', 'create', str(bundle), 'HEAD', '^' + base)
            original = root / 'original.tar'
            with original.open('wb') as output: m.git(repo, 'archive', '--format=tar', commit, output=output)
            source = dict(base_commit=base, commit=commit, tree=tree, bundle_sha256=m.sha(bundle), archive_sha256=m.sha(original))
            target = root / 'ok'; target.mkdir()
            self.assertEqual(m.hydrate(source, repo, bundle, target).read_bytes(), original.read_bytes())
            for key in ('base_commit', 'commit', 'tree', 'bundle_sha256', 'archive_sha256'):
                with self.subTest(key=key):
                    mutated = copy.deepcopy(source); mutated[key] = '0' * len(source[key])
                    target = root / key; target.mkdir()
                    with self.assertRaises((AssertionError, subprocess.CalledProcessError)):
                        m.hydrate(mutated, repo, bundle, target)


if __name__ == '__main__':
    unittest.main()
