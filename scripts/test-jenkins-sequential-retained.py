#!/usr/bin/env python3
"""Mutation controls for offline retained compilation evidence; no worker launches."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('retained_sequential', ROOT / 'scripts/test-jenkins-sequential-contained.py')
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
EVIDENCE = ROOT / 'docs/evidence/jcomp-002-compiler-v2'


class RetainedEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='retained-sequential-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'evidence'
        shutil.copytree(EVIDENCE, self.directory)
        self.campaign_path = self.directory / 'campaign.json'

    def campaign(self):
        return json.loads(self.campaign_path.read_text())

    def save(self, campaign):
        self.campaign_path.write_text(json.dumps(campaign, indent=2) + '\n')

    def reject(self, message):
        with self.assertRaisesRegex(ValueError, message):
            VERIFIER.verify_retained(self.directory)

    def rewrite_receipt(self, before, after):
        campaign = self.campaign()
        record = campaign['records'][0]
        path = self.directory / 'S01-run-1.receipt'
        content = path.read_bytes()
        self.assertIn(before, content)
        content = content.replace(before, after)
        path.write_bytes(content)
        record['receipt_sha256'] = VERIFIER.digest(content)
        self.save(campaign)

    def test_original(self):
        self.assertIn('files=93 fixtures=23 isolated_runs=46', VERIFIER.verify_retained(self.directory))

    def test_missing_file(self):
        (self.directory / 'N12-run-2.edn').unlink()
        self.reject('fixed 93 files')

    def test_extra_file(self):
        (self.directory / 'unearned-receipt').write_text('extra')
        self.reject('fixed 93 files')

    def test_duplicate_record(self):
        campaign = self.campaign()
        campaign['records'][1] = campaign['records'][0]
        self.save(campaign)
        self.reject('duplicate fixture/run')

    def test_duplicate_json_key(self):
        self.campaign_path.write_text(self.campaign_path.read_text().replace('"fixtures": 23,', '"fixtures": 23, "fixtures": 23,'))
        self.reject('duplicate JSON key')

    def test_artifact_digest_drift(self):
        (self.directory / 'S01-run-1.edn').write_bytes(b'{}\n')
        self.reject('artifact digest mismatch')

    def test_source_binding_drift(self):
        campaign = self.campaign()
        campaign['records'][0]['source_sha256'] = '0' * 64
        self.save(campaign)
        self.reject('record source binding')

    def test_context_binding_drift(self):
        campaign = self.campaign()
        campaign['records'][0]['context_sha256'] = '0' * 64
        self.save(campaign)
        self.reject('record context binding')

    def test_campaign_authority_or_population_drift(self):
        original = self.campaign_path.read_bytes()
        for key, value in [('execution_authority', True), ('fixtures', 24), ('isolated_runs', 45)]:
            with self.subTest(field=key):
                campaign = json.loads(original)
                campaign[key] = value
                self.save(campaign)
                self.reject('population or authority claim')
        self.campaign_path.write_bytes(original)

    def test_record_claim_drift(self):
        campaign = self.campaign()
        campaign['records'][0]['status'] = 'unsupported'
        self.save(campaign)
        self.reject('record classification')

    def test_receipt_extra_or_duplicate_field(self):
        original = (self.directory / 'S01-run-1.receipt').read_bytes()
        campaign = self.campaign_path.read_bytes()
        for line, message in [(b'extra=claim\n', 'receipt field set'), (b'status=admitted\n', 'duplicate trusted receipt')]:
            with self.subTest(line=line):
                self.rewrite_receipt(original, original + line)
                self.reject(message)
                (self.directory / 'S01-run-1.receipt').write_bytes(original)
                self.campaign_path.write_bytes(campaign)

    def test_receipt_binding_and_authority_drift(self):
        original = (self.directory / 'S01-run-1.receipt').read_bytes()
        campaign = self.campaign_path.read_bytes()
        for key, replacement in [('execution_authority', 'true'), ('state', 'enabled'),
                                 ('contract_sha256', '0' * 64), ('target_profile_sha256', '0' * 64),
                                 ('launch_source_sha256', '0' * 64), ('launch_context_sha256', '0' * 64)]:
            with self.subTest(field=key):
                line = next(line for line in original.splitlines(keepends=True) if line.startswith((key + '=').encode()))
                self.rewrite_receipt(line, (key + '=' + replacement + '\n').encode())
                self.reject('receipt binding or authority claim')
                (self.directory / 'S01-run-1.receipt').write_bytes(original)
                self.campaign_path.write_bytes(campaign)

    def test_implementation_pin_drift(self):
        original = self.campaign_path.read_bytes()
        for key in ['worker_image_sha256', 'admission_binary_sha256']:
            with self.subTest(field=key):
                campaign = json.loads(original)
                campaign[key] = '0' * 64
                self.save(campaign)
                self.reject('implementation or manifest pin')
        self.campaign_path.write_bytes(original)

    def test_repeated_run_drift_with_updated_digest(self):
        campaign = self.campaign()
        content = b'{}\n'
        (self.directory / 'S01-run-2.edn').write_bytes(content)
        campaign['records'][1]['response_sha256'] = VERIFIER.digest(content)
        self.save(campaign)
        self.reject('repeated-run identity')

    def test_coordinated_artifact_and_index_edits_hit_reviewed_pin(self):
        campaign = self.campaign()
        for run in [1, 2]:
            path = self.directory / f'S01-run-{run}.edn'
            content = path.read_bytes()[:-1] + b' \n'
            path.write_bytes(content)
            campaign['records'][run - 1]['response_sha256'] = VERIFIER.digest(content)
        self.save(campaign)
        self.reject('reviewed campaign bytes changed')

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlinks unavailable')
    def test_symlink_is_not_retained_regular_file(self):
        path = self.directory / 'S01-run-1.receipt'
        path.unlink()
        path.symlink_to('S01-run-2.receipt')
        self.reject('not a regular file')


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RetainedEvidence)
    if suite.countTestCases() != 16:
        raise SystemExit('retained evidence test population changed: expected 16')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or result.testsRun != 16:
        raise SystemExit('retained evidence tests failed, skipped, or did not execute completely')
