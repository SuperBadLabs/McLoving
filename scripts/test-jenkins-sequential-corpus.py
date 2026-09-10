#!/usr/bin/env python3
"""Mutation tests using synthetic metadata; these tests earn no compiler evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('corpus', Path(__file__).with_name(
    'classify-jenkins-sequential-corpus.py'))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class CorpusBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='corpus-mutation-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.rows = C.population()
        records = []
        for number, row in enumerate(self.rows, 1):
            # Synthetic launcher failure deliberately avoids manufacturing a
            # successful source classification or executable worker response.
            stderr = b'E_SOURCE_CLASSIFICATION: synthetic test failure\n'
            (self.directory / f'{number:03d}.stdout').write_bytes(b'')
            (self.directory / f'{number:03d}.stderr').write_bytes(stderr)
            records.append({'number': number, 'historical': row,
                'context_sha256': C.sha(C.context(row, number)), 'status': 'unverified',
                'code': 'E_SOURCE_CLASSIFICATION', 'launcher_exit': 1,
                'stdout_sha256': C.sha(b''), 'stderr_sha256': C.sha(stderr)})
        self.campaign = {
            'schema': 'mcloving.jenkins.sequential-corpus/1',
            'implementation_head': 'a' * 40, 'compiler_source_archive_sha256': 'b' * 64,
            'source_representation': 'unchanged repository source bytes; no Jenkins XML normalization',
            'population_pins': C.PINS, 'contract_sha256': C.CONTRACT, 'profile_sha256': C.PROFILE,
            'worker_image_sha256': 'c' * 64, 'admission_binary_sha256': 'd' * 64,
            'tool_sha256': 'e' * 64, 'summary': C.summary(records), 'records': records}
        self.pin = self.save()

    def save(self):
        content = (json.dumps(self.campaign, indent=2) + '\n').encode()
        (self.directory / 'campaign.json').write_bytes(content)
        return C.sha(content)

    def reject(self, message):
        self.save()
        with self.assertRaisesRegex(ValueError, message):
            C.verify(self.directory, self.pin)

    def test_synthetic_failures_remain_unverified(self):
        result = C.verify(self.directory, self.pin)
        self.assertEqual(result['counts'], {'admitted': 0, 'unsupported': 0,
                         'rejected': 0, 'unverified': 228})
        self.assertFalse(result['classification_complete'])
        self.assertFalse(result['execution_equivalence_claim'])

    def test_missing_identity(self):
        self.campaign['records'].pop()
        self.reject('record population')

    def test_duplicate_identity(self):
        self.campaign['records'][1] = self.campaign['records'][0]
        self.reject('historical identity/order')

    def test_original_diagnostic_preserved(self):
        self.campaign['records'][0]['historical']['worker_v1'] = 'E_NEW_REASON'
        self.reject('historical identity/order')

    def test_redacted_context_uses_retained_bytes(self):
        for number, row in enumerate(self.rows, 1):
            if row['redacted'] == 'true':
                content = C.context(row, number)
                self.assertIn(row['repository_source_sha256'].encode(), content)
                self.assertNotIn(row['source_sha256'].encode(), content)

    def test_redaction_cannot_disappear(self):
        record = next(r for r in self.campaign['records'] if r['historical']['redacted'] == 'true')
        record['historical']['redacted'] = 'false'
        self.reject('historical identity/order')

    def test_context_substitution(self):
        self.campaign['records'][0]['context_sha256'] = 'f' * 64
        self.reject('context binding')

    def test_failure_cannot_be_rejected(self):
        self.campaign['records'][0]['status'] = 'rejected'
        self.reject('borrowed a classification')

    def test_failure_cannot_be_unsupported(self):
        self.campaign['records'][0]['status'] = 'unsupported'
        self.reject('borrowed a classification')

    def test_failure_reason_substitution(self):
        self.campaign['records'][0]['code'] = 'E_SOURCE_TEXT'
        self.reject('unverified diagnostic')

    def test_summary_cannot_borrow_runtime(self):
        self.campaign['summary']['execution_equivalence_claim'] = True
        self.reject('summary or claim')

    def test_summary_cannot_hide_unverified(self):
        self.campaign['summary']['classification_complete'] = True
        self.reject('summary or claim')

    def test_raw_drift(self):
        (self.directory / '001.stderr').write_bytes(b'drift\n')
        self.reject('raw artifact digest')

    def test_missing_raw(self):
        (self.directory / '001.stdout').unlink()
        self.reject('457-file inventory')

    def test_extra_raw(self):
        (self.directory / 'other').write_bytes(b'')
        self.reject('457-file inventory')

    def test_symlink_raw(self):
        (self.directory / '001.stdout').unlink()
        (self.directory / '001.stdout').symlink_to(self.directory / '002.stdout')
        self.reject('not a regular file')

    def test_coordinated_replacement_requires_external_pin(self):
        self.campaign['implementation_head'] = 'f' * 40
        self.reject('reviewed campaign digest')

    def test_duplicate_json_field(self):
        path = self.directory / 'campaign.json'
        path.write_text(path.read_text().replace('"records": [', '"records": [], "records": ['))
        with self.assertRaisesRegex(ValueError, 'duplicate JSON field'):
            C.verify(self.directory, self.pin)

    def test_receipt_cannot_grant_authority(self):
        row = self.rows[0]
        content = ('status=unsupported\nworker_image_sha256=' + 'c' * 64 +
            '\nadmission_binary_sha256=' + 'd' * 64 + '\nlaunch_source_sha256=' +
            row['repository_source_sha256'] + '\nlaunch_context_sha256=' +
            C.sha(C.context(row, 1)) + '\ncode=E_SOURCE_LEXICAL\nexecution_authority=true\n').encode()
        with self.assertRaisesRegex(ValueError, 'receipt field set'):
            C.check_receipt(content, row, 1, 'c' * 64, 'd' * 64)


if __name__ == '__main__':
    unittest.main()
