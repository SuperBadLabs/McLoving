"""Mutation checks for contract integrity, not compiler implementation tests."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import validate


class ManifestIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        original = Path(__file__).resolve().parents[4]
        shutil.copytree(original / validate.BASE, self.root / validate.BASE)
        for path in (validate.PROFILE, validate.HISTORICAL,
                     'docs/architecture/JENKINS_SEQUENTIAL_DECLARATIVE_V1.md'):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original / path, target)
        self.manifest_path = self.root / validate.BASE / 'manifest.json'

    def mutate(self, change):
        manifest = json.loads(self.manifest_path.read_text())
        change(manifest)
        self.manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            validate.verify(self.root)

    def test_original(self):
        self.assertIn('no execution claim', validate.verify(self.root))

    def test_source_drift(self):
        with (self.root / validate.BASE / 'S01.Jenkinsfile').open('a') as source:
            source.write('// drift\n')
        with self.assertRaises(ValueError):
            validate.verify(self.root)

    def test_profile_drift(self):
        (self.root / validate.PROFILE).write_text('substituted')
        with self.assertRaises(ValueError):
            validate.verify(self.root)

    def test_omitted_case(self):
        self.mutate(lambda m: m['fixtures'].pop())

    def test_duplicate_case(self):
        self.mutate(lambda m: m['fixtures'].__setitem__(0, m['fixtures'][1]))

    def test_extra_source(self):
        (self.root / validate.BASE / 'extra.Jenkinsfile').write_text('unexpected')
        with self.assertRaises(ValueError):
            validate.verify(self.root)

    def test_borrowed_denominator(self):
        self.mutate(lambda m: m['denominators'].__setitem__('authored_supported', 11))

    def test_unearned_evidence(self):
        self.mutate(lambda m: m['authority'].__setitem__('execution_evidence', True))

    def test_inconsistent_failure(self):
        self.mutate(lambda m: m['fixtures'][7]['expected'].__setitem__('build_outcome', 'succeeded'))

    def test_work_after_failure(self):
        self.mutate(lambda m: m['fixtures'][7]['expected']['stages'][0]['steps'][1].update(
            outcome='succeeded', exit_code=0, stdout_utf8='must not run\n'))

    def test_contract_reference_substitution(self):
        self.mutate(lambda m: m.__setitem__('contract_path', validate.PROFILE))

    def test_normalized_stage_collision(self):
        self.mutate(lambda m: m['fixtures'][1]['expected']['stages'][1].__setitem__('name', 'build'))

    def test_blank_normalized_stage(self):
        self.mutate(lambda m: m['fixtures'][0]['expected']['stages'][0].__setitem__('name', '! ?'))

    def test_unicode_lowercase_does_not_create_ascii_stage_id(self):
        # Unicode lower() maps the Kelvin sign to k; the contract folds ASCII only.
        self.mutate(lambda m: m['fixtures'][0]['expected']['stages'][0].__setitem__('name', '\u212a'))

    def test_source_symlink(self):
        target = self.root / validate.BASE / 'S01.Jenkinsfile'
        content = target.read_bytes()
        target.unlink()
        replacement = self.root / 'replacement'
        replacement.write_bytes(content)
        target.symlink_to(replacement)
        with self.assertRaises(ValueError):
            validate.verify(self.root)


if __name__ == '__main__':
    unittest.main()
