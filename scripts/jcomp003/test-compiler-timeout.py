#!/usr/bin/env python3
"""Synthetic timeout tests; these never launch the compiler or fixture workloads."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('fixed', Path(__file__).resolve().parents[1] /
                                           'test-jenkins-sequential-contained.py')
FIXED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXED)


class TimeoutTests(unittest.TestCase):
    def exercise(self, stdout, stderr):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            admission = root / 'synthetic-admission'
            admission.write_bytes(b'synthetic test binary identity; never executed')
            output = root / 'evidence'
            argv = ['test', '--image', 'synthetic-image', '--image-sha256', 'a' * 64,
                    '--admission-bin', str(admission), '--output', str(output)]
            error = subprocess.TimeoutExpired(['synthetic-launcher'], 20,
                                             output=stdout, stderr=stderr)
            with patch.object(sys, 'argv', argv), patch.object(FIXED.subprocess, 'run',
                    side_effect=[subprocess.CompletedProcess([], 0), error]) as run:
                with self.assertRaisesRegex(ValueError, 'launcher timed out'):
                    FIXED.main()
            self.assertEqual(run.call_count, 2)  # Validator plus first launch only.
            record = json.loads((output / 'incomplete.json').read_text())
            self.assertFalse(record['verified'])
            self.assertTrue(record['cleanup_inspection_required'])
            self.assertEqual(record['completed_records'], [])
            self.assertEqual(record['reason'], 'launcher_timeout')
            self.assertEqual(record['run'], 1)
            stem = f"{record['fixture']}-run-1-timeout"
            for suffix, content in [('stdout', stdout or b''), ('stderr', stderr or b'')]:
                self.assertEqual((output / f'{stem}.{suffix}').read_bytes(), content)
                self.assertEqual(record[suffix + '_sha256'], FIXED.digest(content))
            self.assertEqual({p.name for p in output.iterdir()},
                             {'incomplete.json', stem + '.stdout', stem + '.stderr'})

    def test_partial_bytes_retained_and_no_second_input(self):
        self.exercise(b'partial\x00response\xff', b'partial\nreceipt\xff')

    def test_absent_partial_streams_retained_as_empty(self):
        self.exercise(None, None)


if __name__ == '__main__':
    unittest.main()
