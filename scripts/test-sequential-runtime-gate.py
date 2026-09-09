#!/usr/bin/env python3
"""Mocked gate controls only; these are not runtime execution evidence."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SequentialGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        for name in ("test-sequential-runtime.sh", "run-verified-rust-test.sh", "verify-rust-test-execution.py"):
            shutil.copyfile(ROOT / "scripts" / name, self.root / "scripts" / name)
        for name in ("bins/agent/tests/sequential_work.rs", "crates/controller-api/tests/sequential_store.rs"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// mock target-presence control\n")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        cargo = self.bin / "cargo"
        cargo.write_text('''#!/usr/bin/env python3
import os, sys
count = 4 if "sequential_store" in sys.argv else 6
mode = os.environ.get("MOCK_MODE", "success")
if mode == "failed": sys.exit(9)
if mode == "empty": count = 0
if mode == "wrong_count": count += 1
if mode == "skipped": print("skipped: missing runtime")
ignored = 1 if mode == "ignored" else 0
print(f"test result: ok. {count} passed; 0 failed; {ignored} ignored; 0 measured; 0 filtered out; finished in 0.01s")
''')
        cargo.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        MCLOVING_TEST_DATABASE_URL="postgres://unit-test-no-connection",
                        MCLOVING_CONTROLLER_BINARY="/bin/true")

    def run_gate(self):
        return subprocess.run(["bash", str(self.root / "scripts/test-sequential-runtime.sh")],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def test_exact_complete_populations_pass_the_mocked_control(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_failed_empty_wrong_skipped_and_ignored_are_refused(self):
        for mode in ("failed", "empty", "wrong_count", "skipped", "ignored"):
            with self.subTest(mode=mode):
                self.env["MOCK_MODE"] = mode
                self.assertNotEqual(self.run_gate().returncode, 0)

    def test_missing_database_and_binary_are_refused(self):
        for name in ("MCLOVING_TEST_DATABASE_URL", "MCLOVING_CONTROLLER_BINARY"):
            with self.subTest(name=name):
                value = self.env.pop(name)
                self.assertNotEqual(self.run_gate().returncode, 0)
                self.env[name] = value
        self.env["MCLOVING_CONTROLLER_BINARY"] = str(self.root / "absent-controller")
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_missing_target_is_refused(self):
        (self.root / "bins/agent/tests/sequential_work.rs").unlink()
        self.assertNotEqual(self.run_gate().returncode, 0)


if __name__ == "__main__":
    unittest.main()
