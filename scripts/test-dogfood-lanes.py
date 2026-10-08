#!/usr/bin/env python3
"""Adversarial checks of the actual finite lane parser; no deployment effects."""
import importlib.util
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('dogfood_lanes', ROOT / 'scripts/dogfood/verify-lanes.py')
assert SPEC and SPEC.loader
LANES = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LANES
SPEC.loader.exec_module(LANES)


class LaneTests(unittest.TestCase):
    def fixture(self, directory):
        root = pathlib.Path(directory)
        import json
        policy = json.loads((ROOT / 'scripts/dogfood/lane-contracts.json').read_text())
        paths = ['.github/workflows/foundation.yml', 'scripts/dogfood/lane-contracts.json',
                 *policy['inputs'], *('scripts/dogfood/' + name for name in LANES.MIRRORED)]
        for relative in paths:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        return root

    def mutation(self, relative, old, new):
        with tempfile.TemporaryDirectory(prefix='mcloving-lane-parser-') as directory:
            root = self.fixture(directory)
            path = root / relative
            text = path.read_text()
            self.assertIn(old, text)
            path.write_text(text.replace(old, new, 1))
            with self.assertRaises(LANES.Drift):
                LANES.check(root)

    def test_all_six_actual_lanes(self):
        self.assertGreater(LANES.check(ROOT), 50)

    def test_wrapped_count_label_target_flags_and_presence(self):
        path = 'scripts/dogfood/controller-postgres.sh'
        for old, new in [
            ('10 notifications', '9 notifications'), ('10 notifications', '10 another-label'),
            ('--include-ignored', ''), ('--test-threads=1', '--test-threads=2'),
            ('--test notifications', '--test scm_webhook'),
            ('10 notifications --require-postgres', '10 notifications'),
            ('-p mcloving-cli', ''), ('--test remote_work', '--test remote_work --features loopback-test')]:
            with self.subTest(old=old, new=new): self.mutation(path, old, new)

    def test_both_directions_multiplicity_comments_suppression_and_order(self):
        line = 'cargo "+${RUST_TOOLCHAIN}" test --locked -p mcloving-controller-store --test postgres_truth'
        path = 'scripts/dogfood/controller-postgres.sh'
        for replacement in ['', '# ' + line, line + '\n' + line, line + ' || true', line + '; true', 'echo ' + line,
                            line.replace('postgres_truth', 'pipeline_operational_state')]:
            with self.subTest(replacement=replacement): self.mutation(path, line, replacement)
        self.mutation('.github/workflows/foundation.yml',
                      'run: cargo +1.97.1 test --locked -p mcloving-controller-store --test postgres_truth',
                      'run: cargo +1.97.1 test --locked -p mcloving-controller-store --test postgres_truth -- --ignored')
        self.mutation(path, 'bash scripts/test-sequential-runtime.sh', 'bash scripts/test-sequential-runtime.sh\npython3 scripts/verify-execution-board.py')

    def test_real_execution_context_and_pinned_complex_blocks(self):
        changes = [
            ('.github/workflows/foundation.yml', 'MCLOVING_TEST_PODMAN: "1"', 'MCLOVING_TEST_PODMAN: "0"'),
            ('.github/workflows/foundation.yml', 'working-directory: compat/jenkins-worker', 'working-directory: compat'),
            ('.github/workflows/foundation.yml', '\njobs:\n', '\ndefaults:\n  run:\n    shell: sh\njobs:\n'),
            ('scripts/dogfood/controller-postgres.sh', 'export MCLOVING_CLI_BINARY=', '# export MCLOVING_CLI_BINARY='),
            ('scripts/dogfood/architecture.sh', '  .github/workflows/*.yaml', ''),
            ('scripts/dogfood/architecture.sh', ': > "${actionlint_config}"', ': > "${actionlint_config}"\ntrue'),
            ('scripts/dogfood/architecture.sh', 'python3 scripts/dogfood/verify-lanes.py', '# python3 scripts/dogfood/verify-lanes.py'),
            ('scripts/dogfood/architecture.sh', '  timeout 60 clojure -M:test', '  timeout 61 clojure -M:test'),
            ('scripts/dogfood/secrets.sh', '--verbose --no-git', '--verbose'),
            ('scripts/dogfood/dependencies.sh', '"${tool_dir}/cargo-deny" check', '"${tool_dir}/cargo-deny" check || true'),
            ('tools/versions.env', 'ACTIONLINT_VERSION="1.7.12"', 'ACTIONLINT_VERSION="1.7.13"'),
            ('.github/workflows/foundation.yml', 'run: bash scripts/verify-jenkins-sequential-retained.sh', 'run: true'),
        ]
        for relative, old, new in changes:
            with self.subTest(relative=relative, old=old): self.mutation(relative, old, new)

    def test_closed_yaml_and_shell_grammar(self):
        self.mutation('.github/workflows/foundation.yml', '      - name: Run real-PostgreSQL transaction and race tests',
                      '      - run: true\n      - name: Run real-PostgreSQL transaction and race tests')
        self.mutation('.github/workflows/foundation.yml', 'run: cargo +1.97.1 test --locked -p mcloving-controller-store --test postgres_truth',
                      'if: false\n        run: cargo +1.97.1 test --locked -p mcloving-controller-store --test postgres_truth')
        for command in ('cargo +1.97.1 test || true', 'echo cargo +1.97.1 test', 'cargo +1.97.1 test; true',
                        'cargo +1.97.1 test | true', 'bash scripts/run-verified-rust-test.sh 0 zero cargo +1.97.1 test'):
            with self.subTest(command=command), self.assertRaises(LANES.Drift):
                LANES.record(command, '.', {}, {'RUST_TOOLCHAIN': '1.97.1'})


class CommentBoundaryTests(unittest.TestCase):
    def test_comment_backslash_cannot_hide_an_extra_actual_lane_command(self):
        import subprocess
        harmless = '# comment ending in backslash \\\nprintf "%s\\n" EXECUTED_AFTER_COMMENT\n'
        result = subprocess.run(['/bin/bash', '-c', harmless], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'EXECUTED_AFTER_COMMENT\n')
        with tempfile.TemporaryDirectory(prefix='mcloving-comment-boundary-') as directory:
            root = LaneTests().fixture(directory)
            self.assertGreater(LANES.check(root), 50)
            path = root / 'scripts/dogfood/rust-lint.sh'
            path.write_text(path.read_text() + '\n# comment ending in backslash \\\npython3 scripts/verify-execution-board.py\n')
            with self.assertRaisesRegex(LANES.Drift, 'command/context multiset changed'):
                LANES.check(root)

    def test_source_authored_canonical_comment_cannot_replace_execution(self):
        import subprocess
        line = 'cargo "+${RUST_TOOLCHAIN}" fmt --all -- --check'
        canonical = LANES.record(line, '.', {}, {'RUST_TOOLCHAIN':'1.97.1'})
        forged = '# canonical-record ' + canonical
        result = subprocess.run(['/bin/bash', '-c', forged + '\n'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        with tempfile.TemporaryDirectory(prefix='mcloving-canonical-comment-') as directory:
            root = LaneTests().fixture(directory)
            path = root / 'scripts/dogfood/rust-lint.sh'
            text = path.read_text(); self.assertEqual(text.count(line), 1)
            path.write_text(text.replace(line, forged, 1))
            with self.assertRaisesRegex(LANES.Drift, 'source-authored canonical record'):
                LANES.check(root)

    def test_quoted_word_internal_and_escaped_hashes_match_harmless_bash(self):
        import json
        import shlex
        import subprocess
        program = "printf '%s\\n' 'quoted#hash' word#hash \\#escaped # ignored backslash \\\nprintf '%s\\n' NEXT\n"
        result = subprocess.run(['/bin/bash', '-c', program], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['quoted#hash', 'word#hash', '#escaped', 'NEXT'])
        lines = [line for line in LANES.logical_lines(program) if line and not line.startswith('#')]
        self.assertEqual(len(lines), 2)
        self.assertEqual(shlex.split(lines[0])[2:], ['quoted#hash', 'word#hash', '#escaped'])
        record = json.loads(LANES.record('cargo +1.97.1 test --locked --features word#hash', '.', {}, {}))
        self.assertEqual(record['rust']['features'], ['word#hash'])
        quoted = json.loads(LANES.record("cargo +1.97.1 test --locked --features 'quoted#hash'", '.', {}, {}))
        self.assertEqual(quoted['rust']['features'], ['quoted#hash'])

    def test_reviewed_multiline_argv_keeps_exact_continuation_semantics(self):
        single = 'bash scripts/run-verified-rust-test.sh 10 notifications --require-postgres cargo +1.97.1 test --locked -p mcloving-controller-api --test notifications -- --include-ignored --test-threads=1'
        continued = 'bash scripts/run-verified-rust-test.sh 10 notifications --require-postgres \\\n  cargo +1.97.1 test --locked -p mcloving-controller-api \\\n  --test notifications -- --include-ignored --test-threads=1\n'
        env = {'MCLOVING_TEST_DATABASE_URL':'postgres://toy'}
        self.assertEqual(LANES.simple(single, '.', env, {}), LANES.simple(continued, '.', env, {}))
        self.assertEqual(LANES.logical_lines('cargo +1.97.1 te\\\nst --locked\n'), ['cargo +1.97.1 test --locked'])
        with self.assertRaises(LANES.Drift): LANES.logical_lines('cargo +1.97.1 test \\')


if __name__ == '__main__': unittest.main()
