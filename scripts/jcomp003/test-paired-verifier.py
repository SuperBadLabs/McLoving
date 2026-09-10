#!/usr/bin/env python3
"""Adversarial tests of the evidence verifier; synthetic data is not a runtime receipt."""
import copy
import hashlib
import io
import tarfile
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('paired', Path(__file__).with_name('verify-paired.py'))
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


class VerifierTests(unittest.TestCase):
    def test_exact_stream_merge_preserves_every_byte(self):
        self.assertTrue(V.merged_exact(b'+ printf a\\n\na\n', b'a\n', b'+ printf a\\n\n'))
        self.assertTrue(V.merged_exact(b'a\n+ next\nb\n', b'a\nb\n', b'+ next\n'))
        self.assertTrue(V.merged_exact(b'+ intentional\n+ trace\n', b'+ intentional\n', b'+ trace\n'))

    def test_merge_rejects_unknown_plus_line_output_changes_and_reordering(self):
        for combined in [b'+ injected\na\n', b'+ trace\na \n', b'+ trace\nb\na\n', b'a\n']:
            with self.subTest(combined=combined):
                self.assertFalse(V.merged_exact(combined, b'a\n', b'+ trace\n'))

    def test_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'record.json'
            path.write_text('{"status":"failed", "status":"succeeded"}')
            with self.assertRaises(AssertionError):
                V.read_json(path)

    def inventory(self, root):
        artifacts = {str(path.relative_to(root)):V.sha(path.read_bytes())
                     for path in root.rglob('*') if path.is_file()}
        (root / 'artifacts.json').write_text(json.dumps(artifacts))

    def test_inventory_exact_files_and_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'observations').mkdir()
            (root / 'observations/one').write_bytes(b'raw')
            self.inventory(root)
            V.verify_inventory(root)
            (root / 'empty').mkdir()
            with self.assertRaises(AssertionError):
                V.verify_inventory(root)

    def test_inventory_rejects_directory_symlink_even_when_unread(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'one').write_bytes(b'raw')
            self.inventory(root)
            (root / 'alias').symlink_to('/tmp', target_is_directory=True)
            with self.assertRaises(AssertionError):
                V.verify_inventory(root)

    def test_inventory_rejects_mutated_or_extra_file(self):
        for mutation in ('mutated', 'extra'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'one').write_bytes(b'raw')
                self.inventory(root)
                (root / ('one' if mutation == 'mutated' else 'two')).write_bytes(b'changed')
                with self.assertRaises(AssertionError):
                    V.verify_inventory(root)

    def test_retained_mode_omits_only_exact_five_observer_binaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'source.tar').write_bytes(b'mandatory archive')
            (root / 'tracer').mkdir()
            (root / 'tracer/observe-exec').write_bytes(b'producer script remains mandatory')
            for name in V.IDENTITY_ONLY_PRODUCT_ARTIFACTS:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
            self.inventory(root)
            for name in V.IDENTITY_ONLY_PRODUCT_ARTIFACTS:
                (root / name).unlink()
            (root / 'tracer/lib').rmdir()
            with self.assertRaises(AssertionError):
                V.verify_inventory(root)
            V.verify_inventory(root, True)
            (root / 'source.tar').unlink()
            with self.assertRaises(AssertionError):
                V.verify_inventory(root, True)
            (root / 'source.tar').write_bytes(b'mandatory archive')
            (root / 'tracer/strace').write_bytes(b'identity mode cannot accept a substituted binary')
            with self.assertRaises(AssertionError):
                V.verify_inventory(root, True)

    @staticmethod
    def encoded(value):
        return ''.join(f'\\x{byte:02x}' for byte in value)

    def trace(self, path, script=b'exit 7', code=7, split=False):
        encoded = self.encoded
        argv = ', '.join('"' + encoded(arg) + '"' for arg in [b'/bin/sh', b'-xe', b'-c', script])
        call = f'execve("{encoded(b"/bin/sh")}", [{argv}], 0x123 /* 12 vars */'
        if split:
            path.write_text(f'41 123.000001 {call} <unfinished ...>\n'
                            '41 123.000002 <... execve resumed>) = 0\n'
                            f'41 123.000003 exit_group({code}) = ?\n')
        else:
            path.write_text(f'41 123.000001 {call}) = 0\n41 123.000003 exit_group({code}) = ?\n')

    def test_independent_trace_exact_argv_and_exit(self):
        for split in (False, True):
            with self.subTest(split=split), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'trace'
                self.trace(path, split=split)
                record, = V.trace_shells(path)
                self.assertEqual(record['argv'], [b'/bin/sh', b'-xe', b'-c', b'exit 7'])
                self.assertEqual(record['exit_code'], 7)

    def test_trace_truncation_and_absent_exit_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'trace'
            self.trace(path)
            original = path.read_text()
            for changed in [original.splitlines()[0] + '\n', original.replace('], 0x123', '...], 0x123')]:
                path.write_text(changed)
                with self.assertRaises(AssertionError):
                    V.trace_shells(path)

    def test_frozen_xtrace_population_and_source_join(self):
        raw = Path(__file__).with_name('xtrace-expectations-v1.json').read_bytes()
        self.assertEqual(V.sha(raw), V.XTRACE_SHA)
        traces = json.loads(raw)['records']
        manifest = json.loads((V.ROOT / 'compat/jenkins-worker/fixtures/sequential-v1/manifest.json').read_bytes())
        expected = {(f['id'], si, ti):step for f in manifest['fixtures'] if f['expected']['compilation'] == 'supported'
                    for si, stage in enumerate(f['expected']['stages'], 1) for ti, step in enumerate(stage['steps'], 1)}
        self.assertEqual(len(expected), 23)
        self.assertEqual(len(traces), 23)
        for record in traces:
            step = expected.pop((record['fixture'], record['stage_ordinal'], record['step_ordinal']))
            self.assertEqual(V.sha(step['script_utf8'].encode()), record['script_sha256'])
            self.assertEqual(V.sha(record['xtrace_utf8'].encode()), record['xtrace_sha256'])
            self.assertEqual(record['xtrace_utf8'] == '', step['outcome'] == 'skipped')
        self.assertEqual(expected, {})

    def synthetic_joins(self, directory):
        cases = []
        records = []
        index = 0
        for number in range(11):
            count = 2 if number < 8 else 1
            names = [f'shell.wrapper{index + i}' for i in range(count)]
            for name in names:
                (directory / name).mkdir()
            cases.append({'fixture':str(number), 'product_build_id':f'build{number}',
                          'product_pipeline_id':f'pipeline{number}', 'product_workspace_namespace':f'namespace{number}',
                          'jenkins_wrapper_records':names,
                          'executed_steps':[{'product_attempt':f'attempt{index + i}'} for i in range(count)]})
            records.append({'fixture':str(number), 'build_id':f'build{number}'})
            index += count
        records.extend({'fixture':f'negative{number}'} for number in range(12))
        return cases, {'records':records}

    def test_global_joins_reject_wrapper_reuse_and_unreferenced_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            cases, complete = self.synthetic_joins(directory)
            V.verify_global_joins(cases, complete, directory)
            changed = copy.deepcopy(cases)
            changed[-1]['jenkins_wrapper_records'][0] = changed[0]['jenkins_wrapper_records'][0]
            with self.assertRaises(AssertionError):
                V.verify_global_joins(changed, complete, directory)
            (directory / 'shell.extra').mkdir()
            with self.assertRaises(AssertionError):
                V.verify_global_joins(cases, complete, directory)

    def test_global_joins_reject_forged_namespace_count_and_build_join(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            cases, complete = self.synthetic_joins(directory)
            changed = copy.deepcopy(cases)
            changed[-1]['product_workspace_namespace'] = changed[0]['product_workspace_namespace']
            with self.assertRaises(AssertionError):
                V.verify_global_joins(changed, complete, directory)
            complete['records'][0]['build_id'] = 'borrowed-build'
            with self.assertRaises(AssertionError):
                V.verify_global_joins(cases, complete, directory)

    def test_source_archive_rejects_substituted_or_absent_producer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.tar'
            content = b'reviewed observer bytes'
            with tarfile.open(path, 'w') as archive:
                member = tarfile.TarInfo('scripts/observer')
                member.size = len(content)
                member.mode = 0o755
                archive.addfile(member, io.BytesIO(content))
            V.source_archive_tree(path, {'scripts/observer':content})
            for required in ({'scripts/observer':b'substituted'}, {'scripts/missing':content}):
                with self.subTest(required=required), self.assertRaises(AssertionError):
                    V.source_archive_tree(path, required)

    def test_fenced_log_chunks_reject_gap_or_unknown_stream(self):
        def chunk(sequence, stream, content):
            return {'fence':1, 'sequence':sequence, 'stream':stream, 'content':list(content),
                    'digest':V.sha(content), 'cursor_id':sequence + 10}
        good = {'logs':[{'attempt_id':'id', 'chunks':[chunk(0, 'stderr', b'+ trace\n'), chunk(1, 'stdout', b'A\n'), chunk(2, 'stderr', b'+ next\n')]}]}
        self.assertEqual(V.product_logs(good, 'id'), {'stdout':b'A\n', 'stderr':b'+ trace\n+ next\n'})
        for chunks in [[chunk(0, 'stdout', b'A'), chunk(2, 'stdout', b'\n')], [chunk(0, 'other', b'A')],
                       [dict(chunk(0, 'stdout', b'A'), digest='0' * 64)]]:
            with self.subTest(chunks=chunks), self.assertRaises(AssertionError):
                V.product_logs({'logs':[{'attempt_id':'id', 'chunks':chunks}]}, 'id')



if __name__ == '__main__':
    unittest.main()
