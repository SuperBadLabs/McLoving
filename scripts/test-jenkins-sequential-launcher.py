#!/usr/bin/env python3
"""Fail-closed launcher controls using fake Podman/admission, never real workloads."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PIN = 'a' * 64
PROFILE = 'feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271'

ADMISSION = r'''#!/usr/bin/env python3
import hashlib,json,os,stat,sys
from pathlib import Path
op=sys.argv[1]
if op.startswith('snapshot-'):
 fd=os.open(sys.argv[2],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  assert stat.S_ISREG(os.fstat(fd).st_mode)
  data=os.read(fd,262145)
  limit=2048 if op.endswith('context') else 262144
  assert len(data)<=limit
  sys.stdout.buffer.write(data)
 finally: os.close(fd)
elif op=='request-sequential':
 if os.environ.get('CASE')=='prepare-failure': sys.exit(31)
 assert Path(sys.argv[2]).read_bytes()==b'source snapshot\n'
 assert Path(sys.argv[3]).read_bytes()==b'context snapshot\n'
 sys.stdout.write('{:canonical-request true}\n')
elif op=='validate-sequential':
 if os.environ.get('CASE')=='validation-failure': sys.exit(32)
 assert Path(sys.argv[2]).read_bytes()==b'{:worker-response true}\n'
 assert Path(sys.argv[3]).read_bytes()==b'source snapshot\n'
 assert Path(sys.argv[4]).read_bytes()==b'context snapshot\n'
 print('status=admitted\nstate=disabled\nexecution_authority=false')
else: sys.exit(33)
'''
PODMAN = r'''#!/usr/bin/env python3
import json,os,sys,time
from pathlib import Path
args=sys.argv[1:]
case=os.environ.get('CASE','')
if args[:2]==['image','inspect']:
 if args[-1]=='{{.Id}}': print('sha256:'+('b' if case=='wrong-image' else 'a')*64)
 else: print('wrong' if case=='wrong-profile' else 'feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271')
elif args[0]=='run':
 Path(os.environ['RUN_LOG']).write_text(json.dumps(args))
 Path(args[args.index('--cidfile')+1]).write_text('mock-container')
 request=sys.stdin.buffer.read()
 assert request==b'{:canonical-request true}\n'
 if case=='mutate-originals':
  Path(os.environ['ORIGINAL_SOURCE']).write_bytes(b'changed')
  Path(os.environ['ORIGINAL_CONTEXT']).write_bytes(b'changed')
 if case=='timeout': time.sleep(10)
 elif case=='stdout-flood': sys.stdout.write('x'*70000)
 elif case=='stderr-flood': sys.stderr.write('x'*70000)
 elif case=='worker-error': sys.stderr.write('worker diagnostics')
 elif case=='worker-exit': sys.exit(7)
 elif case=='multiple-lines': sys.stdout.write('{}\n{}\n')
 else: sys.stdout.write('{:worker-response true}\n')
elif args[0] in ['kill','rm']: pass
else: sys.exit(34)
'''


class LauncherBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sequential-launcher-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        worker = self.root / 'compat/jenkins-worker'
        worker.mkdir(parents=True)
        for name in ['run-worker.sh', 'run-sequential-worker.sh', 'worker-podman-options.sh', 'profile-v1.properties']:
            shutil.copyfile(ROOT / 'compat/jenkins-worker' / name, worker / name)
            (worker / name).chmod(0o700)
        self.launcher = worker / 'run-worker.sh'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name, source in [('podman', PODMAN), ('admission', ADMISSION)]:
            (self.bin / name).write_text(source)
            (self.bin / name).chmod(0o700)
        self.source, self.context = self.root / 'source', self.root / 'context'
        self.source.write_bytes(b'source snapshot\n')
        self.context.write_bytes(b'context snapshot\n')
        self.scratch = self.root / 'scratch'
        self.scratch.mkdir()
        self.log = self.root / 'run.json'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
            TMPDIR=str(self.scratch), MCLOVING_JENKINS_WORKER_IMAGE='mutable-tag',
            MCLOVING_JENKINS_SEQUENTIAL_WORKER_IMAGE_SHA256=PIN,
            MCLOVING_JENKINS_ADMISSION_BIN=str(self.bin / 'admission'), RUN_LOG=str(self.log),
            ORIGINAL_SOURCE=str(self.source), ORIGINAL_CONTEXT=str(self.context))

    def launch(self, case=''):
        result = subprocess.run([str(self.launcher), 'compile-sequential', str(self.source),
            'request-a', str(self.context)], env=dict(self.env, CASE=case), capture_output=True, timeout=15)
        self.assertEqual(list(self.scratch.iterdir()), [], 'private snapshots or stream resources leaked')
        return result

    def denied(self, case='', before_run=False):
        result = self.launch(case)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'worker_image_sha256=', result.stderr)
        if before_run:
            self.assertFalse(self.log.exists())
        return result

    def test_success_immutable_launch_and_observed_receipt(self):
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'{:worker-response true}\n')
        args = json.loads(self.log.read_text())
        self.assertEqual(args[-1], 'sha256:' + PIN)
        for flag, value in [('--network','none'),('--cap-drop','ALL'),('--pull','never'),
                            ('--user','1000:1000'),('--log-driver','none')]:
            self.assertEqual(args[args.index(flag)+1], value)
        self.assertIn('--read-only', args)
        self.assertIn('--unsetenv-all', args)
        self.assertEqual(args.count('--volume'), 1)
        self.assertTrue(args[args.index('--volume')+1].endswith('/source:/input/Jenkinsfile:ro'))
        binary_digest = hashlib.sha256((self.bin/'admission').read_bytes()).hexdigest()
        self.assertIn(('admission_binary_sha256='+binary_digest+'\n').encode(), result.stderr)
        self.assertIn(('worker_image_sha256='+PIN+'\n').encode(), result.stderr)

    def test_missing_pin(self):
        del self.env['MCLOVING_JENKINS_SEQUENTIAL_WORKER_IMAGE_SHA256']
        self.denied(before_run=True)

    def test_image_and_profile_mismatch(self):
        for case in ['wrong-image','wrong-profile']:
            with self.subTest(case=case): self.denied(case,before_run=True)

    def test_preparation_failure(self):
        self.denied('prepare-failure',before_run=True)

    def test_validation_failure(self):
        self.denied('validation-failure')

    def test_original_mutation_does_not_change_snapshots(self):
        result = self.launch('mutate-originals')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.source.read_bytes(),b'changed')
        self.assertIn(('launch_source_sha256='+hashlib.sha256(b'source snapshot\n').hexdigest()).encode(),result.stderr)

    def test_source_and_context_symlinks(self):
        for target in [self.source,self.context]:
            with self.subTest(path=target.name):
                original=target.read_bytes(); target.unlink(); target.symlink_to(self.bin/'admission')
                self.denied(before_run=True); target.unlink(); target.write_bytes(original)

    def test_source_and_context_bounds(self):
        for target, limit in [(self.source,262144),(self.context,2048)]:
            with self.subTest(path=target.name):
                original=target.read_bytes(); target.write_bytes(b'x'*(limit+1))
                self.denied(before_run=True); target.write_bytes(original)

    def test_worker_stderr_exit_and_response_count(self):
        for case in ['worker-error','worker-exit','multiple-lines']:
            with self.subTest(case=case): self.denied(case)

    def test_worker_stream_bounds(self):
        for case in ['stdout-flood','stderr-flood']:
            with self.subTest(case=case):
                self.assertIn(b'exceeded stream limit',self.denied(case).stderr)

    def test_worker_timeout(self):
        self.denied('timeout')


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LauncherBoundary)
    if suite.countTestCases() != 11:
        raise SystemExit('launcher test population changed: expected 11')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or result.testsRun != 11:
        raise SystemExit('launcher tests failed, skipped, or did not execute completely')
