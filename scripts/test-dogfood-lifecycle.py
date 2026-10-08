#!/usr/bin/env python3
"""Actual lifecycle code with an owned-hook API spy; all data is public toy data.

No spy represents GitHub App hooks or invents controller delivery association.
Cross-mode success is deliberately not modeled when its producer is unavailable.
"""
import contextlib
import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('dogfood_lifecycle', ROOT / 'scripts/dogfood/hook-lifecycle.py')
assert SPEC and SPEC.loader
LIFE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIFE)

API = r'''
import json, os, pathlib, stat, sys
root=pathlib.Path(os.environ['OWNED_HOOK_FIXTURE']); args=sys.argv[1:]
store=json.loads((root/'api.json').read_text()); state=root/'state'
method=args[args.index('-X')+1] if '-X' in args else 'GET'
endpoint=next(a for a in args if a.startswith('repos/'))
body=None
if '--input' in args:
 path=pathlib.Path(args[args.index('--input')+1]); body=json.loads(path.read_text())
 assert stat.S_IMODE(path.stat().st_mode)==0o600 and path.stat().st_uid==os.getuid()
 owner=json.loads((state/'hook-owner.json').read_text())
 entry={'method':method,'endpoint':endpoint,'phase':owner['phase'],'retained_id':owner['hook_id'],'argv':args,'body':body,'request_path':str(path)}
else: entry={'method':method,'endpoint':endpoint,'argv':args}
with (root/'calls.jsonl').open('a') as out: out.write(json.dumps(entry)+'\n')
if endpoint=='repos/toy/repository': answer={'id':711,'full_name':'toy/repository','permissions':{'admin':True}}
elif '/hooks?' in endpoint: answer=[list(store['hooks'].values())]
elif method=='POST':
 assert endpoint=='repos/toy/repository/hooks'; key='73'; answer={'id':73,'name':'web',**body}; answer['config'].pop('secret',None); store['hooks'][key]=answer
elif '/hooks/' in endpoint:
 key=endpoint.rsplit('/',1)[1]
 if key not in store['hooks']: sys.exit(22)
 answer=store['hooks'][key]
 if method=='PATCH':
  if store.get('fail_disable') and body.get('active') is False: sys.exit(23)
  answer.update(body); answer.get('config',{}).pop('secret',None)
else: raise AssertionError(args)
(root/'api.json').write_text(json.dumps(store))
if store.get('lose_create_answer') and method=='POST': sys.exit(23)
if store.get('wrong_response_id') and method=='PATCH': answer=dict(answer,id=74)
print(json.dumps(answer))
'''


class LifecycleTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix='mcloving-owned-hook-') as directory:
            root = pathlib.Path(directory); state = root/'state'; state.mkdir(mode=0o700)
            commands = root/'commands'; commands.mkdir()
            gh = commands/'gh'; gh.write_text('#!'+sys.executable+'\n'+API); gh.chmod(0o700)
            (root/'api.json').write_text(json.dumps({'hooks':{}}))
            old = dict(os.environ)
            os.environ.update(OWNED_HOOK_FIXTURE=str(root), PATH=str(commands)+':'+old['PATH'],
                              MCLOVING_DOGFOOD_REPOSITORY='toy/repository', MCLOVING_URL='https://toy.invalid')
            LIFE.begin(state)
            context={'repository':'toy/repository','organization':'toy-org','project':'toy-project','pipeline':'toy-pipeline',
                     'trigger':'toy-trigger','generation':1,'source_generation':'dogfood-1',
                     'route_url':'https://toy.invalid/hooks/toy','trigger_created':True}
            LIFE.write_private(state/'sender-context.json',context)
            LIFE.write_private(state/'hook.json',{'provider':'github','path':'/hooks/toy','secret':'PUBLIC TOY SECRET'})
            try: yield root,state,context
            finally:
                os.environ.clear(); os.environ.update(old)

    def calls(self, root):
        return [json.loads(x) for x in (root/'calls.jsonl').read_text().splitlines()]

    def test_inactive_create_id_persisted_before_activation_and_same_id_url_patch(self):
        with self.fixture() as (root,state,context):
            LIFE.reconcile(state,'public')
            receipt=LIFE.owner(state)
            self.assertEqual(receipt['hook_id'],73); self.assertEqual(receipt['phase'],'public-ready')
            calls=self.calls(root); post=next(c for c in calls if c['method']=='POST')
            self.assertEqual(post['phase'],'pending-create'); self.assertIsNone(post['retained_id']); self.assertIs(post['body']['active'],False)
            activate=next(c for c in calls if c.get('body')=={'active':True})
            self.assertEqual(activate['retained_id'],73); self.assertEqual(activate['phase'],'pending-activate')
            LIFE.begin(state); LIFE.quiesce(state)
            context.update(route_url='https://new.toy.invalid/hooks/toy',trigger_created=False,generation=2,source_generation='dogfood-2')
            LIFE.write_private(state/'sender-context.json',context); LIFE.reconcile(state,'public')
            calls=self.calls(root)
            self.assertEqual(sum(c['method']=='POST' for c in calls),1)
            for call in calls:
                if call['method']=='PATCH': self.assertTrue(call['endpoint'].endswith('/hooks/73'))
                self.assertNotIn('PUBLIC TOY SECRET',' '.join(call['argv']))
                if 'request_path' in call: self.assertFalse(pathlib.Path(call['request_path']).exists())
            self.assertEqual(list(state.glob('.hook-request.*')),[])

    def test_uncertain_create_never_posts_again_or_adopts_matching_url(self):
        with self.fixture() as (root,state,_context):
            (root/'api.json').write_text(json.dumps({'hooks':{},'lose_create_answer':True}))
            with self.assertRaises(LIFE.ExternalFailure): LIFE.reconcile(state,'public')
            self.assertEqual(LIFE.owner(state)['phase'],'pending-create')
            with self.assertRaises(LIFE.Refused): LIFE.begin(state)
            self.assertEqual(sum(c['method']=='POST' for c in self.calls(root)),1)
            self.assertEqual(list(state.glob('.hook-request.*')),[])

    def test_unknown_hook_owner_and_unrecorded_history_refused(self):
        with self.fixture() as (root,state,context):
            (root/'api.json').write_text(json.dumps({'hooks':{'94':{'id':94,'config':{'url':context['route_url']}}}}))
            with self.assertRaisesRegex(LIFE.Refused,'unowned_hook'): LIFE.reconcile(state,'public')
            self.assertFalse(any(c['method'] in {'POST','PATCH'} for c in self.calls(root)))
        with self.fixture() as (_root,state,_context):
            (state/'hook-owner.json').unlink()
            with self.assertRaisesRegex(LIFE.Refused,'unrecorded_sender_history'): LIFE.begin(state)

    def test_disable_failure_wrong_id_and_missing_handoff_do_not_authorize_bridge(self):
        for fault in ('fail_disable','wrong_response_id','no_producer'):
            with self.subTest(fault=fault), self.fixture() as (root,state,context):
                LIFE.reconcile(state,'public'); LIFE.begin(state)
                api=json.loads((root/'api.json').read_text())
                if fault!='no_producer': api[fault]=True
                (root/'api.json').write_text(json.dumps(api))
                def transition():
                    LIFE.quiesce(state)
                    context['trigger_created']=False; LIFE.write_private(state/'sender-context.json',context)
                    LIFE.reconcile(state,'bridge')
                with self.assertRaises((LIFE.Refused,LIFE.ExternalFailure)): transition()
                with self.assertRaises(LIFE.Refused): LIFE.bridge_guard(state)
                if fault=='no_producer':
                    receipt=LIFE.owner(state); self.assertEqual(receipt['phase'],'blocked-handoff')
                    self.assertIn('UNAVAILABLE',receipt['pending_input']['guarantee'])
                    self.assertIs(json.loads((root/'api.json').read_text())['hooks']['73']['active'],False)

    def test_fresh_bridge_and_repeat_have_no_public_sender_or_historical_waiver(self):
        with self.fixture() as (root,state,context):
            LIFE.reconcile(state,'bridge'); LIFE.bridge_guard(state)
            LIFE.begin(state); context['trigger_created']=False; LIFE.write_private(state/'sender-context.json',context)
            LIFE.reconcile(state,'bridge'); LIFE.bridge_guard(state)
            self.assertFalse(any(c['method'] in {'POST','PATCH'} for c in self.calls(root)))
            LIFE.begin(state)
            with self.assertRaisesRegex(LIFE.Refused,'cross_mode'): LIFE.reconcile(state,'public')
            self.assertFalse(any(c['method']=='POST' for c in self.calls(root)))

    def test_owner_uid_inode_schema_and_repo_binding_mutations(self):
        for key,value in [('owner_uid',os.getuid()+1),('state_inode',0),('hook_id','73'),('protocol','wrong')]:
            with self.subTest(key=key), self.fixture() as (_root,state,_context):
                receipt=LIFE.owner(state); receipt[key]=value; LIFE.write_private(state/'hook-owner.json',receipt)
                with self.assertRaises(LIFE.Refused): LIFE.owner(state)
        with self.fixture() as (root,state,context):
            LIFE.reconcile(state,'public'); LIFE.begin(state); LIFE.quiesce(state); context['repository']='other/repository'
            LIFE.write_private(state/'sender-context.json',context)
            with self.assertRaises((LIFE.Refused,LIFE.ExternalFailure)): LIFE.reconcile(state,'public')
            self.assertEqual(sum(c['method']=='POST' for c in self.calls(root)),1)

    def test_pid_reuse_does_not_signal_unknown_process(self):
        with self.fixture() as (_root,state,_context):
            child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
            try:
                actual=LIFE.process(child.pid)
                LIFE.write_private(state/'bridge-process.json',{'protocol':'mcloving.dogfood-process/v1','role':'bridge',
                                  'expected':'toy-script','pid':child.pid,'start_ticks':actual['start_ticks']-1,
                                  'image':actual['image'],'argv':actual['argv']})
                with self.assertRaisesRegex(LIFE.Refused,'pid_reused'): LIFE.stop(state,'bridge','toy-script')
                self.assertIsNone(child.poll()); self.assertTrue((state/'bridge-process.json').exists())
            finally: child.terminate(); child.wait(timeout=5)

    def test_supervisor_holds_one_cloexec_lock_for_entire_child_wait(self):
        import fcntl
        from unittest import mock
        with self.fixture() as (_root,state,_context):
            observations=[]
            class Child:
                pid=os.getpid()
                def __init__(child,args,**kwargs):
                    self.assertEqual(args,['/bin/bash',str(LIFE.HERE/'heman-up.sh'),str(state),'--under-transition-lock'])
                    self.assertIs(kwargs['close_fds'],True); self.assertIs(kwargs['start_new_session'],True)
                    child.observe()
                def observe(child):
                    inode=(state/'transition.lock').stat().st_ino
                    held=[]
                    for name in pathlib.Path('/proc/self/fd').iterdir():
                        try:
                            if name.stat().st_ino==inode: held.append(int(name.name))
                        except FileNotFoundError: pass
                    self.assertEqual(len(held),1)
                    self.assertTrue(fcntl.fcntl(held[0],fcntl.F_GETFD)&fcntl.FD_CLOEXEC)
                    probe=os.open(state/'transition.lock',os.O_RDWR)
                    try:
                        with self.assertRaises(BlockingIOError): fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    finally: os.close(probe)
                    observations.append(True)
                def wait(child): child.observe(); return 0
            with mock.patch.object(LIFE.subprocess,'Popen',Child): self.assertEqual(LIFE.supervise(state),0)
            self.assertEqual(len(observations),2)
            probe=os.open(state/'transition.lock',os.O_RDWR)
            try: fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally: os.close(probe)

    def test_public_flags_cannot_bypass_actual_lock_parent(self):
        with self.fixture() as (_root,state,_context):
            result=subprocess.run([sys.executable,str(ROOT/'scripts/dogfood/hook-lifecycle.py'),'assert-lock',str(state)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            result=subprocess.run(['/bin/bash',str(ROOT/'scripts/dogfood/bridge.sh'),str(state),'--owned-delivery','1001','a'*40,'2026-01-01T00:00:00Z'],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(list(state.glob('deliveries.*.tsv')))


if __name__=='__main__': unittest.main()
