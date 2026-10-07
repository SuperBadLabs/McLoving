#!/usr/bin/env python3
"""Root-native AGENT-012 proof driver, authored NOT RUN.

A guard earns only pristine named positive -> intended diagnostic RED -> restored
same positive. Source copies are disposable; original source is never mutated.
The explicit flag requires a separately assigned root native lane. Keep Cargo
cache/sccache/environment intact and resolve effective target through metadata.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(command, cwd, env, timeout):
    process=subprocess.Popen(command,cwd=cwd,env=env,text=True,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    try:
        output,_=process.communicate(timeout=timeout)
        return process.returncode,output,False
    except subprocess.TimeoutExpired:
        os.killpg(process.pid,signal.SIGTERM)
        try:output,_=process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);output,_=process.communicate()
        return 124,output,True


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root-authorized-native',action='store_true')
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--only',choices=['green','guards'],required=True)
    parser.add_argument('--clause',action='append')
    args=parser.parse_args()
    if not args.root_authorized_native:
        parser.error('root must assign its native lane before invoking this driver')
    source=args.source.resolve();env=os.environ.copy();records=[]
    args.receipt.parent.mkdir(parents=True,exist_ok=True)
    raw=args.receipt.with_name(args.receipt.name+'.raw');raw.mkdir(parents=True,exist_ok=True)
    manifest=json.loads((source/'docs/evidence/agent012-source-candidate/proof-map.json').read_text())
    receipt={'ticket':'AGENT-012','base':manifest['base'],'source':str(source),
        'manifest_sha256':digest(source/'docs/evidence/agent012-source-candidate/proof-map.json'),
        'formatter_history':manifest.get('formatter_history'),
        'phases':records,'all_earned':False}
    def persist():args.receipt.write_text(json.dumps(receipt,indent=2)+'\n')
    def run(label,command,cwd,phase_env,timeout,source_hashes):
        rc,output,stalled=execute(command,cwd,phase_env,timeout)
        log=raw/f'{len(records):03d}-{label.replace(":","-")}.log';log.write_text(output)
        record={'phase':label,'command':command,'cwd':str(cwd),'exit_code':rc,
            'watchdog':stalled,'raw_output':str(log),'raw_output_sha256':digest(log),
            'source_hashes':source_hashes,'earned':False}
        records.append(record);persist();return record,output
    # Resolve the ORIGINAL source's effective target, including env/config-relative
    # Cargo paths, then freeze that absolute directory for all copied phases. Do
    # not replace RUSTC_WRAPPER, sccache, CARGO_HOME or the shared target contract.
    record,output=run('cargo-target-metadata',['cargo','+1.97.1','metadata','--locked','--no-deps','--format-version','1'],source,env,120,{})
    if record['exit_code'] or record['watchdog']:raise SystemExit('target metadata failed; not proof')
    try:
        document=next(line for line in output.splitlines() if line.startswith('{'))
        target=Path(json.loads(document)['target_directory']).resolve()
    except (KeyError,ValueError,TypeError,StopIteration) as error:raise SystemExit(f'invalid effective Cargo target: {error}')
    env['CARGO_TARGET_DIR']=str(target);receipt['effective_cargo_target_dir']=str(target)
    record['earned']=True;persist()
    work=[];seen=set()
    for row in manifest['matrix']+manifest.get('lock_order_controls',[]):
        if args.clause and row['id'] not in args.clause:continue
        drivers=row['candidate_drivers'] if args.only=='green' else [row['guard_driver']]
        for driver in drivers:
            key=(driver['package'],driver['target'],driver['filter'])
            if args.only=='green' and key in seen:continue
            seen.add(key);work.append((row,driver,row['guard_removal']))
        if args.only=='guards' and row.get('additional_guard_removal'):
            extra=dict(row);extra['id']+=':custody-control'
            extra['red_diagnostic']=row['additional_red_diagnostic']
            work.append((extra,row['additional_guard_driver'],row['additional_guard_removal']))
    if not work:raise SystemExit('no named drivers selected; not proof')
    for row,driver,guard in work:
        if driver['requires_postgres'] and not env.get('MCLOVING_TEST_DATABASE_URL'):
            raise SystemExit('disposable MCLOVING_TEST_DATABASE_URL required; skip is not proof')
        with tempfile.TemporaryDirectory(prefix='agent012-proof-') as tmp:
            candidate=Path(tmp)/'source'
            shutil.copytree(source,candidate,ignore=shutil.ignore_patterns('.git','target','node_modules'))
            guarded=candidate/guard['path'];original=guarded.read_bytes()
            receipt.setdefault('guard_bindings',[]).append({'clause':row['id'],'path':guard['path'],
                'pristine_source_sha256':hashlib.sha256(original).hexdigest(),
                'before_sha256':hashlib.sha256(guard['before'].encode()).hexdigest(),
                'after_sha256':hashlib.sha256(guard['after'].encode()).hexdigest(),
                'expected_anchor_occurrences':guard['available_anchor_occurrences'],
                'anchor_phase':guard.get('anchor_phase'),'driver':driver});persist()
            if original.decode().count(guard['before'])!=guard['available_anchor_occurrences']:
                raise SystemExit(f'guard anchor drift: {row["id"]}')
            def hashes():return {path:digest(candidate/path) for path in manifest['source_paths']}
            def phase(label,positive):
                phase_env=env.copy()
                if driver['requires_shipped_binaries']:
                    built,text=run(row['id']+':'+label+':build',['cargo','+1.97.1','build','--locked','-p','mcloving-controller','-p','mcloving-agent'],candidate,phase_env,900,hashes())
                    if built['exit_code'] or built['watchdog']:raise SystemExit('build/setup failure is not semantic proof')
                    built['earned']=True;phase_env['MCLOVING_CONTROLLER_BINARY']=str(target/'debug/mcloving-controller');persist()
                command=['cargo','+1.97.1','test','--locked','-p',driver['package']]+shlex.split(driver['target'])+[driver['filter'],'--','--test-threads=1','--nocapture']
                if positive:command=['bash','scripts/run-verified-rust-test.sh','1',row['id']]+(['--require-postgres'] if driver['requires_postgres'] else [])+command
                observed,text=run(row['id']+':'+label,command,candidate,phase_env,300,hashes())
                setup=bool(re.search(r'could not compile|error\[E\d+\]|skipped:|connect migration role|start shipped controller|fixture proxy serves',text))
                if positive:earned=observed['exit_code']==0 and not observed['watchdog'] and not setup
                else:
                    # libtest --nocapture can split the initial name and FAILED.
                    # Require the authoritative final failed-test list plus
                    # exactly one failed test, rather than a prior panic/name.
                    # FD child output contains its own failure list/results.
                    # Bind only the FINAL list directly to its result line,
                    # and require that result to be the final libtest result.
                    summaries=re.findall(r'^failures:[ \t]*\r?\n(?:[ \t]*\r?\n)*((?:[ \t]+[^\r\n]+\r?\n)+)[ \t]*\r?\n(test result: FAILED\.[^\r\n]*)',text,re.M)
                    results=re.findall(r'^test result:[^\r\n]*',text,re.M)
                    failed=[line.strip() for line in summaries[-1][0].splitlines()] if summaries else []
                    exact=[name for name in failed if name==driver['filter'] or name.endswith('::'+driver['filter'])]
                    denominator=bool(summaries and results and summaries[-1][1]==results[-1] and re.fullmatch(r'test result: FAILED\.\s+0 passed;\s+1 failed;\s+0 ignored;.*',results[-1]))
                    named=len(failed)==1 and len(exact)==1 and denominator
                    diagnostic=bool(re.search(row['red_diagnostic'],text,re.S))
                    earned=observed['exit_code']!=0 and not observed['watchdog'] and not setup and named and diagnostic
                observed['earned']=earned;observed['driver']=driver;observed['intended_diagnostic']=None if positive else row['red_diagnostic'];persist()
                if not earned:raise SystemExit(f'unearned {label}: {row["id"]}; raw output retained')
            phase('pristine-positive',True)
            if args.only=='guards':
                red_error=None
                try:
                    mutated=original.decode().replace(guard['before'],guard['after'],guard['replace_occurrences'])
                    guarded.write_text(mutated);phase('specific-mutant-red',False)
                except SystemExit as error:
                    red_error=str(error)
                finally:
                    guarded.write_bytes(original)
                    receipt.setdefault('restored_sources',[]).append({'clause':row['id'],'path':guard['path'],'sha256':digest(guarded),'matches_pristine':digest(guarded)==hashlib.sha256(original).hexdigest()});persist()
                phase('restored-positive',True)
                if red_error:raise SystemExit(red_error)
    receipt['all_earned']=True;persist()

if __name__=='__main__':main()
