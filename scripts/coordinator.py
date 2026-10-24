"""Standalone, single-writer MCP + CPU coordinator. No bundled model clients."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]
QUEUE = ROOT / 'local/benchmark/coordinator'

def load(name, suffix=''):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_')+suffix, ROOT/'scripts'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def now(): return datetime.now(timezone.utc).isoformat()

def active_hold():
    p=ROOT/'local/service-limit.json'
    if not p.exists(): return None
    value=json.loads(p.read_text(encoding='utf-8-sig'))
    return value if datetime.now(timezone.utc)<datetime.fromisoformat(value['retry_at_utc'].replace('Z','+00:00')) else None

def run():
    import msvcrt
    QUEUE.mkdir(parents=True,exist_ok=True)
    # The OS lock is released on process exit. Never steal another live writer.
    with (ROOT/'local/writer.lock').open('a+b') as lock:
        if lock.tell()==0: lock.write(b'0'); lock.flush()
        lock.seek(0)
        try: msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
        except OSError: raise RuntimeError('Another coordinator owns this workspace') from None
        (QUEUE/'coordinator.lock').write_text(str(os.getpid()))
        helpers=load('cpu-priority-trial')
        helpers.QUEUE=QUEUE
        checkpoints=load('coordinator-json')
        bridge_module=load('mcp-live-bridge')
        bridge=bridge_module.Bridge(ROOT)
        path=QUEUE/'trial.json'
        trial=checkpoints.load_checkpoint(path) if (path.with_name(path.name+'.checkpoints')/'HEAD.json').exists() else dict(state='running',started_utc=now(),rows=[])
        def save_trial(): checkpoints.checkpoint(path,trial)
        def service(script,*args): return helpers.ps(script,*args)
        def finish(row,report):
            try:
                if report['outcome']=='match':
                    row['submission']=service('submit-match.ps1','-Pack',row['pack'],'-Candidate',report['candidate'],'-Model',report['model'])
                else:
                    receipt=service('fnv.ps1','giveup','-Json',json.dumps(dict(claim_id=row['claim_id'],reason=report.get('reason','No official MATCH')[:430],model=report.get('model','Non-AI CPU generator'))))
                    bridge_module.save(Path(row['pack'])/'giveup-receipt.json',receipt)
                    row['released']=True
            except Exception as error:
                # Known identity is quarantined; never replay an uncertain finish.
                row['finalization_error']=type(error).__name__
                save_trial()
        status=service('fnv.ps1','status')
        known={r['claim_id'] for r in trial['rows']}
        if any(c.get('this_key') and c['claim_id'] not in known for c in status['open_claims']):
            raise RuntimeError('Untracked owned claims: reconcile them before starting this coordinator')
        # Reconcile receipts, but never guess that a missing claim was released.
        ledger={r['claim_id']:r for r in json.loads((ROOT/'local/submissions.json').read_text())}
        live={c['claim_id']:c for c in status['open_claims'] if c.get('this_key')}
        for row in trial['rows']:
            if row.get('done'): continue
            if row['claim_id'] in ledger:
                row.update(done=True,stage='done',submission=ledger[row['claim_id']])
            elif row['claim_id'] not in live:
                row.update(stage='quarantined',finalization_error='Claim absent without a local receipt; historical outcome unknown')
        save_trial()
        last_status=time.monotonic()
        try:
            while True:
                hold=active_hold()
                if hold:
                    bridge_module.save(bridge.base/'coordinator.json',dict(utc=now(),state='running',service_pause=hold,uncertain_mutation=bridge.uncertain,max_live_claims=status['limits']['claims'],available_claim_slots=0))
                    time.sleep(5);continue
                if time.monotonic()-last_status>=60:
                    status=service('fnv.ps1','status');last_status=time.monotonic()
                stopping=(ROOT/'local/stop.request').exists()
                bridge.tick(trial,status,service,finish,save_trial,load,stopping=stopping)
                save_trial()
                if stopping and all(r.get('done') or r.get('finalization_error') for r in trial['rows']): break
                time.sleep(2)
        finally:
            save_trial()
            if hasattr(load,'web_service_transport'): load.web_service_transport.close()
            if hasattr(load,'cpu_sweep_runtime'): load.cpu_sweep_runtime.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='Validate local setup without service calls or claims')
    args=parser.parse_args()
    if args.check:
        required=['local/settings.json','local/submissions.json','tools/vc2008/VC/bin/cl.exe','tools/fnvcheck/fnvcheck/fnvcheck.py','local/shared/function_index.json','local/shared/fnvdecomp_symbols.json','local/shared/compiler_tips.md']
        missing=[name for name in required if not (ROOT/name).is_file()]
        print(json.dumps(dict(ready=not missing,missing=missing,service_calls=0)))
        raise SystemExit(bool(missing))
    run()
