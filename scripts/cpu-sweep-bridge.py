"""CPU-first live sweep component. Called only by the service coordinator.

Worker threads compile private candidates; only tick() performs service writes.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone,timedelta
from pathlib import Path
import hashlib,json,os,time,uuid,threading

ROOT=Path(__file__).resolve().parents[1]
def now():return datetime.now(timezone.utc)
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def save(p,v):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
 tmp=p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp');tmp.write_text(json.dumps(v,indent=2),encoding='utf-8')
 for attempt in range(12):
  try:tmp.replace(p);return
  except PermissionError:
   if attempt==11:raise
   time.sleep(.025*(attempt+1))
def near(cpu):
 n=cpu.get('instruction_differences');p=cpu.get('similarity_percent')
 return bool(cpu.get('candidate') and cpu.get('outcome')=='blocked' and type(n)is int and n>=0 and ((type(p)in(int,float) and p>=90) or n<=5))

class Sweep:
 def __init__(self,load,root=ROOT):
  self.root=Path(root);self.load=load;self.pool=ThreadPoolExecutor(max_workers=2);self.jobs={}
  self.uncertain=False
  self.fast_service=None
  self.configured=2;self.compiler_gate=threading.BoundedSemaphore(2)
  self.worker_local=threading.local()
 def configure(self,config):
  workers=config.get('cpu_concurrency',2)
  if type(workers)is not int or not 1<=workers<=16:raise ValueError('CPU concurrency must be1..16')
  if not hasattr(self,'compiler_gate'):self.compiler_gate=threading.BoundedSemaphore(2)
  if not hasattr(self,'worker_local'):self.worker_local=threading.local()
  if workers!=getattr(self,'configured',2):
   old=self.pool;self.pool=ThreadPoolExecutor(max_workers=workers,thread_name_prefix='fnv_cpu')
   old.shutdown(wait=False);self.configured=workers
  self.configured=workers
  self.fast_screen=config.get('fast_screen')is True
  self.return_all_failures=config.get('return_all_failures')is True
 def batches(self):
  source=self.root/'scripts/cpu-sweep-batching.py'
  stamp=source.stat().st_mtime_ns if source.exists() else getattr(self,'batch_stamp',0)
  if not hasattr(self,'batch_module') or getattr(self,'batch_stamp',0)!=stamp:self.batch_module=self.load('cpu-sweep-batching','_cpu_batches');self.batch_stamp=stamp
  return self.batch_module
 def close(self):
  self.pool.shutdown(wait=False)
  if self.fast_service:self.fast_service.close()
 def prepare(self,row):
  helper=self.load('cpu-priority-trial','_sweep_'+uuid.uuid4().hex)
  # Packet retrieval is read-only and belongs on the preparation thread, not
  # on the single writer that dispatches web assignments and finishes claims.
  worker=None
  if getattr(self,'fast_screen',False):
   worker=getattr(self.worker_local,'fast_worker',None)
   if worker is None:
    worker=self.load('cpu-fast-worker','_sweep_'+uuid.uuid4().hex);self.worker_local.fast_worker=worker
   if not (Path(row['pack'])/'pack.json').exists():
    rejected=worker.preflight(row)
    if rejected:return rejected
  if not (Path(row['pack'])/'pack.json').exists():
   helper.ps('hydrate-pack.ps1','-Pack',row['pack'])
  if worker:return worker.prepare(Path(row['pack']),helper,self.compiler_gate)
  result=helper.cpu_prepare(Path(row['pack']))
  result['ghidra']={'outcome':'skipped','reason':'CPU sweep: full draft reserved for near-match review'}
  if near(result['cpu']):
   try:result['ghidra']=helper.add_ghidra(Path(row['pack']))
   except Exception as exc:result['ghidra']={'outcome':'refused','reason':type(exc).__name__}
   pack=Path(row['pack']);candidate=Path(result['cpu']['candidate']).resolve()
   if not candidate.is_relative_to(pack.resolve()):raise ValueError('CPU candidate outside own pack')
   handoff=read(pack/'cpu_assist/handoff.json')
   handoff['ghidra']=result['ghidra']
   handoff['cpu_near_match']=dict(candidate=str(candidate),source_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),instruction_differences=result['cpu'].get('instruction_differences'),similarity_percent=result['cpu'].get('similarity_percent'))
   save(pack/'cpu_assist/handoff.json',handoff)
  return result
 def finish(self,row,report,finish,save_trial):
  # Save an executing marker before the single coordinator invokes a mutation.
  row['sweep_mutation']='executing';row['report']=report;save_trial()
  started=time.monotonic()
  if report['outcome']!='match' and self.fast_service:
   try:
    self.fast_service('fnv.ps1','giveup','-Json',json.dumps(dict(claim_id=row['claim_id'],reason=report.get('reason','No confirmed MATCH')[:430],model=report['model'])))
    row['released']=True
   except RuntimeError:row['finalization_error']='Persistent service release uncertain; reconcile without replay'
  else:finish(row,report)
  row['cpu_sweep_finalize_seconds']=time.monotonic()-started
  row['cpu_sweep_finished_utc']=now().isoformat()
  row.update(done=not row.get('finalization_error'),stage='quarantined' if row.get('finalization_error') else 'done',sweep_mutation='uncertain' if row.get('finalization_error') else 'completed')
  # The claim identity remains known. Quarantine it without replay while
  # unrelated CPU work continues; only an unknown claim mutation stops refill.
  save_trial()
 def tick(self,trial,status,service,finish,save_trial,stopping=False):
  """Feed both slots in a bounded burst, then yield to the other workers."""
  started=time.monotonic();turns=0
  config_path=self.root/'local/cpu-sweep/control.json'
  config=read(config_path) if config_path.exists() else {}
  self.configure(config)
  if callable(getattr(self,'web_pending_probe',None)):self.web_requests_pending=self.web_pending_probe()
  if config.get('compact_checkpoints') is True:
   checkpoint=Path(config['trial_file']).resolve()
   if checkpoint.name!='trial.json' or not checkpoint.is_relative_to((self.root/'local/benchmark').resolve()):raise ValueError('Checkpoint must be a private coordinator trial')
   if int(checkpoint.with_name('coordinator.lock').read_text().strip())!=os.getpid():raise ValueError('Checkpoint writer is not this coordinator')
   if not hasattr(self,'checkpoint_writer'):
    import importlib.util
    spec=importlib.util.spec_from_file_location('_cpu_checkpoint',self.root/'scripts/coordinator-json.py')
    # Test roots may contain no installed workspace modules.
    if not (self.root/'scripts/coordinator-json.py').exists():spec=importlib.util.spec_from_file_location('_cpu_checkpoint',ROOT/'scripts/coordinator-json.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);self.checkpoint_writer=module.checkpoint if config.get('incremental_checkpoints') is True and getattr(self.load,'incremental_checkpoint_installed',False) else module.save
   def compact_save_trial():
    self.checkpoint_writer(checkpoint,trial)
   save_trial=compact_save_trial
  if config.get('persistent_service') is True and self.fast_service is None:
   self.fast_service=self.load('persistent-fnv-service','_cpu_sweep').Service(self.root)
  service=self.fast_service or service
  budget=config.get('burst_seconds',8)
  if getattr(self,'web_requests_pending',False):budget=0
  if type(budget)not in(int,float) or not 0<=budget<=20:raise ValueError('burst_seconds must be0..20')
  while True:
   if callable(getattr(self,'web_pending_probe',None)):self.web_requests_pending=self.web_pending_probe()
   self._turn(trial,status,service,finish,save_trial,stopping)
   turns+=1
   # Never wait/spin on a compiler or extend a sweep indefinitely. A service
   # request already in progress may overrun the scheduling budget safely.
   if stopping or self.uncertain or turns>=8 or time.monotonic()-started>=budget:break
   if config.get('enabled') is not True:break
   if len(self.jobs)>=self.configured and not any(f.done() for f in self.jobs):break
   if not self.jobs:break # no capacity/paused: do not re-poll the service
  metrics=trial['cpu_sweep_metrics']
  metrics.update(last_tick_seconds=round(time.monotonic()-started,3),last_tick_turns=turns,burst_budget_seconds=budget)
  save(self.root/'local/cpu-sweep/progress.json',metrics)
 def _turn(self,trial,status,service,finish,save_trial,stopping=False):
  config_path=self.root/'local/cpu-sweep/control.json'
  config=read(config_path) if config_path.exists() else {}
  if config.get('batch_reservations')is True and self.fast_service:
   self.batches().reconcile_expired_unknown(self,trial,status,save_trial)
   self.batches().reconcile_marker(self,trial,save_trial)
  own=[r for r in trial['rows'] if r.get('cpu_sweep')]
  enabled=config.get('enabled') is True and not stopping and not (self.root/'local/mcp/local-model-drain.json').exists()
  # Restart with an interrupted mutation requires inspection, never replay.
  for row in own:
   if row.get('sweep_mutation')=='executing':
    row.update(stage='quarantined',finalization_error='CPU sweep mutation interrupted; reconcile receipt/status before continuing',sweep_mutation='uncertain')
    save_trial()
   elif row.get('external_owner')=='cpu_sweep' and not row.get('done') and row.get('stage') in ('waiting','ready'):
    row['stage']='cpu_sweeping'
  return_batch=[];harvested=0
  harvest_limit=2 if getattr(self,'web_requests_pending',False) else 4
  for deferred in own:
   if deferred.get('stage')=='cpu_return_waiting' and not deferred.get('done'):return_batch.append((deferred,deferred['report']))
  for future,row in list(self.jobs.items()):
   if not future.done():continue
   if harvested>=harvest_limit:break
   harvested+=1
   del self.jobs[future]
   try:row.update(future.result())
   except Exception as exc:row['cpu']={'outcome':'unsupported','reason':'CPU exception: '+type(exc).__name__}
   cpu=row['cpu'];row['cpu_sweep_completed_utc']=now().isoformat()
   if cpu['outcome']=='match':
    row['cpu_sweep_route']='match'
    self.finish(row,dict(outcome='match',candidate=cpu['candidate'],model='Non-AI CPU C++ generator; refreshed matched declarations and bounded official finishing'),finish,save_trial)
   elif near(cpu) and not stopping and not getattr(self,'return_all_failures',False):
    row.update(stage='ready',cpu_sweep_route='near_review',cpu_review_until=min(now()+timedelta(minutes=15),datetime.fromisoformat(row['expires'].replace('Z','+00:00'))-timedelta(minutes=13)).isoformat())
    row.pop('external_owner',None)
    save_trial()
   else:
    row['cpu_sweep_route']='not_close'
    report=dict(outcome='blocked',reason='CPU-only unmatched: '+str(cpu.get('reason','unsupported'))[:260],model='Non-AI CPU C++ generator; no model call')
    if config.get('batch_finalizations')is True and self.fast_service:return_batch.append((row,report))
    else:self.finish(row,report,finish,save_trial)
  if return_batch:self.batches().finish_many(self,return_batch,save_trial)
  for row in own:
   if not row.get('done') and row.get('cpu_sweep_route')=='near_review' and row.get('stage')=='ready' and (stopping or getattr(self,'return_all_failures',False) or now()>=datetime.fromisoformat(row['cpu_review_until'])):
    self.finish(row,dict(outcome='blocked',reason='CPU near-match review queue deadline; no agent took ownership before reserved checking time',model='Non-AI CPU C++ generator; review not started'),finish,save_trial)
  # Recover compilation-only jobs after a coordinator restart, not mutations.
  for row in own:
   if not row.get('done') and row.get('stage')=='cpu_sweeping' and row not in self.jobs.values() and len(self.jobs)<self.configured:
    self.jobs[self.pool.submit(self.prepare,row)]=row
  active=[r for r in trial['rows'] if r['arm']=='qwen' and not r.get('done')]
  reviews=[r for r in own if not r.get('done') and r.get('cpu_sweep_route')=='near_review']
  capacity=not status['submissions_paused'] and status['submissions_today']<status['limits']['subsPerDay'] and status['awaiting_verification']<status['limits']['pending']
  paused_file=self.root/'local/service-limit.json'
  if paused_file.exists() and now()<datetime.fromisoformat(read(paused_file)['retry_at_utc'].replace('Z','+00:00')):capacity=False
  refilled=0
  refill_limit=0 if getattr(self,'web_requests_pending',False) else min(config.get('refill_per_turn',2),4)
  if config.get('batch_reservations')is True and self.fast_service and hasattr(self.fast_service,'reserve_batch'):
   slots=min(refill_limit,self.configured-len(self.jobs),status['limits']['claims']-len(active))
   if callable(getattr(self,'web_pending_probe',None)) and self.web_pending_probe():slots=0
   if enabled and not self.uncertain and capacity and slots>0:
    refilled=self.batches().reserve_many(self,trial,slots,save_trial)
   refill_limit=0 # one bounded batch only; never replay as individual requests
  while enabled and not self.uncertain and capacity and len(self.jobs)<self.configured and (getattr(self,'return_all_failures',False) or len(reviews)<18) and len(active)<status['limits']['claims'] and refilled<refill_limit:
   if callable(getattr(self,'web_pending_probe',None)) and self.web_pending_probe():break
   refilled+=1
   mutation=self.root/'local/cpu-sweep/claim-operation.json'
   previous=read(mutation) if mutation.exists() else {}
   if previous.get('state') in ('executing','uncertain'):
    self.uncertain=True
   else:
    save(mutation,dict(state='executing',utc=now().isoformat()));save_trial()
    claim_started=time.monotonic()
    try:claim=service('claim-reserve.ps1','-Band','<=255','-Prefer','any')
    except Exception:
     save(mutation,dict(state='uncertain',utc=now().isoformat(),reason='Claim outcome requires status/receipt reconciliation; never replayed'));self.uncertain=True
    else:
     row=dict(**claim,arm='qwen',number=len(trial['rows'])+1,bucket='cpu_sweep',stage='cpu_sweeping',done=False,cpu_sweep=True,external_owner='cpu_sweep',model_arm='cpu_sweep',worker='cpu_sweep_'+claim['claim_id'],cpu_sweep_claim_seconds=time.monotonic()-claim_started)
     trial['rows'].append(row);save_trial();save(mutation,dict(state='completed',claim_id=row['claim_id'],utc=now().isoformat()))
     reserved=set()|{r['address'].lower() for r in active}
     if row['address'].lower() in reserved:
      self.finish(row,dict(outcome='blocked',reason='CPU sweep target already reserved for another worker',model='Non-AI CPU sweep coordinator'),finish,save_trial)
     else:
      self.jobs[self.pool.submit(self.prepare,row)]=row
      active.append(row)
  own=[r for r in trial['rows'] if r.get('cpu_sweep')]
  metrics=dict(utc=now().isoformat(),enabled=enabled,uncertain_mutation=self.uncertain,inflight=len(self.jobs),screened=sum('cpu_sweep_route'in r for r in own),cpu_matches=sum(r.get('cpu_sweep_route')=='match' for r in own),cpu_uploaded=sum(r.get('cpu_sweep_route')=='match' and bool(r.get('submission')) for r in own),near_matches=sum(r.get('cpu_sweep_route')=='near_review' for r in own),review_waiting=sum(r.get('cpu_sweep_route')=='near_review' and r.get('stage')=='ready' and not r.get('done') for r in own),released_not_close=sum(r.get('cpu_sweep_route')=='not_close' and bool(r.get('released')) for r in own))
  stamp=now();recent=[]
  for item in own[-2000:]:
   value=item.get('cpu_sweep_finished_utc') or item.get('cpu_sweep_completed_utc')
   if value and (item.get('released') or item.get('submission')):
    age=(stamp-datetime.fromisoformat(value)).total_seconds()
    if 0<=age<300:recent.append(age)
  metrics.update(configured_workers=self.configured,compiler_concurrency=2,cpu_only_failures_returned=getattr(self,'return_all_failures',False),
                 completed_last_minute=sum(age<60 for age in recent),completed_last_five_minutes=len(recent),functions_per_minute_5m=round(len(recent)/5,2),
                 compiled_functions=sum(int((r.get('cpu')or{}).get('checker_attempts',0) or 0)>0 for r in own))
  trial['cpu_sweep_metrics']=metrics;trial['cpu_sweep_concurrency']=self.configured
  save(self.root/'local/cpu-sweep/progress.json',metrics)
