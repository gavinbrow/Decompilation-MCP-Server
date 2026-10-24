"""MCP job mailbox consumed ONLY by the existing production coordinator.

The MCP HTTP process never calls service mutation helpers. Durable operations
are marked executing before a mutation and are never blindly replayed.
"""
import hashlib
import json
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
import uuid
import time
import os
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'local/mcp/live'
BANDS=('<=255','256-511','512-1K','1K-4K','4K+')
import importlib.util
_feature_spec=importlib.util.spec_from_file_location('_contribution_tools',Path(__file__).with_name('contribution-tools.py'))
features=importlib.util.module_from_spec(_feature_spec);_feature_spec.loader.exec_module(features)

def claim_group(request):
 # Scheduling classes only: no separate capacity cap and no identity changes.
 return 'local_pool' if request.get('agent_id','').startswith(('or_minimax_','oc_minimax_','oc_beam_','fnvqwen_','granite_','ollama_minimax_','ollama_beam_')) else 'web'

def fair_pending(pending,last_band=None,last_groups=None,aging=True):
 """Round-robin bands and local/web groups, preserving FIFO in each group."""
 ordered=sorted(pending,key=lambda entry:(entry[0].stat().st_mtime_ns,entry[0].name))
 if aging:
  overdue=[entry for entry in ordered if entry[1]['operation']=='claim' and time.time()-entry[0].stat().st_mtime>=300]
  fresh=[entry for entry in ordered if entry[1]['operation']=='claim' and time.time()-entry[0].stat().st_mtime<300]
  if overdue and fresh:
   finishing=[entry for entry in ordered if entry[1]['operation']!='claim']
   return fair_pending(finishing+overdue,last_band,last_groups,False)+fair_pending(fresh,last_band,last_groups,False)
 finish=[entry for entry in ordered if entry[1]['operation']!='claim']
 groups={band:[] for band in BANDS}
 for entry in ordered:
  if entry[1]['operation']=='claim':groups[entry[1]['band']].append(entry)
 for band,entries in groups.items():
  buckets={group:[entry for entry in entries if claim_group(entry[1])==group] for group in ('local_pool','web')}
  order=('web','local_pool') if (last_groups or {}).get(band)=='local_pool' else ('local_pool','web')
  groups[band]=[]
  while any(buckets.values()):
   for group in order:
    if buckets[group]:groups[band].append(buckets[group].pop(0))
 start=(BANDS.index(last_band)+1)%len(BANDS) if last_band in BANDS else 0
 bands=BANDS[start:]+BANDS[:start]
 while any(groups.values()):
  for band in bands:
   if groups[band]:finish.append(groups[band].pop(0))
 return finish

def interleave_operations(ordered,claim_first=False,urgent_targets=()):
 """Finishing gets first turn, but cannot monopolize the writer indefinitely."""
 def op(entry):
  try:return features.normalize(entry[1])['operation']
  except ValueError:return entry[1]['operation']
 optional=[entry for entry in ordered if op(entry) in (*features.optional.OPERATIONS,'flag')]
 controls=[entry for entry in ordered if op(entry) not in ('claim','submit','giveup',*features.optional.OPERATIONS,'flag')]
 finishing=[entry for entry in ordered if op(entry) in ('submit','giveup')]
 finishing.sort(key=lambda entry:entry[1]['operation']!='submit')
 claims=[entry for entry in ordered if entry[1]['operation']=='claim']
 # Honor the workspace's pending-web-first policy. Band/FIFO order is stable
 # within each class; active local work, uploads and releases are unaffected.
 claims.sort(key=lambda entry:claim_group(entry[1])!='web')
 if claim_first and claims and claim_group(claims[0][1])=='web':
  urgent=[entry for entry in finishing if entry[1].get('target_id') in urgent_targets]
  controls.extend(urgent);finishing=[entry for entry in finishing if entry not in urgent]
  # Up to two four-claim batches start cloud preparation before a slow upload.
  # CPU turn checks still run between every request/batch.
  first_cloud=[entry for entry in claims if claim_group(entry[1])=='web'][:8]
  controls.extend(first_cloud);claims=[entry for entry in claims if entry not in first_cloud]
 while finishing or claims:
  if finishing:controls.append(finishing.pop(0))
  if claims:controls.append(claims.pop(0))
 return controls+optional

def read(p): return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def response_index_digest(entries):
 return hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def save(p,v):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
 t=p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp')
 t.write_text(json.dumps(v,indent=2),encoding='utf-8')
 for attempt in range(12):
  try:t.replace(p);return
  except PermissionError:
   if attempt==11:raise
   time.sleep(.025*(attempt+1))
def now(): return datetime.now(timezone.utc)
def identity(value):
 if len(value)!=32 or any(c not in '0123456789abcdef' for c in value):raise ValueError('Use a lowercase UUID hex request_id')
 return value
def capacity(status):
 return not status['submissions_paused'] and status['submissions_today']<status['limits']['subsPerDay'] and status['awaiting_verification']<status['limits']['pending']

def capacity_claim_ids(rows,status):
 # Expired historical quarantines preserve receipts/uncertainty, but do not
 # reserve account slots forever once absent from the official open snapshot.
 ids={r['claim_id'] for r in status.get('open_claims',[])}
 for row in rows:
  if row.get('arm')!='qwen' or row.get('done'):continue
  try:expired=now()>=datetime.fromisoformat(row['expires'].replace('Z','+00:00'))
  except (KeyError,ValueError,TypeError):expired=False
  if not expired:ids.add(row['claim_id'])
 return ids
def worker_id(value):
 if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}',value):raise ValueError('agent_id: 1..64 lowercase letters/digits/_/-, starting with a letter')
 return value
def agent_key(value):
 return worker_id(value['agent_id']) if value.get('agent_id') else 'legacy_'+hashlib.sha256(value['model'].encode()).hexdigest()[:16]
def row_agent(row):
 return row.get('external_agent_id') or agent_key(dict(model=row['external_model']))
def target_name(row):return ('argon_' if row.get('external_owner')=='argon_mcp' else 'web_')+row['claim_id']
def dashboard_groups(rows):
 groups={}
 for r in rows:
  if not r.get('external_owner'):continue
  model=r.get('external_model','').lower()
  if 'luna' in model:name='Luna batch'
  elif 'granite' in model:name='Granite local'
  elif 'qwen' in model:name='Fine Qwen'
  elif 'minimax' in model:name='MiniMax'
  elif 'beam' in model:name='Beam'
  elif 'gpt' in model or 'astra' in model:name='GPT web agents'
  elif any(v in model for v in ('claude','haiku','sonnet')):name='Claude web agents'
  elif 'gemini' in model or 'argon' in model:name='Gemini web agents'
  else:name='Other web agents'
  g=groups.setdefault(name,dict(active=0,working=0,preparing=0,blocked=0,completed=0,matches=0,uploaded=0))
  if r.get('done'):
   g['completed']+=1;g['uploaded']+=bool(r.get('submission'));g['matches']+=bool(r.get('submission')) or (r.get('report') or {}).get('outcome')=='match'
  elif r.get('expires') and datetime.fromisoformat(r['expires'].replace('Z','+00:00'))<=now():continue
  else:
   g['active']+=1
   g['blocked']+=bool(r.get('finalization_error'))
   g['working']+=r.get('stage') in ('working','external_working')
   g['preparing']+=r.get('stage') in ('waiting','web_packet_waiting','preparing','web_preparing')
 return groups
def validate_agent(data,agent_id):
 if data.get('requires_agent_id') and agent_id!=data.get('agent_id'):raise ValueError('Supply this assignment\'s own agent_id; do not use another agent\'s target')
 if agent_id and data.get('agent_id') and agent_id!=data['agent_id']:raise ValueError('Agent assignment mismatch')

def expired_acquisition_proven(root,request,proof,trial,status):
 """Close only an expired unknown acquisition; never infer a submission/release."""
 try:
  rid=request['request_id'];base=root/'local/mcp'
  if request.get('operation')!='claim' or proof.get('request_id')!=rid:return False
  original=base/'live/requests'/(rid+'.json')
  if hashlib.sha256(original.read_bytes()).hexdigest()!=proof.get('request_sha256'):return False
  completed=(root/proof['batch_completed']).resolve()
  if not completed.is_relative_to((base/'batches').resolve()) or completed.name!='completed.json':return False
  if hashlib.sha256(completed.read_bytes()).hexdigest()!=proof.get('batch_completed_sha256'):return False
  batch=read(completed);manifest=read(completed.with_name('requests.json'))
  receipt=read(completed.with_name(rid+'.json'))
  if request not in manifest['requests'] or receipt.get('state')!='uncertain' or receipt.get('claim'):return False
  ended=datetime.fromisoformat(batch['utc'].replace('Z','+00:00'))
  maximum=proof['maximum_claim_ms']
  if type(maximum)is not int or maximum<3600000 or maximum<status['limits']['claimMs']:return False
  evidence=(root/proof['status_evidence']).resolve()
  if evidence.parent!=(base/'live/reconciled-acquisitions').resolve():return False
  if hashlib.sha256(evidence.read_bytes()).hexdigest()!=proof.get('status_sha256'):return False
  observed=read(evidence);checked=datetime.fromisoformat(observed['checked_utc'].replace('Z','+00:00'))
  if not 0<=(now()-checked).total_seconds()<=120 or checked<ended+timedelta(milliseconds=maximum,seconds=60):return False
  observed_status=observed['status']
  if observed_status['limits']['claimMs']>maximum:return False
  known={r['claim_id'] for r in trial['rows'] if r.get('arm')=='qwen'}
  for snapshot in (observed_status,status):
   if not isinstance(snapshot['open_claims'],list):return False
   if any(c.get('this_key') and c['claim_id'] not in known for c in snapshot['open_claims']):return False
  if any(r.get('external_request')==rid for r in trial['rows']):return False
  return True
 except (OSError,ValueError,KeyError,TypeError):return False
def live_target(target_id,root=ROOT,agent_id=''):
 if not re.fullmatch(r'(?:argon|web)_clm_[0-9a-f]+',target_id):raise ValueError('Not a live web-agent target')
 data=read(root/'local/mcp/live/targets'/f'{target_id}.json')
 if data['target_id']!=target_id:raise ValueError('Live target identity mismatch')
 validate_agent(data,agent_id)
 if data['state']!='working':raise ValueError('Live target is not available for editing: '+data['state'])
 if now()>=datetime.fromisoformat(data['work_until']):raise ValueError('Worker deadline reached; coordinator will release this claim')
 pack=(root/'work'/data['claim_id']).resolve()
 if not pack.is_relative_to((root/'work').resolve()):raise ValueError('Invalid pack path')
 meta=read(pack/'pack.json')
 if any(meta[k]!=data[k] for k in ('symbol','address','size')):raise ValueError('Live packet identity changed')
 return data,pack

def enqueue(operation,request_id,payload):
 identity(request_id)
 path=BASE/'requests'/f'{request_id}.json'
 value=dict(operation=operation,request_id=request_id,**payload)
 if path.exists():
  previous=read(path)
  if previous!=value:raise ValueError('request_id already used with different arguments')
 else:save(path,value)
 result=BASE/'responses'/path.name
 return read(result) if result.exists() else dict(state='queued',request_id=request_id,poll_after_seconds=5)

class Bridge:
 def __init__(self,root=ROOT):
  self.root=root;self.base=root/'local/mcp/live'
  # Known-target finishing failures quarantine that claim, not unrelated work.
  # An interrupted acquisition with no target still stops new claims.
  self.uncertain=False
  self.unresolved_acquisitions=set()
  self.completed_requests=set();self.terminal_states={}
  # One recovery scan also indexes terminal requests. Do not reopen their
  # request JSON or republish thousands of historical claims on every reload.
  index_path=self.base/'response-index.json';cached={};indexed={}
  try:
   index=read(index_path)
   if index.get('format')==1 and index.get('sha256')==response_index_digest(index['entries']):cached=index['entries']
  except (OSError,ValueError,KeyError,TypeError):pass
  entries=list(os.scandir(self.base/'responses')) if (self.base/'responses').exists() else []
  for entry in entries:
   if not entry.name.endswith('.json') or not entry.is_file():continue
   stat=entry.stat();stamp=[stat.st_mtime_ns,stat.st_size];item=cached.get(entry.name)
   if not item or item[:2]!=stamp:
    value=read(entry.path);item=stamp+[value.get('state'),bool(value.get('target_id'))]
   indexed[entry.name]=item;state=item[2]
   if state=='needs_reconciliation' and not item[3]:
    self.uncertain=True;self.unresolved_acquisitions.add(Path(entry.name).stem)
   if state not in ('queued','waiting_capacity','executing',None):
    self.completed_requests.add(entry.name);self.terminal_states[entry.name]=state
  try:save(index_path,dict(format=1,entries=indexed,sha256=response_index_digest(indexed)))
  except OSError:pass
  self.pending_claims=False
  self.published={}
 def reconcile_saved_acquisitions(self,trial,status,save_trial,load):
  """Adopt operator-reconciled receipts, never repeat an acquisition."""
  for rid in list(self.unresolved_acquisitions):
   proof_path=self.base/'reconciled-acquisitions'/(rid+'.json')
   if not proof_path.exists():continue
   proof=read(proof_path);request=read(self.base/'requests'/(rid+'.json'))
   if proof.get('kind')=='expired_acquisition_no_live_identity':
    if not expired_acquisition_proven(self.root,request,proof,trial,status):continue
    audit=trial.setdefault('expired_acquisition_reconciliations',[])
    if not any(r.get('request_id')==rid for r in audit):
     proof_sha=hashlib.sha256(proof_path.read_bytes()).hexdigest()
     immutable=proof_path.with_name(rid+'-proof-'+proof_sha+'.json')
     if not immutable.exists():save(immutable,proof)
     audit.append(dict(request_id=rid,utc=now().isoformat(),proof_path=str(immutable.relative_to(self.root)),proof_sha256=hashlib.sha256(immutable.read_bytes()).hexdigest(),historical_outcome='unknown',mutations_replayed=0))
    save_trial()
    self.response(request,'closed_unreconciled',reason='Maximum claim lifetime elapsed; fresh status has no untracked owned claim. Historical outcome remains unknown; original mutation will never be replayed.',historical_outcome='unknown')
    self.unresolved_acquisitions.remove(rid);self.completed_requests.add(rid+'.json');self.terminal_states[rid+'.json']='closed_unreconciled'
    continue
   claim=proof.get('claim') or {};cid=claim.get('claim_id')
   current=next((c for c in status.get('open_claims',[]) if c.get('claim_id')==cid and c.get('this_key')),None)
   if request.get('operation')!='claim' or proof.get('request_id')!=rid or not current:continue
   pack=(self.root/'work'/cid).resolve()
   if not all(claim.get(k) for k in ('symbol','address','size','expires','pack')) or Path(claim['pack']).resolve()!=pack:continue
   saved=read(pack/'claim-state.json')
   if any(saved.get(k)!=claim[k] for k in ('claim_id','symbol','address','size','expires')):continue
   if any(current.get(k)!=claim[k] for k in ('address','expires')):continue
   existing=next((r for r in trial['rows'] if r.get('claim_id')==cid),None)
   if existing and existing.get('external_request')!=rid:continue
   if not existing:
    key=agent_key(request)
    existing=dict(**claim,number=len(trial['rows'])+1,arm='qwen',bucket='external',stage='web_packet_waiting',done=False,external_owner='web_mcp',external_agent_id=key,external_explicit_agent=bool(request.get('agent_id')),external_model=request['model'],external_request=rid,external_started_utc=now().isoformat(),external_work_until=min(now()+timedelta(minutes=30),datetime.fromisoformat(claim['expires'].replace('Z','+00:00'))-timedelta(minutes=3)).isoformat(),model_arm='web_'+key,worker='web_'+key,reconciled_acquisition=True)
    trial['rows'].append(existing);trial[existing['model_arm']+'_concurrency']=1
   save_trial();self.publish(existing,load)
   self.unresolved_acquisitions.remove(rid)
   self.completed_requests.add(rid+'.json')
  # A fresh Bridge derives the latch from durable unresolved acquisitions only.
  if not self.unresolved_acquisitions:self.uncertain=False
 def prepare_expired_acquisition_proofs(self,trial,status,service):
  """Writer-only read recovery after the maximum possible claim lifetime.

  Never retry the original mutation. Before expiry, even an empty status is
  insufficient evidence. Preserve the original receipt and unknown outcome.
  """
  if not self.unresolved_acquisitions:return
  try:
   limit=self.root/'local/service-limit.json'
   if limit.exists() and now()<datetime.fromisoformat(read(limit)['retry_at_utc'].replace('Z','+00:00')):return
   maximum=max(3600000,int(status['limits']['claimMs']))
  except (OSError,ValueError,KeyError,TypeError):return
  if not hasattr(self,'expiry_batch_cache'):self.expiry_batch_cache={}
  eligible=[]
  for rid in self.unresolved_acquisitions:
   try:
    request=read(self.base/'requests'/(rid+'.json'))
    if request.get('operation')!='claim' or request.get('request_id')!=rid:continue
    completed=self.expiry_batch_cache.get(rid)
    if completed is None:
     matches=[p.parent/'completed.json' for p in (self.root/'local/mcp/batches').glob('*/'+rid+'.json')]
     if len(matches)!=1:continue
     completed=matches[0];self.expiry_batch_cache[rid]=completed
    receipt=read(completed.with_name(rid+'.json'))
    if receipt.get('state')!='uncertain' or receipt.get('claim'):continue
    if request not in read(completed.with_name('requests.json'))['requests']:continue
    ended=datetime.fromisoformat(read(completed)['utc'].replace('Z','+00:00'))
    if now()<ended+timedelta(milliseconds=maximum,seconds=60):continue
    eligible.append((rid,request,completed,ended))
   except (OSError,ValueError,KeyError,TypeError):continue
  if not eligible:return
  try:
   fresh=dict(service('fnv.ps1','status'));checked=now()
   maximum=max(maximum,int(fresh['limits']['claimMs']))
   known={r['claim_id'] for r in trial['rows'] if r.get('arm')=='qwen'}
   if any(c.get('this_key') and c['claim_id'] not in known for c in fresh['open_claims']):return
   directory=self.base/'reconciled-acquisitions'
   observed=dict(checked_utc=checked.isoformat(),status=fresh)
   evidence=directory/('status-'+uuid.uuid4().hex+'.json');save(evidence,observed)
   for rid,request,completed,ended in eligible:
    if checked<ended+timedelta(milliseconds=maximum,seconds=60):continue
    original=self.base/'requests'/(rid+'.json')
    if read(original)!=request:continue
    proof=dict(kind='expired_acquisition_no_live_identity',request_id=rid,maximum_claim_ms=maximum,
     request_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
     batch_completed=str(completed.relative_to(self.root)),batch_completed_sha256=hashlib.sha256(completed.read_bytes()).hexdigest(),
     status_evidence=str(evidence.relative_to(self.root)),status_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest())
    if expired_acquisition_proven(self.root,request,proof,trial,fresh):save(directory/(rid+'.json'),proof)
   status.clear();status.update(fresh)
  except (OSError,ValueError,KeyError,TypeError,RuntimeError):return
 def install_transport(self,service,load):
  if not load or not getattr(service,'__closure__',None):return
  cells=dict(zip(service.__code__.co_freevars,service.__closure__))
  if 'helpers' not in cells:return
  helpers=cells['helpers'].cell_contents
  helper_source=self.root/'scripts/cpu-priority-trial.py'
  if helper_source.exists() and getattr(load,'assistance_code_stamp',None)!=helper_source.stat().st_mtime_ns:
   helpers.cpu_prepare=load('cpu-priority-trial','_shared_assistance').cpu_prepare
   load.assistance_code_stamp=helper_source.stat().st_mtime_ns
  if getattr(helpers,'mcp_persistent_transport',False)==6:return
  if hasattr(load,'web_service_transport'):
   # Between synchronous commands only. Reload the private helper whitelist;
   # this is not the MCP listener, coordinator, or a model server restart.
   load.web_service_transport.close();del load.web_service_transport
  if not hasattr(load,'web_service_transport'):
   load.web_service_transport=load('persistent-fnv-service','_web_transport').Transport(self.root)
  original=helpers.ps;transport=load.web_service_transport
  import threading
  owner=threading.get_ident()
  def persistent_ps(script,*args):
   if script in ('claim-pack.ps1','claim-reserve.ps1','claim-batch-reserve.ps1') or (script=='fnv.ps1' and args and args[0] in ('status','giveup','packet','flag','checkpoint','function_history')):
    if threading.get_ident()!=owner:raise RuntimeError('Only coordinator may use persistent service transport')
    if script=='fnv.ps1' and args and args[0]=='giveup':
     payload=json.loads(args[-1]);row=next((r for r in getattr(load,'contribution_trial',{}).get('rows',[]) if r.get('claim_id')==payload.get('claim_id')),None)
     if row and 'best_code' not in payload:
      try:best=features.best_source(row)
      except (OSError,ValueError):best=None
      if best:payload['best_code']=best['source'];row['shared_best_source']={k:v for k,v in best.items() if k!='source'}
     args=(*args[:-1],json.dumps(payload))
    started=time.monotonic()
    try:
     result=transport.call(script,*args)
     if script=='fnv.ps1' and args[0]=='status' and result.get('notices'):
      save(self.root/'local/mcp/notices'/((now().strftime('%Y%m%dT%H%M%S'))+'-'+uuid.uuid4().hex+'.json'),dict(utc=now().isoformat(),notices=result['notices']))
     return result
    finally:
     profile=getattr(load,'web_service_profile',[])
     profile.append(dict(utc=now().isoformat(),script=script,operation=args[0] if script=='fnv.ps1' and args else script,seconds=round(time.monotonic()-started,4)))
     load.web_service_profile=profile[-64:]
     try:save(self.root/'local/mcp/service-profile.json',load.web_service_profile)
     except OSError:pass
   # Uploads retain the existing fresh compiler/source/hash/receipt finisher.
   return original(script,*args)
  helpers.ps=persistent_ps;helpers.mcp_persistent_transport=6
 def install_checkpoints(self,callback,load):
  if not load:return
  scope=getattr(callback,'__globals__',{})
  original=scope.get('save')
  if not callable(original):return
  config_path=self.root/'local/cpu-sweep/control.json'
  if not config_path.exists():return
  config=read(config_path)
  if not config.get('compact_checkpoints') or not config.get('trial_file'):return
  checkpoint=Path(config['trial_file']).resolve()
  if not checkpoint.is_relative_to((self.root/'local/benchmark').resolve()) or checkpoint.name!='trial.json':raise ValueError('Invalid coordinator checkpoint')
  import os
  if int(checkpoint.with_name('coordinator.lock').read_text())!=os.getpid():raise ValueError('Checkpoint owner mismatch')
  version=(4,config.get('incremental_checkpoints') is True,(self.root/'scripts/coordinator-json.py').stat().st_mtime_ns,(self.root/'scripts/coordinator-stats.py').stat().st_mtime_ns)
  if getattr(load,'compact_coordinator_checkpoints',None)==version:return
  fast=load('coordinator-json','_checkpoints')
  writer=fast.checkpoint if config.get('incremental_checkpoints') is True else fast.save
  if writer is fast.save and (fast.store_path(checkpoint)/'HEAD.json').exists():raise ValueError('Checkpoint HEAD exists; disabling incremental recovery requires explicit migration')
  original=getattr(original,'_fnv_original',original)
  def compact_save(path,value):
   if Path(path).resolve()!=checkpoint:return original(path,value)
   writer(checkpoint,value)
  compact_save._fnv_original=original
  scope['save']=compact_save
  scope['stats']=load('coordinator-stats','_linear_metrics').stats
  load.incremental_checkpoint_installed=config.get('incremental_checkpoints') is True
  if hasattr(load,'cpu_sweep_runtime'):load.cpu_sweep_runtime.checkpoint_writer=writer
  load.compact_coordinator_checkpoints=version
 def record(self,row,report):
  started=datetime.fromisoformat(row['external_started_utc'])
  row['record']=dict(model=row['external_model'],outcome=report['outcome'],reason=report.get('reason',''),
                     elapsed_seconds=(now()-started).total_seconds(),usage=[],token_usage='unavailable: web app has not supplied token accounting',
                     attempts=sum(1 for _ in (Path(row['pack'])/'mcp_candidates').glob('*/check.json')))
 def reserve_batch(self,requests,trial,service,finish,save_trial,load):
  """Four sequential claims, one preflight, durable receipt per mutation."""
  directory=self.root/'local/mcp/batches'/uuid.uuid4().hex
  manifest=directory/'requests.json'
  save(manifest,dict(requests=requests))
  for request in requests:self.response(request,'executing')
  # Executing mailbox markers are durable; no claim row exists yet to save.
  try:service('claim-batch-reserve.ps1','-RequestsFile',str(manifest))
  except Exception:pass # Recover only persisted identities; never repeat a batch.
  # A durable before_status marker proves this helper never reached a mutation.
  phase=read(directory/'started.json').get('phase') if (directory/'started.json').exists() else None
  rows=trial['rows'];reserved_addresses=set()|{r['address'].lower() for r in rows if not r.get('done')}
  claimed=0
  for request in requests:
   receipt=directory/(request['request_id']+'.json')
   value=read(receipt) if receipt.exists() else {}
   if not value and phase=='before_status':value=dict(state='not_attempted',request_id=request['request_id'])
   if value.get('state')=='not_attempted':
    self.response(request,'queued',reason='batch_not_attempted',poll_after_seconds=5);continue
   claim=value.get('claim')
   if value.get('state')!='reserved' or value.get('request_id')!=request['request_id'] or not isinstance(claim,dict) or not all(claim.get(k) for k in ('claim_id','symbol','address','size','expires','pack')):
    self.uncertain=True;self.unresolved_acquisitions.add(request['request_id']);self.response(request,'needs_reconciliation',reason='Batch reservation outcome unknown; persisted receipts/status must be reconciled, never replayed');continue
   pack=(self.root/'work'/claim['claim_id']).resolve()
   saved=read(pack/'claim-state.json') if (pack/'claim-state.json').exists() else {}
   if Path(claim['pack']).resolve()!=pack or any(saved.get(k)!=claim[k] for k in ('claim_id','symbol','address','size','expires')):
    self.uncertain=True;self.unresolved_acquisitions.add(request['request_id']);self.response(request,'needs_reconciliation',reason='Batch identity validation failed; never replayed');continue
   key=agent_key(request)
   row=dict(**claim,number=len(rows)+1,arm='qwen',bucket='external',stage='web_packet_waiting',done=False,external_owner='web_mcp',external_agent_id=key,external_explicit_agent=bool(request.get('agent_id')),external_model=request['model'],external_request=request['request_id'],external_work_until=min(now()+timedelta(minutes=30),datetime.fromisoformat(claim['expires'].replace('Z','+00:00'))-timedelta(minutes=3)).isoformat(),external_started_utc=now().isoformat(),model_arm='web_'+key,worker='web_'+key)
   rows.append(row);trial[row['model_arm']+'_concurrency']=1;claimed+=1
   if row['address'].lower() in reserved_addresses:
    # Keep a duplicate quarantined; do not perform another service mutation
    # inside the reservation burst. Normal deadline finishing will release it.
    row.update(stage='ready',external_work_until=now().isoformat(),batch_reserved_duplicate=True)
   reserved_addresses.add(row['address'].lower())
   self.last_claim_band=request['band']
   if not hasattr(self,'last_claim_groups'):self.last_claim_groups={}
   self.last_claim_groups[request['band']]=claim_group(request)
   if not row.get('batch_reserved_duplicate'):self.publish(row,load)
  save_trial()
  save(directory/'completed.json',dict(claimed=claimed,uncertain=self.uncertain,utc=now().isoformat()))
  return claimed
 def response(self,request,state,**extra):
  save(self.base/'responses'/f"{request['request_id']}.json",dict(request_id=request['request_id'],state=state,**extra))
 def prepare_web(self,trial,load,finish,save_trial):
  if not load:return
  if not hasattr(load,'web_prep_runtime'):
   load.web_prep_runtime=SimpleNamespace(pool=ThreadPoolExecutor(max_workers=4,thread_name_prefix='web-prep'),jobs={},module=load('free-model-trial','_web_prepare'),helpers=load('cpu-priority-trial','_web_prepare'))
  runtime=load.web_prep_runtime
  runtime.context_load=load
  helper_source=self.root/'scripts/cpu-priority-trial.py'
  if helper_source.exists() and getattr(runtime,'helpers_stamp',None)!=helper_source.stat().st_mtime_ns:
   runtime.helpers=load('cpu-priority-trial','_web_prepare_'+str(helper_source.stat().st_mtime_ns))
   runtime.helpers_stamp=helper_source.stat().st_mtime_ns
  if not hasattr(runtime,'local_pool'):runtime.local_pool=ThreadPoolExecutor(max_workers=2,thread_name_prefix='minimax-prep')
  changed=False
  for future,row in list(runtime.jobs.items()):
   if not future.done():continue
   try:row.update(future.result())
   except Exception as exc:
    failures=int(row.get('preparation_failures',0))+1
    row.update(preparation_failures=failures,preparation_error=type(exc).__name__)
    if not isinstance(exc,ValueError) and failures<3 and now()+timedelta(minutes=2)<datetime.fromisoformat(row['external_work_until']):
     row.update(stage='web_packet_waiting',preparation_retry_after=(now()+timedelta(seconds=10*failures)).isoformat())
     del runtime.jobs[future];changed=True;continue
    row.update(preparation_refused='Preparation exception: '+type(exc).__name__,cpu=dict(outcome='unsupported'),ghidra=dict(outcome='refused'))
   del runtime.jobs[future];changed=True
   if row.get('preparation_refused'):
    report=dict(outcome='blocked',reason='Preparation validation refused: '+row['preparation_refused'],model=row['external_model'])
    finish(row,report);row.update(report=report,done=not row.get('finalization_error'),stage='quarantined' if row.get('finalization_error') else 'done')
   elif row['cpu']['outcome']=='match':
    report=dict(outcome='match',candidate=row['cpu']['candidate'],model='Non-AI CPU C++ generator')
    finish(row,report);row.update(report=report,done=not row.get('finalization_error'),stage='quarantined' if row.get('finalization_error') else 'done')
   else:row['stage']='ready'
  for row in trial['rows']:
   if row.get('external_owner') not in ('web_mcp','argon_mcp') or row.get('done') or row.get('stage') not in ('waiting','web_packet_waiting'):continue
   # Also migrate resumed legacy rows before the main scheduler can steal them.
   if row['stage']=='waiting':row['stage']='web_packet_waiting';changed=True
   if row.get('preparation_retry_after') and now()<datetime.fromisoformat(row['preparation_retry_after']):continue
   local=claim_group(dict(agent_id=row_agent(row)))=='local_pool'
   active=sum((claim_group(dict(agent_id=row_agent(r)))=='local_pool')==local for r in runtime.jobs.values())
   if active>=(2 if local else 4):continue
   row['stage']='web_preparing';changed=True
   pool=runtime.local_pool if local else runtime.pool
   runtime.jobs[pool.submit(self.prepare_owned,row,runtime,local)]=row
  if changed:save_trial()
 def prepare_owned(self,row,runtime,local=False):
  """Read-only download and local compilation, never service mutations."""
  pack=Path(row['pack']);started=time.monotonic()
  if not (pack/'pack.json').exists():runtime.helpers.ps('hydrate-pack.ps1','-Pack',str(pack))
  helpers=runtime.helpers
  if hasattr(runtime.helpers,'cpu_prepare') and hasattr(runtime.helpers,'load'):
   # Ghidra is advisory. Do not repeatedly rerun hydration/CPU while holding
   # scarce preparation slots for90 seconds behind a serialized project.
   # Only the explicit busy exception is recoverable here; changed references
   # and invalid packet spans still fail closed through the existing path.
   def bounded_ghidra(p):
    module=runtime.helpers.load('ghidra-prep')
    if callable(getattr(module,'discover',None)) and not module.discover().get('ready'):
     return dict(outcome='unavailable',reason='Optional Ghidra/JDK not configured; CPU and compiler context retained.',confirmed_match=False,service_calls=0,llm_calls=0)
    try:return module.prepare(Path(p),seconds=45,project_lane='minimax' if local else '',lock_wait_seconds=2)
    except getattr(module,'GhidraBusyError',type('_NeverRaised',(Exception,),{})):
     return dict(outcome='unavailable',reason='Ghidra project busy; bounded2-second advisory wait ended. CPU/compiler context retained; no draft or correctness claim.',confirmed_match=False,service_calls=0,llm_calls=0)
   helpers=SimpleNamespace(cpu_prepare=runtime.helpers.cpu_prepare,add_ghidra=bounded_ghidra)
  value=runtime.module.prepare(str(pack),helpers)
  if not value.get('preparation_refused') and (value.get('cpu') or {}).get('outcome')!='match' and callable(getattr(runtime,'context_load',None)):
   # Build advisory evidence in the existing read-only preparation lane. Opening
   # and closing the reference PE here must not hold up service mutations.
   target_id=target_name(row);context=self.context_value(row,runtime.context_load)
   context_path=self.root/'local/mcp/contexts'/(target_id+'.json');save(context_path,context)
   value['mcp_context_ready']=dict(target_id=target_id,agent_id=row_agent(row),sha256=hashlib.sha256(context_path.read_bytes()).hexdigest())
  value['web_preparation_seconds']=round(time.monotonic()-started,3)
  value['web_preparation_lane']='local_pool' if local else 'web'
  return value
 def context_value(self,row,load):
  return dict(task='Live web-agent claim assigned to '+row_agent(row)+'. Read all sections. Complete readable C++ only; preserve packet flags. Check first differences. Submit only saved official MATCH, or give up with a precise reason before work_until.',
              original_context=load('local-qwen-worker','_mcp_context').context(Path(row['pack'])),
              cpu_ghidra=load('agent-evidence','_mcp_context').prompt_evidence(Path(row['pack'])),
              previous_attempts=features.previous_attempts(row['pack']))
 def publish(self,row,load):
  target_id=target_name(row);pack=Path(row['pack'])
  stamp=(row.get('done'),row.get('stage'),row.get('finalization_error'),row.get('released'),json.dumps(row.get('submission')))
  if self.published.get(target_id)==stamp:return
  if row.get('expired_claim_closure'):state='closed_unreconciled'
  elif row.get('done'):state='submitted' if row.get('submission') else 'released'
  elif row.get('finalization_error'):state='needs_reconciliation'
  elif row['stage']=='ready' and not row.get('batch_reserved_duplicate'):
   # A rejected duplicate has only a reservation receipt, never a hydrated pack.
   # Keep it non-editable until normal deadline finishing releases it; do not
   # build source context or let this known duplicate interrupt other workers.
   # Each entry contains full packet source/headers and the owned target only.
   context_path=self.root/'local/mcp/contexts'/f'{target_id}.json';ready=row.get('mcp_context_ready') or {}
   prepared=ready.get('target_id')==target_id and ready.get('agent_id')==row_agent(row) and context_path.is_file() and hashlib.sha256(context_path.read_bytes()).hexdigest()==ready.get('sha256')
   if not prepared:save(context_path,self.context_value(row,load))
   row['stage']='external_working';state='working'
  else:state='working' if row['stage']=='external_working' else 'preparing'
  if state=='working':
   context_path=self.root/'local/mcp/contexts'/f'{target_id}.json'
   if context_path.exists():
    context=read(context_path)
    if 'previous_attempts' not in context:context['previous_attempts']=features.previous_attempts(pack);save(context_path,context)
  value=dict(target_id=target_id,owner='Argon via MCP' if row.get('external_owner')=='argon_mcp' else 'Web agent '+row_agent(row),agent_id=row_agent(row),requires_agent_id=bool(row.get('external_explicit_agent')),
             claim_id=row['claim_id'],symbol=row['symbol'],address=row['address'],size=row['size'],
             expires=row['expires'],work_until=row['external_work_until'],state=state,model=row['external_model'],
             historical_only=False,submission=row.get('submission'),released=bool(row.get('released')))
  if row.get('expired_claim_closure'):
   value.update(can_request_new=True,historical_outcome='unknown',closure_reason='Claim lease expired and fresh official status has no such open identity; old mutation is never replayed.')
  save(self.base/'targets'/f'{target_id}.json',value)
  self.response(dict(request_id=row['external_request']),state,**{k:v for k,v in value.items() if k!='state'})
  self.published[target_id]=(row.get('done'),row.get('stage'),row.get('finalization_error'),row.get('released'),json.dumps(row.get('submission')))
 def waiting_web(self):
  # Include requests arriving after this tick's original mailbox snapshot.
  with os.scandir(self.base/'requests') as entries:
   for entry in entries:
    if not entry.name.endswith('.json') or entry.name in self.completed_requests:continue
    answer=self.base/'responses'/entry.name
    if answer.exists() and read(answer).get('state') not in ('queued','waiting_capacity'):continue
    request=read(entry.path)
    if request.get('operation')=='claim' and claim_group(request)=='web':return True
  return False
 def reconcile_expired_owned(self,trial,status,service,save_trial,load):
  """Close expired known identities using fresh read evidence, never replay finish.

  A failed old release must not reserve the same agent_id forever. Preserve the
  original error and historical outcome; absence alone before expiry is unsafe.
  """
  try:
   if read(self.root/'local/mcp/expired-claim-recovery.json').get('enabled') is not True:return
  except (OSError,ValueError,AttributeError):return
  candidates=[]
  for row in trial['rows']:
   if row.get('external_owner') not in ('web_mcp','argon_mcp') or row.get('done'):continue
   try:eligible=now()>=datetime.fromisoformat(row['expires'].replace('Z','+00:00'))+timedelta(seconds=60)
   except (KeyError,ValueError,TypeError):eligible=False
   if eligible:candidates.append(row)
  if not candidates:return
  hold=self.root/'local/service-limit.json'
  if hold.exists():
   try:
    if now()<datetime.fromisoformat(read(hold)['retry_at_utc'].replace('Z','+00:00')):return
   except (OSError,ValueError,KeyError,TypeError):return
  # At most once/minute, in this existing single writer. No per-claim API calls.
  if time.monotonic()-getattr(self,'last_expired_owned_check',0)<60:return
  self.last_expired_owned_check=time.monotonic()
  try:
   fresh=dict(service('fnv.ps1','status'));checked=now()
   if not isinstance(fresh.get('open_claims'),list) or not isinstance(fresh.get('limits'),dict):return
   known={r.get('claim_id') for r in trial['rows']}
   if any(c.get('this_key') and c.get('claim_id') not in known for c in fresh['open_claims']):return
  except Exception:return
  open_ids={c['claim_id'] for c in fresh['open_claims']};status.update(fresh)
  closing=[r for r in candidates if r['claim_id'] not in open_ids]
  if not closing:return
  directory=self.base/'reconciled-claims';evidence=dict(checked_utc=checked.isoformat(),status=fresh)
  evidence_hash=hashlib.sha256(json.dumps(evidence,sort_keys=True).encode()).hexdigest()
  evidence_path=directory/('status-'+evidence_hash+'.json');save(evidence_path,evidence)
  for row in closing:
   snapshot=json.loads(json.dumps(row));original_hash=hashlib.sha256(json.dumps(snapshot,sort_keys=True).encode()).hexdigest()
   original_path=directory/(row['claim_id']+'-original-'+original_hash+'.json');save(original_path,snapshot)
   proof=dict(kind='expired_known_claim_absent',claim_id=row['claim_id'],agent_id=row_agent(row),expires=row['expires'],
    checked_utc=checked.isoformat(),status_evidence=str(evidence_path),status_sha256=hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
    original_row=str(original_path),original_sha256=hashlib.sha256(original_path.read_bytes()).hexdigest(),historical_outcome='unknown',mutations_replayed=0)
   proof_path=directory/(row['claim_id']+'-closed.json');save(proof_path,proof)
   row.update(done=True,stage='expired_closed',expired_claim_closure=proof)
  save_trial()
  for row in closing:self.published.pop(target_name(row),None);self.publish(row,load)

 def reopen_reviewed_aliases(self,trial):
  """Operator-requested recovery of an alias that NEVER executed a claim call."""
  for proof_path in (self.base/'reopen-assignment-requests').glob('*.json'):
   try:self._reopen_reviewed_alias(trial,proof_path)
   except (OSError,ValueError,KeyError,TypeError) as exc:
    save(proof_path.with_suffix('.validation-error'),dict(exception=type(exc).__name__,detail=str(exc)[:200],utc=now().isoformat()))
    continue

 def _reopen_reviewed_alias(self,trial,proof_path):
  for proof_path in (proof_path,):
   proof=read(proof_path);rid=identity(proof['request_id']);request_path=self.base/'requests'/(rid+'.json');response_path=self.base/'responses'/(rid+'.json')
   if proof.get('applied'):continue
   request=read(request_path);answer=read(response_path)
   if request.get('operation')!='claim' or answer.get('state')!='already_assigned':continue
   if hashlib.sha256(request_path.read_bytes()).hexdigest()!=proof.get('request_sha256') or hashlib.sha256(response_path.read_bytes()).hexdigest()!=proof.get('response_sha256'):continue
   if agent_key(request)!=proof.get('agent_id') or answer.get('target_id')!=proof.get('old_target_id'):continue
   rows=trial['rows'];old=next((r for r in rows if r.get('external_owner') in ('web_mcp','argon_mcp') and target_name(r)==proof['old_target_id']),None)
   if not old or not old.get('expired_claim_closure') or not old.get('done'):continue
   if any(r.get('external_request')==rid or (not r.get('done') and r.get('external_owner') in ('web_mcp','argon_mcp') and row_agent(r)==agent_key(request)) for r in rows):continue
   other=False
   for p in (self.base/'requests').glob('*.json'):
    if p.name==request_path.name or p.name in self.completed_requests:continue
    a=self.base/'responses'/p.name
    if a.exists() and read(a).get('state') not in ('queued','waiting_capacity','executing'):continue
    r=read(p)
    if r.get('operation')=='claim' and agent_key(r)==agent_key(request):other=True;break
   if other:continue
   # Save the old terminal answer before putting this unexecuted alias back
   # into the queue. Original claim/finish IDs are never reopened or replayed.
   save(proof_path.with_suffix('.original-response'),answer)
   self.response(request,'queued',reason='expired_assignment_reconciled',poll_after_seconds=5)
   self.completed_requests.discard(request_path.name);self.terminal_states.pop(request_path.name,None)
   proof.update(applied=True,applied_utc=now().isoformat(),mutations_replayed=0);save(proof_path,proof)
 def tick(self,trial,status,service,finish,save_trial,load,stopping=False):
  try:return self._tick(trial,status,service,finish,save_trial,load,stopping)
  except FileNotFoundError as exc:
   import traceback
   frames=traceback.extract_tb(exc.__traceback__)
   evidence=dict(utc=now().isoformat(),exception='FileNotFoundError',errno=exc.errno,
       filename=os.fspath(exc.filename) if exc.filename is not None else None,
       filename2=os.fspath(exc.filename2) if getattr(exc,'filename2',None) is not None else None,
       frames=[dict(file=f.filename,function=f.name,line=f.lineno) for f in frames])
   try:save(self.root/'local/mcp/last-bridge-file-error.json',evidence)
   except OSError:pass
   raise
 def _tick(self,trial,status,service,finish,save_trial,load,stopping=False):
  if load and getattr(getattr(load,'cpu_sweep_runtime',None),'uncertain',False):self.uncertain=True
  if self.unresolved_acquisitions:self.prepare_expired_acquisition_proofs(trial,status,service)
  if self.unresolved_acquisitions:self.reconcile_saved_acquisitions(trial,status,save_trial,load)
  # Resolving a web acquisition must not clear an independent CPU quarantine.
  if load and getattr(getattr(load,'cpu_sweep_runtime',None),'uncertain',False):self.uncertain=True
  service_pause=None
  limit_path=self.root/'local/service-limit.json'
  if limit_path.exists():
   limit=read(limit_path)
   if not limit.get('command') and now()<datetime.fromisoformat(limit['retry_at_utc'].replace('Z','+00:00')):service_pause=limit
  if load:load.contribution_trial=trial
  self.install_transport(service,load)
  self.install_checkpoints(save_trial,load)
  self.reconcile_expired_owned(trial,status,service,save_trial,load)
  self.reopen_reviewed_aliases(trial)
  tick_started=time.monotonic()
  pool_control=self.root/'local/opencode/control.json'
  dispatch_config=read(pool_control) if pool_control.exists() else {}
  web_burst=dispatch_config.get('mcp_claim_burst',8)
  if type(web_burst)is not int or not 1<=web_burst<=16:raise ValueError('MCP claim burst must be1..16')
  self.prepare_web(trial,load,finish,save_trial)
  rows=trial['rows'];owned=[r for r in rows if r.get('external_owner') in ('argon_mcp','web_mcp')]
  for row in owned:
   if row.get('done') and not row.get('expired_claim_closure') and self.terminal_states.get(row['external_request']+'.json')==('submitted' if row.get('submission') else 'released'):
    self.published.setdefault(target_name(row),(row.get('done'),row.get('stage'),row.get('finalization_error'),row.get('released'),json.dumps(row.get('submission'))))
  local_draining=(self.base.parent/'local-model-drain.json').exists()
  if local_draining:
   # Hold unassigned local work for a safe code reload. Running model requests
   # and all web assignments keep their ownership and finish normally.
   for row in rows:
    if row['arm']=='qwen' and not row.get('external_owner') and not row.get('done') and row['stage'] in ('ready','waiting'):
     row['stage']='maintenance_held'
  self.pending_claims=False;claimed_this_tick=False
  # Expire unattended sessions; a disconnected app cannot hold claims indefinitely.
  expired_finished=0
  for row in owned:
   if not row.get('done') and not row.get('finalization_error') and (stopping or now()>=datetime.fromisoformat(row['external_work_until'])) and row['stage'] in ('ready','external_working'):
    report=dict(outcome='blocked',reason='MCP worker deadline or coordinator stop; no confirmed submitted MATCH',model=row['external_model'])
    if expired_finished<4:
     self.record(row,report)
     finish(row,report);row.update(report=report,done=not row.get('finalization_error'),stage='quarantined' if row.get('finalization_error') else 'done')
     save_trial()
     expired_finished+=1
   self.publish(row,load)
  pending=[]
  for path in (self.base/'requests').glob('*.json'):
   if path.name in self.completed_requests:continue
   answer=self.base/'responses'/path.name
   if answer.exists() and read(answer).get('state') not in ('queued','waiting_capacity','executing'):
    self.completed_requests.add(path.name);continue
   pending.append((path,read(path)))
  urgent_targets={target_name(r) for r in owned if not r.get('done') and now()+timedelta(minutes=3)>=datetime.fromisoformat(r['external_work_until'])}
  pending=interleave_operations(fair_pending(pending,getattr(self,'last_claim_band',None),getattr(self,'last_claim_groups',{})),dispatch_config.get('cloud_claim_first') is True,urgent_targets)
  # The main loop's two-minute status cache can keep reporting a full account
  # after releases. Refresh read-only capacity at most once per30seconds while
  # claims wait; the same writer and each reservation's fresh preflight remain.
  if load and any(r.get('operation')=='claim' for _,r in pending) and time.monotonic()-getattr(self,'last_dispatch_status_refresh',float('-inf'))>=30:
   self.last_dispatch_status_refresh=time.monotonic()
   try:
    fresh=dict(service('fnv.ps1','status'))
    if not isinstance(fresh.get('open_claims'),list) or not isinstance(fresh.get('limits'),dict):raise ValueError('Incomplete dispatch capacity snapshot')
    status.update(fresh)
   except Exception:
    # Read failure is not permission to claim. Persisted service Retry-After
    # guards still apply; no mutation or retry is performed here.
    for pending_path,pending_request in pending:
     if pending_request.get('operation')=='claim':self.response(pending_request,'queued',reason='status_refresh_unavailable',poll_after_seconds=30)
    pending=[entry for entry in pending if entry[1].get('operation')!='claim']
  def queued_claim_counts():
   counts={'web':0,'local_pool':0}
   for request_path,request_value in pending:
    if request_value.get('operation')!='claim':continue
    response_path=self.base/'responses'/request_path.name
    if response_path.exists() and read(response_path).get('state') not in ('queued','waiting_capacity'):continue
    counts[claim_group(request_value)]+=1
   return counts
  real_web_pending=queued_claim_counts()['web']>0
  claim_dispatch_started=None
  claim_dispatch_seconds=0
  last_cpu_turn=time.monotonic()
  writer_operations=0;finished_this_tick=0
  writer_limit=dispatch_config.get('mcp_writer_operations',16)
  writer_seconds=dispatch_config.get('mcp_writer_seconds',20)
  if type(writer_limit)is not int or not 16<=writer_limit<=48:raise ValueError('MCP writer operations must be16..48')
  if type(writer_seconds)not in(int,float) or not 20<=writer_seconds<=40:raise ValueError('MCP writer seconds must be20..40')
  writer_started=time.monotonic()
  cpu_turn_seconds=0;cpu_turns=0
  for path,request in pending:
   # A long mailbox batch must not leave the independent CPU sweep idle until
   # this tick ends. Same coordinator thread, same durable mutation gates.
   sweep=getattr(load,'cpu_sweep_runtime',None) if load else None
   if sweep and time.monotonic()-last_cpu_turn>=12:
    # Harvest completed preparation during the batch too. Otherwise a ten-
    # second preparation sits finished behind a minute of service operations,
    # leaving its executor idle and making agents look unassigned.
    self.prepare_web(trial,load,finish,save_trial)
    for prepared_row in trial['rows']:
     if prepared_row.get('external_owner') in ('web_mcp','argon_mcp') and (prepared_row.get('stage')=='ready' or prepared_row.get('done')):
      self.publish(prepared_row,load)
    if not self.waiting_web():
     sweep.web_requests_pending=real_web_pending
     cpu_started=time.monotonic()
     sweep.tick(trial,status,service,finish,save_trial,stopping=stopping)
     cpu_turn_seconds+=time.monotonic()-cpu_started;cpu_turns+=1
     if sweep.uncertain:self.uncertain=True
    last_cpu_turn=time.monotonic()
    # Publish liveness/progress during a large batch, rather than looking dead
    # until every release/claim has completed. This is not a service mutation.
    health_path=self.base/'coordinator.json'
    health=read(health_path) if health_path.exists() else {}
    active=[r for r in trial['rows'] if r['arm']=='qwen' and not r.get('done')]
    health.update(utc=now().isoformat(),state='running',uncertain_mutation=self.uncertain,service_pause=service_pause,
       available_claim_slots=max(0,status['limits']['claims']-len(active)),
       active_web_agents=sum(r.get('external_owner') in ('web_mcp','argon_mcp') for r in active),
       in_progress_seconds=round(time.monotonic()-tick_started,3))
    save(health_path,health)
   # A queued amendment earlier in this tick may have changed its band.
   request=read(path)
   try:request=features.normalize(request)
   except ValueError as exc:self.response(request,'refused',reason=str(exc));continue
   answer=self.base/'responses'/path.name
   if answer.exists():
    state=read(answer)['state']
    if state=='executing':
     # A prior crash may have happened after the service committed. Receipts and
     # account identity need explicit reconciliation, never a duplicate mutation.
     known=next((r for r in owned if (request['operation']=='claim' and r.get('external_request')==request['request_id']) or (request.get('target_id') and target_name(r)==request['target_id'])),None)
     if known is not None:
      # A durable claim row already establishes the acquisition identity. An
      # interrupted finish quarantines that target, not every worker's claims.
      if request['operation']=='claim':self.publish(known,load)
      elif request['operation'] in ('flag',*features.optional.OPERATIONS):
       self.response(request,'optional_unavailable',target_id=target_name(known),claim_released=False,reason='Interrupted optional operation; retain original ID and do not replay. Continue ordinary work or release separately.')
      else:
       known.update(stage='quarantined',finalization_error='Interrupted MCP finish; reconcile receipt/status without replay')
       save_trial()
       self.response(request,'needs_reconciliation',target_id=target_name(known),reason=known['finalization_error'])
     elif request['operation'] in ('flag',*features.optional.OPERATIONS):
      self.response(request,'optional_unavailable',claim_released=False,reason='Interrupted optional operation with no current target. Never replay; normal workflow is independent.')
     else:
      self.response(request,'needs_reconciliation',reason='Previous coordinator operation interrupted; not replayed')
      self.uncertain=True;self.unresolved_acquisitions.add(request['request_id'])
    if state not in ('waiting_capacity','queued'):
     self.completed_requests.add(path.name);continue
   if request['operation']=='amend':
    original_path=self.base/'requests'/f"{identity(request['original_request_id'])}.json"
    if not original_path.exists():self.response(request,'refused',reason='Original request not found');continue
    original=read(original_path)
    if original.get('operation')!='claim' or agent_key(original)!=request['agent_id']:
     self.response(request,'refused',reason='Original claim agent mismatch');continue
    original_answer=self.base/'responses'/original_path.name
    previous=read(original_answer) if original_answer.exists() else {}
    if previous.get('state') not in (None,'queued','waiting_capacity'):
     self.response(request,'refused',reason='Claim already dispatched or terminal; inspect original status and give up assigned function if needed',original_state=previous.get('state'),target_id=previous.get('target_id'));continue
    if request.get('cancel'):
     self.response(original,'cancelled',reason='Owner agent cancelled queued request')
     self.completed_requests.add(original['request_id']+'.json')
     self.response(request,'cancelled',original_request_id=original['request_id'])
    else:
     stamp=original_path.stat()
     original['band']=request['band'];save(original_path,original)
     import os
     os.utime(original_path,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
     self.response(original,'queued',reason='request_updated',band=original['band'],poll_after_seconds=5)
     self.response(request,'updated',original_request_id=original['request_id'],band=original['band'])
    continue
   if request['operation']=='claim':
    key=agent_key(request)
    active=[r for r in owned if not r.get('done') and row_agent(r)==key]
    if active:
     self.publish(active[0],load)
     self.response(request,'already_assigned',target_id=target_name(active[0]),agent_id=key,model=active[0]['external_model'])
     continue
    if service_pause:
     self.response(request,'waiting_capacity',reason='service_paused',service_reason=service_pause['reason'],retry_at_utc=service_pause['retry_at_utc'],poll_after_seconds=max(30,int((datetime.fromisoformat(service_pause['retry_at_utc'].replace('Z','+00:00'))-now()).total_seconds())));continue
    if stopping or self.uncertain:
     self.response(request,'paused' if stopping else 'queued',reason='Coordinator stopped' if stopping else 'mutation_reconciliation_required',poll_after_seconds=30);continue
    # Reuse an already-owned CPU near match before spending another claim and
    # download. This transfers local routing only, never service ownership.
    band_bounds={'<=255':(0,255),'256-511':(256,511),'512-1K':(512,1023),'1K-4K':(1024,4095),'4K+':(4096,float('inf'))}
    lo,hi=band_bounds[request['band']]
    review=next((r for r in rows if r.get('cpu_sweep_route')=='near_review' and r.get('stage')=='ready' and not r.get('done') and not r.get('external_owner') and lo<=r['size']<=hi and now()<datetime.fromisoformat(r['cpu_review_until'])),None)
    if review and capacity(status):
     review.update(external_owner='web_mcp',external_agent_id=key,external_explicit_agent=bool(request.get('agent_id')),external_model=request['model'],external_request=request['request_id'],external_started_utc=now().isoformat(),external_work_until=min(now()+timedelta(minutes=30),datetime.fromisoformat(review['expires'].replace('Z','+00:00'))-timedelta(minutes=3)).isoformat(),model_arm='web_'+key,worker='web_'+key)
     owned.append(review);trial['web_'+key+'_concurrency']=1;save_trial();self.publish(review,load)
     continue
    self.pending_claims=True
    preparing=sum(r.get('external_owner') in ('argon_mcp','web_mcp') and not r.get('done') and r['stage'] in ('waiting','preparing','web_preparing','web_packet_waiting') for r in rows)
    live_ids=capacity_claim_ids(rows,status)
    if not capacity(status) or len(live_ids)>=status['limits']['claims']:
     self.response(request,'waiting_capacity',reason='account_claim_limit' if len(live_ids)>=status['limits']['claims'] else 'account_submission_limit',poll_after_seconds=30);continue
    if claimed_this_tick>=web_burst or claim_dispatch_seconds>=30 or preparing>=64 or writer_operations>=writer_limit or (claimed_this_tick and time.monotonic()-writer_started-cpu_turn_seconds>=writer_seconds):
     self.response(request,'queued',reason='preparation_backlog' if preparing>=64 else 'dispatch_budget',available_claim_slots=max(0,status['limits']['claims']-len(live_ids)),queue_wait_seconds=max(0,round(time.time()-path.stat().st_mtime)),scheduling='bounded alternating finishes/claims; aged requests first; round-robin size bands and local/web pools',poll_after_seconds=5);continue
    if dispatch_config.get('fast_claim_batches') is True:
     limit=min(4,web_burst-int(claimed_this_tick),writer_limit-writer_operations,status['limits']['claims']-len(live_ids),64-preparing)
     selected=[];agents={row_agent(r) for r in owned if not r.get('done')}
     for candidate_path,_ in pending:
      candidate=read(candidate_path)
      if candidate.get('operation')!='claim' or claim_group(candidate)!=claim_group(request):continue
      answer_path=self.base/'responses'/candidate_path.name
      if answer_path.exists() and read(answer_path).get('state') not in ('queued','waiting_capacity'):continue
      if agent_key(candidate) in agents:continue
      selected.append(candidate);agents.add(agent_key(candidate))
      if len(selected)>=limit:break
     if len(selected)>=2:
      old_count=len(rows);started=time.monotonic()
      count=self.reserve_batch(selected,trial,service,finish,save_trial,load)
      owned.extend(rows[old_count:]);claimed_this_tick+=count;writer_operations+=len(selected)
      claim_dispatch_seconds+=time.monotonic()-started
      self.prepare_web(trial,load,finish,save_trial)
      continue
    # Durable mailbox marker precedes the mutation; the new identity is saved
    # immediately afterwards. No unchanged trial needs another pre-claim save.
    if claim_dispatch_started is None:claim_dispatch_started=time.monotonic()
    self.response(request,'executing')
    writer_operations+=1
    reservation_started=time.monotonic()
    try:
     transport=getattr(getattr(load,'cpu_sweep_runtime',None),'fast_service',None) if load else None
     # Only claim mutation is synchronous; packet/context downloads run in the
     # bounded preparation lanes. Tests/legacy loaders retain the full helper.
     mode=request.get('context_mode','')
     preference=self.root/'local/mcp/context-preferences'/(key+'.json')
     if not mode and preference.exists():
      try:mode=read(preference).get('context_mode','')
      except (OSError,ValueError,AttributeError):mode=''
     if mode not in ('','classic','lean','resume'):mode=''
     extra=('-ContextMode',mode) if mode in ('lean','resume') else ()
     claim=service('claim-reserve.ps1','-Band',request['band'],'-Prefer','any',*extra) if load else (transport or service)('claim-pack.ps1','-Band',request['band'],'-Prefer','any',*extra)
    except Exception:
     self.uncertain=True;self.unresolved_acquisitions.add(request['request_id']);self.response(request,'needs_reconciliation',reason='Claim helper failed; do not repeat mutation');continue
    claim_dispatch_seconds+=time.monotonic()-reservation_started
    work_until=min(now()+timedelta(minutes=30),datetime.fromisoformat(claim['expires'].replace('Z','+00:00'))-timedelta(minutes=3))
    row=dict(**claim,number=len(rows)+1,arm='qwen',bucket='external',stage='web_packet_waiting' if load else 'waiting',done=False,external_owner='web_mcp',
             external_agent_id=key,external_explicit_agent=bool(request.get('agent_id')),
             external_model=request['model'],external_request=request['request_id'],external_work_until=work_until.isoformat(),external_started_utc=now().isoformat(),model_arm='web_'+key,worker='web_'+key)
    trial[row['model_arm']+'_concurrency']=1
    rows.append(row);owned.append(row);save_trial();claimed_this_tick+=1
    self.last_claim_band=request['band']
    if not hasattr(self,'last_claim_groups'):self.last_claim_groups={}
    self.last_claim_groups[request['band']]=claim_group(request)
    # Keep manual saved targets and all current workers separate even when a
    # caller selects a larger band. The service may return a historical target.
    reserved=set()|{r['address'].lower() for r in rows if r is not row and not r.get('done')}
    if row['address'].lower() in reserved:
     report=dict(outcome='blocked',reason='Target is reserved for another local agent; not assigned',model=row['external_model'])
     finish(row,report);row.update(done=not row.get('finalization_error'),stage='quarantined' if row.get('finalization_error') else 'done',report=report)
     save_trial()
    self.publish(row,load)
   elif request['operation'] in features.optional.OPERATIONS:
    # Optional work has the LAST writer turn, at most one per tick. It never
    # reserves claim capacity or prevents normal claim/check/release/upload.
    aged=time.time()-path.stat().st_mtime>=90 and time.monotonic()-getattr(self,'optional_last_turn',0)>=60
    if getattr(self,'optional_tick',None)==tick_started or (not aged and (writer_operations>=writer_limit or time.monotonic()-writer_started-cpu_turn_seconds>=writer_seconds)):
     self.response(request,'queued',reason='optional_background_budget',poll_after_seconds=30);continue
    row=next((r for r in owned if target_name(r)==request['target_id']),None)
    if not row or row.get('done') or row.get('finalization_error') or (row.get('external_explicit_agent') and request.get('agent_id')!=row_agent(row)):
     self.response(request,'optional_unavailable',reason='No active owned claim; continue normal workflow',claim_released=False);continue
    if now()>=datetime.fromisoformat(row['external_work_until'])-timedelta(seconds=60):
     self.response(request,'optional_unavailable',reason='Near work deadline; release normally instead of optional calls',claim_released=False);continue
    self.optional_tick=tick_started;self.optional_last_turn=time.monotonic();writer_operations+=1
    self.response(request,'executing',target_id=request['target_id']);save_trial()
    try:answer=features.optional.run(self.root,row,request,service,features)
    except (ValueError,OSError,KeyError,TypeError):answer=dict(state='optional_unavailable',reason='Optional validation/storage failed; ordinary work remains available',claim_released=False)
    state=answer.pop('state');self.response(request,state,target_id=request['target_id'],**answer)
   elif request['operation'] in ('submit','giveup','flag'):
    if request['operation']=='flag' and not features.flags_enabled(self.root):
     self.response(request,'refused',reason='Flag reporting disabled by owner. Claim remains active; use ordinary give_up_function with a blocker to release it.',claim_released=False);continue
    if request['operation']=='flag' and getattr(self,'optional_tick',None)==tick_started:
     self.response(request,'queued',reason='optional_background_budget',poll_after_seconds=30);continue
    if writer_operations>=writer_limit or (finished_this_tick and time.monotonic()-writer_started-cpu_turn_seconds>=writer_seconds):
     self.response(request,'queued',reason='writer_turn_budget',poll_after_seconds=5);continue
    row=next((r for r in owned if target_name(r)==request['target_id']),None)
    if row is None or row.get('done') or row.get('finalization_error'):
     self.response(request,'refused',reason='Not an active owned claim');continue
    if row.get('external_explicit_agent') and request.get('agent_id')!=row_agent(row):
     self.response(request,'refused',reason='Agent assignment mismatch');continue
    if now()>=datetime.fromisoformat(row['external_work_until']):
     self.response(request,'refused',reason='Worker deadline reached');continue
    # A service preflight is read-only. Validate ownership and address, not just
    # a stale local target ID, immediately before any finishing mutation.
    try:
     current=service('fnv.ps1','status')
    except Exception:
     self.response(request,'optional_unavailable' if request['operation']=='flag' else 'waiting_capacity',reason='Read-only service preflight unavailable');continue
    claim=next((c for c in current['open_claims'] if c['claim_id']==row['claim_id']),None)
    if not claim or not claim['this_key'] or claim['address'].lower()!=row['address'].lower():
     # The target identity is known. Quarantine this operation without
     # stopping unrelated claims when an old assignment has expired.
     self.response(request,'needs_reconciliation',target_id=request['target_id'],reason='Current service claim ownership/address changed');continue
    if request['operation']=='flag':
     self.optional_tick=tick_started
     if row.get('flag_reports'):
      self.response(request,'optional_unavailable',feature='flag',claim_released=False,reason='One fleet defect report per claim; continue working or release normally.');continue
     cooldown=self.root/'local/mcp/optional/flag-cooldown.json'
     if cooldown.exists() and now()<datetime.fromisoformat(read(cooldown)['retry_at_utc']):
      self.response(request,'optional_unavailable',feature='flag',claim_released=False,reason='Fleet report cooldown; continue work or release normally.',retry_at_utc=read(cooldown)['retry_at_utc']);continue
     save(cooldown,dict(retry_at_utc=(now()+timedelta(minutes=10)).isoformat(),request_id=request['request_id']))
     # Upstream now releases by default. Preserve this bridge's report-only
     # contract explicitly, and never report other workers' functions/units.
     payload=dict(claim_id=row['claim_id'],category=request['category'],note=request['note'],keep_claim=True,scope='function')
     self.response(request,'executing');save_trial();writer_operations+=1
     try:
      receipt=service('fnv.ps1','flag','-Json',json.dumps(payload))
      features.durable(Path(row['pack'])/('flag-receipt-'+request['request_id']+'.json'),dict(request_id=request['request_id'],claim_id=row['claim_id'],address=row['address'],payload=payload,response=receipt,utc=now().isoformat()))
     except Exception:
      self.response(request,'optional_unavailable',target_id=request['target_id'],claim_released=False,reason='Optional flag response unavailable; never replay. Continue ordinary work/release.');continue
     if receipt.get('optional_unavailable'):
      self.response(request,'optional_unavailable',target_id=request['target_id'],claim_released=False,feature='flag',reason=receipt.get('reason'),retry_at_utc=receipt.get('retry_at_utc'));continue
     row.setdefault('flag_reports',[]).append(dict(request_id=request['request_id'],category=request['category'],note=request['note'],receipt=receipt))
     save_trial();self.response(request,'flagged',target_id=request['target_id'],claim_released=False,receipt=receipt);continue
    if request['operation']=='submit' and not capacity(current):
     self.response(request,'waiting_capacity',reason='Account submission capacity reached');continue
    if request['operation']=='submit':
     pack=Path(row['pack']);candidate=(pack/'mcp_candidates'/identity(request['candidate_id'])/'candidate.cpp').resolve()
     check_path=candidate.parent/'check.json'
     check=read(check_path) if check_path.exists() else {}
     digest=hashlib.sha256(candidate.read_bytes()).hexdigest() if candidate.is_file() else None
     provenance=read(candidate.with_name('candidate.cpp.provenance.json')) if candidate.is_file() else {}
     if check.get('status')!='match' or digest!=request['source_sha256'] or check.get('source_sha256')!=digest or provenance.get('source_sha256')!=digest or provenance.get('model')!=row['external_model']:
      self.response(request,'refused',reason='A saved official MATCH with unchanged source hash and assignment model is required');continue
     report=dict(outcome='match',candidate=str(candidate),model=row['external_model'])
    else:
     report=dict(outcome='blocked',reason=request['reason'],model=row['external_model'])
     try:
      if request.get('checkpoint_id'):features.optional.saved_checkpoint(row,request['checkpoint_id'])
      best=features.best_source(row,request)
     except (OSError,ValueError,KeyError):self.response(request,'refused',reason='Best candidate hash, ownership, checker evidence or provenance invalid');continue
     if best:report['candidate']=best['candidate'];row['shared_best_source']={k:v for k,v in best.items() if k!='source'}

    self.response(request,'executing');save_trial()
    writer_operations+=1;finished_this_tick+=1
    self.record(row,report)
    if request['operation']=='giveup' and (best or request.get('checkpoint_id')):
     try:
      payload=dict(claim_id=row['claim_id'],reason=report['reason'],model=row['external_model'])
      if request.get('checkpoint_id'):payload['checkpoint_id']=request['checkpoint_id']
      elif best:payload['best_code']=best['source']
      receipt=service('fnv.ps1','giveup','-Json',json.dumps(payload))
      features.durable(Path(row['pack'])/('giveup-receipt-'+request['request_id']+'.json'),dict(claim_id=row['claim_id'],source_sha256=best['source_sha256'] if best else None,checkpoint_id=request.get('checkpoint_id'),response=receipt))
      row['released']=True
     except Exception:row['finalization_error']='Giveup response uncertain; reconcile without replay'
    else:finish(row,report)
    row.update(report=report,done=not row.get('finalization_error'),stage='quarantined' if row.get('finalization_error') else 'done')
    save_trial();self.publish(row,load)
    self.response(request,'needs_reconciliation' if row.get('finalization_error') else 'submitted' if row.get('submission') else 'released',target_id=request['target_id'],submission=row.get('submission'))
    # The row remains quarantined and its mutation is never replayed. Other
    # owned claims may continue through their unchanged official gates.
   else:self.response(request,'refused',reason='Unknown operation')
  self.prepare_web(trial,load,finish,save_trial)
  if load and (self.root/'local/cpu-sweep/control.json').exists():
   # Runtime lives on the coordinator's loader, surviving mailbox hot reloads.
   # Only compilation runs in threads; this tick remains the service writer.
   if not hasattr(load,'cpu_sweep_runtime'):
    load.cpu_sweep_runtime=load('cpu-sweep-bridge','_coordinator').Sweep(load,self.root)
    load.cpu_sweep_stamp=(self.root/'scripts/cpu-sweep-bridge.py').stat().st_mtime_ns
   stamp=(self.root/'scripts/cpu-sweep-bridge.py').stat().st_mtime_ns
   if stamp!=getattr(load,'cpu_sweep_stamp',None) and load.cpu_sweep_runtime.jobs:
    # A busy continuous sweep never reaches zero jobs. Upgrade coordinator
    # methods between turns while retaining the same executor and futures;
    # already-running read-only preparation finishes on its original method.
    previous=load.cpu_sweep_runtime
    updated=load('cpu-sweep-bridge','_coordinator_'+str(stamp))
    previous.__class__=updated.Sweep
    if previous.fast_service:previous.fast_service.close();previous.fast_service=None
    load.cpu_sweep_stamp=stamp
   if stamp!=getattr(load,'cpu_sweep_stamp',None) and not load.cpu_sweep_runtime.jobs:
    previous=load.cpu_sweep_runtime
    load.cpu_sweep_runtime=load('cpu-sweep-bridge','_coordinator_'+str(stamp)).Sweep(load,self.root)
    claim_operation=self.root/'local/cpu-sweep/claim-operation.json'
    # Known claim finalizations remain quarantined individually. An unresolved
    # claim request can hide a new identity and must still stop new CPU claims.
    load.cpu_sweep_runtime.uncertain=previous.uncertain and (not claim_operation.exists() or read(claim_operation).get('state')!='completed')
    if hasattr(previous,'close'):previous.close()
    else:previous.pool.shutdown(wait=False)
    load.cpu_sweep_stamp=stamp
   load.cpu_sweep_runtime.web_pending_probe=self.waiting_web
   load.cpu_sweep_runtime.web_requests_pending=self.waiting_web()
   load.cpu_sweep_runtime.tick(trial,status,service,finish,save_trial,stopping=stopping)
   self.uncertain=bool(self.unresolved_acquisitions or load.cpu_sweep_runtime.uncertain)
  if local_draining:self.pending_claims=True # inhibit only the main local refill
  active_count=len(capacity_claim_ids(rows,status))
  save(self.base/'worker-groups.json',dict(utc=now().isoformat(),groups=dashboard_groups(rows),account={k:status.get(k) for k in ('verified_matches','awaiting_verification','strikes_last_7_days','submissions_today')}))
  queue_counts=queued_claim_counts()
  save(self.base/'coordinator.json',dict(utc=now().isoformat(),state='draining' if stopping else 'running',uncertain_mutation=self.uncertain,service_pause=service_pause,
      max_live_claims=status['limits']['claims'],active_web_agents=sum(not r.get('done') for r in owned),
      available_claim_slots=max(0,status['limits']['claims']-active_count),pending_web_claims=queue_counts['web']>0,pending_mailbox_claims=self.pending_claims,
      pending_web_request_count=queue_counts['web'],pending_local_request_count=queue_counts['local_pool'],fast_claim_batches=dispatch_config.get('fast_claim_batches') is True,
      preparing_web=sum(not r.get('done') and r.get('stage') in ('waiting','preparing','web_preparing','web_packet_waiting') for r in owned),
      cpu_refill_policy="strict_web_first",cpu_reservation_batch_limit=4,web_preparation_slots=4,local_pool_preparation_slots=2,preparation_backlog_limit=64,claim_dispatch_per_tick=web_burst,writer_operation_limit=writer_limit,writer_budget_seconds=writer_seconds,writer_cpu_turns=cpu_turns,writer_cpu_seconds=round(cpu_turn_seconds,3),writer_operations=writer_operations,finished_this_tick=finished_this_tick,claimed_this_tick=int(claimed_this_tick),last_tick_seconds=round(time.monotonic()-tick_started,3)))
  if claimed_this_tick and active_count<status['limits']['claims'] and not local_draining and not self.waiting_web():
   # A pending web request received this cycle's first slot. Let the main
   # scheduler use remaining capacity too, so continuous web arrivals cannot
   # starve an owner-authorized local pool. Service capacity is checked again.
   self.pending_claims=False
  if local_draining and read(self.base.parent/'local-model-drain.json').get('restart_when_idle'):
   busy=any(r['arm']=='qwen' and not r.get('external_owner') and not r.get('done') and r['stage'] in ('working','preparing','recovered') for r in rows)
   busy=busy or bool(load and getattr(getattr(load,'cpu_sweep_runtime',None),'jobs',{}))
   if not busy:
    # We are between synchronous service mutations. Unwind the coordinator so
    # its finally block atomically saves claims and releases its process lock.
    save_trial()
    raise SystemExit(0)
