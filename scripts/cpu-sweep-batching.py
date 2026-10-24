"""Bounded serialized CPU mutations; only the existing coordinator calls this.

No network threads or mutation retries. Durable per-claim receipts allow one
checkpoint for a group while retaining identities across interrupted responses.
"""
import hashlib,json,os,threading,time,uuid
from pathlib import Path
from datetime import datetime,timezone
from concurrent.futures import Future

def utc():return datetime.now(timezone.utc).isoformat()
def durable(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
 with temp.open('wb') as f:f.write(json.dumps(value,separators=(',',':')).encode());f.flush();os.fsync(f.fileno())
 for n in range(12):
  try:temp.replace(path);return
  except PermissionError:
   if n==11:raise
   time.sleep(.025*(n+1))

def limited(root):
 p=root/'local/service-limit.json'
 if not p.exists():return False
 d=json.loads(p.read_text(encoding='utf-8-sig'))
 return datetime.now(timezone.utc)<datetime.fromisoformat(d['retry_at_utc'].replace('Z','+00:00'))

def finish_many(sweep,pairs,save_trial):
 if threading.get_ident()!=sweep.fast_service.owner:raise RuntimeError('CPU returns require coordinator thread')
 for row,report in pairs:
  if report['outcome']=='match':raise ValueError('MATCH must use the existing official upload finisher')
  p=Path(row['pack']).resolve()
  if not p.is_relative_to((sweep.root/'work').resolve()) or p.name!=row['claim_id']:raise ValueError('CPU release identity mismatch')
  row.update(sweep_mutation='executing',report=report)
 save_trial() # every known identity is executing before the first mutation
 for n,(row,report) in enumerate(pairs):
  if limited(sweep.root):
   for deferred,_ in pairs[n:]:deferred.update(stage='cpu_return_waiting',sweep_mutation='deferred',done=False)
   break
  started=time.monotonic()
  try:
   payload=dict(claim_id=row['claim_id'],reason=report.get('reason','CPU did not obtain official MATCH')[:430],model=report['model'])
   import importlib.util
   spec=importlib.util.spec_from_file_location('_cpu_contributions',Path(__file__).with_name('contribution-tools.py'));helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
   try:best=helper.best_source(row)
   except (OSError,ValueError):best=None
   if best:payload['best_code']=best['source'];row['shared_best_source']={k:v for k,v in best.items() if k!='source'}
   reply=sweep.fast_service('fnv.ps1','giveup','-Json',json.dumps(payload))
   durable(Path(row['pack'])/'cpu-giveup-receipt.json',dict(claim_id=row['claim_id'],address=row['address'],utc=utc(),response=reply))
   row.update(released=True,done=True,stage='done',sweep_mutation='completed')
  except (RuntimeError,OSError,ValueError):
   row.update(done=False,stage='quarantined',sweep_mutation='uncertain',finalization_error='Known CPU return uncertain; inspect receipt/status, never replay')
  row.update(cpu_sweep_finished_utc=utc(),cpu_sweep_finalize_seconds=time.monotonic()-started)
 save_trial()

def reserve_many(sweep,trial,count,save_trial):
 if threading.get_ident()!=sweep.fast_service.owner:raise RuntimeError('CPU reservations require coordinator thread')
 root=sweep.root/'local/cpu-sweep/claim-batches'/uuid.uuid4().hex;root.mkdir(parents=True)
 manifest=root/'requests.json';requests=[dict(request_id=uuid.uuid4().hex,band='<=255') for _ in range(count)]
 durable(manifest,dict(requests=requests));operation=sweep.root/'local/cpu-sweep/claim-operation.json'
 durable(operation,dict(state='executing',batch=str(manifest),utc=utc()));save_trial()
 start=time.monotonic();result=sweep.fast_service.reserve_batch(manifest)
 existing={r['claim_id'] for r in trial['rows']};reserved=set()|{r['address'].lower() for r in trial['rows'] if not r.get('done') and r.get('address')}
 added=[]
 for item in result['results']:
  if item.get('state')!='reserved':continue
  claim=item['claim'];p=Path(claim['pack']).resolve()
  if claim['claim_id'] in existing:continue
  if not p.is_relative_to((sweep.root/'work').resolve()) or p.name!=claim['claim_id']:raise ValueError('Batch claim pack identity mismatch')
  row=dict(claim);row.update(arm='qwen',number=len(trial['rows'])+1,bucket='cpu_sweep',stage='cpu_sweeping',done=False,cpu_sweep=True,external_owner='cpu_sweep',model_arm='cpu_sweep',worker='cpu_sweep_'+claim['claim_id'],cpu_batch_reservation_seconds=time.monotonic()-start)
  duplicate=claim['address'].lower() in reserved
  trial['rows'].append(row);existing.add(claim['claim_id']);reserved.add(claim['address'].lower());added.append((row,duplicate))
 save_trial() # identities/rows durable before starting compilation workers
 state='uncertain' if result['uncertain'] else 'completed'
 durable(operation,dict(state=state,batch=str(manifest),claims=[r['claim_id'] for r,_ in added],utc=utc()))
 if result['uncertain']:sweep.uncertain=True
 for row,duplicate in added:
  if duplicate:
   f=Future();f.set_result(dict(cpu=dict(outcome='unsupported',reason='Function already reserved for another worker',checker_attempts=0,llm_calls=0)))
  else:f=sweep.pool.submit(sweep.prepare,row)
  sweep.jobs[f]=row
 return len(added)

def reconcile_marker(sweep,trial,save_trial):
 """Receipt-only restart recovery, without replaying an interrupted batch."""
 p=sweep.root/'local/cpu-sweep/claim-operation.json'
 if not p.exists():return
 op=json.loads(p.read_text(encoding='utf-8-sig'))
 if op.get('state')not in('executing','uncertain') or not op.get('batch'):return
 manifest=Path(op['batch']).resolve()
 if not manifest.is_relative_to((sweep.root/'local/cpu-sweep/claim-batches').resolve()):raise ValueError('Invalid batch reconciliation path')
 try:phase=json.loads((manifest.parent/'started.json').read_text()).get('phase')
 except (OSError,ValueError):phase=None
 if phase=='before_status':
  durable(p,dict(state='completed',batch=str(manifest),reconciled_by='durable preflight phase: no claim attempted',utc=utc()));sweep.uncertain=False;return
 requests=json.loads(manifest.read_text())['requests'];known={r['claim_id'] for r in trial['rows']};changed=False
 for item in requests:
  try:receipt=json.loads((manifest.parent/(item['request_id']+'.json')).read_text(encoding='utf-8-sig'))
  except (OSError,ValueError):
   if changed:save_trial()
   sweep.uncertain=True;return
  if receipt.get('request_id')!=item['request_id'] or receipt.get('state')not in('reserved','not_attempted'):
   if changed:save_trial()
   sweep.uncertain=True;return
  if receipt['state']=='reserved':
   c=receipt['claim']
   if c['claim_id']not in known:
    expired=datetime.fromisoformat(c['expires'].replace('Z','+00:00'))<=datetime.now(timezone.utc)
    pack=Path(c['pack']).resolve()
    if not pack.is_relative_to((sweep.root/'work').resolve()) or pack.name!=c['claim_id']:raise ValueError('Recovered CPU claim identity mismatch')
    row=dict(c);row.update(arm='qwen',number=len(trial['rows'])+1,bucket='cpu_sweep',done=False,cpu_sweep=True,external_owner='cpu_sweep',model_arm='cpu_sweep',worker='cpu_sweep_'+c['claim_id'],stage='quarantined' if expired else 'cpu_sweeping')
    if expired:row['finalization_error']='Recovered expired batch identity; historical outcome unknown'
    trial['rows'].append(row);known.add(c['claim_id']);changed=True
 if changed:save_trial()
 durable(p,dict(state='completed',batch=str(manifest),reconciled_by='saved per-claim receipts; no mutation replay',utc=utc()))
 sweep.uncertain=False

def reconcile_expired_unknown(sweep,trial,status,save_trial):
 """Close a lost acquisition only after its maximum live lifetime +60seconds.

 The existing coordinator performs one fresh status read. Every owned live
 identity must already be in the durable trial. Historical success remains
 UNKNOWN, original receipts stay unchanged, and the batch is never replayed.
 """
 if threading.get_ident()!=sweep.fast_service.owner:raise RuntimeError('Only coordinator may reconcile CPU acquisition')
 operation=sweep.root/'local/cpu-sweep/claim-operation.json'
 try:
  original=operation.read_bytes();op=json.loads(original)
  if op.get('state')not in ('uncertain','executing') or not op.get('batch'):return False
  manifest=Path(op['batch']).resolve()
  if not manifest.is_relative_to((sweep.root/'local/cpu-sweep/claim-batches').resolve()):return False
  ended=datetime.fromisoformat(op['utc'].replace('Z','+00:00'))
  maximum=max(3600000,int(status['limits']['claimMs']))
  if (datetime.now(timezone.utc)-ended).total_seconds()<maximum/1000+60:return False
  if limited(sweep.root):return False
  requests=json.loads(manifest.read_text())['requests'];receipts={}
  known={r['claim_id'] for r in trial['rows']}
  unknown=False
  for item in requests:
   path=manifest.parent/(item['request_id']+'.json');body=path.read_bytes();receipt=json.loads(body)
   if receipt.get('request_id')!=item['request_id']:return False
   if receipt.get('state')=='reserved':
    if (receipt.get('claim')or{}).get('claim_id')not in known:return False
   elif receipt.get('state')=='uncertain':
    if receipt.get('claim'):return False
    unknown=True
   elif receipt.get('state')!='not_attempted':return False
   receipts[path.name]=dict(sha256=hashlib.sha256(body).hexdigest(),state=receipt['state'])
  if not unknown:return False
  fresh=sweep.fast_service('fnv.ps1','status')
  maximum=max(maximum,int(fresh['limits']['claimMs']))
  checked=datetime.now(timezone.utc)
  if (checked-ended).total_seconds()<maximum/1000+60:return False
  if any(c.get('this_key') and c['claim_id']not in known for c in fresh['open_claims']):return False
  if operation.read_bytes()!=original:return False
  proof=dict(kind='expired_cpu_acquisition_no_live_identity',checked_utc=checked.isoformat(),
   maximum_claim_ms=maximum,operation_sha256=hashlib.sha256(original).hexdigest(),
   manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),receipts=receipts,
   status=fresh,historical_outcome='unknown',mutations_replayed=0)
  proof_digest=hashlib.sha256(json.dumps(proof,separators=(',',':')).encode()).hexdigest()
  proof_path=manifest.parent/('expired-identity-proof-'+proof_digest+'.json');durable(proof_path,proof)
  durable(manifest.parent/'expired-identity-proof.json',proof) # Compatibility view; audit references immutable proof.
  audits=trial.setdefault('cpu_acquisition_reconciliations',[])
  audit=next((a for a in audits if a.get('batch')==str(manifest)),None)
  if audit is None:audit=dict(batch=str(manifest));audits.append(audit)
  audit.update(proof_path=str(proof_path),proof_sha256=hashlib.sha256(proof_path.read_bytes()).hexdigest(),utc=checked.isoformat(),historical_outcome='unknown',mutations_replayed=0)
  save_trial()
  durable(operation,dict(state='completed',batch=str(manifest),proof_path=str(proof_path),historical_outcome='unknown',reconciled_by='maximum claim lifetime elapsed; fresh status accounts for every owned identity; never replayed',utc=checked.isoformat()))
  status.clear();status.update(fresh);sweep.uncertain=False
  return True
 except (OSError,ValueError,KeyError,TypeError,RuntimeError):return False
