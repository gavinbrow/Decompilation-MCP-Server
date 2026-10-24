"""Serialized helper transport for the existing coordinator's CPU sweep.

No autonomous writes, background mutation threads or mutation retries.
"""
from concurrent.futures import ThreadPoolExecutor,TimeoutError as FutureTimeout
from datetime import datetime,timezone
from pathlib import Path
import json,os,shutil,subprocess,threading,time,uuid

class Transport:
 def __init__(self,root):self.root=Path(root);self.proc=None;self.lock=threading.Lock();self.reader=ThreadPoolExecutor(max_workers=1)
 def start(self):
  self.proc=subprocess.Popen([shutil.which('pwsh.exe') or 'powershell.exe','-NoProfile','-File',str(self.root/'scripts/fnv-service-session.ps1')],cwd=self.root,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,encoding='utf-8',creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
 def close(self):
  if self.proc:
   self.terminate()
  self.reader.shutdown(wait=False,cancel_futures=True)
 def terminate(self):
  if os.name=='nt':subprocess.run(['taskkill','/PID',str(self.proc.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  else:self.proc.kill()
  self.proc.wait();self.proc=None
 def call(self,script,*args):
  params={};args=list(args)
  if script=='fnv.ps1':params['Command']=args.pop(0)
  while args:
   key=args.pop(0)
   if not key.startswith('-') or not args:raise ValueError('Invalid helper arguments')
   params[key[1:]]=args.pop(0)
  with self.lock:
   if self.proc is None or self.proc.poll() is not None:self.start()
   identity=uuid.uuid4().hex
   try:
    self.proc.stdin.write(json.dumps(dict(id=identity,script=script,parameters=params))+'\n');self.proc.stdin.flush()
    line=self.reader.submit(self.proc.stdout.readline).result(timeout=180)
    value=json.loads(line.lstrip('\ufeff'))
   except (OSError,ValueError,FutureTimeout):
    self.terminate()
    raise RuntimeError('Helper response uncertain; never replay operation') from None
   if value.get('id')!=identity or not value.get('ok'):raise RuntimeError('Helper refused/failed; reconcile before any mutation retry')
   return value['value']

class Service:
 def __init__(self,root):self.root=Path(root);self.transport=Transport(root);self.owner=threading.get_ident()
 def close(self):self.transport.close()
 def reserve_batch(self,request_file):
  if threading.get_ident()!=self.owner:raise RuntimeError('Only coordinator may reserve CPU batch')
  request_file=Path(request_file).resolve()
  if not request_file.is_relative_to((self.root/'local/cpu-sweep/claim-batches').resolve()):raise ValueError('Batch outside CPU private journal')
  manifest=json.loads(request_file.read_text());requests=manifest['requests']
  if not 1<=len(requests)<=16:raise ValueError('CPU batch size must be1..16')
  refused=False
  try:self.transport.call('cpu-claim-batch-reserve.ps1','-RequestsFile',str(request_file))
  except RuntimeError:refused=True
  results=[];uncertain=False
  if refused:
   try:phase=json.loads((request_file.parent/'started.json').read_text()).get('phase')
   except (OSError,ValueError):phase=None
   if phase=='before_status':
    return dict(results=[dict(request_id=i['request_id'],state='not_attempted') for i in requests],uncertain=False,helper_failed=True,preflight_refused=True)
  for item in requests:
   receipt=request_file.parent/(item['request_id']+'.json')
   try:result=json.loads(receipt.read_text(encoding='utf-8-sig'))
   except (OSError,ValueError):result=dict(request_id=item['request_id'],state='uncertain')
   if result.get('request_id')!=item['request_id'] or result.get('state')not in('reserved','not_attempted'):
    uncertain=True
   elif result['state']=='reserved':
    c=result.get('claim',{})
    if not all(c.get(k) for k in ('claim_id','symbol','address','size','expires','pack')):uncertain=True;continue
   results.append(result)
  return dict(results=results,uncertain=uncertain,helper_failed=refused)
 def __call__(self,script,*args):
  if threading.get_ident()!=self.owner:raise RuntimeError('Only the coordinator thread may use this service transport')
  if script not in ('claim-pack.ps1','claim-reserve.ps1','fnv.ps1'):raise ValueError('Unsupported CPU helper')
  if script=='fnv.ps1' and args[0] not in ('status','giveup'):raise ValueError('Unsupported CPU API operation')
  mutation=script in ('claim-pack.ps1','claim-reserve.ps1') or args[0]=='giveup'
  # Reserve helper already performs a fresh capacity/status preflight. Save
  # that exact snapshot before its mutation instead of fetching status twice.
  before_path=None
  if script=='claim-reserve.ps1':
   before_path=self.root/'local/cpu-sweep/reservations'/(uuid.uuid4().hex+'.json')
   before_path.parent.mkdir(parents=True,exist_ok=True)
   args=tuple(args)+('-BeforeStatusFile',str(before_path))
  before=self.transport.call('fnv.ps1','status') if mutation and script=='claim-pack.ps1' else None
  try:return self.transport.call(script,*args)
  except RuntimeError:
   limit=self.root/'local/service-limit.json'
   if limit.exists() and datetime.now(timezone.utc)<datetime.fromisoformat(json.loads(limit.read_text(encoding='utf-8-sig'))['retry_at_utc'].replace('Z','+00:00')):raise
   after=None
   for delay in (3,10,30):
    time.sleep(delay)
    try:after=self.transport.call('fnv.ps1','status');break
    except RuntimeError:pass
   if after is None:raise RuntimeError('Service unavailable; mutation retained for reconciliation')
   if not mutation:return after
   if script in ('claim-pack.ps1','claim-reserve.ps1'):
    if before_path:
     try:before=json.loads(before_path.read_text(encoding='utf-8-sig'))
     except (OSError,ValueError):raise RuntimeError('Missing durable pre-mutation status; reconcile without replay')
    old={c['claim_id'] for c in before['open_claims']}
    added=[c for c in after['open_claims'] if c['claim_id'] not in old and c['this_key']]
    if len(added)==1:
     claim=added[0];pack=self.root/'work'/claim['claim_id'];pack.mkdir(exist_ok=True)
     if script=='claim-reserve.ps1':
      if not all(claim.get(k) for k in ('symbol','address','size','expires')):raise RuntimeError('Reserved claim identity incomplete; reconcile without replay')
      (pack/'claim-state.json').write_text(json.dumps(claim))
      return dict(claim,pack=str(pack))
     packet=self.transport.call('fnv.ps1','packet','-Json',json.dumps({'claim_id':claim['claim_id']}))
     (pack/'packet.json').write_text(json.dumps(packet));(pack/'claim-state.json').write_text(json.dumps(claim))
     self.transport.call('download-pack.ps1','-Pack',str(pack))
     meta=json.loads((pack/'pack.json').read_text(encoding='utf-8-sig'))
     return dict(claim,pack=str(pack),symbol=meta['symbol'],size=meta['size'])
   else:
    identity=json.loads(args[-1])['claim_id']
    if identity not in {c['claim_id'] for c in after['open_claims']}:return {'reconciled':True}
   raise RuntimeError('Uncertain service operation; stopped without replay')
