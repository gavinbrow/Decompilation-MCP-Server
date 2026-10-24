"""Atomic JSON plus lossless content-addressed coordinator checkpoints.

HEAD is authoritative when present. Every row, including executing mutations,
is durable before HEAD changes. trial.json remains a periodic compatibility
export; recovery must use load_checkpoint(), never that potentially older copy.
"""
import json,time,uuid,hashlib,threading,sys,types,os,re,copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
try:
 import orjson
except ImportError:
 orjson=None

def encode(value):
 if orjson is not None:return orjson.dumps(value,option=orjson.OPT_NON_STR_KEYS)
 return json.dumps(value,separators=(',',':')).encode('utf-8')

def save(path,value):
 path=Path(path);temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
 temporary.write_bytes(encode(value))
 for attempt in range(12):
  try:temporary.replace(path);return
  except PermissionError:
   if attempt==11:raise
   time.sleep(.05*(attempt+1))

def store_path(path):return Path(path).with_name(Path(path).name+'.checkpoints')

def digest(data):return hashlib.sha256(data).hexdigest()

def atomic_bytes(path,data,durable=False):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
 try:
  with temporary.open('wb') as stream:
   stream.write(data)
   if durable:stream.flush();os.fsync(stream.fileno())
  for attempt in range(12):
   try:temporary.replace(path);return
   except PermissionError:
    if attempt==11:raise
    time.sleep(.05*(attempt+1))
 finally:temporary.unlink(missing_ok=True)

def blob_path(root,sha):
 if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha):raise ValueError('Invalid checkpoint digest')
 return root/'objects'/sha[:2]/(sha+'.json')

def read_blob(root,sha):
 body=blob_path(root,sha).read_bytes()
 if digest(body)!=sha:raise ValueError('Checkpoint object hash mismatch')
 return json.loads(body)

def load_checkpoint(path):
 """Read the last complete commit. Corrupt/missing objects fail closed."""
 path=Path(path);root=store_path(path);head=root/'HEAD.json'
 if not head.exists():return json.loads(path.read_text(encoding='utf-8-sig'))
 pointer=json.loads(head.read_bytes());manifest=read_blob(root,pointer['manifest'])
 if manifest.get('format')!=1 or manifest.get('sequence')!=pointer.get('sequence'):raise ValueError('Invalid checkpoint manifest')
 metadata=read_blob(root,manifest['metadata_hash']) if 'metadata_hash' in manifest else manifest['metadata']
 if not isinstance(metadata,dict) or 'rows' in metadata:raise ValueError('Invalid checkpoint metadata')
 hashes_all=[]
 for index_hash in manifest['indexes']:
  hashes=read_blob(root,index_hash)
  if not isinstance(hashes,list) or len(hashes)>64:raise ValueError('Invalid checkpoint row index')
  hashes_all.extend(hashes)
 def row_for(sha):
  row=read_blob(root,sha)
  if not isinstance(row,dict):raise ValueError('Invalid checkpoint row')
  return row
 if len(hashes_all)>512:
  with ThreadPoolExecutor(max_workers=8,thread_name_prefix='checkpoint-read') as pool:rows=list(pool.map(row_for,hashes_all))
 else:rows=[row_for(sha) for sha in hashes_all]
 if len(rows)!=manifest['row_count']:raise ValueError('Checkpoint row count mismatch')
 return dict(metadata,rows=rows)

class CheckpointStore:
 def __init__(self,path,mirror_seconds=30):
  self.path=Path(path);self.root=store_path(path);self.root.mkdir(parents=True,exist_ok=True)
  self.known={p.stem for p in (self.root/'objects').glob('*/*.json')}
  self.sequence=0;head=self.root/'HEAD.json'
  if head.exists():self.sequence=json.loads(head.read_bytes())['sequence']
  self.lock=threading.RLock();self.export_lock=threading.Lock();self.mirror_seconds=mirror_seconds
  self.latest=None;self.mirrored=0;self.mirror_error=None;self.last_mirror=0
  self.wake=threading.Event();self.thread=None;self.written=0
  self.closed=threading.Event()
 def put(self,body):
  sha=digest(body)
  if sha not in self.known:
   atomic_bytes(blob_path(self.root,sha),body,True);self.known.add(sha);self.written+=len(body)
  return sha
 def seed(self,value):
  """Stage immutable objects only; never publish HEAD or mutate the service."""
  for row in value['rows']:self.put(encode(row))
  return len(self.known)
 def commit(self,value):
  started=time.monotonic()
  with self.lock:
   before=self.written;previous=getattr(self,'row_cache',[]);row_cache=[];changed_rows=0
   for n,row in enumerate(value['rows']):
    # Deep equality against an independent snapshot detects nested mutations.
    # Unchanged immutable strings compare by identity; no history re-encoding.
    if n<len(previous) and previous[n][0]==row:entry=previous[n]
    else:
     frozen=copy.deepcopy(row);body=encode(frozen);entry=(frozen,body,self.put(body));changed_rows+=1
    row_cache.append(entry)
   row_bytes=tuple(entry[1] for entry in row_cache);hashes=[entry[2] for entry in row_cache]
   indexes=[self.put(encode(hashes[n:n+64])) for n in range(0,len(hashes),64)]
   metadata={k:v for k,v in value.items() if k!='rows'};metadata_bytes=encode(metadata)
   sequence=self.sequence+1
   metadata_hash=self.put(metadata_bytes)
   if changed_rows==0 and len(row_cache)==len(previous) and metadata_hash==getattr(self,'last_metadata_hash',None):
    profile=dict(sequence=self.sequence,rows=len(hashes),changed_rows=0,logical_bytes=sum(map(len,row_bytes))+len(metadata_bytes),written_bytes=0,seconds=round(time.monotonic()-started,6),unchanged=True,compatibility_sequence=self.mirrored,compatibility_error=self.mirror_error)
    try:save(self.root/'progress.json',profile)
    except OSError:pass
    return profile
   manifest=dict(format=1,sequence=sequence,metadata_hash=metadata_hash,row_count=len(hashes),indexes=indexes)
   manifest_hash=self.put(encode(manifest))
   pointer=encode(dict(manifest=manifest_hash,sequence=sequence))
   # Nothing after this atomic commit is required to recover the current state.
   atomic_bytes(self.root/'HEAD.json',pointer,True);self.written+=len(pointer);self.sequence=sequence
   self.row_cache=row_cache;self.last_metadata_hash=metadata_hash
   self.latest=(sequence,metadata_bytes,row_bytes)
   profile=dict(sequence=sequence,rows=len(hashes),changed_rows=changed_rows,logical_bytes=sum(map(len,row_bytes))+len(metadata_bytes),written_bytes=self.written-before,seconds=round(time.monotonic()-started,6),compatibility_sequence=self.mirrored,compatibility_error=self.mirror_error)
   try:save(self.root/'progress.json',profile)
   except OSError:pass
   if self.thread is None:
    self.thread=threading.Thread(target=self.mirror_loop,daemon=True,name='FNV-checkpoint-export');self.thread.start()
   self.wake.set()
   return profile
 def export_latest(self):
  with self.export_lock:self._export_latest()
 def _export_latest(self):
  with self.lock:latest=self.latest
  if latest is None:return
  sequence,metadata,rows=latest
  if sequence<=self.mirrored:return
  # Immutable encoded buffers keep the export coherent while newer commits run.
  body=(metadata[:-1]+b',"rows":[' if metadata!=b'{}' else b'{"rows":[')+b','.join(rows)+b']}'
  atomic_bytes(self.path,body)
  with self.lock:self.mirrored=max(self.mirrored,sequence);self.mirror_error=None;self.last_mirror=time.monotonic()
 def mirror_loop(self):
  while not self.closed.is_set():
   self.wake.wait(self.mirror_seconds);self.wake.clear()
   if self.closed.is_set():return
   delay=self.mirror_seconds-(time.monotonic()-self.last_mirror)
   if delay>0 and self.closed.wait(delay):return
   try:self.export_latest()
   except Exception as exc:
    self.mirror_error=type(exc).__name__;self.last_mirror=time.monotonic()
   # Telemetry/export failures never undo HEAD or interrupt service mutations.
 def close(self):
  self.closed.set();self.wake.set()
  if self.thread:self.thread.join(10)

# The bridge and CPU component load this file under different module names.
# They must share one store/lock/exporter in the single coordinator process.
_runtime=sys.modules.setdefault('_fnv_checkpoint_shared_runtime',types.ModuleType('_fnv_checkpoint_shared_runtime'))
if not hasattr(_runtime,'stores'):_runtime.stores={};_runtime.lock=threading.Lock()
def checkpoint(path,value):
 key=str(Path(path).resolve())
 with _runtime.lock:
  if key not in _runtime.stores:_runtime.stores[key]=CheckpointStore(key)
  store=_runtime.stores[key]
  if store.__class__ is not CheckpointStore:
   # Same single writer, between commits; retain buffers, locks and exporter.
   with store.lock:store.__class__=CheckpointStore
 return store.commit(value)
