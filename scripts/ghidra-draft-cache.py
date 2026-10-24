"""Reuse only hash-verified analysis drafts for identical private inputs.

Never matching evidence or contribution source. A new claim keeps its own
paths, metadata, official checks, source hashes and submission gates.
"""
import hashlib,json,shutil,uuid
from pathlib import Path

def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def key(identity):
 required=('pack_metadata_sha256','image_sha256','ghidra_version','script_sha256','context_hashes','packet_signature')
 if any(k not in identity for k in required):raise ValueError('Incomplete draft identity')
 return hashlib.sha256(json.dumps({k:identity[k] for k in required},sort_keys=True,separators=(',',':')).encode()).hexdigest()
def atomic(p,v):
 p.parent.mkdir(parents=True,exist_ok=True);tmp=p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp');tmp.write_text(json.dumps(v),encoding='utf-8');tmp.replace(p)
def register(root,result_path):
 root=Path(root).resolve();result_path=Path(result_path).resolve()
 if not result_path.is_relative_to(root/'work'):raise ValueError('Draft outside private work')
 value=read(result_path)
 if value.get('outcome')!='draft':return False
 atomic(root/'local/ghidra/draft-cache'/f"{key(value['identity'])}.json",{'result':str(result_path)})
 return True
def restore(root,identity,folder):
 root=Path(root).resolve();folder=Path(folder).resolve()
 if not folder.is_relative_to(root/'work'):raise ValueError('Destination outside private work')
 index=root/'local/ghidra/draft-cache'/f'{key(identity)}.json'
 if not index.exists():return None
 try:
  source=Path(read(index)['result']).resolve()
  if not source.is_relative_to(root/'work'):return None
  old=read(source)
  if old.get('outcome')!='draft' or key(old['identity'])!=key(identity):return None
  draft=Path(old['draft']).resolve();analysis=Path(old['analysis']).resolve()
  if draft.parent!=source.parent or analysis.parent!=source.parent:return None
  if sha(draft)!=old['draft_sha256'] or sha(analysis)!=old['analysis_sha256']:return None
  if not read(analysis).get('decompile_completed'):return None
  folder.mkdir(parents=True,exist_ok=True)
  for src,dest in ((draft,folder/'draft.c'),(analysis,folder/'analysis.json')):
   if src!=dest:shutil.copyfile(src,dest)
  result=dict(old,identity=identity,pack=identity['pack'],draft=str(folder/'draft.c'),analysis=str(folder/'analysis.json'),cache_hit=True,shared_draft_cache_hit=True,reused_from_result=str(source),elapsed_seconds=0)
  atomic(folder/'result.json',result)
  return result
 except (OSError,ValueError,KeyError,TypeError):return None

if __name__=='__main__':
 import argparse,time
 p=argparse.ArgumentParser();p.add_argument('--prime',action='store_true');a=p.parse_args()
 if not a.prime:p.error('Use --prime for the finite private index build')
 root=Path(__file__).resolve().parents[1];t=time.monotonic();count=0;refused=0
 for result in (root/'work').glob('*/cpu_assist/ghidra/result.json'):
  try:count+=bool(register(root,result))
  except (OSError,ValueError,KeyError,TypeError):refused+=1
 print(json.dumps({'registered':count,'refused':refused,'seconds':round(time.monotonic()-t,3)}))
