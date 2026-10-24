"""Finite local preparation/finishing pipeline alongside coordinator-owned agents.

Never starts models or obtains/releases/submits claims. Reports remain private.
"""
import argparse
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/'scripts'/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def read(path): return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(path,value):
    path=Path(path).resolve()
    if not any(path.is_relative_to(ROOT/p) for p in ('work','local')):
        raise ValueError('Reports must remain private under local/ or work/')
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    temporary.write_text(json.dumps(value,indent=2));temporary.replace(path)

def prepare(pack,ghidra='auto',cpu_check=False,seconds=120,screening=None):
    """Prepare a handoff; seconds bounds Ghidra, generators own separate budgets."""
    if ghidra not in ('auto','on','off') or not 30<=seconds<=600:
        raise ValueError('Invalid preparation mode or budget')
    assist=load('cpu-assist');pack=assist.pack_path(pack)
    start=time.monotonic(); metadata_hash=sha(pack/'pack.json')
    output=pack/'cpu_assist';bundle_file=output/'handoff.json'
    # Always preserve evidence before attempting any whole-function generator.
    handoff=assist.bundle(pack,bundle_file) if screening is None else assist.bundle(pack,bundle_file,screening=screening)
    result=dict(version=1,claim_id=pack.name,pack=str(pack),pack_metadata_sha256=metadata_hash,
                handoff=str(bundle_file),partial=handoff.get('partial_analysis',handoff.get('partial')),
                screening=handoff['screening'],cpu_result=None,ghidra=None,
                source_authorship='Agent must record actual model/tools when returning source',
                confirmed_match=False,upload_authorized=False,service_calls=0,llm_calls=0)
    if cpu_check and handoff['screening']['supported']:
        # The existing full-function generators keep their own bounded budgets.
        cpu_result=assist.load_cpu().solve(pack,'assist_cpu',max_size=255)
        result['cpu_result']=cpu_result
        # Rechecked again by the normal coordinator before any future upload.
        result['confirmed_match']=cpu_result.get('outcome')=='match'
        handoff=assist.bundle(pack,bundle_file)
    families=ROOT/'local/benchmark/assist-pipeline/families.json'
    result['families']=load('function-families').suggest(pack,families) if families.is_file() else dict(suggestions=[],reason='Build catalog first')
    if ghidra!='off':
        try:
            engine=load('ghidra-prep'); runtime=engine.discover()
            available=bool(runtime.get('ready',runtime.get('available',False)))
            # Explicit on must attempt and report the actual dependency error.
            if ghidra=='on' or available: result['ghidra']=engine.prepare(pack,seconds=seconds)
            else: result['ghidra']=dict(outcome='unavailable',dependencies=runtime)
        except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error:
            result['ghidra']=dict(outcome='blocked',reason=str(error)[:500])
    else: result['ghidra']=dict(outcome='disabled')
    if sha(pack/'pack.json')!=metadata_hash: raise ValueError('Pack metadata changed during preparation')
    # Everything the model needs is reachable from one hash-bound JSON handoff.
    handoff['family_suggestions']=result['families']
    handoff['ghidra']=result['ghidra']
    handoff['workflow']=['Read partial observations and unknowns; snippets are not validated source.',
                         'Inspect source neighborhood, headers and any Ghidra draft.',
                         'Write complete readable C++ inside this original pack with truthful provenance.',
                         'Return best source to cpu-finish for bounded official finishing.',
                         'Coordinator alone validates live claim and submits a fresh official MATCH.']
    assist.save(bundle_file,handoff)
    result.update(elapsed_seconds=time.monotonic()-start,utc=datetime.now(timezone.utc).isoformat())
    save(output/'pipeline.json',result)
    return result

def selected_packs(manifest,limit):
    value=read(manifest)
    rows=value if isinstance(value,list) else value.get('rows',value.get('results',[]))
    if not isinstance(rows,list): raise ValueError('Expected rows/results list in saved manifest')
    packs=[];seen=set(); assist=load('cpu-assist')
    for row in rows:
        if not isinstance(row,dict): continue
        path=row.get('pack') or (str(ROOT/'work'/row['claim_id']) if row.get('claim_id') else None)
        if not path: continue
        pack=assist.pack_path(path); meta=read(pack/'pack.json')
        address=int(meta['address'],16)
        if address in seen: continue
        seen.add(address);packs.append(pack)
        if len(packs)>=limit: break
    return packs

def batch(manifest,limit=20,jobs=2,ghidra='off',cpu_check=False,output=None):
    if not 1<=limit<=1000 or not 1<=jobs<=4: raise ValueError('Batch limit 1..1000 and jobs1..4')
    if ghidra!='off' and jobs!=1: raise ValueError('Ghidra project uses one preparation at a time; select --jobs1')
    packs=selected_packs(manifest,limit)
    # Load the small existing generator modules before concurrent reads.
    # CPU checking can use up to four internal compiler jobs per preparation.
    if cpu_check and jobs>2: raise ValueError('CPU-check preparation supports at most2 outer jobs (8 compilers)')
    started=time.monotonic()
    def job(pack):
        try:return prepare(pack,ghidra,cpu_check)
        except Exception as error:return dict(pack=str(pack),outcome='error',reason=str(error)[:500])
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool: rows=list(pool.map(job,packs))
    result=dict(version=1,utc=datetime.now(timezone.utc).isoformat(),manifest=str(Path(manifest).resolve()),
                functions=len(rows),errors=sum(r.get('outcome')=='error' for r in rows),
                confirmed_matches=sum(bool(r.get('confirmed_match')) for r in rows),
                elapsed_seconds=time.monotonic()-started,rows=rows,service_calls=0,llm_calls=0,uploaded=0,
                note='Local saved-function development. Partial observations are not full matches; no model control arm.')
    save(output or ROOT/'local/benchmark/assist-pipeline/batch.json',result)
    return result

def doctor():
    checker=ROOT/'tools/fnvcheck/fnvcheck/fnvcheck.py'
    help_run=subprocess.run([sys.executable,str(checker),'--help'],capture_output=True,text=True,timeout=20)
    ghidra=load('ghidra-prep').discover()
    try: import z3; z3_ready=True
    except ImportError: z3_ready=False
    value=dict(checker_solve_slots='--solve-slots' in help_run.stdout,checker_permute='--permute' in help_run.stdout,
               ghidra=ghidra,z3=z3_ready,cuda_python=sys.executable,
               family_catalog=(ROOT/'local/benchmark/assist-pipeline/families.json').is_file(),
               models_started=False,claims_created=0)
    save(ROOT/'local/benchmark/assist-pipeline/doctor.json',value);return value

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('prepare');p.add_argument('--pack',type=Path,required=True);p.add_argument('--ghidra',choices=['auto','on','off'],default='auto');p.add_argument('--cpu-check',action='store_true');p.add_argument('--seconds',type=int,default=120,help='Ghidra stage budget; optional CPU generators retain their separate existing bounds')
    p=sub.add_parser('batch');p.add_argument('--manifest',type=Path,required=True);p.add_argument('--limit',type=int,default=20);p.add_argument('--jobs',type=int,default=2);p.add_argument('--ghidra',choices=['auto','on','off'],default='off');p.add_argument('--cpu-check',action='store_true');p.add_argument('--output',type=Path)
    p=sub.add_parser('catalog');p.add_argument('--limit',type=int,default=1000)
    sub.add_parser('doctor')
    p=sub.add_parser('finish');p.add_argument('--pack',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True);p.add_argument('--model',required=True);p.add_argument('--checks',type=int,default=48);p.add_argument('--jobs',type=int,default=4);p.add_argument('--seconds',type=int,default=180);p.add_argument('--engine',choices=['local','upstream','hybrid'],default='hybrid')
    args=parser.parse_args(); data=vars(args);command=data.pop('command')
    if command=='prepare': result=prepare(**data)
    elif command=='batch': result=batch(**data)
    elif command=='finish': result=load('cpu-finish').search(**data)
    elif command=='doctor': result=doctor()
    else:
        result=load('function-families').build(**data);result={k:v for k,v in result.items() if k!='families'}
    if command=='batch': result={k:v for k,v in result.items() if k!='rows'}
    if command=='finish':
        result={k:result.get(k) for k in ('claim_id','outcome','confirmed_match','attempted','official_checks','cache_hits','elapsed_seconds','best','provenance','upload_authorized')}
        result['report']=str(Path(args.pack).resolve()/'cpu_finish/latest.json')
    if command=='prepare':
        result=dict(claim_id=result['claim_id'],handoff=result['handoff'],report=str(Path(args.pack).resolve()/'cpu_assist/pipeline.json'),
                    fragment_count=(result['partial'] or {}).get('fragment_count',0),
                    family_suggestions=len(result['families'].get('suggestions',[])),
                    ghidra=result['ghidra'],confirmed_match=result['confirmed_match'],
                    elapsed_seconds=result['elapsed_seconds'],upload_authorized=False)
    print(json.dumps(result,indent=2))
    return 1 if result.get('errors') else 0

if __name__=='__main__': raise SystemExit(main())
