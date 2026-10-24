"""CPU-only sweep screening. No service/model calls or claims in this module.

Unsupported functions get a concise reason instead of expensive agent handoffs.
Supported functions retain the existing bounded compiler/search/checker path.
"""
import hashlib,importlib.util,json,threading,time,uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
LOCAL=threading.local()

def generator():
    files=[ROOT/'scripts'/name for name in ('cpu-template-worker.py','small-wrapper-patterns.py','call-patterns.py','vector-copy-patterns.py','integer-search.py','matched-knowledge.py')]
    files.append(ROOT/'local/benchmark/corpus-expansion/knowledge.json')
    stamp=tuple((str(p),p.stat().st_mtime_ns,p.stat().st_size) for p in files if p.is_file())
    if getattr(LOCAL,'stamp',None)!=stamp:
        spec=importlib.util.spec_from_file_location('cpu_fast_generator_'+uuid.uuid4().hex,ROOT/'scripts/cpu-template-worker.py')
        core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
        LOCAL.core=core;LOCAL.stamp=stamp
    return LOCAL.core

def preflight(row,core=None):
    """Reject unsupported byte patterns using authenticated claim metadata.

    No context pack is needed to decide that the current generator lacks a
    pattern. A potentially supported function ALWAYS downloads its real pack
    before generating/checking any contribution. This stub is never compiled.
    """
    start=time.monotonic();pack=Path(row['pack']).resolve()
    try:
        claim=json.loads((pack/'claim-state.json').read_text(encoding='utf-8-sig'))
        if any(claim.get(k)!=row.get(k) for k in ('claim_id','address','symbol','size')):return None
        source=claim.get('source_file') or claim.get('source');flags=claim.get('flags')
        if not source or not isinstance(flags,list) or not flags or not all(isinstance(f,str) for f in flags):return None
        if not 1<=int(claim['size'])<=255:return None
        stub=pack/'cpu_preflight/NOT_A_CONTEXT_PACK';stub.mkdir(parents=True,exist_ok=True)
        meta={k:claim[k] for k in ('address','symbol','size')};meta.update(source=source,flags=flags,triage_only=True)
        (stub/'pack.json').write_text(json.dumps(meta))
        candidates,reason=(core or generator()).templates(stub,255)
        if candidates:return None
    except (ValueError,KeyError,OSError,TypeError):return None
    result=dict(cpu=dict(outcome='unsupported',reason=reason,checker_attempts=0,llm_calls=0,
                        elapsed_seconds=time.monotonic()-start,route='partial_unsupported',
                        priority=3,similarity_percent=None,instruction_differences=None),
                preparation=dict(mode='authenticated_claim_metadata_and_private_image_screen',
                                 claim_metadata_sha256=hashlib.sha256((pack/'claim-state.json').read_bytes()).hexdigest(),
                                 packet_download_skipped=True,context_pack_used=False),
                ghidra=dict(outcome='skipped',reason='CPU-only unsupported pattern; no agent handoff'))
    folder=pack/'cpu_fast';folder.mkdir(exist_ok=True);tmp=folder/(uuid.uuid4().hex+'.tmp')
    tmp.write_text(json.dumps(result));tmp.replace(folder/'result.json')
    return result

def prepare(pack,helper,compiler_gate,core=None):
    start=time.monotonic();pack=Path(pack).resolve();meta_path=pack/'pack.json'
    before=hashlib.sha256(meta_path.read_bytes()).hexdigest()
    if json.loads(meta_path.read_text()).get('triage_only'):raise ValueError('Never compile a triage stub')
    core=core or generator();candidates,reason=core.templates(pack,255)
    if not candidates:
        result=dict(cpu=dict(outcome='unsupported',reason=reason,checker_attempts=0,llm_calls=0,
                            elapsed_seconds=time.monotonic()-start,route='partial_unsupported',
                            priority=3,similarity_percent=None,instruction_differences=None),
                    preparation=dict(mode='cpu_only_fast_screen',pack_metadata_sha256=before),
                    ghidra=dict(outcome='skipped',reason='CPU-only; failures returned without agent handoffs'))
    else:
        with compiler_gate:
            result=helper.cpu_prepare(pack)
        result['ghidra']=dict(outcome='skipped',reason='CPU-only sweep; no agent handoff')
        result['cpu']['fast_screen_seconds']=time.monotonic()-start
    if hashlib.sha256(meta_path.read_bytes()).hexdigest()!=before:
        raise ValueError('Pack metadata changed during CPU preparation')
    folder=pack/'cpu_fast';folder.mkdir(exist_ok=True)
    tmp=folder/(uuid.uuid4().hex+'.tmp');tmp.write_text(json.dumps(result));tmp.replace(folder/'result.json')
    return result
