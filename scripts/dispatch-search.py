"""Bounded typed switch/member-call synthesis; no model or service calls."""
from pathlib import Path
import concurrent.futures
import importlib.util

s=importlib.util.spec_from_file_location('dispatch_core',Path(__file__).with_name('integer-search.py'))
core=importlib.util.module_from_spec(s);s.loader.exec_module(core)
cs=core.cs;Unsupported=core.Unsupported

def analyze(pack):
    meta=core.read(Path(pack)/'pack.json')
    if meta['size']!=62:raise Unsupported('outside_member_dispatch_family')
    pe=core.pefile.PE(core.read(core.ROOT/'local/settings.json')['checker_image'],fast_load=True)
    try:
        a=int(meta['address'],16);data=pe.get_data(a-pe.OPTIONAL_HEADER.ImageBase,meta['size'])
    finally:pe.close()
    md=cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_32);md.detail=True;code=list(md.disasm(data,a));calls=[];normalized=[]
    for i in code:
        text=i.op_str
        if i.mnemonic=='call':
            if i.operands[0].type!=cs.x86.X86_OP_IMM or i.operands[0].imm not in core._function_index():raise Unsupported('dispatch_call_not_indexed')
            calls.append(f'FUN_{i.operands[0].imm:08x}');text='indexed_method'
        elif i.mnemonic.startswith('j'):text=str(i.operands[0].imm-a)
        normalized.append(i.mnemonic+' '+text)
    profile=core.ROOT/'local/benchmark/dispatch-family-shape.json'
    if not profile.exists() or normalized!=core.read(profile)['instructions'] or sum(i.size for i in code)!=62 or len(calls)!=2:raise Unsupported('member_dispatch_structure_differs')
    return dict(meta=meta,calls=calls)

def source(plan,style):
    choose,notify=plan['calls'];name=plan['meta']['symbol'];local=('success','handled','result','ignored')[style%4]
    first='unsigned char' if style<4 else 'int'
    text=f'''struct DispatchItem;
struct DispatchOwner {{ void {choose}(bool*, DispatchItem*); }};
struct DispatchItem {{
    unsigned int unknown00;
    unsigned int unknown04;
    DispatchOwner* owner;
    void {notify}({first}, {first}, {first});
}};
struct Dispatcher {{
'''+''.join(f'    unsigned int unknown{i:02x};\n' for i in range(0,0x14,4))+'''    DispatchOwner* owner;
'''+''.join(f'    unsigned int unknown{i:02x};\n' for i in range(0x18,0x30,4))+f'''    int mode;
    void {name}(DispatchItem* item);
}};
void Dispatcher::{name}(DispatchItem* item)
{{
    switch (mode) {{
    case 0:
    case 1:
        item->{notify}(5, 1, 0);
        break;
    case 2:
        if (item->owner == owner) {{
            bool {local};
            owner->{choose}(&{local}, item);
        }}
        break;
    }}
}}
'''
    return text

def search(pack,worker,max_checks=32,jobs=4,seconds=90):
    started=core.time.monotonic();pack=Path(pack).resolve();plan=analyze(pack);folder=pack/worker/'dispatch-search';folder.mkdir(parents=True,exist_ok=True)
    sources=[]
    for n in range(8):
        text=source(plan,n)
        text=text.replace('case 0:\n    case 1:',f'case 0:\n        item->{plan["calls"][1]}(5, 1, 0);\n        break;\n    case 1:')
        if text not in sources:sources.append(text)
    checks=[];chosen=None
    for start in range(0,min(len(sources),max_checks),jobs):
        if core.time.monotonic()-started>seconds-45:break
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            batch=list(pool.map(lambda n:core.check_candidate(pack,folder,n+1,sources[n],worker+'_dispatch'),range(start,min(start+jobs,len(sources),max_checks))))
        checks.extend(batch);chosen=next((c for c in batch if core.score(c)[0]==0),None)
        if chosen:break
    record=dict(owner=worker,claim_id=pack.name,symbol=plan['meta']['symbol'],size=plan['meta']['size'],pattern='structured_member_dispatch',llm_calls=0,service_calls=0,gpu_work_performed=False,outcome='match' if chosen else 'blocked',checker_attempts=len(checks),variants_generated=len(sources),elapsed_seconds=core.time.monotonic()-started,ended_utc=core.datetime.now(core.timezone.utc).isoformat(),reason='' if chosen else 'Typed dispatch candidates still differ',best_attempt=min(checks,key=core.score)['attempt'] if checks else None)
    if chosen:record['candidate']=chosen['candidate']
    core.save(folder/'result.json',record);return record
