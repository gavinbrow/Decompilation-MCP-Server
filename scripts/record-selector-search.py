"""Structured call/loop/local recovery for allocate-sort-select-copy-free routines.

Family recognition verifies the complete instruction shape and indexed callees.
The C++ generator uses real records, calls, locals, loops and cleanup. Relocations
are resolved exclusively by the unchanged official checker; no numeric addresses
are emitted into source. No service requests are made.
"""
from pathlib import Path
import concurrent.futures
import importlib.util

s=importlib.util.spec_from_file_location('selector_core',Path(__file__).with_name('integer-search.py'))
core=importlib.util.module_from_spec(s);s.loader.exec_module(core)
cs=core.cs;Unsupported=core.Unsupported

def analyze(pack):
    pack=Path(pack);meta=core.read(pack/'pack.json')
    if meta['size']!=237 or '/Od' not in meta['flags']:raise Unsupported('outside_record_selector_family')
    pe=core.pefile.PE(core.read(core.ROOT/'local/settings.json')['checker_image'],fast_load=True)
    try:
        a=int(meta['address'],16);data=pe.get_data(a-pe.OPTIONAL_HEADER.ImageBase,meta['size'])
    finally:pe.close()
    md=cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_32);md.detail=True;code=list(md.disasm(data,a))
    if sum(i.size for i in code)!=237:raise Unsupported('selector_decode_incomplete')
    # Every instruction is validated against this semantic family. Only call,
    # callback and ordinary global relocation operands may vary.
    shape='push mov sub mov mov mov push mov push lea push mov call mov cmp jle cmp jne xor jmp mov mov mov push push mov push mov push call add mov mov cmp jge mov imul add push mov push mov call movzx test jne mov add mov jmp mov cmp jge mov imul add mov mov mov mov mov mov mov mov mov mov push call add mov jmp jmp mov mov mov push call add xor mov pop ret'.split()
    if [i.mnemonic for i in code]!=shape:raise Unsupported('selector_control_flow_shape_differs')
    calls=[i.operands[0].imm for i in code if i.mnemonic=='call' and i.operands[0].type==cs.x86.X86_OP_IMM]
    if len(calls)!=5 or calls[3]!=calls[4] or not all(t in core._function_index() for t in calls):raise Unsupported('selector_call_targets_not_indexed')
    callback=next((i.operands[0].imm for i in code if i.mnemonic=='push' and i.operands[0].type==cs.x86.X86_OP_IMM and i.operands[0].imm!=12),None)
    if callback not in core._function_index():raise Unsupported('selector_callback_not_indexed')
    # Compare all instruction encodings after masking relocation fields only.
    # This private structural exemplar is opcode/operand metadata, not emitted
    # game bytes or executable code. Relative branch offsets remain checked.
    normalized=[]
    for i in code:
        text=i.op_str
        if i.mnemonic=='call':text='indexed_callee'
        elif i.mnemonic=='push' and i.operands[0].type==cs.x86.X86_OP_IMM and i.operands[0].imm==callback:text='indexed_comparator'
        elif i.mnemonic=='mov' and i.operands[0].type==cs.x86.X86_OP_MEM and not i.operands[0].mem.base and not i.operands[0].mem.index:text='sort_context, eax'
        elif i.mnemonic.startswith('j'):text=str(i.operands[0].imm-a)
        normalized.append(i.mnemonic+' '+text)
    expected=core.read(core.ROOT/'local/benchmark/selector-family-shape.json') if (core.ROOT/'local/benchmark/selector-family-shape.json').exists() else None
    if expected is None or normalized!=expected['instructions']:raise Unsupported('selector_operand_layout_requires_new_family')
    query_info=core._call_declaration(calls[0],3,True)
    return dict(meta=meta,calls=[f'FUN_{t:08x}' for t in calls],query_owner=query_info['owner'],callback=f'FUN_{callback:08x}',kind='record_selector',normalized=normalized)

def source(plan,style):
    query,sort,predicate,release,_=plan['calls'];callback=plan['callback'];name=plan['meta']['symbol']
    names=[('entries','count','index','selected','discarded'),('points','size','i','buffer','unused'),('records','length','position','chosen','remaining'),('array','total','current','releaseSelected','releaseOther')][style%4]
    entries,count,index,selected,discarded=names
    # Real branch-scoped temporaries reproduce the two cleanup lifetimes; no
    # filler locals or stack padding are generated.
    owner=plan['query_owner']
    text=f'''struct SelectedRecord {{ int x; int y; int z; }};
extern void* selectionContext;
int __cdecl {callback}(const void*, const void*);
void __cdecl {sort}(int, int, int, int);
struct SelectionPredicate {{ bool {predicate}(int, SelectedRecord*); }};
struct RecordSelector {{ bool {name}(void* context, int flags, SelectedRecord* output); }};
bool RecordSelector::{name}(void* context, int flags, SelectedRecord* output)
{{
    SelectedRecord* {entries} = 0;
    int {count} = (({owner}*)this)->{query}((int)&{entries}, (int)context, flags);
    if ({count} <= 0 || {entries} == 0)
        return false;
    int {index} = 0;
    selectionContext = context;
    {sort}((int){entries}, {count}, sizeof(SelectedRecord), (int)&{callback});
    {index} = 0;
    while ({index} < {count} && !((SelectionPredicate*)this)->{predicate}(flags, &{entries}[{index}])) {{
        ++{index};
    }}
    if ({index} < {count}) {{
        *output = {entries}[{index}];
        SelectedRecord* {selected} = {entries};
        _Deallocate({selected});
        return true;
    }} else {{
        SelectedRecord* {discarded} = {entries};
        _Deallocate({discarded});
        return false;
    }}
}}
'''
    if style//4%2:text=text.replace('sizeof(SelectedRecord)','12')
    if style//8%2:text=text.replace('++'+index,index+' += 1')
    return text

def search(pack,worker,max_checks=32,jobs=4,seconds=90):
    started=core.time.monotonic();pack=Path(pack).resolve();plan=analyze(pack);folder=pack/worker/'record-selector-search';folder.mkdir(parents=True,exist_ok=True)
    sources=list(dict.fromkeys(source(plan,n) for n in range(16)));checks=[];chosen=None
    for start in range(0,min(len(sources),max_checks),jobs):
        if core.time.monotonic()-started>seconds-45:break
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            batch=list(pool.map(lambda n:core.check_candidate(pack,folder,n+1,sources[n],worker+'_selector'),range(start,min(start+jobs,len(sources),max_checks))))
        checks.extend(batch);chosen=next((c for c in batch if core.score(c)[0]==0),None)
        if chosen:break
    record=dict(owner=worker,claim_id=pack.name,symbol=plan['meta']['symbol'],size=plan['meta']['size'],pattern='structured_record_selector',llm_calls=0,service_calls=0,gpu_work_performed=False,outcome='match' if chosen else 'blocked',checker_attempts=len(checks),variants_generated=len(sources),elapsed_seconds=core.time.monotonic()-started,ended_utc=core.datetime.now(core.timezone.utc).isoformat(),reason='' if chosen else 'Structured selector candidate has remaining official instruction differences',best_attempt=min(checks,key=core.score)['attempt'] if checks else None)
    if chosen:record['candidate']=chosen['candidate']
    core.save(folder/'result.json',record);return record
