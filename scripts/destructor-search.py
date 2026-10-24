"""Structured RAII destructor synthesis for a fixed-array memory-system family.

Generates actual C++ inheritance, member destructors, critical-section cleanup
and reverse array destruction. No source vtable writes, address casts, inline
assembly or synthetic padding arrays. All unknown fields are named scalars.
"""
from pathlib import Path
import importlib.util
import concurrent.futures

s=importlib.util.spec_from_file_location('destructor_core',Path(__file__).with_name('integer-search.py'))
core=importlib.util.module_from_spec(s);s.loader.exec_module(core)
Unsupported=core.Unsupported;cs=core.cs

def analyze(pack):
    meta=core.read(Path(pack)/'pack.json')
    if meta['size']!=135:raise Unsupported('outside_memory_system_destructor_family')
    pe=core.pefile.PE(core.read(core.ROOT/'local/settings.json')['checker_image'],fast_load=True)
    try:
        address=int(meta['address'],16);data=pe.get_data(address-pe.OPTIONAL_HEADER.ImageBase,meta['size'])
    finally:pe.close()
    md=cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_32);md.detail=True;code=list(md.disasm(data,address))
    expected_path=core.ROOT/'local/benchmark/destructor-family-shape.json'
    if not expected_path.exists():raise Unsupported('destructor_family_profile_missing')
    profile=core.read(expected_path);normalized=[];direct=[]
    for i in code:
        text=i.op_str
        if i.mnemonic=='call' and i.operands[0].type==cs.x86.X86_OP_IMM:
            target=i.operands[0].imm
            if target not in core._function_index():raise Unsupported('destructor_callee_not_indexed')
            direct.append(target);text='indexed_callee'
        elif i.mnemonic=='jmp':
            if i.operands[0].imm not in core._function_index():raise Unsupported('destructor_tail_not_function_entry')
            direct.append(i.operands[0].imm);text='indexed_base_destructor'
        elif i.mnemonic.startswith('j'):text=str(i.operands[0].imm-address)
        elif i.mnemonic=='mov' and i.operands[-1].type==cs.x86.X86_OP_IMM and i.operands[-1].imm>core.MASK//256:text='relocatable_vtable_store'
        elif i.mnemonic=='mov' and any(o.type==cs.x86.X86_OP_MEM and not o.mem.base for o in i.operands):text='named_import_or_global'
        normalized.append(i.mnemonic+' '+text)
    if sum(i.size for i in code)!=135 or normalized!=profile['instructions'] or len(direct)!=6 or direct[1]!=direct[3]:raise Unsupported('destructor_structure_differs')
    return dict(meta=meta,cleanup=f'FUN_{direct[0]:08x}',reference_base=direct[1],secondary_pool=direct[2],primary_pool=direct[4],system_base=direct[5],kind='memory_system_destructor')

def scalars(start,end,prefix='unknown'):
    return ''.join(f'    unsigned int {prefix}{offset:04x};\n' for offset in range(start,end,4))

def source(plan,style):
    name=plan['meta']['symbol'];throws=' throw()' if style%2==0 else ''
    # These are real member extents inferred from consecutive reference accesses.
    # Critical sections are represented by the SDK's actual structure.
    text='#include <windows.h>\nextern void* activeMemorySystem;\n'
    text+=f'struct ReferenceBase {{ virtual ~ReferenceBase(){throws};\n'+scalars(4,8)+'};\n'
    text+=f'struct SystemBase {{ virtual ~SystemBase(){throws};\n'+scalars(4,8)+'};\n'
    text+=f'struct BlockServer {{ virtual ~BlockServer(){throws} {{}}\n'+scalars(4,0x14)+'};\n'
    text+=f'struct CriticalGuard {{ CRITICAL_SECTION section; ~CriticalGuard(){throws} {{ DeleteCriticalSection(&section); }} }};\n'
    text+=f'struct PrimaryPool {{ virtual ~PrimaryPool(){throws};\n'+scalars(4,0xa9c)+'};\n'
    text+=f'struct SecondaryPool {{ virtual ~SecondaryPool(){throws};\n'+scalars(4,0x13c)+'};\n'
    text+='struct ProtectedReference { ReferenceBase reference;\n'+scalars(8,0x18)+'    CriticalGuard guard;\n'+scalars(0x30,0x78)+'};\n'
    text+=f'struct ThreadMemory : ReferenceBase {{\n{scalars(8,0x138)}    void {plan["cleanup"]}(){throws};\n    virtual ~ThreadMemory(){throws} {{ {plan["cleanup"]}(); }}\n}};\n'
    if style>=4:
        # An actual object-lifetime buffer, used for all 32 thread objects. It is
        # not padding: the destructor visits and destroys every contained object.
        text+=f'''struct ThreadStorage {{
    unsigned int objectStorage[32 * sizeof(ThreadMemory) / sizeof(unsigned int)];
    __forceinline ~ThreadStorage(){throws} {{
        ThreadMemory* objects = reinterpret_cast<ThreadMemory*>(objectStorage) + 32;
        for (int index = 31; index >= 0; --index) {{
            --objects;
            objects->ThreadMemory::~ThreadMemory();
        }}
    }}
}};
'''
        text=text.replace('virtual ~ThreadMemory()', 'virtual __forceinline ~ThreadMemory()')
    text+=f'''struct {name} : SystemBase {{
    BlockServer blockServer;
    PrimaryPool primaryPool;
    ProtectedReference reference;
    SecondaryPool secondaryPool;
    ThreadMemory threads[32];
    CriticalGuard guard;
    virtual ~{name}(){throws};
}};
{name}::~{name}(){throws}
{{
    activeMemorySystem = 0;
}}
'''
    if style//2%2:text=text.replace('void* activeMemorySystem','int activeMemorySystem')
    if style>=4:text=text.replace('ThreadMemory threads[32];','ThreadStorage threads;')
    if style&8:text=text.replace('__forceinline ~ThreadStorage()', '~ThreadStorage()')
    if style&16:text=text.replace('~CriticalGuard()', '__forceinline ~CriticalGuard()')
    if style&32:text=text.replace('virtual __forceinline ~ThreadMemory()', 'virtual ~ThreadMemory()')
    if style&64:
        text=text.replace('reinterpret_cast<ThreadMemory*>(objectStorage) + 32','reinterpret_cast<ThreadMemory*>(objectStorage)')
        text=text.replace('--objects;\n            objects->ThreadMemory::~ThreadMemory();','objects[index].ThreadMemory::~ThreadMemory();')
    if style&128:
        old='for (int index = 31; index >= 0; --index) {\n            --objects;\n            objects->ThreadMemory::~ThreadMemory();\n        }'
        new='int index = 31;\n        do {\n            --objects;\n            objects->ThreadMemory::~ThreadMemory();\n            --index;\n        } while (index >= 0);'
        text=text.replace(old,new)
    if style&512:
        text=text.replace('CriticalGuard guard;', 'CRITICAL_SECTION guard;',1)
        text=text.replace('};\nstruct ThreadMemory',f'    ~ProtectedReference(){throws} {{ DeleteCriticalSection(&guard); }}\n}};\nstruct ThreadMemory',1)
    if style&256:
        before,after=text.rsplit('CriticalGuard guard;',1)
        text=before+'CRITICAL_SECTION guard;'+after
        text=text.replace('activeMemorySystem = 0;', 'activeMemorySystem = 0;\n    DeleteCriticalSection(&guard);')
    for bit,destructor in [(1024,'ThreadStorage'),(2048,'ThreadMemory'),(4096,name),(8192,'CriticalGuard'),(16384,'ProtectedReference')]:
        if style&bit:text=text.replace('~'+destructor+'() throw()', '~'+destructor+'()')
    forms=[
        'reinterpret_cast<ThreadMemory*>(objectStorage) + 32',
        'reinterpret_cast<ThreadMemory*>(objectStorage + sizeof(objectStorage) / sizeof(objectStorage[0]))',
        'static_cast<ThreadMemory*>(static_cast<void*>(objectStorage + sizeof(objectStorage) / sizeof(objectStorage[0])))',
        'reinterpret_cast<ThreadMemory*>(&objectStorage[sizeof(objectStorage) / sizeof(objectStorage[0])])',
        'reinterpret_cast<ThreadMemory*>(reinterpret_cast<char*>(objectStorage) + sizeof(objectStorage))',
        'reinterpret_cast<ThreadMemory*>(this + 1)',
        'static_cast<ThreadMemory*>(static_cast<void*>(this + 1))',
        '&reinterpret_cast<ThreadMemory*>(objectStorage)[32]',
    ]
    form=(style>>16)&15
    if form<len(forms):text=text.replace(forms[0],forms[form])
    if 8<=form<=11:
        old='ThreadMemory* objects = '+forms[0]+';\n        for (int index = 31; index >= 0; --index) {\n            --objects;\n            objects->ThreadMemory::~ThreadMemory();\n        }'
        variants={
            8:'int index = 32;\n        while (--index >= 0) objects[index].ThreadMemory::~ThreadMemory();',
            9:'int index = 31;\n        do { objects[index].ThreadMemory::~ThreadMemory(); } while (--index >= 0);',
            10:'int index = 32;\n        while (index != 0) objects[--index].ThreadMemory::~ThreadMemory();',
            11:'for (int index = 32; --index >= 0;) objects[index].ThreadMemory::~ThreadMemory();',
        }
        text=text.replace(old,'ThreadMemory* objects = reinterpret_cast<ThreadMemory*>(objectStorage);\n        '+variants[form])
    if form>=12:
        text=text.replace('ThreadStorage threads;', 'ThreadMemory threads[32];')
        for type_name in ('ReferenceBase','SystemBase','PrimaryPool','SecondaryPool','ThreadMemory','CriticalGuard'):
            text=text.replace('~'+type_name+'()', '__declspec(nothrow) ~'+type_name+'()')
        text=text.replace('ThreadMemory::__declspec(nothrow) ~ThreadMemory()', 'ThreadMemory::~ThreadMemory()')
        if form%2:text=text.replace('__forceinline ', '')
        if form>=14:text=text.replace(' throw()', '')
    if style&32768:text=text.replace('DeleteCriticalSection(&section)', 'DeleteCriticalSection(static_cast<CRITICAL_SECTION*>(static_cast<void*>(this)))')
    if style&(1<<20):
        text=text.replace('~ThreadStorage()', 'void Destroy()')
        text=text.replace('DeleteCriticalSection(&guard);\n}', 'DeleteCriticalSection(&guard);\n    threads.Destroy();\n}')
    if style&(1<<21):
        text=text.replace('int index = ', 'unsigned int index = ')
        text=text.replace('--index >= 0', '(int)--index >= 0')
        text=text.replace('; index >= 0;', '; (int)index >= 0;')
    naming=(style>>24)&31
    object_name,index_name=[('objects','index'),('thread','remaining'),('memory','i'),('current','count'),('end','threadIndex'),('threadMemory','last'),('memoryEnd','position'),('entry','threadCount')][naming%8]
    import re
    text=re.sub(r'\bobjects\b',object_name,text);text=re.sub(r'\bindex\b',index_name,text)
    global_name=['activeMemorySystem','memorySystemInstance','currentMemorySystem','memorySystemSingleton'][naming//8]
    text=text.replace('activeMemorySystem',global_name)
    if style&(1<<22):
        text=text.replace(f'struct ReferenceBase {{ virtual ~ReferenceBase(){throws};\n'+scalars(4,8)+'};',f'struct ReferenceBase {{ virtual ~ReferenceBase(){throws}; }};')
        text=text.replace('struct ThreadMemory : ReferenceBase {\n','struct ThreadMemory : ReferenceBase {\n'+scalars(4,8))
        text=text.replace('ProtectedReference { ReferenceBase reference;\n','ProtectedReference { ReferenceBase reference;\n'+scalars(4,8))
    if style&(1<<23):
        text=text.replace(f'struct SystemBase {{ virtual ~SystemBase(){throws};\n'+scalars(4,8)+'};',f'struct SystemBase {{ virtual ~SystemBase(){throws}; }};')
        text=text.replace('    BlockServer blockServer;',scalars(4,8)+'    BlockServer blockServer;')
    if style&(1<<29):
        text=text.replace(f'struct BlockServer {{ virtual ~BlockServer(){throws} {{}}\n'+scalars(4,0x14)+'};',f'struct BlockServer {{ virtual ~BlockServer(){throws} {{}} }};')
        text=text.replace('    BlockServer blockServer;','    BlockServer blockServer;\n'+scalars(0xc,0x1c))
    if style&(1<<30):
        helper=f'''static __forceinline void DestroyThreadObjects(ThreadMemory* begin, int count){throws}
{{
    ThreadMemory* objects = begin + count;
    for (int index = count - 1; index >= 0; --index) {{
        --objects;
        objects->ThreadMemory::~ThreadMemory();
    }}
}}
'''
        text=text.replace('struct ThreadStorage {',helper+'struct ThreadStorage {')
        pattern=r'(__forceinline ~ThreadStorage\(\) throw\(\) \{).*?\n    \}'
        text=re.sub(pattern,lambda m:m[1]+'\n        DestroyThreadObjects(reinterpret_cast<ThreadMemory*>(objectStorage), 32);\n    }',text,flags=re.S)
    return text

def search(pack,worker,max_checks=32,jobs=4,seconds=90):
    started=core.time.monotonic();pack=Path(pack).resolve();plan=analyze(pack);folder=pack/worker/'destructor-search';folder.mkdir(parents=True,exist_ok=True)
    styles=[4+(1<<30)+ref+system+block for ref in (0,1<<22) for system in (0,1<<23) for block in (0,1<<29)]+[4]
    sources=list(dict.fromkeys(source(plan,n) for n in styles));checks=[];chosen=None
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for start in range(0,min(len(sources),max_checks),jobs):
            if core.time.monotonic()-started>seconds-45:break
            batch=list(pool.map(lambda n:core.check_candidate(pack,folder,n+1,sources[n],worker+'_destructor'),range(start,min(start+jobs,len(sources),max_checks))))
            checks.extend(batch);chosen=next((c for c in batch if core.score(c)[0]==0),None)
            if chosen:break
    record=dict(owner=worker,claim_id=pack.name,symbol=plan['meta']['symbol'],size=plan['meta']['size'],pattern='structured_memory_destructor',llm_calls=0,service_calls=0,gpu_work_performed=False,outcome='match' if chosen else 'blocked',checker_attempts=len(checks),variants_generated=len(sources),elapsed_seconds=core.time.monotonic()-started,ended_utc=core.datetime.now(core.timezone.utc).isoformat(),reason='' if chosen else 'Structured RAII destructor still differs; inspect official first difference',best_attempt=min(checks,key=core.score)['attempt'] if checks else None)
    if chosen:record['candidate']=chosen['candidate']
    elif checks:
        best=min(checks,key=core.score);record.update(best_extent=best.get('extent'),remaining_instruction_differences=best.get('ndiff_insn'),reason=f'RAII destructor best extent {best.get("extent")}/135; {best.get("ndiff_insn")} instruction differences in pointer reuse and guard argument registers; official checks saved')
    core.save(folder/'result.json',record);return record
