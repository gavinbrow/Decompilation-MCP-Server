"""Non-AI reduction-loop synthesis, checked against a bounded x86 interpreter.

The interpreter runs only private synthetic memory; it never executes native
instructions or calls game code. Sources are ordinary array-reduction C++ loops.
No API calls, binaries, inline assembly or source-level register emulation.
"""
from __future__ import annotations
import concurrent.futures
import importlib.util
import time
from pathlib import Path
import numpy as np

spec=importlib.util.spec_from_file_location('integer_core',Path(__file__).with_name('integer-search.py'))
core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
cs=core.cs;MASK=core.MASK;Unsupported=core.Unsupported

def decode(data,address=0):
    decoder=cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_32);decoder.detail=True
    code=list(decoder.disasm(data,address))
    if not code or sum(i.size for i in code)!=len(data) or len(code)>128:raise Unsupported('loop_decode_or_size_limit')
    addresses={i.address for i in code};backedges=[]
    allowed={'mov','movzx','lea','push','pop','add','sub','inc','dec','imul','and','or','xor','not','neg','shl','sal','shr','sar','cmp','test','ret','jmp','je','jne','jz','jnz','jl','jle','jg','jge','jb','jbe','ja','jae','js','jns'}
    for i in code:
        if i.mnemonic not in allowed:raise Unsupported('unsupported_loop_instruction:'+i.mnemonic)
        if i.mnemonic.startswith('j'):
            if len(i.operands)!=1 or i.operands[0].type!=cs.x86.X86_OP_IMM or i.operands[0].imm not in addresses:raise Unsupported('external_or_indirect_loop_branch')
            if i.operands[0].imm<i.address:backedges.append((i.address,i.operands[0].imm))
        for operand in i.operands:
            if operand.type==cs.x86.X86_OP_MEM and (operand.mem.segment or not operand.mem.base):raise Unsupported('loop_requires_named_global_or_segment')
    if not 1<=len(backedges)<=2:raise Unsupported('requires_one_or_two_natural_backedges')
    returns=[i.operands[0].imm if i.operands else 0 for i in code if i.mnemonic=='ret']
    if not returns or len(set(returns))!=1 or returns[0] not in (0,8):raise Unsupported('loop_requires_two_stack_arguments')
    return code,returns[0]

def analyze(pack):
    meta=core.read(Path(pack)/'pack.json')
    if not 1<=int(meta['size'])<=255:raise Unsupported('outside_loop_scope')
    pe=core.pefile.PE(core.read(core.ROOT/'local/settings.json')['checker_image'],fast_load=True)
    try:
        address=int(meta['address'],16);data=pe.get_data(address-pe.OPTIONAL_HEADER.ImageBase,int(meta['size']))
        if len(data)!=int(meta['size']):raise Unsupported('incomplete_loop_span')
        code,cleanup=decode(data,address)
        upper=pe.OPTIONAL_HEADER.ImageBase+pe.OPTIONAL_HEADER.SizeOfImage
        for i in code:
            for o in i.operands:
                if not i.mnemonic.startswith('j') and o.type==cs.x86.X86_OP_IMM and pe.OPTIONAL_HEADER.ImageBase<=o.imm<upper:raise Unsupported('loop_game_address_literal')
    finally:pe.close()
    pair=paired_dot_plan(code)
    return dict(meta=meta,data=data.hex(),address=address,cleanup=cleanup,instructions=len(code),kind='paired_member_dot' if pair else 'bounded_array_reduction',**(pair or {}))

def paired_dot_plan(code):
    """Two interleaved accumulator streams, fixed count, plus one tail product."""
    if len(code)!=28:return None
    fixed={0:'push ebx',1:'push ebp',2:'push esi',3:'xor esi, esi',4:'push edi',5:'xor edi, edi',9:'mov ebp, dword ptr [eax - 4]',10:'imul ebp, dword ptr [edx - 8]',11:'add esi, ebp',12:'mov ebp, dword ptr [eax]',13:'imul ebp, dword ptr [edx]',14:'add edi, ebp',15:'add eax, 8',16:'add edx, 0x10',17:'sub ebx, 1',21:'lea eax, [edi + esi]',22:'pop edi',23:'pop esi',24:'pop ebp',25:'add eax, edx',26:'pop ebx',27:'ret'}
    if any((code[n].mnemonic+' '+code[n].op_str).strip()!=text for n,text in fixed.items()):return None
    for n,op,dst in [(6,'lea','edx'),(7,'lea','eax'),(8,'lea','ebx'),(19,'mov','edx'),(20,'imul','edx')]:
        i=code[n]
        if i.mnemonic!=op or len(i.operands)!=2 or i.reg_name(i.operands[0].reg)!=dst or i.operands[1].type!=cs.x86.X86_OP_MEM:return None
        memory=i.operands[1].mem
        if i.reg_name(memory.base)!=('esi' if n==8 else 'ecx') or memory.index or memory.segment:return None
    if code[18].mnemonic!='jne' or code[18].operands[0].imm!=code[9].address:return None
    start_a=code[6].operands[1].mem.disp-8;start_b=code[7].operands[1].mem.disp-4
    count=code[8].operands[1].mem.disp;tail_a=code[20].operands[1].mem.disp;tail_b=code[19].operands[1].mem.disp
    if not (0<=start_a<start_b and 1<=count<=32 and start_a+16*count<=tail_a<start_b and start_b+8*count<=tail_b<=512):return None
    if any(n%4 for n in (start_a,start_b,tail_a,tail_b)):return None
    return dict(start_a=start_a,start_b=start_b,count=count,tail_a=tail_a,tail_b=tail_b)

def signed(x):return (int(x)^0x80000000)-0x80000000

def execute(code,values,count,array_argument=0,max_steps=2048,this_fields=None):
    """Independent scalar x86 reference for read-only arrays and local stack state."""
    stack_base=0x70000000;array_base=0x50000000
    memory={stack_base:0x7fffffff,stack_base+4:array_base if array_argument==0 else count,stack_base+8:count if array_argument==0 else array_base}
    memory.update({array_base+4*i:int(v)&MASK for i,v in enumerate(values)})
    regs={'esp':stack_base,'ebp':0x60000000,'ebx':0x60000100,'esi':0x60000200,'edi':0x60000300}
    if this_fields is not None:
        regs['ecx']=0x51000000
        memory.update({regs['ecx']+offset:int(value)&MASK for offset,value in this_fields.items()})
    indexes={i.address:n for n,i in enumerate(code)};position=0;flags=None
    def getreg(name):
        parent={'al':'eax','ax':'eax','cl':'ecx','cx':'ecx','dl':'edx','dx':'edx'}.get(name,name)
        if parent not in regs:raise Unsupported('undefined_loop_register:'+name)
        return regs[parent] & (0xff if len(name)==2 and name.endswith('l') else 0xffff if name in ('ax','cx','dx') else MASK)
    def address(i,o):
        return (getreg(i.reg_name(o.mem.base))+(getreg(i.reg_name(o.mem.index))*o.mem.scale if o.mem.index else 0)+o.mem.disp)&MASK
    def load(i,o):
        if o.type==cs.x86.X86_OP_IMM:return o.imm&MASK
        if o.type==cs.x86.X86_OP_REG:return getreg(i.reg_name(o.reg))
        if o.type!=cs.x86.X86_OP_MEM or o.size!=4:raise Unsupported('unsupported_loop_load')
        a=address(i,o)
        if a not in memory:raise Unsupported('uninitialized_or_out_of_bounds_loop_read')
        return memory[a]
    def store(i,o,v):
        v=int(v)&MASK
        if o.type==cs.x86.X86_OP_REG:
            name=i.reg_name(o.reg)
            if o.size==4:regs[name]=v;return
            parent={'al':'eax','cl':'ecx','dl':'edx'}.get(name)
            if parent and parent in regs:regs[parent]=(regs[parent]&0xffffff00)|(v&255);return
            raise Unsupported('partial_loop_register_write')
        a=address(i,o)
        if o.size!=4 or a%4 or not (stack_base-512<=a<stack_base or a in (stack_base+4,stack_base+8)):raise Unsupported('nonlocal_loop_store')
        memory[a]=v
    def setflags(op,a,b,result):
        nonlocal flags
        z=(result&MASK)==0;s=bool(result&0x80000000);carry=False;overflow=False
        if op in ('cmp','sub','dec'):
            carry=a<b;overflow=bool((a^b)&(a^result)&0x80000000)
        elif op in ('add','inc'):
            carry=a+b>MASK;overflow=bool(~(a^b)&(a^result)&0x80000000)
        elif op=='neg':carry=a!=0;overflow=a==0x80000000
        elif op in ('shl','sal','shr','sar'):
            if b==0:return
            carry=bool((a>>(32-b))&1) if op in ('shl','sal') else bool((a>>(b-1))&1)
            if b==1:overflow=(s!=carry) if op in ('shl','sal') else bool(a&0x80000000) if op=='shr' else False
        elif op=='imul':flags=None;return
        if op in ('inc','dec') and flags is not None:carry=flags['b']
        flags=dict(z=z,s=s,lt=s!=overflow,le=z or s!=overflow,b=carry,be=carry or z)
    for _ in range(max_steps):
        if not 0<=position<len(code):raise Unsupported('loop_fell_outside_function')
        i=code[position];op=i.mnemonic;o=i.operands;position+=1
        if op=='ret':
            if regs['esp']!=stack_base or 'eax' not in regs:raise Unsupported('unbalanced_loop_return')
            return regs['eax']&MASK
        if op=='push':
            v=load(i,o[0]);regs['esp']-=4;memory[regs['esp']]=v;continue
        if op=='pop':
            if regs['esp'] not in memory:raise Unsupported('uninitialized_loop_pop')
            v=memory[regs['esp']];regs['esp']+=4;store(i,o[0],v);continue
        if op=='mov':store(i,o[0],load(i,o[1]));continue
        if op=='movzx':store(i,o[0],load(i,o[1]));continue
        if op=='lea':store(i,o[0],address(i,o[1]));continue
        if op.startswith('j'):
            if op=='jmp':take=True
            elif flags is None:raise Unsupported('unknown_loop_branch_flags')
            else:
                take={'je':flags['z'],'jz':flags['z'],'jne':not flags['z'],'jnz':not flags['z'],'jl':flags['lt'],'jle':flags['le'],'jg':not flags['le'],'jge':not flags['lt'],'jb':flags['b'],'jbe':flags['be'],'ja':not flags['be'],'jae':not flags['b'],'js':flags['s'],'jns':not flags['s']}[op]
            if take:position=indexes[o[0].imm]
            continue
        if op in ('xor','sub') and len(o)==2 and o[0].type==cs.x86.X86_OP_REG and o[1].type==cs.x86.X86_OP_REG and o[0].reg==o[1].reg:
            store(i,o[0],0);setflags(op,0,0,0);continue
        a=load(i,o[0]);b=load(i,o[1]) if len(o)>1 else 1
        if op=='cmp':setflags(op,a,b,(a-b)&MASK);continue
        if op=='test':setflags(op,a,b,a&b);continue
        if op=='imul' and len(o)==3:a,b=load(i,o[1]),load(i,o[2])
        if op in ('shl','sal','shr','sar'):b&=31
        operations={'add':lambda:a+b,'sub':lambda:a-b,'inc':lambda:a+1,'dec':lambda:a-1,'imul':lambda:a*b,'and':lambda:a&b,'or':lambda:a|b,'xor':lambda:a^b,'not':lambda:~a,'neg':lambda:-a,'shl':lambda:a<<b,'sal':lambda:a<<b,'shr':lambda:a>>b,'sar':lambda:signed(a)>>b}
        if op not in operations:raise Unsupported('unsupported_loop_operation')
        result=operations[op]()&MASK;store(i,o[0],result)
        if op!='not':setflags(op,a,b,result)
    raise Unsupported('loop_execution_step_limit')

FAMILIES=[('sum',0),('xor',0),('or',0),('and',MASK),('product',1),('max',0),('min',MASK),
          ('sum_squares',0),('count_zero',0),('count_nonzero',0),('count_negative',0),
          ('signed_max',0x80000000),('signed_min',0x7fffffff)]

def reduce_values(xp,values,counts,family,initial):
    columns=xp.arange(values.shape[1],device=values.device) if xp.__name__=='torch' else xp.arange(values.shape[1])
    active=columns[None,:]<counts[:,None]
    result=xp.full((values.shape[0],),initial,dtype=xp.int64,device=values.device) if xp.__name__=='torch' else xp.full((values.shape[0],),initial,dtype=xp.int64)
    for column in range(values.shape[1]):
        v=values[:,column]
        # int64 carries DWORD bit patterns on CPU/CUDA; explicit signed mapping
        # prevents UINT_MAX / INT_MIN ordering differences between backends.
        signed_v=(v^0x80000000)-0x80000000
        signed_result=(result^0x80000000)-0x80000000
        next_value={'sum':lambda:(result+v)&MASK,'xor':lambda:result^v,'or':lambda:result|v,'and':lambda:result&v,'product':lambda:(result*v)&MASK,'max':lambda:xp.maximum(result,v),'min':lambda:xp.minimum(result,v),
                    'sum_squares':lambda:(result+((v*v)&MASK))&MASK,
                    'count_zero':lambda:result+(v==0),
                    'count_nonzero':lambda:result+(v!=0),
                    'count_negative':lambda:result+(signed_v<0),
                    'signed_max':lambda:xp.where(signed_result<signed_v,v,result),
                    'signed_min':lambda:xp.where(signed_result>signed_v,v,result)}[family]()
        result=xp.where(active[:,column],next_value,result)
    return result

def candidate_source(plan,family,initial,array_argument=0,style=0):
    if plan['kind']=='paired_member_dot':return paired_dot_source(plan,style)
    kind='unsigned int';count_kind='int' if style%2==0 else 'unsigned int'
    args=[f'const {kind}* values',f'{count_kind} count']
    if array_argument:args.reverse()
    update={'sum':'result += values[index];','xor':'result ^= values[index];','or':'result |= values[index];','and':'result &= values[index];','product':'result *= values[index];','max':'if (result < values[index]) result = values[index];','min':'if (result > values[index]) result = values[index];',
            'sum_squares':'result += values[index] * values[index];',
            'count_zero':'if (values[index] == 0) ++result;',
            'count_nonzero':'if (values[index] != 0) ++result;',
            'count_negative':'if ((int)values[index] < 0) ++result;',
            'signed_max':'if ((int)result < (int)values[index]) result = values[index];',
            'signed_min':'if ((int)result > (int)values[index]) result = values[index];'}[family]
    if style<2:body=f'    for ({count_kind} index = 0; index < count; ++index)\n        {update}'
    elif style<4:body=f'    {count_kind} index = 0;\n    while (index < count) {{\n        {update}\n        ++index;\n    }}'
    else:
        update=update.replace('values[index]','*values')
        body=f'    while (count > 0) {{\n        {update}\n        ++values;\n        --count;\n    }}'
    convention='__stdcall' if plan['cleanup'] else '__cdecl'
    return f'{kind} {convention} {plan["meta"]["symbol"]}({", ".join(args)})\n{{\n    {kind} result = {initial}u;\n{body}\n    return result;\n}}\n'

def paired_dot_source(plan,style):
    if style>=6:return paired_dot_flat_source(plan,style-6)
    a,b,n,ta,tb=(plan[k] for k in ('start_a','start_b','count','tail_a','tail_b'))
    fields=[];offset=0
    for at,declaration,extent in [(a,f'    Coefficient coefficients[{n}];\n',16*n),(ta,'    unsigned int tailWeight;\n',4),(b,f'    Pair pairs[{n}];\n',8*n),(tb,'    unsigned int tailValue;\n',4)]:
        while offset<at:fields.append(f'    unsigned int unknown{offset:02x};\n');offset+=4
        fields.append(declaration);offset+=extent
    name=plan['meta']['symbol']
    declarations='struct Coefficient { unsigned int first; unsigned int unknown04; unsigned int second; unsigned int unknown0c; };\nstruct Pair { unsigned int first; unsigned int second; };\n'
    declarations+='struct DotObject {\n'+''.join(fields)+f'    unsigned int {name}();\n}};\n'
    if style<2:
        body=f'    for (unsigned int index = 0; index < {n}u; ++index) {{\n        first += pairs[index].first * coefficients[index].first;\n        second += pairs[index].second * coefficients[index].second;\n    }}'
    elif style<4:
        body=f'    const Pair* pair = pairs;\n    const Coefficient* coefficient = coefficients;\n    for (unsigned int remaining = {n}u; remaining != 0; --remaining) {{\n        first += pair->first * coefficient->first;\n        second += pair->second * coefficient->second;\n        ++pair;\n        ++coefficient;\n    }}'
    else:
        body=f'    const Pair* pair = pairs;\n    const Coefficient* coefficient = coefficients;\n    unsigned int remaining = {n}u;\n    do {{\n        first += pair->first * coefficient->first;\n        second += pair->second * coefficient->second;\n        ++pair;\n        ++coefficient;\n    }} while (--remaining != 0);'
    expression='first + second + tailWeight * tailValue' if style%2==0 else 'tailWeight * tailValue + first + second'
    return declarations+f'unsigned int DotObject::{name}()\n{{\n    unsigned int first = 0;\n    unsigned int second = 0;\n{body}\n    return {expression};\n}}\n'

def paired_dot_flat_source(plan,style):
    # A real indexed numeric workspace, not a padding array. Both strided views
    # and the tail operands lie inside this one array, including final pointers.
    a,b,n,ta,tb=(plan[k] for k in ('start_a','start_b','count','tail_a','tail_b'))
    name=plan['meta']['symbol'];length=(tb-a)//4+1
    fields=''.join(f'    unsigned int unknown{offset:02x};\n' for offset in range(0,a,4))
    declarations=f'struct DotObject {{\n{fields}    unsigned int samples[{length}];\n    unsigned int {name}();\n}};\n'
    left='    const unsigned int* weight = samples + 2;\n'
    qualifier='const volatile' if style>=24 else 'const'
    right=f'    {qualifier} unsigned int* point = samples + {(b-a)//4+1};\n'
    pointers=left+right if style%2==0 else right+left
    first='point[-1] * weight[-2]' if style%4<2 else 'weight[-2] * point[-1]'
    second='point[0] * weight[0]' if style%4<2 else 'weight[0] * point[0]'
    body=f'    unsigned int remaining = {n}u;\n    do {{\n        first += {first};\n        second += {second};\n        point += 2;\n        weight += 4;\n    }} while (--remaining != 0);'
    tail_value=f'((const volatile unsigned int*)samples)[{(tb-a)//4}]' if style>=24 else f'samples[{(tb-a)//4}]'
    tail=f'{tail_value} * samples[{(ta-a)//4}]'
    total='first + second' if style%8<4 else 'second + first'
    if style<8:ending=f'    return ({total}) + {tail};'
    elif style<16:ending=f'    unsigned int total = {total};\n    unsigned int tail = {tail};\n    return total + tail;'
    else:ending=f'    unsigned int tail = {tail};\n    return tail + ({total});'
    if style>=24:ending=f'    unsigned int result = first;\n    result += second;\n    result += {tail};\n    return result;'
    text=declarations+f'unsigned int DotObject::{name}()\n{{\n    unsigned int first = 0;\n    unsigned int second = 0;\n{pointers}{body}\n{ending}\n}}\n'
    if style>=32:text=text.replace('unsigned int','int')
    return text

def filter_candidates(plan,backend='cpu'):
    begun=time.monotonic();code,_=decode(bytes.fromhex(plan['data']),plan['address'])
    rng=np.random.default_rng(0xF04);samples=128
    if plan.get('kind')=='paired_member_dot':return filter_paired_dot(plan,code,backend)
    values=rng.integers(0,2**32,size=(samples,32),dtype=np.int64)
    values[:5]=np.array([0,1,MASK,0x80000000,0x7fffffff])[:,None]
    counts=np.resize(np.array([0,1,2,3,7,16,31,32],dtype=np.int64),samples)
    xp=np;dev_values=values;dev_counts=counts;gpu=False
    if backend=='cuda':
        import os
        if os.environ.get('CUDA_VISIBLE_DEVICES') not in (None,'',core.GPU_UUID):raise RuntimeError('GPU visibility pinned to other device')
        os.environ['CUDA_VISIBLE_DEVICES']=core.GPU_UUID
        import torch
        if not torch.cuda.is_available() or torch.cuda.device_count()!=1:raise RuntimeError('Configured CUDA device unavailable')
        xp=torch;dev_values=torch.from_numpy(values).to('cuda');dev_counts=torch.from_numpy(counts).to('cuda');gpu=True
    survivors=[];tested=0;reference_errors=[]
    for array_argument in (0,1):
        try:reference=np.array([execute(code,row,int(n),array_argument) for row,n in zip(values,counts)],dtype=np.int64)
        except Unsupported as e:reference_errors.append(str(e));continue
        for family,initial in FAMILIES:
            expected=reduce_values(np,values,counts,family,initial);tested+=1
            ok=bool(np.array_equal(reference,expected))
            if gpu:
                actual=reduce_values(xp,dev_values,dev_counts,family,initial).cpu().numpy()
                if not np.array_equal(expected,actual):raise RuntimeError('GPU/CPU loop filter disagreement')
            if ok:survivors.append((family,initial,array_argument))
    return survivors,dict(samples=samples,max_test_iterations=32,grammar_candidates=tested,survivors=len(survivors),gpu_work_performed=gpu,reference_errors=reference_errors,elapsed_seconds=time.monotonic()-begun,note='Bounded interpreter tests are a filter, never byte-match evidence')

def filter_paired_dot(plan,code,backend):
    begun=time.monotonic();rng=np.random.default_rng(0xF04);samples=128
    values=rng.integers(0,2**32,size=(samples,plan['tail_b']//4+1),dtype=np.int64)
    values[0]=0;values[1]=MASK
    expected=np.array([execute(code,[],0,this_fields={4*n:int(v) for n,v in enumerate(row)}) for row in values],dtype=np.int64)
    def calculation(xp,v):
        result=v[:,plan['tail_a']//4]*v[:,plan['tail_b']//4]
        for n in range(plan['count']):
            result=(result+v[:,plan['start_a']//4+4*n]*v[:,plan['start_b']//4+2*n]+v[:,plan['start_a']//4+4*n+2]*v[:,plan['start_b']//4+2*n+1])&MASK
        return result&MASK
    actual=calculation(np,values)
    if not np.array_equal(actual,expected):raise RuntimeError('Paired-loop model differs from x86 interpreter')
    gpu=False
    if backend=='cuda':
        import os
        if os.environ.get('CUDA_VISIBLE_DEVICES') not in (None,'',core.GPU_UUID):raise RuntimeError('GPU visibility pinned to another device')
        os.environ['CUDA_VISIBLE_DEVICES']=core.GPU_UUID
        import torch
        if not torch.cuda.is_available() or torch.cuda.device_count()!=1:raise RuntimeError('Configured CUDA device unavailable')
        device_values=torch.from_numpy(values).to('cuda');device_result=calculation(torch,device_values).cpu().numpy()
        if not np.array_equal(device_result,expected):raise RuntimeError('CUDA device paired-loop model disagreement')
        gpu=True
    return [('paired_dot',0,0)],dict(samples=samples,max_test_iterations=plan['count'],grammar_candidates=1,survivors=1,gpu_work_performed=gpu,elapsed_seconds=time.monotonic()-begun,note='CPU/GPU candidate model checked against independent bounded x86 interpreter; official byte match still required')

def search(pack,worker,backend='cpu',max_checks=32,jobs=4,seconds=90):
    started=time.monotonic();pack=Path(pack).resolve();folder=pack/worker/'loop-search';folder.mkdir(parents=True,exist_ok=True)
    plan=analyze(pack);record=dict(owner=worker,claim_id=pack.name,symbol=plan['meta']['symbol'],size=plan['meta']['size'],pattern='bounded_loop_search',llm_calls=0,service_calls=0,gpu_work_performed=False,outcome='unsupported',checker_attempts=0,started_utc=core.datetime.now(core.timezone.utc).isoformat())
    survivors,stats=filter_candidates(plan,backend);record.update(semantic_filter=stats,gpu_work_performed=stats['gpu_work_performed'])
    styles=list(range(30,46))+list(range(30)) if plan['kind']=='paired_member_dot' else list(range(6))
    sources=list(dict.fromkeys(candidate_source(plan,family,initial,arg,style) for family,initial,arg in survivors for style in styles))
    checks=[];chosen=None
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for start in range(0,min(max_checks,len(sources)),jobs):
            if time.monotonic()-started>seconds-45:break
            futures=[pool.submit(core.check_candidate,pack,folder,n+1,sources[n],worker+'_loop') for n in range(start,min(start+jobs,len(sources),max_checks))]
            batch=[f.result() for f in futures];checks.extend(batch)
            chosen=next((c for c in batch if core.score(c)[0]==0),None)
            if chosen:break
    record.update(outcome='match' if chosen else 'blocked',checker_attempts=len(checks),variants_generated=len(sources),reason='' if chosen else 'No matching bounded reduction-loop candidate; reference errors and checks saved',elapsed_seconds=time.monotonic()-started,ended_utc=core.datetime.now(core.timezone.utc).isoformat())
    if chosen:record['candidate']=chosen['candidate']
    core.save(folder/'result.json',record);return record
