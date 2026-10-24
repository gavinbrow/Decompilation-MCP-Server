"""Bounded, non-AI x86 integer lifting and C++ candidate search.

No service calls. Only the official fnvcheck may establish a MATCH. This subset
supports initialized scalar stack locals and bounded named-call sequences.
Arbitrary writes, unknown pointer accesses and unstructured control flow remain
rejected; separate family generators handle additional structured loops/calls.
Private analysis and candidates stay inside the original pack directory.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from datetime import datetime,timezone
try:
    import capstone as cs
    import pefile
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[1]/'.venv/Lib/site-packages'))
    import capstone as cs
    import pefile

ROOT=Path(__file__).resolve().parents[1]
MASK=0xffffffff
MAX_CANDIDATES=96
MAX_SECONDS=90
MAX_CHECKS=32
GPU_UUID=os.environ.get('FNV_FILTER_GPU_UUID','')

class Unsupported(ValueError):pass
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def save(p,v):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
    t=p.with_suffix('.tmp');t.write_text(json.dumps(v,indent=2));os.replace(t,p)
def const(x):return ('const',int(x)&MASK)
def binary(op,a,b):return (op,a,b)
def nodes(e):return 1+sum(nodes(x) for x in e[1:] if isinstance(x,tuple))

def register_inputs(e):
    found={e[1]} if e[0]=='regarg' else set()
    for child in e[1:]:
        if isinstance(child,tuple):found.update(register_inputs(child))
    return found

def lift(data,address=0,expected_size=None,capture=None):
    """Fail closed on every unimplemented instruction/operand/ABI feature."""
    decoder=cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_32);decoder.detail=True
    code=list(decoder.disasm(data,address))
    if not code or sum(i.size for i in code)!=len(data):raise Unsupported('incomplete_instruction_decode')
    if expected_size is not None and len(data)!=expected_size:raise Unsupported('incomplete_reference_span')
    if len(code)>48 or code[-1].mnemonic!='ret':raise Unsupported('requires_straight_line_return')
    regs={'ecx':('this',),'edx':('regarg',1)};register_args=set();saved=[];sp=0;frame=None;fields=set();args=set();operations=0;flags=None;carry=None;comparison_flags=None
    stack_values={};bindings=[];allocation=[];calls=[];pushed=[];caller_cleanup=0;member_storage=False
    def stack_offset(i,o):
        if o.type!=cs.x86.X86_OP_MEM or o.mem.index or o.mem.segment:return None
        base=i.reg_name(o.mem.base)
        if base=='esp':return o.mem.disp+sp
        if base=='ebp' and frame is not None:return o.mem.disp+frame
        return None
    def value(i,o):
        if o.type==cs.x86.X86_OP_IMM:return const(o.imm)
        if o.type==cs.x86.X86_OP_REG:
            r=i.reg_name(o.reg)
            if r not in regs or regs[r] is None:raise Unsupported('undefined_or_pointer_register:'+r)
            expression=regs[r]
            if expression==('this',):
                expression=('regarg',0)
            register_args.update(register_inputs(expression))
            return expression
        if o.type!=cs.x86.X86_OP_MEM or o.size!=4 or o.mem.index or o.mem.segment:raise Unsupported('unsupported_memory_operand')
        base=i.reg_name(o.mem.base);d=o.mem.disp
        if base in ('esp','ebp'):
            offset=d+(sp if base=='esp' else frame if frame is not None else -9999)
            if offset<0:
                if offset not in stack_values:raise Unsupported('uninitialized_stack_local')
                return stack_values[offset]
            if offset<4 or offset%4 or offset>64:raise Unsupported('stack_local_or_invalid_argument')
            arg=offset//4-1;args.add(arg);return ('arg',arg)
        if regs.get(base)==('this',) and 0<=d<=256 and d%4==0:
            fields.add(d);return ('field',d)
        raise Unsupported('unsupported_pointer_or_absolute_memory')
    for n,i in enumerate(code):
        op=i.mnemonic;operands=i.operands
        if capture is not None and n==capture[0]:
            expression=value(i,operands[capture[1]])
            return dict(expression=expression,fields=sorted(fields),register_args=sorted(register_args),arg_count=max(args)+1 if args else 0)
        if op=='ret':
            if n!=len(code)-1 or saved or sp!=0 or pushed or caller_cleanup:raise Unsupported('unbalanced_frame_or_early_return')
            cleanup=operands[0].imm if operands else 0
            if cleanup<0 or cleanup%4 or cleanup>64:raise Unsupported('unsupported_return_cleanup')
            if cleanup and args and max(args)>=cleanup//4:raise Unsupported('argument_cleanup_mismatch')
            break
        if op=='push' and len(operands)==1 and operands[0].type==cs.x86.X86_OP_REG and i.reg_name(operands[0].reg) in ('ebp','ebx','esi','edi') and i.reg_name(operands[0].reg) not in regs:
            r=i.reg_name(operands[0].reg)
            saved.append((r,regs.get(r),sp-4));sp-=4;continue
        if op=='push' and len(operands)==1:
            if len(pushed)>=8:raise Unsupported('call_argument_limit')
            pushed.append(value(i,operands[0]));sp-=4;continue
        if op=='pop' and len(operands)==1 and saved:
            r=i.reg_name(operands[0].reg);old,v,position=saved.pop()
            if r!=old or sp!=position:raise Unsupported('nonstandard_register_restore')
            regs[r]=v;sp+=4;continue
        if op=='mov' and i.op_str=='ebp, esp':frame=sp;continue
        if op=='mov' and i.op_str=='esp, ebp' and frame is not None:
            if pushed or caller_cleanup:raise Unsupported('unbalanced_call_frame')
            sp=frame;allocation=[];continue
        if op in ('sub','add') and len(operands)==2 and operands[0].type==cs.x86.X86_OP_REG and i.reg_name(operands[0].reg)=='esp' and operands[1].type==cs.x86.X86_OP_IMM:
            amount=operands[1].imm
            if amount<0 or amount%4 or amount>256:raise Unsupported('unsupported_stack_allocation')
            flags=None;carry=None;comparison_flags=None
            if op=='sub':
                allocation.append((sp-amount,sp));sp-=amount
            elif caller_cleanup:
                if amount!=caller_cleanup:raise Unsupported('partial_caller_cleanup')
                sp+=amount;caller_cleanup=0
            elif allocation and amount==allocation[-1][1]-allocation[-1][0]:sp+=amount;allocation.pop()
            else:raise Unsupported('untracked_stack_cleanup')
            continue
        if op=='mov' and len(operands)==2 and operands[0].type==cs.x86.X86_OP_MEM:
            offset=stack_offset(i,operands[0])
            if operands[0].size!=4 or offset is None or not any(lo<=offset<hi for lo,hi in allocation) or offset%4:raise Unsupported('nonlocal_memory_write')
            src=operands[1];expr=regs.get(i.reg_name(src.reg)) if src.type==cs.x86.X86_OP_REG else None
            expr=expr if expr==('this',) else value(i,src)
            if offset in stack_values:raise Unsupported('reassigned_stack_local_requires_loop_lifter')
            stack_values[offset]=expr
            if expr==('this',):member_storage=True
            if expr!=('this',):bindings.append(dict(offset=offset,expression=expr))
            continue
        if op=='call':
            if len(calls)>=4 or caller_cleanup:raise Unsupported('call_sequence_limit')
            if len(operands)!=1 or operands[0].type!=cs.x86.X86_OP_IMM:raise Unsupported('indirect_call_requires_signature')
            target=operands[0].imm & MASK
            index=_function_index()
            if target not in index:raise Unsupported('call_target_missing_from_function_index')
            cleanup_next=code[n+1] if n+1<len(code) else None
            cdecl=bool(cleanup_next and cleanup_next.mnemonic=='add' and cleanup_next.op_str.startswith('esp,'))
            receiver=regs.get('ecx')
            member=not cdecl and receiver==('this',)
            if not cdecl and not member and pushed:raise Unsupported('unknown_callee_calling_convention')
            if not cdecl and not member:raise Unsupported('call_without_proven_calling_convention')
            arguments=list(reversed(pushed));amount=4*len(arguments)
            symbol=f'FUN_{target:08x}'
            declaration=_call_declaration(target,len(arguments),member)
            calls.append(dict(target=symbol,arguments=arguments,member=member,declaration=declaration,fields_before=sorted(fields)))
            if cdecl:caller_cleanup=amount
            else:sp+=amount
            pushed=[]
            if declaration['return_type']=='void':regs.pop('eax',None)
            else:regs['eax']=('call',len(calls)-1)
            regs.pop('ecx',None);regs.pop('edx',None);flags=None;carry=None;comparison_flags=None;operations+=1
            continue
        if op in ('cmp','test') and len(operands)==2:
            a,b=value(i,operands[0]),value(i,operands[1]);flags=('sub',a,b) if op=='cmp' else ('and',a,b);carry=('ult',a,b) if op=='cmp' else const(0);comparison_flags=(op,a,b);continue
        if not operands or operands[0].type!=cs.x86.X86_OP_REG:raise Unsupported('memory_write_or_control_flow:'+op)
        dst=i.reg_name(operands[0].reg)
        if dst in ('esp','ebp'):raise Unsupported('stack_mutation')
        if op=='mov' and len(operands)==2:
            src=operands[1]
            # Preserve the symbolic this pointer only for register copies.
            expr=regs.get(i.reg_name(src.reg)) if src.type==cs.x86.X86_OP_REG else None
            expr=expr if expr==('this',) else value(i,src)
            if operands[0].size!=4:raise Unsupported('partial_register_write')
            regs[dst]=expr;continue
        if op=='lea' and len(operands)==2:
            m=operands[1].mem
            if m.segment or operands[1].type!=cs.x86.X86_OP_MEM:raise Unsupported('unsupported_lea')
            expr=const(m.disp)
            for r,scale in [(m.base,1),(m.index,m.scale)]:
                if r:
                    reg=i.reg_name(r)
                    if reg not in regs or regs[reg][0]=='this':raise Unsupported('pointer_lea')
                    part=regs[reg] if scale==1 else ('mul',regs[reg],const(scale))
                    expr=part if expr==const(0) else ('add',expr,part)
            regs[dst]=expr;operations+=1;continue
        if op.startswith('set') and dst=='al' and flags is not None:
            if regs.get('eax')!=const(0):raise Unsupported('setcc_with_unknown_upper_bits')
            if comparison_flags is not None:
                kind,a,b=comparison_flags;test=comparison_condition(op,a,b,kind)
            elif op in ('sete','setz','setne','setnz'):
                test=('eq' if op in ('sete','setz') else 'ne',flags,const(0))
            else:raise Unsupported('setcc_without_explicit_comparison')
            regs['eax']=test;operations+=1;continue
        if op.startswith('cmov') and len(operands)==2 and operands[0].size==4:
            if comparison_flags is None:raise Unsupported('cmov_without_explicit_comparison')
            kind,a,b=comparison_flags
            regs[dst]=('select',comparison_condition(op,a,b,kind),value(i,operands[1]),value(i,operands[0]));operations+=1;continue
        if op=='movzx' and dst=='eax' and len(operands)==2 and operands[1].type==cs.x86.X86_OP_REG and i.reg_name(operands[1].reg)=='al' and regs.get('eax',(None,))[0] in ('eq','ne','slt','sle','sgt','sge','ult','ule','ugt','uge'):
            continue
        if operands[0].size!=4:raise Unsupported('partial_register_arithmetic')
        if op in ('xor','sub') and len(operands)==2 and operands[1].type==cs.x86.X86_OP_REG and i.reg_name(operands[1].reg)==dst:
            regs[dst]=const(0);flags=regs[dst];carry=const(0);comparison_flags=None;continue
        if op=='sbb' and len(operands)==2 and operands[1].type==cs.x86.X86_OP_REG and i.reg_name(operands[1].reg)==dst:
            if carry is None:raise Unsupported('sbb_without_proven_carry')
            regs[dst]=('neg',carry);flags=regs[dst];comparison_flags=None;operations+=1;continue
        if op in ('add','sub','and','or','xor','shl','sal','shr','sar','imul'):
            if op=='imul' and len(operands)==3:a,b=value(i,operands[1]),value(i,operands[2])
            elif len(operands)==2:a,b=value(i,operands[0]),value(i,operands[1])
            else:raise Unsupported('unsupported_arithmetic_arity')
            operation={'imul':'mul','sal':'shl'}.get(op,op)
            if operation in ('shl','shr','sar') and b[0]!='const':raise Unsupported('variable_shift_count')
            comparison_flags=None
            regs[dst]=(operation,a,b);flags=None if operation in ('mul','shl','shr','sar') else regs[dst]
            carry=('ult',a,b) if operation=='sub' else ('ult',regs[dst],a) if operation=='add' else const(0) if operation in ('and','or','xor') else None
            operations+=1
        elif op in ('neg','not','inc','dec') and len(operands)==1:
            a=value(i,operands[0]);regs[dst]=(op,a) if op in ('neg','not') else ('add' if op=='inc' else 'sub',a,const(1))
            if op!='not':flags=regs[dst];comparison_flags=None
            if op=='neg':carry=('ne',a,const(0))
            operations+=1
        else:raise Unsupported('unsupported_instruction:'+op)
        if nodes(regs[dst])>80:raise Unsupported('expression_complexity_limit')
    result=regs.get('eax')
    if result is None and calls and calls[-1]['declaration']['return_type']=='void':result=('void',)
    if not result or result[0]=='this':raise Unsupported('no_scalar_return_value')
    def contains_field(e):return e[0]=='field' or any(contains_field(x) for x in e[1:] if isinstance(x,tuple))
    if any(c['fields_before'] for c in calls) and (len(calls)!=1 or bindings or contains_field(result)):
        raise Unsupported('field_aliasing_across_call_requires_summary')
    register_args.update(register_inputs(result))
    for binding in bindings:register_args.update(register_inputs(binding['expression']))
    for call in calls:
        for argument in call['arguments']:register_args.update(register_inputs(argument))
    if register_args and (fields or member_storage or any(c['member'] for c in calls)):raise Unsupported('ambiguous_member_and_fastcall_registers')
    return dict(expression=result,fields=sorted(fields),register_args=sorted(register_args),arg_count=max(cleanup//4,max(args)+1 if args else 0),member=bool(fields) or member_storage or any(c['member'] for c in calls),cleanup=cleanup,operations=operations,instructions=len(code),bindings=bindings,calls=calls)

_INDEX=None
_CALL_SYMBOLS=None
_MATCHED_CONTRACTS=None
def _function_index():
    global _INDEX
    if _INDEX is None:_INDEX={int(r['address'],16) for r in read(ROOT/'local/shared/function_index.json')}
    return _INDEX

def _call_declaration(target,count,member):
    """Only an actual supplied decorated symbol may define a callable ABI."""
    global _CALL_SYMBOLS,_MATCHED_CONTRACTS
    if _CALL_SYMBOLS is None:
        _CALL_SYMBOLS={}
        for row in read(ROOT/'local/shared/fnvdecomp_symbols.json')['functions']:_CALL_SYMBOLS.setdefault(int(row['address'],16),[]).append(row['symbol'])
    name=f'FUN_{target:08x}'
    # Int-only signatures in the supported first call subset. No fabricated alias.
    import re
    types={'H':'int','I':'unsigned int','X':'void','_N':'bool'}
    for symbol in _CALL_SYMBOLS.get(target,[]):
        if member:
            match=re.fullmatch(r'\?'+name+r'@([A-Za-z_]\w*)@@QAE(H|I|X|_N)(.*)@Z',symbol)
            if not match:continue
            owner,ret,encoded=match.groups()
        else:
            match=re.fullmatch(r'\?'+name+r'@@YA(H|I|X|_N)(.*)@Z',symbol)
            if not match:continue
            ret,encoded=match.groups();owner=None
        parameters=[]
        while encoded and encoded!='X':
            token='_N' if encoded.startswith('_N') else encoded[0]
            if token not in types or token=='X':break
            parameters.append(types[token]);encoded=encoded[len(token):]
        if len(parameters)==count and encoded in ('','X'):
            return dict(name=name,owner=owner,return_type=types[ret],argument_types=parameters)
    if not member:
        if _MATCHED_CONTRACTS is None:
            import importlib.util
            spec=importlib.util.spec_from_file_location('call_knowledge',ROOT/'scripts/matched-knowledge.py')
            knowledge=importlib.util.module_from_spec(spec);spec.loader.exec_module(knowledge)
            _MATCHED_CONTRACTS=knowledge.load_data().get('call_contracts',{})
        known=_MATCHED_CONTRACTS.get(f'{target:08x}')
        if known and len(known['argument_types'])==count:
            return dict(name=name,owner=None,return_type=known['return_type'],argument_types=known['argument_types'],
                        learned_from_contributions=True)
    # The official checker supports deriving unnamed relocation bindings. The
    # target must still be a real function-index entry and its ABI must be proven
    # by this call site; this supplies a readable stand-in, not an address cast.
    return dict(name=name,owner='CallTarget_'+format(target,'08x') if member else None,return_type='int',argument_types=['int']*count,inferred_from_callsite=True)

def comparison_condition(mnemonic,a,b,kind='cmp'):
    """32-bit condition from an explicit CMP/TEST, including sign-only jumps."""
    suffix=mnemonic[1:] if mnemonic.startswith('j') else mnemonic[3:] if mnemonic.startswith('set') else mnemonic[4:]
    if kind=='test':a,b=('and',a,b),const(0)
    operation={'e':'eq','z':'eq','ne':'ne','nz':'ne','l':'slt','le':'sle','g':'sgt','ge':'sge','b':'ult','c':'ult','nae':'ult','be':'ule','na':'ule','a':'ugt','nbe':'ugt','ae':'uge','nb':'uge','nc':'uge'}.get(suffix)
    if operation:return (operation,a,b)
    if suffix in ('s','ns'):
        # SF is the sign bit of the wrapped subtraction, not signed A < B:
        # these differ when a subtraction overflows.
        difference=('sub',a,b)
        return ('ne' if suffix=='s' else 'eq',('and',difference,const(0x80000000)),const(0))
    raise Unsupported('unsupported_condition:'+mnemonic)


def lift_branch(data,address=0):
    """Bounded acyclic, side-effect-free decision tree: <=4 branches/8 leaves.

    Each complete path is lifted independently by the straight-line verifier.
    There is no speculative native execution and every reachable path must be
    supported. Backedges, external jumps, calls and incompatible cleanup fail.
    """
    decoder=cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_32);decoder.detail=True
    code=list(decoder.disasm(data,address));indexes={i.address:n for n,i in enumerate(code)}
    if not code or sum(i.size for i in code)!=len(data) or len(code)>48:raise Unsupported('conditional_decode_or_complexity_limit')
    branches=[n for n,i in enumerate(code) if i.mnemonic.startswith('j') and i.mnemonic!='jmp']
    if not 1<=len(branches)<=4:raise Unsupported('requires_bounded_forward_conditionals')
    if any(i.mnemonic=='call' for i in code):raise Unsupported('conditional_calls_require_control_flow_summary')
    leaves=[];conditions=[];walks=0
    def destination(i,position):
        if len(i.operands)!=1 or i.operands[0].type!=cs.x86.X86_OP_IMM:raise Unsupported('indirect_branch')
        target=indexes.get(i.operands[0].imm)
        if target is None or target<=position:raise Unsupported('backward_or_external_branch')
        return target
    def walk(position,prefix):
        nonlocal walks
        walks+=1
        if walks>15:raise Unsupported('conditional_path_limit')
        prefix=list(prefix)
        while position<len(code):
            i=code[position]
            if i.mnemonic=='jmp':position=destination(i,position);continue
            if i.mnemonic.startswith('j'):
                comparisons=[n for n,item in enumerate(prefix) if item.mnemonic in ('cmp','test')]
                if not comparisons:raise Unsupported('conditional_without_supported_comparison')
                comparison=comparisons[-1]
                if any(item.mnemonic not in ('mov','lea') for item in prefix[comparison+1:]):raise Unsupported('conditional_flags_modified')
                # A temporary RET makes the partial prefix independently decodable;
                # capture stops before the comparison and does not consume the RET.
                linear=b''.join(item.bytes for item in prefix)+b'\xc3'
                left=lift(linear,address,capture=(comparison,0));right=lift(linear,address,capture=(comparison,1))
                condition=comparison_condition(i.mnemonic,left['expression'],right['expression'],prefix[comparison].mnemonic)
                conditions.extend((left,right))
                yes=walk(destination(i,position),prefix)
                no=walk(position+1,prefix)
                return ('select',condition,yes,no)
            prefix.append(i)
            if i.mnemonic=='ret':
                if len(leaves)>=8:raise Unsupported('conditional_leaf_limit')
                plan=lift(b''.join(item.bytes for item in prefix),address)
                if plan.get('calls'):raise Unsupported('conditional_calls_require_control_flow_summary')
                leaves.append(plan);return plan['expression']
            position+=1
        raise Unsupported('missing_return_path')
    expression=walk(0,[])
    if len({p['cleanup'] for p in leaves})!=1:raise Unsupported('conditional_cleanup_mismatch')
    plans=leaves+conditions
    fields=sorted({field for plan in plans for field in plan['fields']})
    register_args=sorted({r for p in plans for r in p.get('register_args',[])})
    if register_args and fields:raise Unsupported('ambiguous_member_and_fastcall_registers')
    return dict(expression=expression,fields=fields,register_args=register_args,arg_count=max(p['arg_count'] for p in plans),member=any(p.get('member') for p in leaves) or bool(fields),cleanup=leaves[0]['cleanup'],operations=sum(p['operations'] for p in leaves)+len(branches),instructions=len(code),conditional=True,conditional_branches=len(branches),conditional_leaves=len(leaves))

def analyze(pack):
    meta=read(Path(pack)/'pack.json');size=int(meta['size'])
    if not 1<=size<=255:raise Unsupported('outside_255_byte_search_scope')
    pe=pefile.PE(read(ROOT/'local/settings.json')['checker_image'],fast_load=True)
    try:
        address=int(meta['address'],16);data=pe.get_data(address-pe.OPTIONAL_HEADER.ImageBase,size)
        try:plan=lift(data,address,size)
        except Unsupported as first:
            if len(data)!=size:raise Unsupported('incomplete_reference_span')
            try:plan=lift_branch(data,address)
            except Unsupported:raise first
        upper=pe.OPTIONAL_HEADER.ImageBase+pe.OPTIONAL_HEADER.SizeOfImage
        def guard(e):
            if e[0]=='const' and pe.OPTIONAL_HEADER.ImageBase<=e[1]<upper:raise Unsupported('game_address_literal_requires_named_symbol')
            for x in e[1:]:
                if isinstance(x,tuple):guard(x)
        guard(plan['expression'])
        for binding in plan.get('bindings',[]):guard(binding['expression'])
        for call in plan.get('calls',[]):
            for argument in call['arguments']:guard(argument)
    finally:pe.close()
    plan['meta']=meta
    context=Path(pack)/meta.get('source','')
    plan['context_source']=context.read_text(encoding='utf-8',errors='replace') if context.is_file() else ''
    return plan

def render(e):
    op=e[0]
    if op=='const':return str(e[1])+'u'
    if op=='arg':return 'arg'+str(e[1])
    if op=='regarg':return 'registerArg'+str(e[1])
    if op=='call':return 'callResult'+str(e[1])
    if op=='source_local':return e[1]
    if op=='void':return ''
    if op=='field':return 'field'+format(e[1],'02x')
    if op in ('neg','not'):return '('+('0u - ' if op=='neg' else '~')+render(e[1])+')'
    if op=='select':return f'({render(e[1])} ? {render(e[2])} : {render(e[3])})'
    a,b=render(e[1]),render(e[2])
    if op in ('slt','sle','sgt','sge','ult','ule','ugt','uge'):
        symbol={'lt':'<','le':'<=','gt':'>','ge':'>='}[op[1:]]
        if op[0]=='s':a,b=f'(int){a}',f'(int){b}'
        return f'({a} {symbol} {b})'
    if op=='sar':return f'((unsigned int)((int){a} >> ({b} & 31u)))'
    symbol={'add':'+','sub':'-','mul':'*','and':'&','or':'|','xor':'^','shl':'<<','shr':'>>','eq':'==','ne':'!='}[op]
    if op in ('shl','shr'):b=f'({b} & 31u)'
    return f'({a} {symbol} {b})'

def source(plan,expression,style=0):
    expr=render(expression);name=plan['meta']['symbol'];kind='void' if expression[0]=='void' else 'bool' if expression[0] in ('eq','ne') and style%3==2 else 'unsigned int' if style%3==1 else 'int'
    parameters=['unsigned int registerArg'+str(i) for i in range(2)] if plan.get('register_args') else []
    parameters+=['unsigned int arg'+str(i) for i in range(plan['arg_count'])]
    # VC2008 tail-call eligibility depends on the complete cdecl parameter list,
    # including unused trailing parameters. Bound this ABI variant to two words.
    if kind=='void' and plan.get('calls') and not plan['member'] and not plan['cleanup'] and not plan.get('register_args'):
        parameters += ['unsigned int unused'+str(i) for i in range(style%3)]
    params=', '.join(parameters)
    declaration='';qualifier=''
    if plan['member']:
        fields=''.join(f'    unsigned int field{i:02x};\n' for i in range(0,max(plan['fields'])+4 if plan['fields'] else 0,4))
        declaration=f'struct SearchObject {{\n{fields}    {kind} {name}({params});\n}};\n';qualifier='SearchObject::'
    else:qualifier='__fastcall ' if plan.get('register_args') else '__stdcall ' if plan['cleanup'] else '__cdecl '
    body='    return;' if kind=='void' else f'    return ({kind}){expr};'
    if style>=3 and kind!='void':
        local='result' if style<6 else 'value'
        body=f'    unsigned int {local} = {expr};\n    return ({kind}){local};'
    if style>=6 and expression[0]=='select':
        body=f'    if ({render(expression[1])})\n        return ({kind}){render(expression[2])};\n    return ({kind}){render(expression[3])};'
    call_lines=[];helpers=[];owners=set()
    for number,call in enumerate(plan.get('calls',[])):
        declaration_info=call['declaration'];owner=declaration_info['owner'];target=call['target']
        signature=', '.join(declaration_info['argument_types'])
        return_type=declaration_info['return_type']
        if owner:
            import re
            if owner not in owners and not re.search(r'\b(?:struct|class)\s+'+re.escape(owner)+r'\b',plan.get('context_source','')):
                helpers.append(f'struct {owner} {{ {return_type} {target}({signature}); }};\n');owners.add(owner)
            function=f'(({owner}*)this)->{target}'
        else:
            helpers.append(f'{return_type} __cdecl {target}({signature});\n');function=target
        arguments=', '.join('('+arg_type+')'+render(arg) for arg_type,arg in zip(declaration_info['argument_types'],call['arguments']))
        if return_type=='void':call_lines.append(f'    {function}({arguments});')
        else:call_lines.append(f'    unsigned int callResult{number} = (unsigned int){function}({arguments});')
    if style>=3 and plan.get('bindings') and kind!='void':
        aliases={};local_lines=[]
        def aliased(e):
            def substitute(node):
                if node in aliases:return ('source_local',aliases[node])
                return tuple(substitute(x) if isinstance(x,tuple) else x for x in node)
            return render(substitute(e))
        for number,binding in enumerate(plan['bindings']):
            local=('local' if style<6 else 'value')+str(number)
            local_lines.append(f'    unsigned int {local} = {aliased(binding["expression"])};')
            aliases[binding['expression']]=local
        body='\n'.join(local_lines)+f'\n    return ({kind}){aliased(expression)};'
    if call_lines:body='\n'.join(call_lines)+'\n'+body
    declaration=''.join(helpers)+declaration
    return declaration+f'{kind} {qualifier}{name}({params})\n{{\n{body}\n}}\n'

def variants(reference,limit=MAX_CANDIDATES):
    """Bounded grammar neighborhood; includes incorrect alternatives for filtering."""
    found=[reference];seen={reference}
    def add(e):
        if e not in seen and nodes(e)<=100 and len(found)<limit:seen.add(e);found.append(e)
    def edits(e):
        op=e[0];out=[]
        if len(e)==3 and isinstance(e[1],tuple) and isinstance(e[2],tuple):
            a,b=e[1:]
            if op in ('add','mul','and','or','xor','eq','ne'):out.append((op,b,a))
            if op in ('add','sub','and','or','xor'):
                out.extend((replacement,a,b) for replacement in ('add','sub','and','or','xor') if replacement!=op)
            if op=='add':out.append(('sub',a,('neg',b)))
            if op=='sub':out.append(('add',a,('neg',b)))
            if op in ('add','and','or','xor') and a[0]==op:out.append((op,a[1],(op,a[2],b)))
            if op=='mul' and b[0]=='const' and 1<b[1]<=16:
                terms=[('shl',a,const(bit)) if bit else a for bit in range(5) if b[1]&(1<<bit)]
                x=terms[0]
                for t in terms[1:]:x=('add',x,t)
                out.append(x)
        for i,x in enumerate(e[1:],1):
            if isinstance(x,tuple):
                for v in edits(x):out.append(e[:i]+(v,)+e[i+1:])
        return out[:limit]
    frontier=[reference]
    for _ in range(2):
        following=[]
        for e in frontier:
            for v in edits(e):
                if v not in seen:add(v);following.append(v)
                if len(found)>=limit:return found
        frontier=following
    return found

def evaluate(e,xp,env):
    op=e[0]
    if op=='const':return e[1]
    if op in ('arg','regarg','field','call'):return env[(op,e[1])]
    a=evaluate(e[1],xp,env)
    if op=='select':return xp.where(a!=0,evaluate(e[2],xp,env),evaluate(e[3],xp,env))
    if op=='not':return ~a & MASK
    if op=='neg':return (0-a)&MASK
    b=evaluate(e[2],xp,env)
    if op in ('slt','sle','sgt','sge','ult','ule','ugt','uge'):
        if op[0]=='s':a,b=((a^0x80000000)-0x80000000),((b^0x80000000)-0x80000000)
        result={'lt':lambda:a<b,'le':lambda:a<=b,'gt':lambda:a>b,'ge':lambda:a>=b}[op[1:]]()
        if hasattr(result,'astype'):return result.astype('int64')
        if hasattr(result,'to'):return result.to(dtype=xp.int64)
        return int(result)
    if op=='sar':
        # int64 representation of sign-extended int32, on both backends.
        return (((a ^ 0x80000000)-0x80000000) >> (b&31))&MASK
    if op=='shl':return (a << (b&31))&MASK
    if op=='shr':return (a >> (b&31))&MASK
    if op in ('eq','ne'):
        result=a==b if op=='eq' else a!=b
        if hasattr(result,'astype'):return result.astype('int64')
        if hasattr(result,'to'):return result.to(dtype=xp.int64)
        return int(result)
    return {'add':lambda:(a+b)&MASK,'sub':lambda:(a-b)&MASK,'mul':lambda:(a*b)&MASK,'and':lambda:a&b,'or':lambda:a|b,'xor':lambda:a^b}[op]()

def _legacy_filter_expressions(plan,expressions,backend='cpu',sample_count=8192):
    import numpy as np
    if plan['expression']==('void',):return expressions,dict(backend='cpu',gpu_work_performed=False,samples=0,candidates=len(expressions),survivors=len(expressions),rejected=0,note='Void call order and arguments preserved; official checker required')
    begun=time.monotonic();rng=np.random.default_rng(0xF04)
    edges=np.array([0,1,2,31,32,255,65535,0x7fffffff,0x80000000,0xfffffffe,0xffffffff],dtype=np.int64)
    keys=[('regarg',i) for i in plan.get('register_args',[])]+[('arg',i) for i in range(plan['arg_count'])]+[('field',i) for i in plan['fields']]+[('call',i) for i in range(len(plan.get('calls',[])))]
    env={k:np.concatenate((np.roll(edges,n),rng.integers(0,2**32,size=sample_count-len(edges),dtype=np.int64))) for n,k in enumerate(keys)}
    reference=evaluate(plan['expression'],np,env)
    cpu_mask=[bool(np.all(evaluate(e,np,env)==reference)) for e in expressions]
    gpu=False;device_name=None
    if backend=='cuda':
        if os.environ.get('CUDA_VISIBLE_DEVICES') not in (None,'',GPU_UUID):raise RuntimeError('GPU visibility pinned to another device')
        os.environ['CUDA_VISIBLE_DEVICES']=GPU_UUID
        import torch
        if not torch.cuda.is_available() or torch.cuda.device_count()!=1:raise RuntimeError('Configured CUDA device unavailable')
        device_name=torch.cuda.get_device_name(0)
        if torch.cuda.mem_get_info(0)[0]<512*1024**2:raise RuntimeError('Insufficient CUDA device memory')
        device_env={k:torch.from_numpy(v).to('cuda') for k,v in env.items()}
        expected=torch.as_tensor(reference,device='cuda')
        gpu_mask=[]
        for e in expressions:
            actual=torch.as_tensor(evaluate(e,torch,device_env),device='cuda')
            gpu_mask.append(bool(torch.all(actual==expected).item()))
        if gpu_mask!=cpu_mask:raise RuntimeError('GPU/CPU semantic-filter disagreement')
        gpu=True
    return [e for e,ok in zip(expressions,cpu_mask) if ok],dict(backend=backend,gpu_work_performed=gpu,device=device_name,samples=sample_count,candidates=len(expressions),survivors=sum(cpu_mask),rejected=len(expressions)-sum(cpu_mask),elapsed_seconds=time.monotonic()-begun,note='Sample filter only; calls modeled as independent opaque results with source call order/arguments preserved; official byte match required')

_BATCH_FILTER=None
def filter_expressions(plan,expressions,backend='cpu',sample_count=8192):
    """Use reusable batched filtering; comparison remains the official checker's."""
    global _BATCH_FILTER
    if plan['expression']==('void',):
        return _legacy_filter_expressions(plan,expressions,backend,sample_count)
    if _BATCH_FILTER is None:
        spec=importlib.util.spec_from_file_location('fnv_candidate_filter',ROOT/'scripts/candidate-filter.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        _BATCH_FILTER=module
    return _BATCH_FILTER.filter_integer(plan,expressions,backend,sample_count)

def check_candidate(pack,folder,number,text,worker):
    candidate=folder/f'candidate-{number:03d}.cpp';candidate.write_text(text)
    save(candidate.with_name(candidate.name+'.provenance.json'),dict(model='Non-AI CPU C++ generator',source_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),generator='integer-search/check_candidate',llm_calls=0))
    review=subprocess.run([str(ROOT/'.venv/Scripts/python.exe'),str(ROOT/'scripts/source-address-review.py'),str(candidate)],capture_output=True,text=True,timeout=15)
    if review.returncode:return dict(status='source_review_required',candidate=str(candidate),attempt=number)
    command=[shutil.which('pwsh.exe'),'-NoProfile','-File',str(ROOT/'scripts/fnvcheck.ps1'),'-Pack',str(pack),'-Candidate',str(candidate),'-Worker',f'{worker}_search_{number:03d}','-Json']
    try:
        p=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=45)
        result=json.loads(p.stdout.lstrip('\ufeff'));result['return_code']=p.returncode
    except (subprocess.TimeoutExpired,ValueError) as e:result=dict(status='checker_error',reason=type(e).__name__)
    result.update(candidate=str(candidate),attempt=number);save(folder/f'check-{number:03d}.json',result)
    return result

def score(check):
    if check.get('status')=='match' and check.get('return_code')==0:return (0,0,0)
    # Diagnostic ranking only: no tolerance is used for acceptance.
    return (1 if check.get('status')=='wip' else 2,int(check.get('ndiff_insn') or 99999),int(check.get('diffs') or 99999))

def feedback(check,pending):
    lines=str(check.get('diff') or '').splitlines()
    original=next((line[5:] for line in lines if line.startswith('ORIG ')),'')
    candidate=next((line[6:] for line in lines if line.startswith('YOURS ')),'')
    operation=original.split(' ',1)[0]
    preferred={'imul':' * ','shl':' << ','sal':' << ','shr':' >> ','sar':' >> ','and':' & ','or':' | ','xor':' ^ ','lea':' * '}.get(operation)
    if preferred:pending=sorted(pending,key=lambda text:preferred not in text)
    return pending,dict(first_original=original,first_candidate=candidate,prioritized_cpp_operator=preferred)

def search(pack,worker='cpu_search',backend='cpu',max_checks=MAX_CHECKS,jobs=4,seconds=MAX_SECONDS):
    if not 1<=jobs<=8 or not 1<=max_checks<=96 or not 1<=seconds<=300:raise ValueError('Search budget outside bounds')
    started=time.monotonic();pack=Path(pack).resolve();folder=pack/worker/'integer-search';folder.mkdir(parents=True,exist_ok=True)
    meta=read(pack/'pack.json');record=dict(owner=worker,claim_id=pack.name,symbol=meta['symbol'],size=meta['size'],pattern='integer_symbolic_search',llm_calls=0,service_calls=0,checker_attempts=0,gpu_work_performed=False,outcome='unsupported',started_utc=datetime.now(timezone.utc).isoformat(),compiler_jobs=jobs,max_checks=max_checks,max_seconds=seconds)
    try:plan=analyze(pack)
    except Unsupported as e:
        record['reason']=str(e);record['elapsed_seconds']=time.monotonic()-started;record['ended_utc']=datetime.now(timezone.utc).isoformat();save(folder/'result.json',record);return record
    save(folder/'analysis.json',plan)
    survivors,filter_stats=filter_expressions(plan,variants(plan['expression']),backend)
    record.update(semantic_filter=filter_stats,gpu_work_performed=filter_stats['gpu_work_performed'])
    sources=[];seen=set()
    # First check direct forms of every surviving expression, then local forms.
    for styles in (range(3),range(3,9)):
        for e in survivors:
            for style in styles:
                text=source(plan,e,style)
                if text not in seen:seen.add(text);sources.append(text)
    record['variants_generated']=len(sources);checks=[];chosen=None
    feedback_records=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for start in range(0,min(len(sources),max_checks),jobs):
            if time.monotonic()-started>seconds-45:record['budget_reason']='wall_time_budget';break
            futures=[pool.submit(check_candidate,pack,folder,i+1,sources[i],worker) for i in range(start,min(start+jobs,len(sources),max_checks))]
            batch=[f.result() for f in futures];checks.extend(batch)
            best=min(batch,key=score)
            save(folder/'progress.json',dict(checks=len(checks),best_attempt=best['attempt'],best_score=score(best),elapsed_seconds=time.monotonic()-started))
            match=next((c for c in batch if score(c)[0]==0),None)
            if match:chosen=match;break
            # First-difference evidence orders subsequent source styles.
            # No compiler flags, reference spans or comparisons are modified.
            pending,hint=feedback(best,sources[start+jobs:]);sources[start+jobs:]=pending
            feedback_records.append(dict(after_attempt=best['attempt'],**hint))
            save(folder/'feedback.json',feedback_records)
    record.update(outcome='match' if chosen else 'blocked',checker_attempts=len(checks),elapsed_seconds=time.monotonic()-started,reason='' if chosen else 'Bounded candidate search exhausted; inspect first instruction difference',best_attempt=min(checks,key=score)['attempt'] if checks else None)
    if chosen:record['candidate']=chosen['candidate']
    record['ended_utc']=datetime.now(timezone.utc).isoformat()
    save(folder/'result.json',record);return record

def main():
    p=argparse.ArgumentParser();p.add_argument('--pack',type=Path,required=True);p.add_argument('--worker',default='cpu_search');p.add_argument('--backend',choices=['cpu','cuda'],default='cpu');p.add_argument('--checks',type=int,default=32);p.add_argument('--jobs',type=int,default=4);p.add_argument('--seconds',type=int,default=90);a=p.parse_args()
    print(json.dumps(search(a.pack,a.worker,a.backend,a.checks,a.jobs,a.seconds),indent=2))
if __name__=='__main__':main()
