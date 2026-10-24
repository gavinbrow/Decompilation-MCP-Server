"""No model calls. Decode narrow patterns, emit readable C++, run official checker.

Historical benchmark mode never submits. Live mode reports through the existing
single coordinator; unsupported targets can be handed to Luna under the same claim.
"""
import argparse
import concurrent.futures
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from datetime import datetime,timezone
import re
import capstone
import pefile

ROOT=Path(__file__).resolve().parents[1]
QUEUE=ROOT/'local/benchmark/queue'
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def utc():return datetime.now(timezone.utc).isoformat()
def save(p,value):
    p.parent.mkdir(parents=True,exist_ok=True)
    temporary=p.with_suffix('.tmp');temporary.write_text(json.dumps(value,indent=2));os.replace(temporary,p)

_SYMBOLS_BY_ADDRESS=None
_FUNCTION_ADDRESSES=None
_MATCHED_GLOBALS=None
def named_global(address):
    """Return only simple global identifiers with a known MSVC data type."""
    global _SYMBOLS_BY_ADDRESS
    if _SYMBOLS_BY_ADDRESS is None:
        symbols=read(ROOT/'local/shared/fnvdecomp_symbols.json')['functions']
        _SYMBOLS_BY_ADDRESS={int(item['address'],16):item['symbol'] for item in symbols}
    decorated=_SYMBOLS_BY_ADDRESS.get(address,'')
    match=re.fullmatch(r'\?([A-Za-z_]\w*)@@3(HA|IA|PAXA)',decorated)
    if not match:
        global _MATCHED_GLOBALS
        if _MATCHED_GLOBALS is None:_MATCHED_GLOBALS=family_engine('matched-knowledge').load()
        known=_MATCHED_GLOBALS.get(f'{address:08x}')
        return (known['name'],known['ctype']) if known else None
    name,kind=match.groups()
    ctype={'HA':'int','IA':'unsigned int','PAXA':'void*'}[kind]
    return name,ctype

def indexed_function(address):
    """The shared function index is the only source for synthesized FUN names."""
    global _FUNCTION_ADDRESSES
    if _FUNCTION_ADDRESSES is None:
        rows=read(ROOT/'local/shared/function_index.json')
        _FUNCTION_ADDRESSES={int(item['address'],16) for item in rows if item.get('address')}
    return address in _FUNCTION_ADDRESSES

def scalar_memory_templates(code,name,cleanup):
    """Recognize complete scalar load/store bodies; no calls or guessed aliases.

    Returns source only for exact operand shapes. All candidates still require
    the official checker; these patterns do not interpret arbitrary memory.
    """
    if not code or code[-1].mnemonic!='ret':return []
    body=code[:-1]
    def reg(i,o,r):return o.type==capstone.x86.X86_OP_REG and i.reg_name(o.reg)==r
    def mem(i,o,r,width,limit=512):
        return (o.type==capstone.x86.X86_OP_MEM and o.size==width and
                i.reg_name(o.mem.base)==r and not o.mem.index and not o.mem.segment and
                0<=o.mem.disp<=limit and o.mem.disp%(4 if r=='esp' else width)==0)
    def fields(offset,kind):
        result=[];position=0
        while position<offset:
            width=4 if position%4==0 and position+4<=offset else 1
            result.append('    '+('unsigned int' if width==4 else 'unsigned char')+f' unk{position:02x};\n');position+=width
        return ''.join(result)+f'    {kind} value;\n'
    def method(offset,kind,returns,parameters,statement):
        return (f'struct CpuObject {{\n{fields(offset,kind)}    {returns} {name}({parameters});\n}};\n'
                f'{returns} CpuObject::{name}({parameters})\n{{\n    {statement}\n}}\n')
    # x87 float/double argument stores. Match the stack width and cleanup,
    # including unused trailing integer parameters rather than dropping them.
    if len(body)==2 and body[0].mnemonic=='fld' and body[1].mnemonic=='fstp':
        first,last=body;a=first.operands[0];b=last.operands[0]
        if (a.size in (4,8) and mem(first,a,'esp',a.size) and a.mem.disp==4 and
            mem(last,b,'ecx',a.size) and cleanup>=a.size and cleanup<=32 and cleanup%4==0):
            kind='float' if a.size==4 else 'double'
            params=', '.join([kind+' input']+[f'int unused{i}' for i in range((cleanup-a.size)//4)])
            return [('float_member_setter',method(b.mem.disp,kind,'void',params,'value = input;'))]
    # Scalar x87 getters with ignored stack parameters use thiscall RET n.
    if len(body)==1 and body[0].mnemonic=='fld' and cleanup and cleanup<=32 and cleanup%4==0:
        i=body[0];o=i.operands[0]
        if o.size in (4,8) and mem(i,o,'ecx',o.size):
            kind='float' if o.size==4 else 'double';params=', '.join(f'int unused{i}' for i in range(cleanup//4))
            return [('float_member_getter_unused_arguments',method(o.mem.disp,kind,kind,params,'return value;'))]
    # Read a scalar through a pointer member. The pointee is represented by
    # named scalar fields at measured offsets, never absolute addresses.
    if len(body) in (2,3) and not cleanup and body[0].mnemonic=='mov' and body[1].mnemonic in ('mov','movzx','movsx'):
        first,last=body[:2];dst,pointer=first.operands;out,value=last.operands
        if (reg(first,dst,'eax') and mem(first,pointer,'ecx',4) and reg(last,out,'eax') and
            value.size in (1,2,4) and mem(last,value,'eax',value.size)):
            width=value.size
            kind='int' if width==4 else ('signed char' if width==1 else 'short') if last.mnemonic=='movsx' else ('unsigned char' if width==1 else 'unsigned short')
            if (width==4 and last.mnemonic!='mov') or (width<4 and last.mnemonic not in ('movsx','movzx')):return []
            expression='value->value'
            if len(body)==3:
                adjust=body[2]
                if adjust.mnemonic!='add' or len(adjust.operands)!=2:return []
                target,amount=adjust.operands
                if not (width==4 and reg(adjust,target,'eax') and amount.type==capstone.x86.X86_OP_IMM and 0<=amount.imm<=4096):return []
                kind='unsigned int';expression+=f' + {amount.imm}u'
            source=(f'struct CpuScalar {{\n{fields(value.mem.disp,kind)}}};\n'
                    f'struct CpuObject {{\n{fields(pointer.mem.disp,"CpuScalar*")}    {kind} {name}();\n}};\n'
                    f'{kind} CpuObject::{name}()\n{{\n    return {expression};\n}}\n')
            return [('nested_scalar_member_getter',source)]
    # A nested floating-point setter stores the supplied scalar through the
    # observed pointer member; no arbitrary pointer expression is synthesized.
    if len(body)==3 and body[0].mnemonic=='mov' and body[1].mnemonic=='fld' and body[2].mnemonic=='fstp':
        first,load,store=body;a,b=first.operands;c=load.operands[0];d=store.operands[0]
        if (reg(first,a,'eax') and mem(first,b,'ecx',4) and c.size in (4,8) and cleanup==c.size and
            mem(load,c,'esp',c.size) and c.mem.disp==4 and mem(store,d,'eax',c.size)):
            kind='float' if c.size==4 else 'double'
            source=(f'struct CpuScalar {{\n{fields(d.mem.disp,kind)}}};\n'
                    f'struct CpuObject {{\n{fields(b.mem.disp,"CpuScalar*")}    void {name}({kind} input);\n}};\n'
                    f'void CpuObject::{name}({kind} input)\n{{\n    value->value = input;\n}}\n')
            return [('nested_float_member_setter',source)]
    # Copy one byte between two independently supplied stack pointers.
    if len(body)==4 and not cleanup and all(i.mnemonic=='mov' for i in body):
        first,load,second,store=body;a,b=first.operands;c,d=load.operands;e,f=second.operands;g,h=store.operands
        if (reg(first,a,'eax') and mem(first,b,'esp',4) and b.mem.disp==8 and reg(load,c,'cl') and mem(load,d,'eax',1) and d.mem.disp==0 and
            reg(second,e,'eax') and mem(second,f,'esp',4) and f.mem.disp==4 and mem(store,g,'eax',1) and g.mem.disp==0 and reg(store,h,'cl')):
            return [('byte_pointer_copy',f'void __cdecl {name}(unsigned char* output, const unsigned char* input)\n{{\n    *output = *input;\n}}\n')]
    # A byte out-parameter copy is semantically distinct from a bool return.
    # Observe the CL load and AL-independent void return exactly.
    if len(body)==3 and cleanup==4 and all(i.mnemonic=='mov' for i in body):
        first,second,last=body;a,b=first.operands;c,d=second.operands;e,f=last.operands
        if (reg(first,a,'cl') and mem(first,b,'ecx',1) and reg(second,c,'eax') and mem(second,d,'esp',4) and d.mem.disp==4 and
            mem(last,e,'eax',1) and e.mem.disp==0 and reg(last,f,'cl')):
            return [('member_byte_out_parameter',method(b.mem.disp,'unsigned char','unsigned char*','unsigned char* output','*output = value;\n    return output;')),
                    ('member_byte_out_parameter',method(b.mem.disp,'unsigned char','void','unsigned char* output','*output = value;'))]
    # A constant byte written through the first stack pointer.
    if len(body)==2 and 4<=cleanup<=64 and cleanup%4==0 and body[0].mnemonic=='mov' and body[1].mnemonic=='mov':
        first,last=body;a,b=first.operands;c,d=last.operands
        if (reg(first,a,'eax') and mem(first,b,'esp',4) and b.mem.disp==4 and mem(last,c,'eax',1) and c.mem.disp==0 and
            d.type==capstone.x86.X86_OP_IMM and 0<=d.imm<=255):
            params=', '.join(['unsigned char* output']+[f'int unused{i}' for i in range(1,cleanup//4)])
            return [('constant_byte_out_parameter',f'void __stdcall {name}({params})\n{{\n    *output = {d.imm};\n}}\n')]
    return []

def _templates(pack,max_size=255):
    meta=read(pack/'pack.json');size=int(meta['size'])
    if not 1<=size<=max_size:return [],'outside_cpu_function_scope'
    pe=pefile.PE(read(ROOT/'local/settings.json')['checker_image'],fast_load=True)
    base=pe.OPTIONAL_HEADER.ImageBase;upper=base+pe.OPTIONAL_HEADER.SizeOfImage
    address=int(meta['address'],16);data=pe.get_data(address-base,size);pe.close()
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);decoder.detail=True
    code=list(decoder.disasm(data,address))
    if not code or sum(i.size for i in code)!=size:return [],'not_complete_returning_body'
    # Canonical frame around one absolute scalar read. No body operand can
    # reference the frame/stack, so removing it for recognition loses no flow.
    if (len(code)==5 and [i.mnemonic for i in code]==['push','mov','mov','pop','ret'] and
        code[0].op_str=='ebp' and code[1].op_str=='ebp, esp' and code[3].op_str=='ebp' and
        not code[4].operands and len(code[2].operands)==2 and
        code[2].operands[0].type==capstone.x86.X86_OP_REG and
        code[2].operands[1].type==capstone.x86.X86_OP_MEM and
        not code[2].operands[1].mem.base and not code[2].operands[1].mem.index and not code[2].operands[1].mem.segment):
        code=[code[2],code[4]]
    call_candidates=family_engine('call-patterns').from_code(code,meta['symbol'],indexed_function,named_global)
    if call_candidates:return call_candidates,'bounded_call_pattern_available'
    vector_candidates=family_engine('vector-copy-patterns').from_code(code,meta['symbol'])
    if vector_candidates:return vector_candidates,'bounded_vector_copy_available'
    if code[-1].mnemonic!='ret':return [],'not_complete_returning_body'
    cleanup=int(code[-1].op_str,0) if code[-1].op_str else 0
    if cleanup%4 or cleanup>64:return [],'unsupported_stack_cleanup'
    body=code[:-1];name=meta['symbol'];args=[f'int arg{i}' for i in range(cleanup//4)]
    convention='__stdcall' if cleanup else '__cdecl'
    def free(expression,kind='int',parameters=None):
        return f'{kind} {convention} {name}({", ".join(args if parameters is None else parameters)})\n{{\n    return {expression};\n}}\n'
    def immediate(instruction,register):
        return instruction.mnemonic=='mov' and len(instruction.operands)==2 and instruction.operands[0].type==capstone.x86.X86_OP_REG and instruction.reg_name(instruction.operands[0].reg)==register and instruction.operands[1].type==capstone.x86.X86_OP_IMM
    def field_declarations(offset,value_type):
        # Declare every byte before the observed field by name.  Use naturally
        # aligned scalar fields where possible; never synthesize padding arrays.
        fields=[];position=0
        while position<offset:
            if position%4==0 and position+4<=offset:
                fields.append(f'    unsigned int unk{position:02x};\n');position+=4
            else:
                fields.append(f'    unsigned char unk{position:02x};\n');position+=1
        fields.append(f'    {value_type} value;\n')
        return ''.join(fields)
    def method_source(offset,value_type,return_type,params,expression):
        fields=field_declarations(offset,value_type)
        signature=', '.join(params)
        return f'struct CpuObject {{\n{fields}    {return_type} {name}({signature});\n}};\n{return_type} CpuObject::{name}({signature})\n{{\n    return {expression};\n}}\n'
    def operand_constant(operand):
        return operand.type==capstone.x86.X86_OP_IMM
    def int_literal(value,unsigned=False):
        value &= 0xffffffff
        return f'0x{value:08x}u' if unsigned else str(value if value<0x80000000 else value-0x100000000)
    scalar_candidates=scalar_memory_templates(code,name,cleanup)
    if scalar_candidates:return scalar_candidates,'supported'
    if len(body)==2 and body[0].mnemonic=='xor' and body[0].op_str=='eax, eax' and body[1].mnemonic=='xor' and body[1].op_str=='edx, edx':
        return [('int64_zero_return',free('0','__int64'))],'supported'
    # x87 scalar returns: only exact, side-effect-free member loads.
    if cleanup==0 and len(body)==1 and body[0].mnemonic in ('fldz','fld1'):
        return [('float_constant_return',free('0.0f' if body[0].mnemonic=='fldz' else '1.0f','float'))],'supported'
    if cleanup==0 and len(body)==1 and body[0].mnemonic=='fld':
        operand=body[0].operands[0]
        if (operand.type==capstone.x86.X86_OP_MEM and not operand.mem.index and
            body[0].reg_name(operand.mem.base)=='ecx' and operand.size in (4,8) and
            0<=operand.mem.disp<=256 and operand.mem.disp%operand.size==0):
            kind='float' if operand.size==4 else 'double'
            return [('float_member_getter',method_source(operand.mem.disp,kind,kind,[],'value'))],'supported'
    if cleanup==0 and len(body)==2 and body[0].mnemonic=='mov' and body[1].mnemonic=='fld':
        first,last=body[0],body[1]
        destination,pointer=first.operands
        value=last.operands[0]
        if (destination.type==capstone.x86.X86_OP_REG and first.reg_name(destination.reg)=='eax' and
            pointer.type==capstone.x86.X86_OP_MEM and first.reg_name(pointer.mem.base)=='ecx' and not pointer.mem.index and
            value.type==capstone.x86.X86_OP_MEM and last.reg_name(value.mem.base)=='eax' and not value.mem.index and
            value.size in (4,8) and 0<=pointer.mem.disp<=256 and pointer.mem.disp%4==0 and
            0<=value.mem.disp<=256 and value.mem.disp%value.size==0):
            kind='float' if value.size==4 else 'double'
            inner=field_declarations(value.mem.disp,kind)
            outer=field_declarations(pointer.mem.disp,'CpuScalar*')
            source=(f'struct CpuScalar {{\n{inner}}};\nstruct CpuObject {{\n{outer}'
                    f'    {kind} {name}();\n}};\n{kind} CpuObject::{name}()\n{{\n    return value->value;\n}}\n')
            return [('nested_float_member_getter',source)],'supported'
    if len(body)==1 and immediate(body[0],'eax'):
        value=body[0].operands[1].imm & 0xffffffff
        if base<=value<upper:
            known=named_global(value)
            if known:
                global_name,ctype=known
                return [('symbolic_global_address',f'extern {ctype} {global_name};\n'+free('&'+global_name,ctype+'*'))],'supported'
            section=pe.get_section_by_rva(value-base)
            if section is not None and section.Characteristics&0x40000000 and not section.Characteristics&0x20000000:
                # The value denotes an object identity in a readable data
                # section. An incomplete object asserts no layout or scalar
                # type. DAT names use the checker's standard symbolic binding;
                # no numeric pointer, source body or saved solution is emitted.
                global_name=f'DAT_{value:08x}'
                return [('opaque_data_address',f'struct CpuOpaque;\nextern CpuOpaque {global_name};\n'+free('&'+global_name,'CpuOpaque*'))],'supported'
            return [],'address_literal_requires_named_symbol'
        literal=str(value if value<0x80000000 else value-0x100000000)
        return [('constant_return',free(literal))],'supported'
    if len(body)==1 and body[0].mnemonic=='mov' and len(body[0].operands)==2:
        destination,source=body[0].operands
        if (destination.type==capstone.x86.X86_OP_REG and body[0].reg_name(destination.reg)=='eax' and
            source.type==capstone.x86.X86_OP_MEM and not source.mem.base and not source.mem.index):
            global_symbol=named_global(source.mem.disp & 0xffffffff)
            if global_symbol:
                global_name,ctype=global_symbol
                if ctype.startswith(('class ','struct ')):return [],'opaque_object_requires_address_only'
                declaration=f'extern {ctype} {global_name};\n'
                source_code=declaration+free(global_name,ctype)
                return [('symbolic_global_getter',source_code)],'supported'
    if len(body)==1 and immediate(body[0],'al') and body[0].operands[1].imm in (0,1):
        return [('boolean_return',free('true' if body[0].operands[1].imm else 'false','bool'))],'supported'
    if body and body[0].mnemonic=='xor' and body[0].op_str=='eax, eax':
        if len(body)==1:return [('zero_return',free('0'))],'supported'
        if len(body)==2 and body[1].mnemonic=='inc' and body[1].op_str=='eax':return [('one_return',free('1'))],'supported'
    if not body and not cleanup:return [('empty_function',f'void {name}()\n{{\n}}\n')],'supported'
    # Only the first real stack argument is read; remaining arguments are unused.
    if body and body[0].mnemonic=='mov' and body[0].op_str=='eax, dword ptr [esp + 4]':
        parameters=args or ['int arg0']
        if len(body)==1:return [('argument_return',free('arg0',parameters=parameters))],'supported'
        if len(body)==2 and body[1].mnemonic=='mov' and body[1].op_str=='eax, dword ptr [eax]':
            parameters=['const int* value']+args[1:]
            return [('pointer_dereference',free('*value',parameters=parameters))],'supported'
    # Simple fastcall arithmetic uses ECX and EDX for its first two integer
    # parameters.  Keep this limited to complete, straight-line return bodies.
    if not cleanup and body:
        fast_params=['int a','int b']
        if len(body)==1 and body[0].mnemonic=='mov' and body[0].op_str in ('eax, ecx','eax, edx'):
            value='a' if body[0].op_str.endswith('ecx') else 'b'
            return [('fastcall_argument_return',f'int __fastcall {name}(int a, int b)\n{{\n    return {value};\n}}\n')],'supported'
        if len(body)==2 and body[0].mnemonic=='mov' and body[0].op_str=='eax, ecx' and body[1].mnemonic in ('add','sub','and','or','xor','imul'):
            target,source=body[1].operands
            if (target.type==capstone.x86.X86_OP_REG and body[1].reg_name(target.reg)=='eax' and
                source.type==capstone.x86.X86_OP_REG and body[1].reg_name(source.reg)=='edx'):
                op={'add':'+','sub':'-','and':'&','or':'|','xor':'^','imul':'*'}[body[1].mnemonic]
                return [(f'fastcall_{body[1].mnemonic}',f'int __fastcall {name}(int a, int b)\n{{\n    return a {op} b;\n}}\n')],'supported'
        if len(body)==1 and body[0].mnemonic=='lea':
            dst,memory=body[0].operands
            if (dst.type==capstone.x86.X86_OP_REG and body[0].reg_name(dst.reg)=='eax' and memory.type==capstone.x86.X86_OP_MEM and
                body[0].reg_name(memory.mem.base)=='ecx' and body[0].reg_name(memory.mem.index)=='edx' and memory.mem.scale in (1,2,4,8) and abs(memory.mem.disp)<=4096):
                expr='a' if memory.mem.scale==0 else f'a + b * {memory.mem.scale}'
                if memory.mem.disp:expr+=f' + ({memory.mem.disp})'
                return [('fastcall_index_arithmetic',f'int __fastcall {name}(int a, int b)\n{{\n    return {expr};\n}}\n')],'supported'
    # Read a scalar from a named pointer member using one stack index.  The
    # scale determines only the declared element type, not a guessed layout.
    if len(body)==3 and cleanup==4 and body[0].mnemonic=='mov' and body[0].op_str=='eax, dword ptr [esp + 4]' and body[1].mnemonic=='mov' and body[2].mnemonic=='mov':
        d0,s0=body[0].operands;d1,s1=body[1].operands;d2,s2=body[2].operands
        if (d1.type==capstone.x86.X86_OP_REG and body[1].reg_name(d1.reg)=='edx' and s1.type==capstone.x86.X86_OP_MEM and body[1].reg_name(s1.mem.base)=='ecx' and not s1.mem.index and s1.mem.disp==0 and
            d2.type==capstone.x86.X86_OP_REG and body[2].reg_name(d2.reg)=='eax' and s2.type==capstone.x86.X86_OP_MEM and body[2].reg_name(s2.mem.base)=='edx' and body[2].reg_name(s2.mem.index)=='eax' and s2.mem.scale in (1,2,4) and s2.mem.disp==0):
            ctype={1:'unsigned char',2:'unsigned short',4:'int'}[s2.mem.scale]
            source=f'struct CpuObject {{ {ctype}* values; {ctype} {name}(int index); }};\n{ctype} CpuObject::{name}(int index)\n{{\n    return values[index];\n}}\n'
            return [('indexed_value_getter',source)],'supported'
    # A bounded two-constant branch return: one compare/test, a conditional
    # branch over one constant assignment, then the common return.  This does
    # not attempt general CFG recovery or loop/control-state synthesis.
    if len(body)==4 and not cleanup and body[0].mnemonic in ('cmp','test') and body[1].mnemonic=='mov' and body[2].mnemonic.startswith('j') and body[3].mnemonic=='mov':
        compare=body[0];first=body[1].operands;branch=body[2];second=body[3].operands
        if (first[0].type==capstone.x86.X86_OP_REG and body[1].reg_name(first[0].reg)=='eax' and first[1].type==capstone.x86.X86_OP_IMM and
            second[0].type==capstone.x86.X86_OP_REG and body[3].reg_name(second[0].reg)=='eax' and second[1].type==capstone.x86.X86_OP_IMM and
            int(branch.operands[0].imm)==code[-1].address and
            not (base<=(int(first[1].imm)&0xffffffff)<upper) and
            not (base<=(int(second[1].imm)&0xffffffff)<upper)):
            condition=None;relation={'je':'==','jz':'==','jne':'!=','jnz':'!=','jl':'<','jle':'<=','jg':'>','jge':'>=','jb':'<','jbe':'<=','ja':'>','jae':'>=','js':'<0','jns':'>=0'}.get(branch.mnemonic)
            left,right=compare.operands
            if compare.mnemonic=='test' and left.type==capstone.x86.X86_OP_REG and right.type==capstone.x86.X86_OP_REG and compare.reg_name(left.reg)==compare.reg_name(right.reg) and relation in ('==','!='):
                reg=compare.reg_name(left.reg);parameter={'ecx':'a','edx':'b'}.get(reg)
                if parameter:condition=f'{parameter} {"==" if relation=="==" else "!="} 0'
            elif compare.mnemonic=='cmp' and left.type==capstone.x86.X86_OP_REG and right.type==capstone.x86.X86_OP_IMM and relation and relation not in ('<0','>=0'):
                reg=compare.reg_name(left.reg);parameter={'ecx':'a','edx':'b'}.get(reg)
                if parameter:
                    unsigned=branch.mnemonic in ('jb','jbe','ja','jae');constant=int_literal(right.imm,unsigned)
                    condition=f'{parameter} {relation} {constant}'
            elif compare.mnemonic=='test' and left.type==capstone.x86.X86_OP_REG and right.type==capstone.x86.X86_OP_IMM and relation in ('==','!='):
                reg=compare.reg_name(left.reg);parameter={'ecx':'a','edx':'b'}.get(reg)
                if parameter:
                    condition=f'({parameter} & {int_literal(right.imm,True)}) {relation} 0'
            elif compare.mnemonic in ('cmp','test') and left.type==capstone.x86.X86_OP_MEM and compare.reg_name(left.mem.base)=='ecx' and not left.mem.index and left.mem.disp>=0 and left.mem.disp%4==0:
                offset=left.mem.disp
                if compare.mnemonic=='test' and right.type==capstone.x86.X86_OP_IMM and relation in ('==','!='):
                    condition=f'(value & {int_literal(right.imm,True)}) {relation} 0'
                elif compare.mnemonic=='cmp' and right.type==capstone.x86.X86_OP_IMM and relation and relation not in ('<0','>=0'):
                    unsigned=branch.mnemonic in ('jb','jbe','ja','jae');condition=f'value {relation} {int_literal(right.imm,unsigned)}'
                if condition:
                    source=method_source(offset,'int','int',[],f'({condition}) ? {int_literal(first[1].imm)} : {int_literal(second[1].imm)}')
                    return [('bounded_member_branch_return',source)],'supported'
            if condition:
                source=f'int __fastcall {name}(int a, int b)\n{{\n    return ({condition}) ? {int_literal(first[1].imm)} : {int_literal(second[1].imm)};\n}}\n'
                return [('bounded_fastcall_branch_return',source)],'supported'
    # A compact forwarding wrapper is recoverable when every pushed value is
    # one of its original stack arguments and the target is a function-index
    # entry.  This emits symbolic C++ declarations, never an address literal.
    if cleanup and cleanup%4==0 and 1<=cleanup//4<=8 and len(body)>=4:
        count=cleanup//4;call=body[-2];adjust=body[-1]
        if (call.mnemonic=='call' and call.operands and call.operands[0].type==capstone.x86.X86_OP_IMM and
            adjust.mnemonic=='add' and len(adjust.operands)==2 and adjust.reg_name(adjust.operands[0].reg)=='esp' and
            adjust.operands[1].type==capstone.x86.X86_OP_IMM and adjust.operands[1].imm==count*4):
            target=call.operands[0].imm & 0xffffffff
            registers={};pushed=[];valid=True;push_count=0
            for insn in body[:-2]:
                if insn.mnemonic=='mov' and len(insn.operands)==2 and insn.operands[0].type==capstone.x86.X86_OP_REG and insn.operands[1].type==capstone.x86.X86_OP_MEM:
                    dst,src=insn.operands
                    if insn.reg_name(src.mem.base)!='esp' or src.mem.index or src.mem.disp<4 or (src.mem.disp-4*push_count-4)%4:
                        valid=False;break
                    arg=(src.mem.disp-4*push_count-4)//4
                    if not 0<=arg<count:valid=False;break
                    registers[insn.reg_name(dst.reg)]=arg
                elif insn.mnemonic=='push' and len(insn.operands)==1 and insn.operands[0].type==capstone.x86.X86_OP_REG:
                    reg=insn.reg_name(insn.operands[0].reg)
                    if reg not in registers:valid=False;break
                    pushed.append(registers[reg]);push_count+=1
                else:
                    valid=False;break
            if valid and pushed==list(range(count-1,-1,-1)) and indexed_function(target):
                parameters=[f'void* arg{i}' for i in range(count)];args=', '.join(parameters);symbol=f'FUN_{target:08x}'
                source=f'extern "C" void __cdecl {symbol}({args});\nextern "C" void __stdcall {name}({args})\n{{\n    {symbol}({args.replace("void* ","").replace(", ",", ")});\n}}\n'
                typed=source.replace('void* arg','int arg')
                return [('symbolic_forwarding_wrapper',text) for text in
                        (source,typed,typed.replace(f'extern "C" void __stdcall {name}',f'void __stdcall {name}'))],'supported'
    if len(body)==1 and not cleanup and body[0].mnemonic=='lea' and len(body[0].operands)==2:
        first,memory=body[0].operands
        if first.type==capstone.x86.X86_OP_REG and body[0].reg_name(first.reg)=='eax' and memory.type==capstone.x86.X86_OP_MEM and body[0].reg_name(memory.mem.base)=='ecx' and not memory.mem.index and abs(memory.mem.disp)<=4096:
            offset=memory.mem.disp
            source=f'struct CpuObject {{ char* {name}(); }};\nchar* CpuObject::{name}()\n{{\n    return reinterpret_cast<char*>(this) + {offset};\n}}\n'
            return [('interior_pointer',source)],'supported'
    if len(body)==1 and not cleanup and body[0].mnemonic=='mov' and body[0].op_str=='eax, dword ptr [ecx]':
        source=f'struct CpuObject {{ int value; int {name}(); }};\nint CpuObject::{name}()\n{{\n    return value;\n}}\n'
        return [('first_field_getter',source)],'supported'
    # Scalar member getters, including sign/zero-extending byte and word loads.
    # The field declaration uses only named preceding members, at the observed
    # offsets, so these are real C++ layouts rather than padding tricks.
    if len(body)==1 and body[0].mnemonic in ('mov','movzx','movsx') and len(body[0].operands)==2:
        dst,src=body[0].operands
        if (dst.type==capstone.x86.X86_OP_REG and body[0].reg_name(dst.reg)=='eax' and
            src.type==capstone.x86.X86_OP_MEM and body[0].reg_name(src.mem.base)=='ecx' and
            not src.mem.index and 0<=src.mem.disp<=0x200):
            offset=src.mem.disp;width=src.size
            if width in (1,2,4) and (offset%width)==0:
                if width==4:ctype='int'
                elif width==2:ctype='short' if body[0].mnemonic=='movsx' else 'unsigned short'
                else:ctype='signed char' if body[0].mnemonic=='movsx' else 'unsigned char'
                params=[f'int arg{i}' for i in range(cleanup//4)]
                source=method_source(offset,ctype,ctype,params,'value')
                return [(f'member_getter_{width*8}bit',source)],'supported'
    # Scalar member setter with a single stack argument.
    if len(body)==2 and cleanup==4 and body[0].mnemonic=='mov' and body[0].op_str=='eax, dword ptr [esp + 4]' and body[1].mnemonic in ('mov','mov byte ptr','mov word ptr'):
        dst,src=body[1].operands
        if (dst.type==capstone.x86.X86_OP_MEM and body[1].reg_name(dst.mem.base)=='ecx' and not dst.mem.index and
            dst.mem.disp>=0 and dst.mem.disp<=0x40 and src.type==capstone.x86.X86_OP_REG and body[1].reg_name(src.reg)=='eax'):
            width=dst.size;offset=dst.mem.disp
            if width in (1,2,4) and offset%width==0:
                ctype={1:'unsigned char',2:'unsigned short',4:'int'}[width]
                source=f'struct CpuObject {{\n{field_declarations(offset,ctype)}    void {name}({ctype} value);\n}};\nvoid CpuObject::{name}({ctype} value)\n{{\n    this->value = value;\n}}\n'
                return [(f'member_setter_{width*8}bit',source)],'supported'
    # Member value plus one integer parameter.
    if len(body)==2 and cleanup==4 and body[0].mnemonic=='mov' and body[1].mnemonic in ('add','sub','and','or','xor'):
        a,b=body[0].operands; c,d=body[1].operands
        if (a.type==capstone.x86.X86_OP_REG and body[0].reg_name(a.reg)=='eax' and b.type==capstone.x86.X86_OP_MEM and body[0].reg_name(b.mem.base)=='ecx' and not b.mem.index and 0<=b.mem.disp<=0x200 and b.mem.disp%4==0 and
            c.type==capstone.x86.X86_OP_REG and body[1].reg_name(c.reg)=='eax' and d.type==capstone.x86.X86_OP_MEM and body[1].reg_name(d.mem.base)=='esp' and d.mem.disp==4):
            offset=b.mem.disp;op={'add':'+','sub':'-','and':'&','or':'|','xor':'^'}[body[1].mnemonic]
            source=method_source(offset,'int','int',['int amount'],f'value {op} amount')
            return [(f'member_{body[1].mnemonic}_parameter',source)],'supported'
    # Single-member arithmetic with an immediate. Unsigned constants retain
    # their exact 32-bit pattern for masks and shifts.
    if len(body)==2 and body[0].mnemonic=='mov' and body[1].mnemonic in ('add','sub','and','or','xor','imul','shl','shr','sar'):
        d0,s0=body[0].operands; d1,s1=body[1].operands
        if (d0.type==capstone.x86.X86_OP_REG and body[0].reg_name(d0.reg)=='eax' and s0.type==capstone.x86.X86_OP_MEM and body[0].reg_name(s0.mem.base)=='ecx' and not s0.mem.index and 0<=s0.mem.disp<=0x200 and s0.mem.disp%4==0 and
            d1.type==capstone.x86.X86_OP_REG and body[1].reg_name(d1.reg)=='eax' and s1.type==capstone.x86.X86_OP_IMM):
            offset=s0.mem.disp;value=s1.imm & 0xffffffff;literal=int_literal(value,unsigned=body[1].mnemonic in ('and','or','xor','shl','shr'))
            op={'add':'+','sub':'-','and':'&','or':'|','xor':'^','imul':'*','shl':'<<','shr':'>>','sar':'>>'}[body[1].mnemonic]
            expression=f'value {op} {literal}'
            if body[1].mnemonic=='shr':expression=f'(unsigned int)value >> {int(s1.imm)&31}'
            if body[1].mnemonic=='shl':expression=f'value << {int(s1.imm)&31}'
            if body[1].mnemonic=='sar':expression=f'value >> {int(s1.imm)&31}'
            source=method_source(offset,'int','int',[],expression)
            return [(f'member_{body[1].mnemonic}_immediate',source)],'supported'
    # Exact zero comparison returning bool. Keep the supported instruction
    # shape narrow; several visually similar out-parameter forms allocate
    # registers differently and must fall through to the model worker.
    if len(body)==3 and body[0].mnemonic=='xor' and body[0].op_str=='eax, eax' and body[1].mnemonic=='cmp' and body[2].mnemonic in ('sete','setne'):
        compared=body[1].operands[0]; zero=body[1].operands[1]; flag=body[2].operands[0]
        if (compared.type==capstone.x86.X86_OP_MEM and body[1].reg_name(compared.mem.base)=='ecx' and not compared.mem.index and compared.mem.disp>=0 and compared.mem.disp%4==0 and
            zero.type==capstone.x86.X86_OP_REG and body[1].reg_name(zero.reg)=='eax' and flag.type==capstone.x86.X86_OP_REG and body[2].reg_name(flag.reg)=='al'):
            offset=compared.mem.disp; fields=''.join(f'    int unk{i:02x};\n' for i in range(0,offset,4)); operator='==' if body[2].mnemonic=='sete' else '!='
            source=f'struct CpuObject {{\n{fields}    int value;\n    bool {name}();\n}};\nbool CpuObject::{name}()\n{{\n    return value {operator} 0;\n}}\n'
            return [('member_zero_comparison',source)],'supported'
    # Integer comparisons and bit tests returning a bool.  Only recognize the
    # standard zeroed-EAX / condition-byte idiom so flags and return width are
    # fully accounted for.
    if (len(body)==3 and body[0].mnemonic=='xor' and body[0].op_str=='eax, eax' and
        body[1].mnemonic in ('cmp','test') and body[2].mnemonic.startswith('set')):
        left,right=body[1].operands;flag=body[2].operands[0]
        if flag.type==capstone.x86.X86_OP_REG and body[2].reg_name(flag.reg)=='al':
            relation={'sete':'==','setz':'==','setne':'!=','setnz':'!=','setl':'<','setle':'<=','setg':'>','setge':'>=','setb':'<','setbe':'<=','seta':'>','setae':'>='}.get(body[2].mnemonic)
            if body[1].mnemonic=='test' and left.type==capstone.x86.X86_OP_MEM and right.type==capstone.x86.X86_OP_IMM:
                if (body[1].reg_name(left.mem.base)=='ecx' and not left.mem.index and left.mem.disp>=0 and left.mem.disp%4==0 and body[2].mnemonic in ('sete','setz','setne','setnz')):
                    offset=left.mem.disp;mask=int_literal(right.imm,True);op='==' if body[2].mnemonic in ('sete','setz') else '!='
                    source=method_source(offset,'int','bool',[],f'(value & {mask}) {op} 0')
                    return [('member_bit_test_bool',source)],'supported'
            if body[1].mnemonic=='cmp' and left.type==capstone.x86.X86_OP_MEM and right.type==capstone.x86.X86_OP_IMM and relation:
                if body[1].reg_name(left.mem.base)=='ecx' and not left.mem.index and left.mem.disp>=0 and left.mem.disp%4==0:
                    unsigned=body[2].mnemonic in ('setb','setbe','seta','setae')
                    ctype='unsigned int' if unsigned else 'int';constant=int_literal(right.imm,unsigned)
                    source=method_source(left.mem.disp,ctype,'bool',[],f'value {relation} {constant}')
                    return [('member_integer_comparison_bool',source)],'supported'
    # Member-array element address: first argument is the element index.
    if len(body)==3 and cleanup==4 and body[0].mnemonic=='mov' and body[0].op_str=='eax, dword ptr [esp + 4]' and body[1].mnemonic=='mov' and body[1].op_str=='edx, dword ptr [ecx]' and body[2].mnemonic=='lea':
        operands=body[2].operands
        if len(operands)==2 and operands[1].type==capstone.x86.X86_OP_MEM:
            memory=operands[1].mem
            if body[2].reg_name(memory.base)=='edx' and body[2].reg_name(memory.index)=='eax' and memory.scale in (1,2,4) and memory.disp==0:
                kind={1:'char',2:'short',4:'int'}[memory.scale]
                source=f'struct CpuObject {{ {kind}* values; {kind}* {name}(int index); }};\n{kind}* CpuObject::{name}(int index)\n{{\n    return values + index;\n}}\n'
                return [('array_element_pointer',source)],'supported'
    # Indexed pointer into the first object member; accept only canonical
    # byte/word/dword scaling and return a pointer of the corresponding type.
    if len(body)==3 and cleanup==4 and body[0].mnemonic=='mov' and body[1].mnemonic=='mov' and body[2].mnemonic=='lea':
        d0,s0=body[0].operands; d1,s1=body[1].operands; d2,m2=body[2].operands
        if (d0.type==capstone.x86.X86_OP_REG and body[0].reg_name(d0.reg)=='eax' and s0.type==capstone.x86.X86_OP_MEM and body[0].reg_name(s0.mem.base)=='ecx' and s0.mem.disp==0 and not s0.mem.index and
            d1.type==capstone.x86.X86_OP_REG and body[1].reg_name(d1.reg)=='ecx' and s1.type==capstone.x86.X86_OP_MEM and body[1].reg_name(s1.mem.base)=='esp' and s1.mem.disp==4 and
            d2.type==capstone.x86.X86_OP_REG and body[2].reg_name(d2.reg)=='eax' and m2.type==capstone.x86.X86_OP_MEM and body[2].reg_name(m2.mem.base)=='eax' and body[2].reg_name(m2.mem.index)=='ecx' and m2.mem.disp==0 and m2.mem.scale in (1,2,4)):
            kind={1:'char',2:'short',4:'int'}[m2.mem.scale]
            source=f'struct CpuObject {{ {kind}* values; {kind}* {name}(int index); }};\n{kind}* CpuObject::{name}(int index)\n{{\n    return values + index;\n}}\n'
            return [('array_element_pointer',source)],'supported'
    wrapper_candidates=family_engine('small-wrapper-patterns').from_code(code,name,indexed_function)
    if wrapper_candidates:return wrapper_candidates,'bounded_small_wrapper_available'
    return [],'no_safe_template_for_instruction_pattern'

_SEARCH=None
_FAMILIES={}
def family_engine(name):
    if name not in _FAMILIES:
        spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/(name+'.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);_FAMILIES[name]=module
    return _FAMILIES[name]
def search_engine():
    global _SEARCH
    if _SEARCH is None:
        spec=importlib.util.spec_from_file_location('integer_search',ROOT/'scripts/integer-search.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        _SEARCH=module
    return _SEARCH

def scoped_tags(source,symbol):
    """Keep synthesized tags unique across all template-consuming entrypoints."""
    tags=set(re.findall(r'\b(?:struct|class)\s+(Cpu\w+)\s*(?:\{|:)',source))
    if 'CpuMethod' in source and 'typedef' in source:tags.add('CpuMethod')
    if not tags:return source
    prefix='FnvCpu_'+re.sub(r'\W','_',symbol)+'_'
    return re.sub(r'\b(?:'+ '|'.join(sorted(tags,key=len,reverse=True))+r')\b',lambda match:prefix+match[0],source)

def templates(pack,max_size=255):
    candidates,reason=_templates(pack,max_size)
    meta=read(pack/'pack.json')
    if candidates:return [(pattern,scoped_tags(source,meta['symbol'])) for pattern,source in candidates],reason
    if int(meta['size'])>max_size:return candidates,reason
    engine=search_engine()
    try:plan=engine.analyze(pack)
    except engine.Unsupported as error:
        for family,pattern in [('record-selector-search','structured_record_selector'),('dispatch-search','structured_member_dispatch'),('destructor-search','structured_memory_destructor'),('loop-search','bounded_loop_search')]:
            module=family_engine(family)
            try:plan=module.analyze(pack)
            except module.Unsupported:continue
            preview=module.candidate_source(plan,'sum',0) if family=='loop-search' else module.source(plan,0)
            return [(pattern,preview)],family+'_available'
        return [],'integer_search:'+str(error)
    return [('integer_symbolic_search',engine.source(plan,plan['expression']))],'symbolic_integer_search_available'

def solve(pack,worker,max_size=255,compiler_jobs=4):
    started=time.monotonic();meta=read(pack/'pack.json');folder=pack/worker;folder.mkdir(exist_ok=True)
    candidates,reason=templates(pack,max_size);outcome='unsupported';attempts=0;chosen=None;pattern=None
    if candidates and candidates[0][0]=='integer_symbolic_search':
        record=search_engine().search(pack,worker,jobs=compiler_jobs)
        record.update(supported=True,ended_utc=utc(),max_size=max_size)
        save(folder/'result.json',record)
        return record
    structured={'structured_record_selector':'record-selector-search','structured_member_dispatch':'dispatch-search','structured_memory_destructor':'destructor-search','bounded_loop_search':'loop-search'}
    if candidates and candidates[0][0] in structured:
        family=structured[candidates[0][0]]
        record=family_engine(family).search(pack,worker,jobs=compiler_jobs)
        record.update(supported=True,ended_utc=utc(),max_size=max_size)
        save(folder/'result.json',record)
        return record
    for pattern,source in candidates:
        candidate=folder/'candidate.cpp';candidate.write_text(source)
        save(candidate.with_suffix(candidate.suffix+'.provenance.json'),dict(model='Non-AI CPU template generator',source_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),generator='cpu-template-worker',llm_calls=0))
        review=subprocess.run([str(ROOT/'.venv/Scripts/python.exe'),str(ROOT/'scripts/source-address-review.py'),str(candidate)],capture_output=True,text=True,timeout=15)
        if review.returncode:reason='source_address_review_required';continue
        command=[shutil.which('pwsh.exe'),'-NoProfile','-File',str(ROOT/'scripts/fnvcheck.ps1'),'-Pack',str(pack),'-Candidate',str(candidate),'-Worker',worker,'-Json']
        result=subprocess.run(command,capture_output=True,text=True,timeout=60,cwd=ROOT)
        attempts+=1
        try:check=json.loads(result.stdout.lstrip('\ufeff'))
        except ValueError:check=dict(status='checker_error',errors=['Checker did not return JSON'])
        save(folder/f'check-{attempts:02}.json',check)
        if result.returncode==0 and check.get('status')=='match':outcome='match';reason='';chosen=candidate;break
        outcome='blocked';reason='Template did not produce official MATCH: '+str(check.get('status'))
    record=dict(owner=worker,claim_id=pack.name,symbol=meta['symbol'],size=meta['size'],max_size=max_size,outcome=outcome,pattern=pattern,reason=reason,checker_attempts=attempts,supported=bool(candidates),elapsed_seconds=time.monotonic()-started,ended_utc=utc(),llm_calls=0)
    if chosen:record['candidate']=str(chosen)
    save(folder/'result.json',record)
    return record

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--benchmark',type=int);parser.add_argument('--claim-set',type=Path,help='Benchmark the exact claim IDs listed in a prior report JSON');parser.add_argument('--worker',default='cpu_01');parser.add_argument('--max-size',type=int,default=32,help='Maximum function size in bytes for a benchmark (default: 32)');parser.add_argument('--output',type=Path,help='Optional benchmark report path; defaults to cpu-template-pilot.json')
    parser.add_argument('--jobs',type=int,default=2,help='Outer benchmark jobs (1..2)')
    parser.add_argument('--compiler-jobs',type=int,default=2,help='Compilers per outer job (total <=4)')
    parser.add_argument('--knowledge',type=Path,help='Isolated optional declaration library')
    args=parser.parse_args()
    if args.knowledge:os.environ['FNV_MATCHED_KNOWLEDGE']=str(args.knowledge.resolve())
    if args.benchmark:
        if not 1<=args.max_size<=1024:parser.error('--max-size must be between 1 and 1024')
        if not 1<=args.jobs<=2 or not 1<=args.compiler_jobs<=4 or args.jobs*args.compiler_jobs>4:parser.error('Benchmark requires 1..2 outer jobs and at most 4 total compiler jobs')
        # Historical local checks only; no API or service calls. A claim-set
        # file makes before/after pilot comparisons use the same targets.
        selected=[]
        if args.claim_set:
            prior=read(args.claim_set)
            rows=prior if isinstance(prior,list) else prior.get('results',[])
            seen=set()
            for row in rows:
                claim=row.get('claim_id')
                p=ROOT/'work'/claim/'pack.json' if claim else None
                if p and p.is_file():
                    meta=read(p)
                    identity=int(meta['address'],16)
                    if 1<=int(meta['size'])<=args.max_size and identity not in seen:selected.append(p.parent);seen.add(identity)
                if len(selected)>=args.benchmark:break
        else:
            seen=set()
            for p in sorted((ROOT/'work').glob('clm_*/pack.json'),key=lambda p:p.stat().st_mtime,reverse=True):
                meta=read(p)
                if 1<=int(meta['size'])<=args.max_size and meta['address'] not in seen:
                    selected.append(p.parent);seen.add(meta['address'])
                if len(selected)>=args.benchmark:break
        begun=time.monotonic()
        def job(item):
            index,pack=item
            try:
                row=solve(pack,f'{args.worker}_bench_{index:04}',args.max_size,args.compiler_jobs)
                row['address']=read(pack/'pack.json')['address']
                return row
            except Exception as error:return dict(claim_id=pack.name,outcome='error',reason=type(error).__name__,elapsed_seconds=0)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:rows=list(pool.map(job,enumerate(selected)))
        grouped={}
        for row in rows:
            key=row.get('pattern') or 'unclassified'
            stat=grouped.setdefault(key,dict(screened=0,supported=0,matches=0,failures=0,elapsed_seconds=0.0))
            stat['screened']+=1
            stat['elapsed_seconds']+=float(row.get('elapsed_seconds',0))
            if int(row.get('checker_attempts',0))>0 or row.get('outcome')=='match':stat['supported']+=1
            if row.get('outcome')=='match':stat['matches']+=1
            elif int(row.get('checker_attempts',0))>0:stat['failures']+=1
        matches=sum(r['outcome']=='match' for r in rows)
        report=dict(utc=utc(),screened=len(rows),supported=sum(v['supported'] for v in grouped.values()),matches=matches,failures=sum(v['failures'] for v in grouped.values()),max_size=args.max_size,wall_seconds=time.monotonic()-begun,llm_calls=0,uploaded=0,pattern_summary=grouped,baseline_claim_set=str(args.claim_set) if args.claim_set else None,method='Exact baseline claim set' if args.claim_set else f'Recent distinct targets up to {args.max_size} bytes; historical local checks only, never submitted',results=rows)
        if args.claim_set:
            old_matches=int(prior.get('matches',0)) if isinstance(prior,dict) else 0
            if isinstance(prior,dict):report['baseline_comparison']=dict(baseline_screened=int(prior.get('screened',len(rows))),baseline_supported=int(prior.get('supported',0)),baseline_matches=old_matches,delta_matches=matches-old_matches,baseline_match_rate=(old_matches/len(rows) if rows else 0.0),expanded_match_rate=(matches/len(rows) if rows else 0.0))
        save((ROOT/args.output) if args.output else ROOT/'local/benchmark/cpu-template-pilot.json',report)
        print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2));return
    marker=ROOT/'local/benchmark/cpu-runner-status.json';save(marker,dict(state='online',pid=os.getpid(),utc=utc(),workers=1,llm_calls=0))
    last=None
    try:
        while True:
            state=read(QUEUE/'state.json')
            if state.get('state') in ('stop','stopped','account_limit'):break
            if (QUEUE/'stop.request').exists() or state.get('state')=='needs_attention':time.sleep(2);continue
            path=QUEUE/'assignments'/f'{args.worker}.json';task=read(path)
            if task.get('state')=='stop':break
            if task.get('state')!='work' or task.get('claim_id')==last:time.sleep(2);continue
            last=task['claim_id'];pack=ROOT/task['pack']
            try:result=solve(pack,args.worker,255)
            except Exception as error:result=dict(outcome='blocked',reason='CPU worker error: '+type(error).__name__,elapsed_seconds=0)
            with (ROOT/'local/benchmark/cpu.jsonl').open('a',encoding='utf-8') as stream:stream.write(json.dumps(result)+'\n')
            current=read(path)
            if current.get('claim_id')!=last:continue
            report=dict(worker=args.worker,claim_id=last,outcome='match' if result['outcome']=='match' else 'handoff',reported_utc=utc(),reason=result.get('reason',''))
            if result.get('candidate'):report['candidate']=result['candidate']
            save(QUEUE/'results'/f'{args.worker}.json',report)
    finally:save(marker,dict(state='offline',pid=os.getpid(),utc=utc()))

if __name__=='__main__':main()
