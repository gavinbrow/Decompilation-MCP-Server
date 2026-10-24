"""Bounded call-wrapper generators learned from independently checked contributions.

Recognizers validate the complete instruction/operand graph. Targets, offsets and
vtable slots come from each input; there is no per-address solution lookup. Output
is readable C++ and must pass the unchanged official compiler/checker.
"""
import json
from pathlib import Path
import re
import capstone as cs
import pefile

ROOT = Path(__file__).resolve().parents[1]


def reg(i, operand, name):
    return operand.type == cs.x86.X86_OP_REG and i.reg_name(operand.reg) == name


def mem(i, operand, base, offset=None, size=4):
    return (operand.type == cs.x86.X86_OP_MEM and operand.size == size and
            i.reg_name(operand.mem.base) == base and not operand.mem.index and
            not operand.mem.segment and 0 <= operand.mem.disp <= 512 and
            (offset is None or operand.mem.disp == offset) and operand.mem.disp % min(size, 4) == 0)


def imm(operand, value=None):
    return operand.type == cs.x86.X86_OP_IMM and (value is None or operand.imm == value)


def pair(i, mnemonic, left, right):
    return i.mnemonic == mnemonic and len(i.operands) == 2 and left(i, i.operands[0]) and right(i, i.operands[1])


def rr(i, mnemonic, a, b):
    return pair(i, mnemonic, lambda i,o: reg(i,o,a), lambda i,o: reg(i,o,b))


def rm(i, a, b, offset=None, size=4, mnemonic='mov'):
    return pair(i, mnemonic, lambda i,o: reg(i,o,a), lambda i,o: mem(i,o,b,offset,size))


def single_reg(i, mnemonic, name):
    return i.mnemonic == mnemonic and len(i.operands) == 1 and reg(i,i.operands[0],name)


def direct(i, mnemonic, indexed):
    return i.mnemonic == mnemonic and len(i.operands) == 1 and imm(i.operands[0]) and indexed(i.operands[0].imm)


def fields(offset, kind, name):
    out, position = [], 0
    while position < offset:
        size = 4 if position % 4 == 0 and position + 4 <= offset else 1
        out.append(f'    {"unsigned int" if size == 4 else "unsigned char"} unk{position:02x};\n')
        position += size
    return ''.join(out) + f'    {kind} {name};\n'


def virtuals(slot, returns, params):
    return ''.join(f'    virtual void slot{i:02x}();\n' for i in range(0,slot,4)) + f'    virtual {returns} Invoke({params});\n'


def cleanup_free(code, name, indexed):
    if len(code) != 16:
        return []
    c = code
    checks = [single_reg(c[0],'push','esi'), rr(c[1],'mov','esi','ecx'), direct(c[2],'call',indexed),
              pair(c[3],'test',lambda i,o: mem(i,o,'esp',8,1),lambda i,o: imm(o,1)),
              c[4].mnemonic == 'je' and len(c[4].operands) == 1 and imm(c[4].operands[0],c[13].address),
              direct(c[5],'call',indexed), rm(c[6],'edx','esi',size=2,mnemonic='movzx'),
              rm(c[7],'ecx','eax'), rm(c[8],'eax','ecx',0), rm(c[9],'eax','eax'),
              single_reg(c[10],'push','edx'), single_reg(c[11],'push','esi'), single_reg(c[12],'call','eax'),
              rr(c[13],'mov','eax','esi'), single_reg(c[14],'pop','esi'),
              c[15].mnemonic == 'ret' and len(c[15].operands)==1 and imm(c[15].operands[0],4)]
    if not all(checks):
        return []
    size_offset, holder_offset, slot = (c[i].operands[1].mem.disp for i in (6,7,9))
    if size_offset % 2 or holder_offset % 4 or slot % 4 or slot > 256:
        return []
    cleanup, allocator = (f'FUN_{c[i].operands[0].imm:08x}' for i in (2,5))
    source = ('struct CpuAllocator {\n' + virtuals(slot,'void','void* block, unsigned int size') + '};\n'
              'struct CpuAllocatorHolder {\n' + fields(holder_offset,'CpuAllocator*','allocator') + '};\n'
              f'CpuAllocatorHolder* __cdecl {allocator}();\n'
              'struct CpuObject {\n' + fields(size_offset,'unsigned short','size') +
              f'    void {cleanup}();\n    CpuObject* {name}(unsigned int flags);\n}};\n'
              f'CpuObject* CpuObject::{name}(unsigned int flags)\n{{\n    {cleanup}();\n'
              f'    if (flags & 1) {{\n        CpuAllocatorHolder* holder = {allocator}();\n'
              '        holder->allocator->Invoke(this, size);\n    }\n    return this;\n}\n')
    return [('cleanup_allocator_free',source)]


def boolean_call(code, name, indexed):
    if len(code) != 8:
        return []
    c = code
    if not all([rm(c[0],'eax','esp',4), single_reg(c[1],'push','eax'), direct(c[2],'call',indexed),
                rr(c[3],'xor','ecx','ecx'), rr(c[4],'test','al','al'),
                c[5].mnemonic in ('sete','setne') and len(c[5].operands)==1 and reg(c[5],c[5].operands[0],'cl'),
                rr(c[6],'mov','al','cl'), c[7].mnemonic=='ret' and len(c[7].operands)==1 and imm(c[7].operands[0],4)]):
        return []
    target=f'FUN_{c[2].operands[0].imm:08x}'
    op='==' if c[5].mnemonic=='sete' else '!='
    source=(f'extern char __stdcall {target}(void*);\n'
            f'bool __stdcall {name}(void* argument)\n{{\n    char result = {target}(argument);\n    return result {op} 0;\n}}\n')
    return [('narrow_call_boolean',source)]


def virtual_forward(code, name):
    """Three complete observed wrapper shapes, with variable field/slot offsets."""
    c=code; owner=slot=value=None; form=None; cleanup=0
    if len(c)==4 and rm(c[0],'ecx','ecx') and rm(c[1],'eax','ecx',0) and rm(c[2],'edx','eax') and single_reg(c[3],'jmp','edx'):
        owner=c[0].operands[1].mem.disp;slot=c[2].operands[1].mem.disp;form='tail'
    elif len(c)==8 and all([rr(c[0],'mov','eax','ecx'),rm(c[1],'ecx','eax'),rm(c[2],'edx','ecx',0),
                           rm(c[3],'eax','eax'),rm(c[4],'edx','edx'),single_reg(c[5],'push','eax'),
                           single_reg(c[6],'call','edx'),c[7].mnemonic=='ret' and not c[7].operands]):
        owner=c[1].operands[1].mem.disp;value=c[3].operands[1].mem.disp;slot=c[4].operands[1].mem.disp;form='member'
    elif len(c)==12 and all([single_reg(c[0],'push','esi'),rm(c[1],'esi','esp',8),rr(c[2],'mov','eax','ecx'),
                            rm(c[3],'ecx','eax'),rm(c[4],'edx','ecx',0),rm(c[5],'eax','eax'),rm(c[6],'edx','edx'),
                            single_reg(c[7],'push','esi'),single_reg(c[8],'push','eax'),single_reg(c[9],'call','edx'),
                            single_reg(c[10],'pop','esi'),c[11].mnemonic=='ret' and len(c[11].operands)==1 and imm(c[11].operands[0],4)]):
        owner=c[3].operands[1].mem.disp;value=c[5].operands[1].mem.disp;slot=c[6].operands[1].mem.disp;form='member_argument';cleanup=4
    if form is None or slot % 4 or slot>256 or owner % 4 or (value is not None and (value%4 or value==owner)):
        return []
    owner_fields={owner:('CpuInterface*','target')}
    if value is not None:owner_fields[value]=('void*','value')
    out='';position=0
    for offset,(kind,field) in sorted(owner_fields.items()):
        if offset<position:return []
        # fields() offsets start at zero; generate the gap relative to current position.
        while position<offset:
            out+=f'    unsigned int unk{position:02x};\n';position+=4
        out+=f'    {kind} {field};\n';position+=4
    params='int argument' if cleanup else ''
    callparams='void* value, int argument' if cleanup else 'void* value' if value is not None else ''
    expression='target->Invoke(value, argument)' if cleanup else 'target->Invoke(value)' if value is not None else 'target->Invoke()'
    candidates=[]
    for returns in ('void','int'):
        source=('struct CpuInterface {\n'+virtuals(slot,returns,callparams)+'};\nstruct CpuObject {\n'+out+
                f'    {returns} {name}({params});\n}};\n{returns} CpuObject::{name}({params})\n{{\n    '+
                ('' if returns=='void' else 'return ')+expression+';\n}\n')
        candidates.append(('virtual_member_forward',source))
    return candidates


def stack_record_call(code, name, indexed, named_global):
    """A typed three-field stack local passed to one member call, four arguments."""
    if len(code)!=17:return []
    c=code
    def stack_adjust(i,mnemonic,value):
        return pair(i,mnemonic,lambda i,o:reg(i,o,'esp'),lambda i,o:imm(o,value))
    def absolute(i):
        return (len(i.operands)==1 and i.operands[0].type==cs.x86.X86_OP_MEM and i.operands[0].size==4
                and not i.operands[0].mem.base and not i.operands[0].mem.index and not i.operands[0].mem.segment)
    checks=[stack_adjust(c[0],'sub',12),rm(c[1],'eax','esp',28),c[2].mnemonic=='fld' and absolute(c[2]),
            pair(c[3],'mov',lambda i,o:mem(i,o,'esp',8),lambda i,o:reg(i,o,'eax')),
            c[4].mnemonic=='fstp' and len(c[4].operands)==1 and mem(c[4],c[4].operands[0],'esp',4),
            rm(c[5],'eax','esp',24),rm(c[6],'edx','esp',0,mnemonic='lea'),single_reg(c[7],'push','edx'),
            rm(c[8],'edx','esp',20),single_reg(c[9],'push','eax'),rm(c[10],'eax','esp',28),
            single_reg(c[11],'push','edx'),single_reg(c[12],'push','eax'),
            pair(c[13],'mov',lambda i,o:mem(i,o,'esp',16),lambda i,o:imm(o)),direct(c[14],'call',indexed),
            stack_adjust(c[15],'add',12),c[16].mnemonic=='ret' and len(c[16].operands)==1 and imm(c[16].operands[0],16)]
    if not all(checks):return []
    bound=named_global(c[2].operands[0].mem.disp & 0xffffffff)
    descriptor=named_global(c[13].operands[1].imm & 0xffffffff)
    if not bound or not descriptor or bound[1]!='float' or descriptor[1]!='unsigned char':return []
    target=f'FUN_{c[14].operands[0].imm:08x}'
    source=('struct CpuCallData { void* descriptor; float bound; unsigned int value; };\n'
            f'extern float {bound[0]};\nextern unsigned char {descriptor[0]};\n'
            f'struct CpuObject {{\n    void {target}(void*, void*, unsigned int, CpuCallData*);\n'
            f'    void {name}(void*, void*, unsigned int, unsigned int);\n}};\n'
            f'void CpuObject::{name}(void* first, void* second, unsigned int third, unsigned int fourth)\n{{\n'
            '    CpuCallData data;\n    data.value = fourth;\n'+f'    data.bound = {bound[0]};\n    data.descriptor = &{descriptor[0]};\n'
            f'    {target}(second, first, third, &data);\n}}\n')
    return [('stack_record_member_call',source)]


def null_guarded_call(code, name, indexed):
    c=code
    if len(c)!=15:return []
    checks=[rm(c[0],'eax','esp',4),rr(c[1],'test','eax','eax'),
            c[2].mnemonic=='jne' and len(c[2].operands)==1 and imm(c[2].operands[0],c[4].address),
            c[3].mnemonic=='ret' and not c[3].operands,rm(c[4],'ecx','esp',12),rm(c[5],'edx','esp',8),
            c[6].mnemonic=='push' and len(c[6].operands)==1 and imm(c[6].operands[0],0),
            c[7].mnemonic=='push' and len(c[7].operands)==1 and imm(c[7].operands[0],0),single_reg(c[8],'push','ecx'),
            c[9].mnemonic=='push' and len(c[9].operands)==1 and imm(c[9].operands[0],0),
            single_reg(c[10],'push','edx'),single_reg(c[11],'push','eax'),direct(c[12],'call',indexed),
            pair(c[13],'add',lambda i,o:reg(i,o,'esp'),lambda i,o:imm(o,24)),c[14].mnemonic=='ret' and not c[14].operands]
    if not all(checks):return []
    target=f'FUN_{c[12].operands[0].imm:08x}'
    return [('null_guarded_forward',f'extern int __cdecl {target}(void*, int, int, int, int, int);\n'
             f'int __cdecl {name}(void* first, int second, int third)\n{{\n    if (!first) return 0;\n'
             f'    return {target}(first, second, 0, third, 0, 0);\n}}\n')]


def direct_tail(code, name, indexed):
    """A complete one-step object selection/adjustment and indexed member tail."""
    if len(code)!=2 or not direct(code[1],'jmp',indexed):return []
    first=code[0];target=f'FUN_{code[1].operands[0].imm:08x}'
    selection=None;owner_fields='';parameters='';convention=''
    if rm(first,'ecx','ecx'):
        owner_fields=fields(first.operands[1].mem.disp,'CpuTarget*','target')
        selection='target'
    elif rm(first,'ecx','esp',4):
        selection='target';parameters='CpuTarget* target';convention='__cdecl '
    elif pair(first,'add',lambda i,o:reg(i,o,'ecx'),lambda i,o:imm(o)):
        offset=first.operands[1].imm
        if offset==0 or abs(offset)>512:return []
        selection=f'reinterpret_cast<CpuTarget*>(reinterpret_cast<char*>(this) + ({offset}))'
    if selection is None:return []
    results=[]
    for returns in ('void','int'):
        declaration=f'struct CpuTarget {{ {returns} {target}(); }};\n'
        signature=f'{returns} {convention}{name}({parameters})'
        if not convention:
            declaration+='struct CpuOwner {\n'+owner_fields+f'    {returns} {name}();\n}};\n'
            signature=f'{returns} CpuOwner::{name}()'
        source=declaration+signature+'\n{\n    '+('return ' if returns!='void' else '')+f'{selection}->{target}();\n}}\n'
        results.append(('direct_member_tail',source))
    return results


def scalar_stores(code,name):
    """Complete scalar stores, including ignored stack args and narrow values."""
    if not code or code[-1].mnemonic!='ret' or len(code)>3:return []
    ret=code[-1];cleanup=0
    if ret.operands:
        if len(ret.operands)!=1 or not imm(ret.operands[0]):return []
        cleanup=ret.operands[0].imm
    if cleanup<0 or cleanup>64 or cleanup%4:return []
    body=code[:-1];params=['int arg'+str(i) for i in range(cleanup//4)]
    ctype=None;expression=None;offset=None;operation='='
    if len(body)==1 and body[0].mnemonic in ('mov','or','and','xor') and len(body[0].operands)==2:
        instruction=body[0];dest,value=instruction.operands
        if not mem(instruction,dest,'ecx',size=dest.size) or dest.size not in (1,2,4) or not imm(value):return []
        offset=dest.mem.disp;ctype={1:'unsigned char',2:'unsigned short',4:'unsigned int'}[dest.size]
        # Symbolic pointer stores are handled separately; never emit an image
        # address as a scalar constant merely to reproduce its bytes.
        literal=value.imm & ((1<<(dest.size*8))-1)
        if dest.size==4 and 0x400000<=literal<0x1400000:return []
        expression=f'0x{literal:x}u';operation={'mov':'=','or':'|=','and':'&=','xor':'^='}[instruction.mnemonic]
    elif len(body)==2 and cleanup>=4 and body[0].mnemonic=='mov' and body[1].mnemonic=='mov':
        load,store=body
        if len(load.operands)!=2 or len(store.operands)!=2:return []
        temporary,argument=load.operands;dest,value=store.operands
        if temporary.type!=cs.x86.X86_OP_REG or value.type!=cs.x86.X86_OP_REG or temporary.reg!=value.reg:return []
        if argument.size not in (1,2,4) or argument.size!=dest.size:return []
        if not mem(load,argument,'esp',4,size=argument.size) or not mem(store,dest,'ecx',size=dest.size):return []
        if load.reg_name(temporary.reg) not in {1:('al',),2:('ax',),4:('eax',)}[argument.size]:return []
        ctype={1:'unsigned char',2:'unsigned short',4:'unsigned int'}[dest.size]
        offset=dest.mem.disp;params[0]=ctype+' arg0';expression='arg0'
    if expression is None:return []
    signature=', '.join(params)
    source='struct CpuObject {\n'+fields(offset,ctype,'value')+f'    void {name}({signature});\n}};\n'
    source+=f'void CpuObject::{name}({signature})\n{{\n    value {operation} {expression};\n}}\n'
    return [('scalar_member_store',source)]


def virtual_tail(code,name):
    """Additional complete vtable tails with optional stack or EDX forwarding."""
    c=code;offset=None;slot=None;direct_object=False
    if len(c)==3 and rm(c[0],'eax','ecx',0) and rm(c[1],'edx','eax') and single_reg(c[2],'jmp','edx'):
        direct_object=True;slot=c[1].operands[1].mem.disp
    elif len(c)==4 and rm(c[0],'ecx','ecx') and rm(c[1],'eax','ecx',0) and rm(c[2],'eax','eax') and single_reg(c[3],'jmp','eax'):
        offset=c[0].operands[1].mem.disp;slot=c[2].operands[1].mem.disp
    if slot is None or slot%4 or slot>256:return []
    results=[]
    for count in range(3):
        arguments=', '.join('int arg'+str(i) for i in range(count));values=', '.join('arg'+str(i) for i in range(count))
        source='struct CpuInterface {\n'+virtuals(slot,'void',arguments)
        if direct_object:
            source+=f'    void {name}({arguments});\n}};\nvoid CpuInterface::{name}({arguments})\n{{\n    Invoke({values});\n}}\n'
        else:
            source+='};\nstruct CpuOwner {\n'+fields(offset,'CpuInterface*','target')+f'    void {name}({arguments});\n}};\n'
            source+=f'void CpuOwner::{name}({arguments})\n{{\n    target->Invoke({values});\n}}\n'
        results.append(('virtual_tail_forward',source))
    if not direct_object:
        # The untouched incoming EDX can be a real fastcall argument. Explicitly
        # preserve it; do not invent a clobber to force register allocation.
        source='struct CpuInterface;\ntypedef void (__fastcall *CpuMethod)(CpuInterface*, int);\n'
        source+='struct CpuVtable {\n'+''.join(f'    CpuMethod slot{i:02x};\n' for i in range(0,slot+4,4))+'};\n'
        source+='struct CpuInterface { CpuVtable* vtable; };\nstruct CpuOwner {\n'+fields(offset,'CpuInterface*','target')+'};\n'
        source+=f'void __fastcall {name}(CpuOwner* self, int argument)\n{{\n    CpuInterface* target = self->target;\n    target->vtable->slot{slot:02x}(target, argument);\n}}\n'
        results.append(('virtual_tail_forward',source))
    return results


def framed_zero_argument_call(code,name,indexed):
    if len(code)!=5:return []
    c=code
    if not (single_reg(c[0],'push','ebp') and rr(c[1],'mov','ebp','esp') and direct(c[2],'call',indexed)
            and single_reg(c[3],'pop','ebp') and c[4].mnemonic=='ret' and not c[4].operands):return []
    target=f'FUN_{c[2].operands[0].imm:08x}'
    return [('framed_zero_argument_call',f'extern void __cdecl {target}();\nvoid __cdecl {name}()\n{{\n    {target}();\n}}\n')]


def pointer_table_lookup(code,name):
    """Count-bounded first-match lookup through an object's pointer table."""
    if len(code)!=19:return []
    c=code
    def jump(i,mnemonic,target):
        return i.mnemonic==mnemonic and len(i.operands)==1 and imm(i.operands[0],target)
    checks=[rm(c[0],'edx','ecx'),single_reg(c[1],'push','esi'),rr(c[2],'xor','eax','eax'),single_reg(c[3],'push','edi'),
            rr(c[4],'test','edx','edx'),jump(c[5],'jle',c[15].address),rm(c[6],'ecx','ecx'),rm(c[7],'esi','esp',12),
            rm(c[8],'edi','ecx',0),pair(c[9],'cmp',lambda i,o:mem(i,o,'edi'),lambda i,o:reg(i,o,'esi')),
            jump(c[10],'je',c[16].address),single_reg(c[11],'inc','eax'),
            pair(c[12],'add',lambda i,o:reg(i,o,'ecx'),lambda i,o:imm(o,4)),rr(c[13],'cmp','eax','edx'),
            jump(c[14],'jl',c[8].address),pair(c[15],'or',lambda i,o:reg(i,o,'eax'),lambda i,o:imm(o) and o.imm&0xffffffff==0xffffffff),
            single_reg(c[16],'pop','edi'),single_reg(c[17],'pop','esi'),
            c[18].mnemonic=='ret' and len(c[18].operands)==1 and imm(c[18].operands[0],4)]
    if not all(checks):return []
    count,table,key=(c[i].operands[1 if i!=9 else 0].mem.disp for i in (0,6,9))
    if count==table:return []
    layout={count:('int','count'),table:('CpuEntry**','entries')};source='struct CpuEntry {\n'+fields(key,'int','key')+'};\n'
    source+='struct CpuObject {\n';position=0
    for offset,(kind,field) in sorted(layout.items()):
        while position<offset:source+=f'    unsigned int unk{position:02x};\n';position+=4
        source+=f'    {kind} {field};\n';position+=4
    source+=f'    int {name}(int key);\n}};\nint CpuObject::{name}(int key)\n{{\n'
    source+='    int limit = count;\n    int index = 0;\n    if (limit > 0) {\n        CpuEntry** entry = entries;\n        do {\n'
    source+='            if ((*entry)->key == key) return index;\n            ++index;\n            ++entry;\n        } while (index < limit);\n    }\n    return -1;\n}\n'
    return [('pointer_table_lookup',source)]


def allocate_initialize(code,name,indexed):
    """Virtual allocation, measured size field, initialization and null offset."""
    if len(code)!=18:return []
    c=code
    checks=[direct(c[0],'call',indexed),rm(c[1],'ecx','eax'),rm(c[2],'eax','ecx',0),rm(c[3],'edx','eax'),
            c[4].mnemonic=='push' and len(c[4].operands)==1 and imm(c[4].operands[0]),single_reg(c[5],'call','edx'),
            rm(c[6],'edx','esp',4),pair(c[7],'mov',lambda i,o:reg(i,o,'ecx'),lambda i,o:imm(o)),
            pair(c[8],'mov',lambda i,o:mem(i,o,'eax',size=2),lambda i,o:reg(i,o,'cx')),
            single_reg(c[9],'push','edx'),rr(c[10],'mov','ecx','eax'),direct(c[11],'call',indexed),rr(c[12],'test','eax','eax'),
            c[13].mnemonic=='je' and len(c[13].operands)==1 and imm(c[13].operands[0],c[16].address),
            pair(c[14],'add',lambda i,o:reg(i,o,'eax'),lambda i,o:imm(o)),
            c[15].mnemonic=='ret' and not c[15].operands,rr(c[16],'xor','eax','eax'),c[17].mnemonic=='ret' and not c[17].operands]
    if not all(checks):return []
    size=c[4].operands[0].imm;offset=c[14].operands[1].imm;size_field=c[8].operands[0].mem.disp
    holder=c[1].operands[1].mem.disp;slot=c[3].operands[1].mem.disp
    if not 1<=size<=4096 or size_field+2>size or c[7].operands[1].imm!=size or not 0<offset<size or slot>256 or slot%4:return []
    helper=f'FUN_{c[0].operands[0].imm:08x}';initialize=f'FUN_{c[11].operands[0].imm:08x}'
    source='struct CpuBlock;\nstruct CpuAllocator {\n'+virtuals(slot,'void*','unsigned int size')+'};\n'
    source+='struct CpuHolder {\n'+fields(holder,'CpuAllocator*','allocator')+'};\n'
    source+=f'void* __cdecl {helper}();\nstruct CpuBlock {{\n'+fields(size_field,'unsigned short','size')+f'    CpuBlock* {initialize}(unsigned int value);\n}};\n'
    source+=f'void* __cdecl {name}(unsigned int value)\n{{\n    CpuHolder* holder = static_cast<CpuHolder*>({helper}());\n'
    source+=f'    CpuBlock* block = static_cast<CpuBlock*>(holder->allocator->Invoke({size}));\n'
    source+=f'    block->size = {size};\n    block = block->{initialize}(value);\n'
    source+=f'    if (block) return reinterpret_cast<char*>(block) + {offset};\n    return 0;\n}}\n'
    return [('allocator_initialize_offset',source)]


def from_code(code, name, indexed, named_global=lambda address:None):
    if not re.fullmatch(r'[A-Za-z_]\w*',name):return []
    for recognizer in (cleanup_free, boolean_call):
        candidates=recognizer(code,name,indexed)
        if candidates:return candidates
    candidates=virtual_forward(code,name) or null_guarded_call(code,name,indexed)
    return (candidates or stack_record_call(code,name,indexed,named_global) or
            direct_tail(code,name,indexed) or scalar_stores(code,name) or virtual_tail(code,name) or
            framed_zero_argument_call(code,name,indexed) or pointer_table_lookup(code,name) or allocate_initialize(code,name,indexed))


def templates(pack, indexed, named_global=lambda address:None):
    meta=json.loads((Path(pack)/'pack.json').read_text(encoding='utf-8-sig'))
    if not re.fullmatch(r'[A-Za-z_]\w*',meta['symbol']):return []
    if not 1<=int(meta['size'])<=255:return []
    settings=json.loads((ROOT/'local/settings.json').read_text(encoding='utf-8-sig'))
    pe=pefile.PE(settings['checker_image'],fast_load=True)
    try:
        address=int(meta['address'],16);size=int(meta['size'])
        data=pe.get_data(address-pe.OPTIONAL_HEADER.ImageBase,size)
    finally:pe.close()
    decoder=cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_32);decoder.detail=True
    code=list(decoder.disasm(data,address))
    if not code or sum(i.size for i in code)!=size:return []
    return from_code(code,meta['symbol'],indexed,named_global)
