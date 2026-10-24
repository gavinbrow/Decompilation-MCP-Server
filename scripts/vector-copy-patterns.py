"""Bounded aligned-vector/scalar copies with named fields and explicit pointers.

This is a complete-body recognizer, not an instruction-to-C++ transcription.
Only acyclic copies between observed input/output fields are accepted. SIMD
arithmetic, stack temporaries, overlapping fields and unknown accesses fail closed.
The unchanged official compiler/checker alone establishes a MATCH.
"""
import capstone as cs


def from_code(code,name):
    if len(code)<8 or len(code)>72:return []
    if [i.mnemonic+' '+i.op_str for i in code[:3]]!=['push ebp','mov ebp, esp','and esp, 0xfffffff0']:return []
    if code[-3].mnemonic+' '+code[-3].op_str!='mov esp, ebp' or code[-2].mnemonic+' '+code[-2].op_str!='pop ebp' or code[-1].mnemonic!='ret':return []
    cleanup=code[-1].operands[0].imm if code[-1].operands else 0
    if cleanup<0 or cleanup>32 or cleanup%4:return []
    registers={'ecx':('this',)};values={};layouts={};writes=[];used_args=set();x87=[]
    def memory(instruction,operand,width):
        if operand.type!=cs.x86.X86_OP_MEM or operand.size!=width or operand.mem.index or operand.mem.segment:return None
        owner=registers.get(instruction.reg_name(operand.mem.base));offset=operand.mem.disp
        if owner is None or offset<0 or offset>512 or offset%width:return None
        layout=layouts.setdefault(owner,{})
        if any(offset!=p and offset<p+w and p<offset+width for p,w in layout.items()):return None
        if offset in layout and layout[offset]!=width:return None
        layout[offset]=width
        return owner,offset,width
    for instruction in code[3:-3]:
        operands=instruction.operands
        if instruction.mnemonic=='mov' and len(operands)==2 and operands[0].type==cs.x86.X86_OP_REG:
            dest,source=operands;target=instruction.reg_name(dest.reg)
            if target not in ('eax','ecx','edx') or dest.size!=4:return []
            if source.type==cs.x86.X86_OP_REG:
                owner=registers.get(instruction.reg_name(source.reg))
                if owner is None:return []
                registers[target]=owner
            elif (source.type==cs.x86.X86_OP_MEM and source.size==4 and instruction.reg_name(source.mem.base)=='ebp'
                  and not source.mem.index and not source.mem.segment and 8<=source.mem.disp<=36 and source.mem.disp%4==0):
                argument=(source.mem.disp-8)//4;used_args.add(argument);registers[target]=('arg',argument)
            else:return []
        elif instruction.mnemonic=='movaps' and len(operands)==2:
            left,right=operands
            if left.type==cs.x86.X86_OP_REG and instruction.reg_name(left.reg).startswith('xmm'):
                value=memory(instruction,right,16);key=instruction.reg_name(left.reg)
                if value is None or key in values:return []
                values[key]=value
            elif right.type==cs.x86.X86_OP_REG and instruction.reg_name(right.reg).startswith('xmm'):
                dest=memory(instruction,left,16);key=instruction.reg_name(right.reg)
                # Do not delay another live load across this write: two input
                # pointers may alias. Plain assignments preserve the observed
                # load/store order only when this is the sole pending value.
                if dest is None or key not in values or len(values)!=1 or x87:return []
                writes.append((dest,values.pop(key)))
            else:return []
        elif instruction.mnemonic=='fld' and len(operands)==1:
            value=memory(instruction,operands[0],4)
            if value is None or x87:return []
            x87.append(value)
        elif instruction.mnemonic=='fstp' and len(operands)==1:
            dest=memory(instruction,operands[0],4)
            if dest is None or not x87 or values:return []
            writes.append((dest,x87.pop()))
        else:return []
    if values or x87 or not writes or len(writes)>16 or not any(w==16 for layout in layouts.values() for w in layout.values()):return []
    member=('this',) in layouts
    if cleanup and (not member or used_args and max(used_args)>=cleanup//4):return []
    count=max(cleanup//4,max(used_args)+1 if used_args else 0)
    if count>8:return []
    # Separate pointer identities remain separate types. Aliasing loads/stores
    # retain their statement order; no speculative operation reordering occurs.
    def tag(owner):return 'CpuObject' if owner==('this',) else 'CpuData'+str(owner[1])
    def variable(owner):return 'this' if owner==('this',) else 'input'+str(owner[1])
    declarations='#include <xmmintrin.h>\n'
    parameters=', '.join((tag(('arg',i))+'* input'+str(i)) if ('arg',i) in layouts else 'int unused'+str(i) for i in range(count))
    for owner,layout in sorted(layouts.items(),key=lambda item:item[0][0]=='this'):
        declarations+='struct '+tag(owner)+' {\n';position=0
        for offset,width in sorted(layout.items()):
            while position<offset:
                declarations+=f'    unsigned int unk{position:02x};\n';position+=4
            declarations+=f'    {"__m128" if width==16 else "float"} field{offset:02x};\n';position+=width
        if owner==('this',):declarations+=f'    void {name}({parameters});\n'
        declarations+='};\n'
    signature='void '+('CpuObject::' if member else '__cdecl ')+name+'('+parameters+')'
    statements=''
    for (owner,offset,width),(source_owner,source_offset,_) in writes:
        statements+=f'    {variable(owner)}->field{offset:02x} = {variable(source_owner)}->field{source_offset:02x};\n'
    return [('aligned_vector_copy',declarations+signature+'\n{\n'+statements+'}\n')]
