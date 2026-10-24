"""Complete small wrapper graphs; declarations and offsets come from each target.

No saved bodies, address lookup, compiler directives or checker exceptions. Every
candidate still requires the unchanged official compiler and byte comparison.
"""
import capstone as cs
import re


def from_code(code, name, indexed):
    if not re.fullmatch(r'[A-Za-z_]\w*', name):
        return []
    def reg(i, o, value):
        return o.type == cs.x86.X86_OP_REG and i.reg_name(o.reg) == value

    def memory(i, o, base, offset=None, size=4):
        return (o.type == cs.x86.X86_OP_MEM and o.size == size and
                i.reg_name(o.mem.base) == base and not o.mem.index and
                not o.mem.segment and 0 <= o.mem.disp <= 4096 and
                o.mem.disp % min(size, 4) == 0 and
                (offset is None or o.mem.disp == offset))

    def immediate(o, value=None):
        return o.type == cs.x86.X86_OP_IMM and (value is None or o.imm == value)

    def rr(i, mnemonic, left, right):
        return (i.mnemonic == mnemonic and len(i.operands) == 2 and
                reg(i, i.operands[0], left) and reg(i, i.operands[1], right))

    def rm(i, left, base, offset=None, size=4, mnemonic='mov'):
        return (i.mnemonic == mnemonic and len(i.operands) == 2 and
                reg(i, i.operands[0], left) and
                memory(i, i.operands[1], base, offset, size))

    def single(i, mnemonic, value):
        return i.mnemonic == mnemonic and len(i.operands) == 1 and reg(i, i.operands[0], value)

    def ret(i, cleanup=0):
        return i.mnemonic == 'ret' and (not i.operands if cleanup == 0 else
                                       len(i.operands) == 1 and immediate(i.operands[0], cleanup))

    def fields(offset, kind, field='value'):
        position = 0
        result = ''
        while position < offset:
            width = 4 if position % 4 == 0 and position + 4 <= offset else 1
            result += f'    {"unsigned int" if width == 4 else "unsigned char"} unk{position:03x};\n'
            position += width
        return result + f'    {kind} {field};\n'

    c = code
    # Free void wrapper: optional object, one forwarded stack argument. The
    # branch must land on the common RET; no other effects or hidden path.
    if len(c) == 7 and all((rm(c[0], 'ecx', 'esp', 4), rr(c[1], 'test', 'ecx', 'ecx'),
                           c[2].mnemonic == 'je' and len(c[2].operands) == 1 and immediate(c[2].operands[0], c[6].address),
                           rm(c[3], 'eax', 'esp', 8), single(c[4], 'push', 'eax'),
                           c[5].mnemonic == 'call' and len(c[5].operands) == 1 and immediate(c[5].operands[0]),
                           ret(c[6]))):
        address = c[5].operands[0].imm
        if indexed(address):
            target = f'FUN_{address:08x}'
            return [('null_guarded_member_argument',
                     f'struct CpuTarget {{ void {target}(int value); }};\n'
                     f'void __cdecl {name}(CpuTarget* object, int value)\n{{\n'
                     f'    if (object) object->{target}(value);\n}}\n')]

    # Free wrapper selects a genuine virtual member on its first argument and
    # supplies one non-address scalar constant. Use real C++ virtual dispatch.
    if len(c) == 6 and all((rm(c[0], 'ecx', 'esp', 4), rm(c[1], 'eax', 'ecx', 0),
                           rm(c[2], 'edx', 'eax'), c[3].mnemonic == 'push' and len(c[3].operands) == 1,
                           single(c[4], 'call', 'edx'), ret(c[5]))):
        operand = c[3].operands[0]
        slot = c[2].operands[1].mem.disp
        # Without a canonical class declaration only the first virtual member
        # can be represented honestly. Never synthesize unused virtual slots.
        if immediate(operand) and -32768 <= operand.imm <= 32767 and slot == 0:
            return [('stack_object_virtual_constant',
                     'struct CpuInterface {\n    virtual void Invoke(int value);\n};\n'
                     f'void __cdecl {name}(CpuInterface* object)\n{{\n'
                     f'    object->Invoke({operand.imm});\n}}\n')]

    # VC2008 /Od member frame, followed by exactly one scalar read or write.
    # The local is the real spilled this pointer, not an invented source local.
    if len(c) not in (9, 10):
        return []
    if not (single(c[0], 'push', 'ebp') and rr(c[1], 'mov', 'ebp', 'esp') and
            single(c[2], 'push', 'ecx') and c[3].mnemonic == 'mov' and len(c[3].operands) == 2 and
            c[3].operands[0].type == cs.x86.X86_OP_MEM and c[3].operands[0].size == 4 and
            c[3].reg_name(c[3].operands[0].mem.base) == 'ebp' and c[3].operands[0].mem.disp == -4 and
            not c[3].operands[0].mem.index and not c[3].operands[0].mem.segment and reg(c[3], c[3].operands[1], 'ecx') and
            c[4].mnemonic == 'mov' and len(c[4].operands) == 2 and reg(c[4], c[4].operands[0], 'eax') and
            c[4].operands[1].type == cs.x86.X86_OP_MEM and c[4].operands[1].size == 4 and
            c[4].reg_name(c[4].operands[1].mem.base) == 'ebp' and c[4].operands[1].mem.disp == -4 and
            not c[4].operands[1].mem.index and not c[4].operands[1].mem.segment and
            rr(c[-3], 'mov', 'esp', 'ebp') and single(c[-2], 'pop', 'ebp')):
        return []
    kind = None
    statement = None
    parameters = ''
    returns = ''
    if len(c) == 9 and ret(c[-1]) and len(c[5].operands) in (1, 2):
        load = c[5]
        source = load.operands[-1]
        if load.mnemonic == 'mov' and len(load.operands) == 2:
            width = source.size
            if width in (1, 2, 4) and memory(load, source, 'eax', size=width) and reg(load, load.operands[0], {1:'al', 2:'ax', 4:'eax'}[width]):
                kind = {1:'unsigned char', 2:'unsigned short', 4:'unsigned int'}[width]
        elif load.mnemonic == 'fld' and source.size in (4, 8) and memory(load, source, 'eax', size=source.size):
            kind = 'float' if source.size == 4 else 'double'
        if kind:
            offset = source.mem.disp
            returns = kind
            statement = 'return value;'
    elif len(c) == 10 and ret(c[-1], 4):
        load, store = c[5:7]
        if load.mnemonic == 'mov' and store.mnemonic == 'mov' and len(load.operands) == len(store.operands) == 2:
            value, argument = load.operands
            dest, copied = store.operands
            width = argument.size
            if (width in (1, 2, 4) and rm(load, {1:'cl', 2:'cx', 4:'ecx'}[width], 'ebp', 8, width) and
                    memory(store, dest, 'eax', size=width) and reg(store, copied, {1:'cl', 2:'cx', 4:'ecx'}[width])):
                kind = {1:'unsigned char', 2:'unsigned short', 4:'unsigned int'}[width]
                offset = dest.mem.disp
                parameters = kind + ' input'
                returns = 'void'
                statement = 'value = input;'
    if not kind:
        return []
    return [('framed_scalar_member', 'struct CpuObject {\n' + fields(offset, kind) +
             f'    {returns} {name}({parameters});\n}};\n'
             f'{returns} CpuObject::{name}({parameters})\n{{\n    {statement}\n}}\n')]
