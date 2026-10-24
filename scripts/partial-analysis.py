"""Bounded private x86 observations and partial expressions for agent handoffs.

This is a recovery aid, not a decompiler correctness proof. Each block is analyzed
independently; unknown instructions/calls discard affected expression state. No
reference bytes or full instruction listing are emitted. Nothing calls a model,
service or checker, and snippets are never submission candidates.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import capstone as cs
import pefile

ROOT = Path(__file__).resolve().parents[1]
REGISTERS = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp')
ALIASES = {name: full for full, names in {
    'eax': ('eax', 'ax', 'al', 'ah'), 'ebx': ('ebx', 'bx', 'bl', 'bh'),
    'ecx': ('ecx', 'cx', 'cl', 'ch'), 'edx': ('edx', 'dx', 'dl', 'dh'),
    'esi': ('esi', 'si'), 'edi': ('edi', 'di'), 'ebp': ('ebp', 'bp'), 'esp': ('esp', 'sp')
}.items() for name in names}


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def analyze_bytes(data, address=0, symbols=None, max_instructions=256):
    """Return observations even if a function cannot be completely reconstructed.

    Expressions use abstract block-entry register inputs. They apply only within
    one block, and caller-supplied symbols are trusted names, never invented names.
    """
    if not 1 <= max_instructions <= 1024:
        raise ValueError('Instruction budget must be 1..1024')
    if len(data) > 4096:
        raise ValueError('Partial analysis is limited to 4096 reference bytes')
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    decoder.detail = True
    code = list(decoder.disasm(data, address, count=max_instructions))
    by_address = {item.address: item for item in code}
    end = address + len(data)
    decoded_end = code[-1].address + code[-1].size if code else address
    complete_decode = decoded_end == end
    symbols = symbols or {}
    leaders = {address}
    edges, calls, stack, unresolved, fragments = [], [], [], [], []

    def offset(at): return at - address
    def problem(at, kind, detail):
        if len(unresolved) < 64:
            unresolved.append(dict(offset=offset(at), kind=kind, detail=detail))

    for item in code:
        after = item.address + item.size
        branch = item.group(cs.CS_GRP_JUMP)
        if branch:
            direct = bool(item.operands and item.operands[0].type == cs.x86.X86_OP_IMM)
            target = item.operands[0].imm & 0xffffffff if direct else None
            conditional = item.mnemonic != 'jmp'
            edge = dict(from_offset=offset(item.address), conditional=conditional,
                        condition=item.mnemonic, target_offset=offset(target) if target is not None and address <= target < end else None,
                        internal=target in by_address if target is not None else False,
                        backward=bool(target is not None and target < item.address))
            if target is not None and target in symbols: edge['target_symbol'] = symbols[target]
            edges.append(edge)
            if target in by_address: leaders.add(target)
            elif target is not None and address <= target < end:
                problem(item.address, 'branch_into_undecoded_region', 'Branch target is not a decoded instruction boundary.')
            else:
                problem(item.address, 'external_or_indirect_branch', 'Resolve tail call or computed branch from packet declarations.')
            if after in by_address: leaders.add(after)
        elif item.group(cs.CS_GRP_RET):
            if after in by_address: leaders.add(after)
        elif item.mnemonic == 'call':
            direct = bool(item.operands and item.operands[0].type == cs.x86.X86_OP_IMM)
            target = item.operands[0].imm & 0xffffffff if direct else None
            entry = dict(offset=offset(item.address), direct=direct, symbol=symbols.get(target),
                         calling_convention='unresolved', arguments='unresolved', side_effects='unknown')
            calls.append(entry)
            problem(item.address, 'call_contract_unknown', 'Recover argument types, calling convention and memory effects before composing surrounding fragments.')
    if not complete_decode:
        problem(decoded_end, 'incomplete_decode', 'Instruction budget or invalid bytes prevented decoding the complete packet span.')

    blocks = []
    for start in sorted(leaders):
        if start not in by_address: continue
        next_start = min((point for point in leaders if point > start), default=decoded_end)
        instructions = [item for item in code if start <= item.address < next_start]
        if not instructions: continue
        blocks.append(dict(start_offset=offset(start), end_offset=offset(instructions[-1].address + instructions[-1].size),
                           instruction_count=len(instructions), entry_state='independent symbolic register inputs'))
        regs = {reg: f'block_{offset(start):x}_{reg}' for reg in REGISTERS}
        sp = 0 if start == address else None
        frame = None
        locals_ = {}

        def val(item, operand):
            if operand.type == cs.x86.X86_OP_IMM:
                # Immediates can be pointers. Do not turn game addresses into C++ literals.
                number = operand.imm & 0xffffffff
                return str(number) + 'u' if number < 0x10000 else None
            if operand.type == cs.x86.X86_OP_REG and operand.size == 4:
                return regs.get(item.reg_name(operand.reg))
            if operand.type == cs.x86.X86_OP_MEM:
                base = item.reg_name(operand.mem.base)
                if operand.size == 4 and not operand.mem.index and not operand.mem.segment:
                    relative = (sp if base == 'esp' else frame if base == 'ebp' else None)
                    if relative is not None:
                        slot = relative + operand.mem.disp
                        if slot in locals_: return locals_[slot]
                        if slot >= 4 and slot % 4 == 0: return f'entry_stack_dword_{slot // 4}'
                # Unknown memory is an explicit boundary, never an invented C++ dereference.
            return None

        def emit(item, text, assumptions=None):
            if len(fragments) < 96:
                fragments.append(dict(offset=offset(item.address), block_offset=offset(start), snippet=text,
                                      status='partial_unverified', assumptions=assumptions or ['32-bit unsigned integer operation; block-entry inputs need types and names.']))

        for item in instructions:
            op, operands = item.mnemonic, item.operands
            handled = False
            if op == 'push' and len(operands) == 1 and operands[0].size == 4:
                expression = val(item, operands[0])
                if sp is not None: sp -= 4
                if sp is not None:
                    if expression is not None: locals_[sp] = expression
                    else: locals_.pop(sp, None)
                regs.pop('esp', None)
                stack.append(dict(offset=offset(item.address), operation='push', entry_esp_offset=sp))
                handled = True
            elif op == 'pop' and len(operands) == 1 and operands[0].size == 4:
                if operands[0].type == cs.x86.X86_OP_REG:
                    destination = ALIASES.get(item.reg_name(operands[0].reg))
                    regs.pop(destination, None)
                    if destination == 'esp': sp = None
                    if destination == 'ebp': frame = None
                if sp is not None: sp += 4
                regs.pop('esp', None)
                stack.append(dict(offset=offset(item.address), operation='pop', entry_esp_offset=sp))
                handled = True
            elif op in ('add', 'sub') and len(operands) == 2 and operands[0].type == cs.x86.X86_OP_REG and item.reg_name(operands[0].reg) == 'esp' and operands[1].type == cs.x86.X86_OP_IMM:
                if sp is not None: sp += operands[1].imm * (1 if op == 'add' else -1)
                regs.pop('esp', None)
                stack.append(dict(offset=offset(item.address), operation='stack_adjustment', entry_esp_offset=sp))
                handled = True
            elif op == 'mov' and len(operands) == 2:
                left, right = operands
                if left.type == cs.x86.X86_OP_REG and left.size == 4:
                    destination = item.reg_name(left.reg)
                    expression = val(item, right)
                    if destination == 'ebp': frame = sp if right.type == cs.x86.X86_OP_REG and item.reg_name(right.reg) == 'esp' else None
                    if destination == 'esp':
                        sp = frame if right.type == cs.x86.X86_OP_REG and item.reg_name(right.reg) == 'ebp' else None
                    if expression is not None:
                        regs[destination] = expression
                        if destination not in ('esp', 'ebp'): emit(item, f'{destination} = {expression};')
                    else:
                        regs.pop(destination, None)
                        problem(item.address, 'unknown_value', 'Memory load or value needs packet types and pointer analysis.')
                    handled = True
                elif left.type == cs.x86.X86_OP_MEM:
                    base = item.reg_name(left.mem.base)
                    relative = sp if base == 'esp' else frame if base == 'ebp' else None
                    if relative is not None and not left.mem.index and not left.mem.segment and left.size == 4:
                        slot = relative + left.mem.disp
                        expression = val(item, right)
                        if expression is not None:
                            locals_[slot] = expression
                            emit(item, f'stack_dword_{slot:+d} = {expression};', ['Observed stack slot, not yet a typed C++ local or argument.'])
                        else: locals_.pop(slot, None)
                        stack.append(dict(offset=offset(item.address), operation='stack_write', entry_esp_offset=slot))
                        handled = True
            elif op in ('add', 'sub', 'and', 'or', 'xor', 'imul') and len(operands) == 2 and operands[0].type == cs.x86.X86_OP_REG and operands[0].size == 4:
                destination = item.reg_name(operands[0].reg)
                if destination == 'esp': sp = None
                if destination == 'ebp': frame = None
                a, b = val(item, operands[0]), val(item, operands[1])
                if op == 'xor' and operands[1].type == cs.x86.X86_OP_REG and operands[0].reg == operands[1].reg:
                    expression = '0u'
                elif a is not None and b is not None:
                    operator = {'add': '+', 'sub': '-', 'and': '&', 'or': '|', 'xor': '^', 'imul': '*'}[op]
                    expression = f'({a} {operator} {b})'
                else: expression = None
                if expression is not None and len(expression) <= 512:
                    regs[destination] = expression
                    emit(item, f'{destination} = {expression};')
                else: regs.pop(destination, None)
                handled = True
            elif op == 'call':
                # Unknown callees can write memory (including through stack pointers).
                # Invalidate all expression state: even callee-saved registers might
                # hold expressions based on memory that was modified by the call.
                regs.clear(); locals_.clear(); frame = None; sp = None
                handled = True
            elif op in ('cmp', 'test') and len(operands) == 2:
                a, b = val(item, operands[0]), val(item, operands[1])
                if a is not None and b is not None:
                    emit(item, f'/* {op}: {a}, {b} */', ['Comparison observation only; branch condition and flag liveness require reconstruction.'])
                handled = True
            elif item.group(cs.CS_GRP_RET):
                if regs.get('eax') is not None: emit(item, f'/* possible EAX result: {regs["eax"]} */', ['Return type is unresolved; EAX may not be the function return value.'])
                handled = True
            elif item.group(cs.CS_GRP_JUMP) or op == 'nop': handled = True
            if not handled:
                problem(item.address, 'unsupported_semantics', f'{op}: expressions depending on this instruction are discarded.')
                # Conservative barrier: unknown opcodes/partial writes must never
                # leave a stale expression that appears recovered to the model.
                regs.clear(); locals_.clear(); frame = None; sp = None
    return dict(version=1, status='partial_analysis_only', confirmed_match=False, upload_authorized=False,
                complete_decode=complete_decode, decoded_instructions=len(code), reference_size=len(data),
                basic_blocks=blocks, control_flow=edges, calls=calls, stack_observations=stack[:128],
                fragments=fragments, unresolved=unresolved,
                limitations=['Independent block-local expressions; no dataflow merge or alias proof.',
                             'No ABI inference, floating-point reconstruction, complete C++ or correctness proof.',
                             'A fully compiled official checker MATCH is required for submission.'])


def analyze_pack(pack, root=None):
    root = Path(root or ROOT).resolve()
    pack = Path(pack).resolve()
    if not pack.is_relative_to(root / 'work') or not (pack / 'pack.json').is_file():
        raise ValueError('Pack must be an existing folder under work/')
    meta_file = pack / 'pack.json'
    metadata_bytes = meta_file.read_bytes()
    meta = json.loads(metadata_bytes.decode('utf-8-sig'))
    size = int(meta['size'])
    if not 1 <= size <= 4096: raise ValueError('Partial analysis requires a packet size of 1..4096 bytes')
    address = int(meta['address'], 16)
    image = pefile.PE(read(root / 'local/settings.json')['checker_image'], fast_load=True)
    try:
        data = image.get_data(address - image.OPTIONAL_HEADER.ImageBase, size)
    finally: image.close()
    if len(data) != size: raise ValueError('Private reference does not contain the complete packet span')
    symbols = {}
    index = root / 'local/shared/function_index.json'
    if index.is_file():
        for row in read(index):
            if row.get('address') and isinstance(row.get('symbol'), str) and re.fullmatch(r'[A-Za-z_]\w*', row['symbol']):
                symbols[int(row['address'], 16)] = row['symbol']
    result = analyze_bytes(data, address, symbols)
    if metadata_bytes != meta_file.read_bytes(): raise ValueError('Pack metadata changed during analysis')
    result.update(identity={key: meta[key] for key in ('symbol', 'address', 'size')}, claim_id=pack.name,
                  pack_metadata_sha256=hashlib.sha256(metadata_bytes).hexdigest(), llm_calls=0, service_calls=0)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pack', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = analyze_pack(args.pack)
    output = (args.output or args.pack / 'cpu_assist/partial-analysis.json').resolve()
    if not any(output.is_relative_to(ROOT / parent) for parent in ('local', 'work')):
        raise ValueError('Partial reports must remain under ignored local/ or work/')
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(result, indent=2), encoding='utf-8')
    temporary.replace(output)
    print(json.dumps(dict(report=str(output), fragments=len(result['fragments']), unresolved=len(result['unresolved']), status=result['status'])))


if __name__ == '__main__': main()
