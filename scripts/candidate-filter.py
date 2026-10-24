"""Bounded 32-bit expression filtering. Samples/SMT are never byte MATCH evidence.

Pure data only: no eval, game execution, claims, network or model calls.
CUDA is process-pinned to the explicitly configured device before Torch import.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
try:
    import numpy as np
except ImportError:
    sys.path.append(str(ROOT / '.venv/Lib/site-packages'))
    import numpy as np

MASK = 0xffffffff
GPU_UUID = os.environ.get('FNV_FILTER_GPU_UUID','')
BINARY = {'add', 'sub', 'mul', 'and', 'or', 'xor', 'shl', 'shr', 'sar',
          'eq', 'ne', 'ult', 'ule', 'ugt', 'uge', 'slt', 'sle', 'sgt', 'sge'}
ARITY = dict.fromkeys(BINARY, 2) | {'neg': 1, 'not': 1, 'select': 3}
_CUDA = None


def expression(value, depth=0, budget=None, max_nodes=64, max_depth=16):
    """Validate/normalize a small, explicitly enumerated expression grammar."""
    if budget is None: budget = [0]
    budget[0] += 1
    if depth > max_depth or budget[0] > max_nodes: raise ValueError('Expression exceeds depth/node budget')
    if not isinstance(value, (list, tuple)) or not value or not isinstance(value[0], str):
        raise ValueError('Expression must be an operator array')
    op = value[0]
    if op == 'const':
        if len(value) != 2 or type(value[1]) is not int or not -(1 << 63) <= value[1] < (1 << 64):
            raise ValueError('Invalid integer constant')
        return ('const', value[1] & MASK)
    if op == 'var':
        if len(value) != 2 or not isinstance(value[1], str) or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,47}', value[1]):
            raise ValueError('Invalid variable name')
        return tuple(value)
    if op not in ARITY or len(value) != ARITY[op] + 1: raise ValueError('Unknown operator or arity')
    return (op, *(expression(child, depth + 1, budget, max_nodes, max_depth) for child in value[1:]))


def variables(expr):
    if expr[0] == 'var': return {expr[1]}
    if expr[0] == 'const': return set()
    return set().union(*(variables(child) for child in expr[1:]))


def shape(expr):
    if expr[0] in ('var', 'const'): return (expr[0],)
    return (expr[0], *(shape(child) for child in expr[1:]))


def evaluate_group(expressions, xp, env, count, device=None):
    """Evaluate one structural group as candidate-by-sample arrays.

    Constants and variable selectors differ across rows. Device inputs stay
    resident across batches; synchronization happens once per batch, not row.
    """
    def array(value):
        return xp.asarray(value, dtype=xp.int64) if device is None else xp.as_tensor(value, dtype=xp.int64, device=device)
    def integer(value):
        return value.astype(np.int64) if device is None else value.to(dtype=xp.int64)
    def visit(nodes):
        op = nodes[0][0]
        if op == 'const':
            a = array([n[1] for n in nodes])[:, None]
            return xp.broadcast_to(a, (len(nodes), count))
        if op == 'var': return xp.stack([env[n[1]] for n in nodes], axis=0) if device is None else xp.stack([env[n[1]] for n in nodes], dim=0)
        a = visit([n[1] for n in nodes])
        if op == 'not': return (~a) & MASK
        if op == 'neg': return (-a) & MASK
        b = visit([n[2] for n in nodes])
        if op == 'select': return xp.where(a != 0, b, visit([n[3] for n in nodes]))
        if op in {'eq', 'ne'}: return integer(a == b if op == 'eq' else a != b)
        if op[0:1] in ('s', 'u') and op[1:] in ('lt', 'le', 'gt', 'ge'):
            if op[0] == 's': a, b = (a ^ 0x80000000) - 0x80000000, (b ^ 0x80000000) - 0x80000000
            return integer({'lt': lambda: a < b, 'le': lambda: a <= b, 'gt': lambda: a > b, 'ge': lambda: a >= b}[op[1:]]())
        if op == 'sar': return (((a ^ 0x80000000) - 0x80000000) >> (b & 31)) & MASK
        return {'add': lambda: (a + b) & MASK, 'sub': lambda: (a - b) & MASK,
                'mul': lambda: (a * b) & MASK, 'and': lambda: a & b, 'or': lambda: a | b,
                'xor': lambda: a ^ b, 'shl': lambda: (a << (b & 31)) & MASK,
                'shr': lambda: a >> (b & 31)}[op]()
    return visit(expressions)


def pin_cuda():
    global _CUDA
    if _CUDA is not None:
        if os.environ.get('CUDA_VISIBLE_DEVICES') != GPU_UUID: raise RuntimeError('CUDA visibility changed')
        return _CUDA
    if 'torch' in sys.modules: raise RuntimeError('Run CUDA filter in a fresh process before importing Torch')
    if os.environ.get('CUDA_VISIBLE_DEVICES') not in (None, '', GPU_UUID): raise RuntimeError('CUDA visibility conflict')
    os.environ['CUDA_VISIBLE_DEVICES'] = GPU_UUID
    import torch
    if not torch.cuda.is_available() or torch.cuda.device_count() != 1:
        raise RuntimeError('Configured CUDA device unavailable')
    if torch.cuda.mem_get_info(0)[0] < 512 * 1024**2: raise RuntimeError('Less than 512MiB free on CUDA device')
    _CUDA = torch
    return torch


def smt_compare(reference, candidate, timeout_ms=250, expression_limits=(64, 16)):
    """Check exact pure bitvector expressions; not C++/ABI or game equivalence."""
    if not 1 <= timeout_ms <= 2000: raise ValueError('SMT timeout must be 1..2000ms')
    try:
        import z3
    except ImportError:
        sys.path.append(str(ROOT / '.venv/Lib/site-packages'))
        import z3
    if not 1 <= expression_limits[0] <= 128 or not 1 <= expression_limits[1] <= 128:
        raise ValueError('Expression limits outside bounds')
    reference, candidate = [expression(e, max_nodes=expression_limits[0], max_depth=expression_limits[1]) for e in (reference, candidate)]
    names = sorted(variables(reference) | variables(candidate))
    if len(names) > 32: raise ValueError('Too many variables')
    symbols = {n: z3.BitVec(n, 32) for n in names}
    def lift(e):
        op = e[0]
        if op == 'var': return symbols[e[1]]
        if op == 'const': return z3.BitVecVal(e[1], 32)
        a = lift(e[1])
        if op == 'not': return ~a
        if op == 'neg': return -a
        b = lift(e[2])
        if op == 'select': return z3.If(a != 0, b, lift(e[3]))
        if op in {'eq', 'ne', 'ult', 'ule', 'ugt', 'uge', 'slt', 'sle', 'sgt', 'sge'}:
            pred = {'eq': lambda: a == b, 'ne': lambda: a != b,
                    'ult': lambda: z3.ULT(a, b), 'ule': lambda: z3.ULE(a, b),
                    'ugt': lambda: z3.UGT(a, b), 'uge': lambda: z3.UGE(a, b),
                    'slt': lambda: a < b, 'sle': lambda: a <= b,
                    'sgt': lambda: a > b, 'sge': lambda: a >= b}[op]()
            return z3.If(pred, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        return {'add': lambda: a + b, 'sub': lambda: a - b, 'mul': lambda: a * b,
                'and': lambda: a & b, 'or': lambda: a | b, 'xor': lambda: a ^ b,
                'shl': lambda: a << (b & 31), 'shr': lambda: z3.LShR(a, b & 31),
                'sar': lambda: a >> (b & 31)}[op]()
    solver = z3.Solver(); solver.set(timeout=timeout_ms)
    solver.add(lift(reference) != lift(candidate))
    answer = solver.check()
    if answer == z3.unsat: return {'status': 'equivalent_bitvectors'}
    if answer == z3.unknown: return {'status': 'unknown', 'reason': solver.reason_unknown()}
    model = solver.model()
    return {'status': 'counterexample', 'inputs': {n: model.eval(symbols[n], model_completion=True).as_long() for n in names}}


def run(spec, backend='cpu', batch_size=64, smt=False, smt_timeout_ms=250, smt_limit=32, expression_limits=(64, 16)):
    begun = time.perf_counter()
    if backend not in ('cpu', 'cuda') or not 1 <= batch_size <= 256: raise ValueError('Invalid backend/batch size')
    if not isinstance(spec, dict) or not isinstance(spec.get('candidates'), list) or not 1 <= len(spec['candidates']) <= 4096:
        raise ValueError('Need 1..4096 candidates')
    if not 1 <= expression_limits[0] <= 128 or not 1 <= expression_limits[1] <= 128:
        raise ValueError('Expression limits outside bounds')
    normalize = lambda e: expression(e, max_nodes=expression_limits[0], max_depth=expression_limits[1])
    reference = normalize(spec['reference']); candidates = [normalize(e) for e in spec['candidates']]
    names = sorted(set().union(variables(reference), *(variables(e) for e in candidates)))
    if len(names) > 32: raise ValueError('At most 32 variables')
    count = spec.get('samples', 8192)
    if type(count) is not int or not 16 <= count <= 65536 or count * len(candidates) > 16777216:
        raise ValueError('Sample/work budget exceeded')
    seed = spec.get('seed', 384)
    if type(seed) is not int or not 0 <= seed < 2**64: raise ValueError('Invalid random seed')
    rng = np.random.default_rng(seed)
    env = {n: rng.integers(0, 2**32, count, dtype=np.int64) for n in names}
    edges = np.array([0, 1, 2, 31, 32, 255, 65535, 0x7fffffff, 0x80000000, 0xfffffffe, MASK], dtype=np.int64)
    for i, name in enumerate(names): env[name][:len(edges)] = np.roll(edges, i)
    supplied = spec.get('inputs', {})
    if not isinstance(supplied, dict) or set(supplied) - set(names): raise ValueError('Invalid input variable')
    for name, values in supplied.items():
        if not isinstance(values, list) or len(values) != count or any(type(v) is not int or not 0 <= v <= MASK for v in values):
            raise ValueError('Explicit input column must contain sample-count uint32 values')
        env[name] = np.asarray(values, dtype=np.int64)
    expected = evaluate_group([reference], np, env, count)[0]
    torch = pin_cuda() if backend == 'cuda' else None
    device_env = {n: torch.from_numpy(v).to('cuda') for n, v in env.items()} if torch else None
    if torch: torch.cuda.synchronize(); torch.cuda.reset_peak_memory_stats()
    groups = defaultdict(list)
    for i, e in enumerate(candidates): groups[shape(e)].append(i)
    survivors = []; fingerprints = defaultdict(list); mismatches = {}; batches = 0; evaluation_seconds = 0.0
    for indices in groups.values():
        for start in range(0, len(indices), batch_size):
            chunk = indices[start:start + batch_size]; expressions = [candidates[i] for i in chunk]
            tick = time.perf_counter(); cpu = evaluate_group(expressions, np, env, count)
            if torch:
                gpu = evaluate_group(expressions, torch, device_env, count, 'cuda').cpu().numpy()
                if not np.array_equal(cpu, gpu): raise RuntimeError('CPU/CUDA result disagreement')
            evaluation_seconds += time.perf_counter() - tick; batches += 1
            for i, values in zip(chunk, cpu):
                fingerprint = hashlib.sha256(values.tobytes()).hexdigest(); fingerprints[fingerprint].append(i)
                failed = np.flatnonzero(values != expected)
                if not len(failed): survivors.append(i)
                else: mismatches[str(i)] = {'sample': int(failed[0]), 'inputs': {n: int(v[failed[0]]) for n, v in env.items()},
                                           'expected': int(expected[failed[0]]), 'actual': int(values[failed[0]])}
    survivors.sort(); smt_results = {}
    if not 0 <= smt_limit <= 128: raise ValueError('SMT limit must be 0..128')
    if smt:
        for i in survivors[:smt_limit]: smt_results[str(i)] = smt_compare(reference, candidates[i], smt_timeout_ms, expression_limits)
        survivors = [i for i in survivors if smt_results.get(str(i), {}).get('status') != 'counterexample']
    elapsed = time.perf_counter() - begun
    return {'backend': backend, 'device': torch.cuda.get_device_name(0) if torch else 'CPU',
            'gpu_uuid': GPU_UUID if torch else None, 'gpu_work_performed': bool(torch),
            'samples': count, 'candidates': len(candidates), 'batches': batches, 'structural_groups': len(groups),
            'survivor_indices': survivors, 'survivors': len(survivors), 'rejected': len(candidates) - len(survivors),
            'sample_duplicate_groups': [v for v in fingerprints.values() if len(v) > 1],
            'duplicate_note': 'Sample signatures only; preserve distinct C++ forms for compiler finishing.',
            'mismatches': mismatches, 'smt_results': smt_results,
            'elapsed_seconds': elapsed, 'evaluation_seconds': evaluation_seconds,
            'candidate_samples_per_second': count * len(candidates) / elapsed,
            'peak_cuda_mib': torch.cuda.max_memory_allocated() / 1024**2 if torch else 0,
            'cpu_cuda_parity': True if torch else None,
            'llm_calls': 0, 'service_calls': 0, 'official_match_claimed': False,
            'note': 'Pure expression filtering only. Official compiler/checker required for every full-function MATCH.'}


def demo():
    x = ['var', 'x']; y = ['var', 'y']
    return {'reference': ['add', x, y], 'candidates': [['add', x, y], ['add', y, x],
            ['sub', x, ['neg', y]], ['xor', x, y]] + [['add', x, ['const', i]] for i in range(64)], 'samples': 8192}


def filter_integer(plan, expressions, backend='cpu', sample_count=8192, smt=False):
    """Adapter for integer-search's validated pure-expression IR.

    Opaque call results are independent inputs; no call/ABI equivalence is
    asserted here. Caller must preserve original calls/arguments/order exactly.
    Returned survivors retain every distinct C++ formulation.
    """
    if backend not in ('cpu', 'cuda'): raise ValueError('Invalid backend')
    def convert(e, depth=0):
        if depth > 128: raise ValueError('Integer IR exceeds depth budget')
        if not isinstance(e, (list, tuple)) or not e: raise ValueError('Invalid integer IR')
        if e[0] in ('arg', 'regarg', 'field', 'call'):
            if len(e) != 2: raise ValueError('Invalid integer IR input')
            if e[0] == 'regarg' and isinstance(e[1], str) and e[1] in ('ecx', 'edx'):
                return ['var', f'regarg_s{e[1]}']
            if type(e[1]) is not int or not 0 <= e[1] <= 0x100000:
                raise ValueError('Invalid integer IR input')
            return ['var', f'{e[0]}_i{e[1]}']
        if e[0] == 'const': return list(e)
        return [e[0], *(convert(child, depth + 1) for child in e[1:])]
    values = list(expressions)
    if not values:
        return [], {'backend': backend, 'gpu_work_performed': False, 'samples': 0,
                    'candidates': 0, 'survivors': 0, 'survivor_indices': [], 'rejected': 0,
                    'elapsed_seconds': 0, 'llm_calls': 0, 'service_calls': 0,
                    'official_match_claimed': False, 'note': 'No candidates to filter'}
    request = {'reference': convert(plan['expression']), 'candidates': [convert(e) for e in values], 'samples': sample_count}
    # Existing integer-search bounds allow80-node lifts and100-node variants.
    # Preserve those bounds rather than rejecting previously supported plans.
    result = run(request, backend=backend, smt=smt, expression_limits=(128, 128))
    result['opaque_calls_note'] = 'Call results are independent inputs; preserve call order/arguments; no ABI proof.'
    return [values[i] for i in result['survivor_indices']], result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path); p.add_argument('--demo', action='store_true')
    p.add_argument('--backend', choices=['cpu', 'cuda'], default='cpu'); p.add_argument('--batch-size', type=int, default=64)
    p.add_argument('--smt', action='store_true'); p.add_argument('--smt-limit', type=int, default=32)
    p.add_argument('--smt-timeout-ms', type=int, default=250); p.add_argument('--output', type=Path)
    args = p.parse_args()
    if bool(args.input) == args.demo: p.error('Choose exactly one of --input or --demo')
    if args.input and args.input.stat().st_size > 8 * 1024**2: p.error('Input exceeds 8MiB')
    spec = demo() if args.demo else json.loads(args.input.read_text(encoding='utf-8-sig'))
    result = run(spec, args.backend, args.batch_size, args.smt, args.smt_timeout_ms, args.smt_limit)
    if args.output:
        output = args.output.resolve()
        if not any(output.is_relative_to(ROOT / folder) for folder in ('local', 'work')):
            p.error('Private output must stay under local/ or work/')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
