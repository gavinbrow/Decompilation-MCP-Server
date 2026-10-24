"""Local CPU triage and reviewable subagent handoffs. No service/model calls.

This tool never obtains or releases claims, uploads, or starts workers. Its
historical checks are evidence for tooling development, never upload authority.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / 'local/benchmark/cpu-assist'


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private_path(path, root=None):
    """All reports, diagnostic excerpts and returned source stay ignored."""
    root = root or ROOT
    path = Path(path).resolve()
    if not any(path.is_relative_to((root / parent).resolve()) for parent in ('local', 'work')):
        raise ValueError('Output must be inside ignored local/ or work/')
    return path


def pack_path(path, root=None):
    root = root or ROOT
    path = Path(path).resolve()
    if not path.is_relative_to((root / 'work').resolve()) or not (path / 'pack.json').is_file():
        raise ValueError('Pack must be an existing folder under work/')
    return path


def save(path, value):
    path = private_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2), encoding='utf-8')
    temporary.replace(path)


def load_cpu():
    spec = importlib.util.spec_from_file_location('cpu_assist_worker', ROOT / 'scripts/cpu-template-worker.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def partial_analysis(pack):
    """Save recoverable observations even when whole-function templates fail."""
    spec = importlib.util.spec_from_file_location('cpu_assist_partial', Path(__file__).with_name('partial-analysis.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    value = module.analyze_pack(pack, root=ROOT)
    path = pack / 'cpu_assist/partial-analysis.json'
    save(path, value)
    return dict(path=str(path), status=value['status'], complete_decode=value['complete_decode'],
                fragment_count=len(value['fragments']), unresolved_count=len(value['unresolved']),
                fragments=value['fragments'][:24], unresolved=value['unresolved'][:24],
                limitations=value['limitations'], confirmed_match=False, upload_authorized=False)


def normalize_reason(reason):
    # Register-specific details are useful locally but would fragment priorities.
    reason = str(reason).split(':', 2)
    return ':'.join(reason[:2])[:120]


def features(pack, meta):
    """Only classify instructions. No disassembly or reference bytes in reports."""
    import capstone
    import pefile
    image = pefile.PE(read(ROOT / 'local/settings.json')['checker_image'], fast_load=True)
    address = int(meta['address'], 16)
    data = image.get_data(address - image.OPTIONAL_HEADER.ImageBase, int(meta['size']))
    image.close()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    code = list(decoder.disasm(data, address))
    if sum(item.size for item in code) != len(data) or len(data) != int(meta['size']):
        return ['incomplete_decode']
    found = set()
    for item in code:
        if item.mnemonic == 'call': found.add('calls')
        if item.mnemonic.startswith('j'):
            found.add('branches')
            if (item.operands and item.operands[0].type == capstone.x86.X86_OP_IMM
                    and address <= item.operands[0].imm < item.address):
                found.add('loops')
        if item.mnemonic.startswith('f'): found.add('x87')
        for operand in item.operands:
            if operand.type != capstone.x86.X86_OP_MEM: continue
            base = item.reg_name(operand.mem.base)
            if base in ('esp', 'ebp'): found.add('stack')
            if operand.mem.index: found.add('indexed_memory')
            if operand.size in (1, 2): found.add('narrow_memory')
            if operand.access & capstone.CS_AC_WRITE: found.add('memory_writes')
    return sorted(found or {'scalar'})


def classify(pack, cpu=None, max_size=255, template_result=None):
    pack = pack_path(pack)
    meta = read(pack / 'pack.json')
    cpu = cpu or load_cpu()
    candidates, reason = cpu.templates(pack, max_size) if template_result is None else template_result
    flags = features(pack, meta)
    normalized = normalize_reason(reason)
    return dict(claim_id=pack.name, pack=str(pack), symbol=meta['symbol'], address=meta['address'],
                size=int(meta['size']), supported=bool(candidates),
                pattern=candidates[0][0] if candidates else None,
                reason=str(reason), features=flags,
                cluster=normalized + '|' + ','.join(flags))


def rank(rows, examples=3):
    groups = {}
    for row in rows:
        if row.get('supported') or row.get('error'): continue
        group = groups.setdefault(row['cluster'], dict(cluster=row['cluster'], count=0,
                                  reason=normalize_reason(row['reason']), features=row['features'], examples=[]))
        group['count'] += 1
        if len(group['examples']) < examples:
            group['examples'].append({key: row[key] for key in ('claim_id', 'pack', 'symbol', 'size')})
    # Frequency is evidence; do not invent estimates of how hard a cluster is.
    return sorted(groups.values(), key=lambda group: (-group['count'], group['cluster']))


def scan(limit=1000, max_size=255):
    if not 1 <= limit <= 10000 or not 1 <= max_size <= 255:
        raise ValueError('Limit must be 1..10000 and max-size 1..255')
    begun = time.monotonic()
    cpu = load_cpu()
    rows = []
    seen = set()
    for file in sorted((ROOT / 'work').glob('clm_*/pack.json'), key=lambda p: p.stat().st_mtime, reverse=True):
        meta = read(file)
        address = int(meta['address'], 16)
        if address in seen or not 1 <= int(meta['size']) <= max_size: continue
        seen.add(address)
        try: row = classify(file.parent, cpu, max_size)
        except Exception as error:
            row = dict(claim_id=file.parent.name, supported=False, error=type(error).__name__)
        rows.append(row)
        if len(rows) >= limit: break
    return dict(utc=datetime.now(timezone.utc).isoformat(), method='Historical local screening only; no compiler checks',
                screened=len(rows), supported=sum(row['supported'] for row in rows),
                errors=sum('error' in row for row in rows), llm_calls=0, service_calls=0, uploaded=0,
                elapsed_seconds=time.monotonic() - begun, ranked_opportunities=rank(rows), results=rows)


def evidence(pack, limit=8):
    candidates = []
    checks = []
    # Bound enumeration as well as output; gigantic old search folders are optional evidence.
    for count, file in enumerate(pack.rglob('*')):
        if count >= 5000: break
        if not file.is_file() or not file.resolve().is_relative_to(pack): continue
        if file.suffix == '.cpp': candidates.append(file)
        if file.suffix == '.json' and file.name.startswith(('check', 'coordinator-check')): checks.append(file)
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    checks.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    diagnostic = []
    for file in checks[:limit]:
        try: value = read(file)
        except (ValueError, OSError): continue
        if not isinstance(value, dict): continue
        diagnostic.append(dict(path=str(file), status=value.get('status'),
                               instruction_differences=value.get('ndiff_insn'),
                               byte_differences=value.get('diffs'),
                               first_differences=str(value.get('diff') or '')[:2048]))
    return dict(candidate_paths=[str(path) for path in candidates[:limit]], latest_checks=diagnostic)


def bundle(pack, output, screening=None):
    pack = pack_path(pack)
    row = classify(pack) if screening is None else screening
    meta=read(pack/'pack.json')
    if row.get('pack')!=str(pack) or row.get('claim_id')!=pack.name or any(row.get(k)!=meta[k] for k in ('symbol','address','size')):
        raise ValueError('Screening belongs to a different packet')
    try:
        partial = partial_analysis(pack)
    except (ValueError, OSError) as error:
        partial = dict(status='analysis_unavailable', reason=str(error)[:512], confirmed_match=False, upload_authorized=False)
    value = dict(version=2, historical_only=True, created_utc=datetime.now(timezone.utc).isoformat(),
                 identity={key: row[key] for key in ('claim_id', 'pack', 'symbol', 'address', 'size')},
                 pack_metadata_sha256=sha256(pack / 'pack.json'), screening=row, evidence=evidence(pack), partial_analysis=partial,
                 candidate_directory=str(pack / 'cpu_assist'),
                 instructions=[
                     'Read AGENTS.md, packet rules, source neighborhood and headers before editing.',
                     'Analyze this original pack only. Write readable C++ under candidate_directory.',
                     'Read partial_analysis: reuse recovered observations, resolve listed unknowns, and do not join independent block expressions without dataflow/alias checks.',
                     'Partial snippets are unverified pseudocode, not complete or uploadable C++. Preserve correct pieces while completing unresolved regions.',
                     'Use the official compiler/checker unchanged; fix the first instruction difference.',
                     'No service requests, claims, releases, uploads, AI worker starts or model API calls.',
                     'No assembly, byte emission, absolute game addresses, filler arrays or leaked sources.',
                     'Return source path, exact official check evidence, limitations and model/tool provenance.',
                     'Historical/released claims are development evidence only and must not be uploaded.',
                     'Only the coordinator can validate current ownership/capacity and authorize submission.'
                 ])
    save(output, value)
    return value


def verify(bundle_file, candidate, worker='cpu_assist', model=None):
    if model is not None and (not isinstance(model, str) or not model.strip() or len(model.strip()) > 500):
        raise ValueError('Explicit model/author details must contain 1..500 characters')
    if not re.fullmatch(r'cpu_assist(?:_[A-Za-z0-9]+)?', worker): raise ValueError('Invalid isolated worker name')
    value = read(private_path(bundle_file))
    pack = pack_path(value['identity']['pack'])
    if sha256(pack / 'pack.json') != value['pack_metadata_sha256']:
        raise ValueError('Pack metadata changed since handoff; create a new bundle')
    meta = read(pack / 'pack.json')
    if any(str(meta[key]) != str(value['identity'][key]) for key in ('symbol', 'address', 'size')):
        raise ValueError('Bundle identity does not match original pack')
    if pack.name != value['identity']['claim_id']: raise ValueError('Claim identity mismatch')
    candidate = Path(candidate).resolve()
    if not candidate.is_relative_to(pack) or candidate.suffix != '.cpp' or not candidate.is_file():
        raise ValueError('Returned candidate must be a .cpp file inside its original pack')
    source_hash = sha256(candidate)
    review = subprocess.run([str(ROOT / '.venv/Scripts/python.exe'), str(ROOT / 'scripts/source-address-review.py'), str(candidate)],
                            capture_output=True, text=True, timeout=15)
    if review.returncode:
        result = dict(status='source_review_required', return_code=review.returncode)
    else:
        command = [shutil.which('pwsh.exe') or 'pwsh.exe', '-NoProfile', '-File', str(ROOT / 'scripts/fnvcheck.ps1'),
                   '-Pack', str(pack), '-Candidate', str(candidate), '-Worker', worker, '-Json']
        checked = subprocess.run(command, capture_output=True, text=True, timeout=60, cwd=ROOT)
        try: result = json.loads(checked.stdout.lstrip('\ufeff'))
        except ValueError: result = dict(status='checker_error', reason='Official wrapper did not return JSON')
        result['return_code'] = checked.returncode
    stable = source_hash == sha256(candidate) and sha256(pack / 'pack.json') == value['pack_metadata_sha256']
    result.update(confirmed_match=result.get('status') == 'match' and result.get('return_code') == 0 and stable,
                  source_stable=stable, source_sha256=source_hash, candidate=str(candidate),
                  claim_id=pack.name, historical_only=True, upload_authorized=False, service_calls=0, llm_calls=0)
    if model is not None and result['confirmed_match']:
        provenance = candidate.with_suffix(candidate.suffix + '.provenance.json')
        save(provenance, dict(model=model.strip(), source_sha256=source_hash))
        result['provenance'] = str(provenance)
    elif model is None:
        result['provenance_note'] = 'No explicit model/author attribution supplied; no metadata generated'
    save(pack / worker / 'assist-check.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    screen = commands.add_parser('scan')
    screen.add_argument('--limit', type=int, default=1000)
    screen.add_argument('--max-size', type=int, default=255)
    screen.add_argument('--output', type=Path, default=DEFAULT_OUTPUT / 'triage.json')
    handoff = commands.add_parser('bundle')
    handoff.add_argument('--pack', type=Path, required=True)
    handoff.add_argument('--output', type=Path, required=True)
    check = commands.add_parser('verify')
    check.add_argument('--bundle', type=Path, required=True)
    check.add_argument('--candidate', type=Path, required=True)
    check.add_argument('--worker', default='cpu_assist')
    check.add_argument('--model', '--author-details', dest='model', help='Explicit model/tool/human authorship; stored hash-bound only after confirmed MATCH')
    args = parser.parse_args()
    if args.command == 'scan':
        private_path(args.output)
        result = scan(args.limit, args.max_size)
        save(args.output, result)
        print(json.dumps({key: value for key, value in result.items() if key not in ('results', 'ranked_opportunities')}, indent=2))
        print('Private ranked report:', private_path(args.output))
    elif args.command == 'bundle':
        result = bundle(args.pack, args.output)
        print(json.dumps(dict(bundle=str(private_path(args.output)), identity=result['identity']), indent=2))
    else:
        result = verify(args.bundle, args.candidate, args.worker, args.model)
        print(json.dumps(result, indent=2))
        return 0 if result['confirmed_match'] else 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
