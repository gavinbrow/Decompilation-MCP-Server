"""Bounded local source search. Diagnostic scores never authorize submission."""
import argparse
import concurrent.futures
import hashlib
import itertools
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|\s+|.', re.S)
IDENT = re.compile(r'^[A-Za-z_]\w*$')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''): h.update(chunk)
    return h.hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    temporary.write_text(json.dumps(value, indent=2), encoding='utf-8')
    temporary.replace(path)


def private_pack(pack):
    pack = Path(pack).resolve()
    if not pack.is_relative_to((ROOT / 'work').resolve()) or not (pack / 'pack.json').is_file():
        raise ValueError('Pack must be an original local work pack')
    return pack


def tokens(text):
    return TOKEN.findall(text)


def significant(items):
    return [(n, item) for n, item in enumerate(items)
            if not item.isspace() and not item.startswith(('//', '/*'))]


def function_body(items, symbol):
    """Find a definition rather than a prototype; deliberately narrow fallback."""
    sig = significant(items)
    name = symbol.rsplit('::', 1)[-1]
    for i, (_, item) in enumerate(sig):
        if item != name or i + 1 >= len(sig) or sig[i + 1][1] != '(': continue
        depth = 0
        closing = None
        for j in range(i + 1, len(sig)):
            if sig[j][1] == '(': depth += 1
            if sig[j][1] == ')':
                depth -= 1
                if not depth: closing = j; break
        if closing is None: continue
        j = closing + 1
        while j < len(sig) and sig[j][1] in ('const', 'volatile'): j += 1
        if j >= len(sig) or sig[j][1] != '{': continue
        depth = 0
        for k in range(j, len(sig)):
            if sig[k][1] == '{': depth += 1
            if sig[k][1] == '}':
                depth -= 1
                if not depth: return sig[j][0], sig[k][0]
    return None


def local_names(text, symbol):
    items = tokens(text)
    bounds = function_body(items, symbol)
    if not bounds: return []
    sig = significant(items)
    body = [(n, item) for n, item in sig if bounds[0] < n < bounds[1]]
    # Only simple scalar locals immediately following a statement boundary.
    # Class objects, arrays, pointer declarators and for-initializers are left alone.
    declarations = []
    for i, (position, item) in enumerate(body):
        if item not in ('int', 'float', 'double', 'bool', 'char', 'short', 'long', 'unsigned', 'signed'): continue
        previous = body[i - 1][1] if i else '{'
        if previous not in ('{', '}', ';'): continue
        j = i + 1
        while j < len(body) and body[j][1] in ('int', 'char', 'short', 'long', 'unsigned', 'signed'): j += 1
        if j + 1 >= len(body) or not IDENT.match(body[j][1]) or body[j + 1][1] not in ('=', ';'): continue
        name = body[j][1]
        # If an identifier also names a field/type/parameter or is declared twice,
        # do not risk renaming that spelling. Every occurrence must be in this body.
        occurrences = [(n, item) for n, item in sig if item == name]
        if any(not bounds[0] < n < bounds[1] for n, _ in occurrences): continue
        if sum(1 for _, candidate in declarations if candidate == name): continue
        member = False
        for k, (_, value) in enumerate(sig):
            if value != name: continue
            before = ''.join(v for _, v in sig[max(0, k - 2):k])
            if before.endswith(('.', '->', '::')): member = True
        if not member: declarations.append((body[j][0], name))
    # Reject duplicate declarations, including block shadowing.
    result = []
    for _, name in declarations:
        declaration_pattern = r'\b(?:int|float|double|bool|char|short|long|unsigned|signed)\s+(?:(?:int|char|short|long)\s+)?' + re.escape(name) + r'\b'
        clean = ''.join(item if not item.startswith(('//', '/*', '"', "'")) else ' ' for item in items)
        if len(re.findall(declaration_pattern, clean)) == 1: result.append(name)
    return result[:12]


def rename(text, mapping):
    return ''.join(mapping.get(item, item) if IDENT.match(item) else item for item in tokens(text))


def guarded_source(text, seed):
    clean = ''.join(item if not item.startswith(('//', '/*', '"', "'")) else ' ' for item in tokens(text))
    if re.search(r'\b(?:__asm|_asm|asm|__declspec\s*\(\s*naked)\b', clean):
        raise ValueError('Assembly/naked functions are prohibited')
    # Source variants cannot introduce preprocessing or remove existing directives.
    directives = lambda value: re.findall(r'^\s*#.*$', value, re.M)
    if directives(text) != directives(seed): raise ValueError('Variants cannot alter preprocessing directives')


def variants(seed, symbol, alternatives=None, limit=96):
    output = []
    seen = set()
    def add(text, label):
        guarded_source(text, seed)
        digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
        if digest not in seen and len(output) < limit:
            seen.add(digest); output.append(dict(source=text, label=label, source_sha256=digest))
    add(seed, 'original')
    names = local_names(seed, symbol)
    all_identifiers = {item for item in tokens(seed) if IDENT.match(item)}
    for name in names:
        for prefix in ('local_value_', 'temporary_', 'v_'):
            replacement = prefix + name
            if replacement not in all_identifiers: add(rename(seed, {name: replacement}), 'rename:' + name + ':' + replacement)
    if names:
        for prefix in ('local_value_', 'temporary_', 'v_'):
            mapping = {name: prefix + name for name in names}
            if not set(mapping.values()) & all_identifiers: add(rename(seed, mapping), 'rename_all:' + prefix)
    if alternatives:
        if not isinstance(alternatives, list) or len(alternatives) > 8: raise ValueError('At most eight explicit alternative groups')
        groups = []
        for group in alternatives:
            find, replacements = group.get('find'), group.get('replacements')
            if not isinstance(find, str) or not find or seed.count(find) != 1:
                raise ValueError('Each alternative find must occur exactly once in original source')
            if not isinstance(replacements, list) or not 1 <= len(replacements) <= 8 or any(not isinstance(v, str) for v in replacements):
                raise ValueError('Each alternative needs 1..8 replacement strings')
            groups.append([(find, value) for value in [find] + replacements])
        # Bound Cartesian enumeration even when duplicate combinations arise.
        for combination in itertools.islice(itertools.product(*groups), limit * 4):
            text = seed
            for find, value in combination:
                if text.count(find) != 1: raise ValueError('Alternative groups overlap')
                text = text.replace(find, value, 1)
            add(text, 'explicit_alternatives')
            if len(output) >= limit: break
    return output


def context_fingerprint(pack):
    """Include original context, compiler, checker, shared bindings and image."""
    meta = read(pack / 'pack.json')
    paths = {pack / 'pack.json'}
    paths.add(pack / meta['source'])
    for name in meta.get('headers', []):
        if not isinstance(name, str): raise ValueError('Unrecognized header metadata')
        paths.add(pack / name)
    # Include local include closure, even if headers are missing from metadata.
    pending = list(paths)
    while pending:
        path = pending.pop().resolve()
        if not path.is_relative_to(pack) or not path.is_file(): raise ValueError('Missing/escaping pack dependency')
        if path.suffix.lower() not in ('.cpp', '.c', '.h', '.hpp'): continue
        for include in re.findall(r'^\s*#\s*include\s*"([^"\n]+)"', path.read_text(encoding='utf-8', errors='replace'), re.M):
            found = next((p.resolve() for p in (path.parent / include, pack / 'include' / include, pack / 'src' / include) if p.is_file()), None)
            if found is not None and found not in {p.resolve() for p in paths}: paths.add(found); pending.append(found)
    for name in ('fnvcheck.ps1', 'vc2008.cmd', 'source-address-review.py', 'cpu-finish.py'):
        paths.add(ROOT / 'scripts' / name)
    official_pointer=ROOT/'local/checker-official.json'
    if official_pointer.exists():
        paths.add(official_pointer)
        official_release=Path(read(official_pointer)['release']).resolve()
        if not official_release.is_relative_to((ROOT/'tools/checker-releases').resolve()):raise ValueError('Invalid official release')
        paths.update(official_release.glob('*.py'));paths.update(official_release.glob('*.json'))
    paths.update((ROOT / 'tools/fnvcheck/fnvcheck').glob('*.py'))
    paths.update((ROOT / 'tools/fnvcheck/fnvcheck').glob('*.json'))
    # Bind WIP caches to the exact assistance release and runtime gate too.
    paths.add(ROOT / 'scripts/checker-runtime.py')
    pointer = ROOT / 'local/checker-assistance.json'
    paths.add(pointer)
    if pointer.is_file():
        try:
            release = Path(read(pointer)['release']).resolve()
            if release.is_relative_to((ROOT / 'tools/checker-releases').resolve()):
                paths.update(release.glob('*.py'))
                paths.update(release.glob('*.json'))
        except (OSError, ValueError, KeyError, TypeError):
            pass  # Runtime falls back to official; corrupt pointer is still hashed.

    paths.update(ROOT / 'local/shared' / name for name in ('function_index.json', 'fnvdecomp_symbols.json'))
    compiler = ROOT / 'tools/vc2008'
    paths.update(compiler / 'VC/bin' / name for name in ('cl.exe', 'c1xx.dll', 'c2.dll'))
    paths.add(compiler / 'provenance.json')
    paths.update((compiler / 'VC/include').rglob('*.h'))
    settings = read(ROOT / 'local/settings.json')
    paths.add(Path(settings.get('checker_image') or settings['game_exe']))
    hashes = {str(path.resolve()): sha(path) for path in sorted(paths, key=str) if path.is_file()}
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest(), hashes


def score(check):
    if check.get('status') == 'match' and check.get('return_code') == 0: return (0, 0, 0)
    def metric(name):
        value = check.get(name)
        return value if isinstance(value, int) and value >= 0 else 999999
    return (1 if check.get('status') == 'wip' else 2, metric('ndiff_insn'), metric('diffs'))


def prioritize(pending, check):
    lines = str(check.get('diff') or '').splitlines()
    first = next((line[5:] for line in lines if line.startswith('ORIG ')), '')
    operator = {'imul': '*', 'shl': '<<', 'sal': '<<', 'shr': '>>', 'sar': '>>', 'and': '&', 'or': '|', 'xor': '^'}.get(first.split(' ', 1)[0])
    return sorted(pending, key=lambda variant: operator not in variant['source']) if operator else pending


def bounded_process(command, timeout):
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=max(0.1, timeout))
        return dict(return_code=process.returncode, timed_out=False, stdout=stdout, stderr=stderr)
    except subprocess.TimeoutExpired:
        if os.name == 'nt':
            subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=15)
        else: process.kill()
        stdout, stderr = process.communicate()
        return dict(return_code=process.returncode, timed_out=True, stdout=stdout, stderr=stderr)


def official_check(pack, candidate, worker, timeout):
    begun = time.monotonic()
    review = bounded_process([str(ROOT / '.venv/Scripts/python.exe'), str(ROOT / 'scripts/source-address-review.py'), str(candidate)], min(timeout, 15))
    if review['return_code'] or review['timed_out']: return dict(status='source_review_required', return_code=review['return_code'])
    command = [shutil.which('pwsh.exe') or 'pwsh.exe', '-NoProfile', '-File', str(ROOT / 'scripts/fnvcheck.ps1'), '-Pack', str(pack), '-Candidate', str(candidate), '-Worker', worker, '-Json']
    try:
        process = bounded_process(command, max(0.1, timeout - (time.monotonic() - begun)))
        if process['timed_out']: return dict(status='checker_timeout', return_code=None)
        check = json.loads(process['stdout'].lstrip('\ufeff'))
        check['return_code'] = process['return_code']
        return check
    except subprocess.TimeoutExpired: return dict(status='checker_timeout', return_code=None)
    except ValueError: return dict(status='checker_error', return_code=None)


def upstream_finish(pack, candidate, worker, trials, jobs, seconds):
    """Run the upstream solver on a private copy; its score is only diagnostic."""
    output = candidate.with_name(candidate.stem + '.permuted.cpp')
    command = [shutil.which('pwsh.exe') or 'pwsh.exe', '-NoProfile', '-File', str(ROOT / 'scripts/fnvcheck.ps1'),
               '-Pack', str(pack), '-Candidate', str(candidate), '-Worker', worker,
               '-Permute', '-Trials', str(trials), '-Jobs', str(jobs)]
    result = bounded_process(command, seconds)
    result.update(stdout=result['stdout'][-16000:], stderr=result['stderr'][-4000:])
    result.update(candidate=str(output) if output.is_file() else None, requested_trials=trials, jobs=jobs,
                  compiler_attempt_count=None, note='Upstream scores and solver MATCH require a fresh plain official check')
    return result


def search(pack, candidate, model, checks=48, jobs=4, seconds=180, alternatives=None, worker='cpu_finish', use_cache=True, engine='local'):
    if not 1 <= checks <= 256 or not 1 <= jobs <= 8 or not 5 <= seconds <= 1800: raise ValueError('Budget outside checks1..256/jobs1..8/seconds5..1800')
    if not isinstance(model, str) or not model.strip() or len(model) > 500: raise ValueError('Explicit source/model attribution required')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,39}', worker): raise ValueError('Invalid worker name')
    if engine not in ('local', 'upstream', 'hybrid'): raise ValueError('Unknown finishing engine')
    pack = private_pack(pack)
    candidate = Path(candidate).resolve()
    if not candidate.is_relative_to(pack) or candidate.suffix != '.cpp': raise ValueError('Candidate must stay inside its original pack')
    begun = time.monotonic()
    source_hash, metadata_hash = sha(candidate), sha(pack / 'pack.json')
    seed = candidate.read_text(encoding='utf-8-sig')
    context_hash, dependencies = context_fingerprint(pack)
    run_id = uuid.uuid4().hex[:12]
    folder = pack / worker / run_id
    folder.mkdir(parents=True)
    cache = ROOT / 'local/cpu-finish-cache'
    pending = variants(seed, read(pack / 'pack.json')['symbol'], alternatives, limit=checks)
    record = dict(version=1, claim_id=pack.name, original_candidate=str(candidate), original_source_sha256=source_hash,
                  pack_metadata_sha256=metadata_hash, context_sha256=context_hash, dependencies=dependencies,
                  owner=worker, model=model.strip(), engine=engine, generated_variants=len(pending), checks_budget=checks,
                  seconds_budget=seconds, jobs=jobs, service_calls=0, llm_calls=0, upload_authorized=False,
                  historical_ownership_not_checked=True, started_utc=datetime.now(timezone.utc).isoformat())
    save(folder / 'identity.json', record)
    results = []
    upstream_result = None
    def job(number, variant):
        path = folder / ('candidate-%03d.cpp' % number)
        path.write_text(variant['source'], encoding='utf-8')
        digest = sha(path)
        key = hashlib.sha256((context_hash + ':' + digest).encode()).hexdigest()
        cache_path = cache / (key + '.json')
        check = None
        if use_cache and variant['label'] != 'official_permute' and cache_path.is_file():
            previous = read(cache_path)
            if previous.get('context_sha256') == context_hash and previous.get('source_sha256') == digest and previous.get('check', {}).get('status') == 'wip' and previous['check'].get('return_code') == 1:
                check = dict(previous['check'], cache_hit=True)
        if check is None:
            remaining = seconds - (time.monotonic() - begun)
            if remaining < 1: return dict(status='budget_exhausted', candidate=str(path), attempt=number)
            check = official_check(pack, path, worker + '_' + run_id + '_' + str(number), min(45, max(1, remaining)))
            check['cache_hit'] = False
            if check.get('status') == 'wip' and check.get('return_code') == 1:
                save(cache_path, dict(context_sha256=context_hash, source_sha256=digest, check=check))
        check.update(candidate=str(path), attempt=number, variation=variant['label'], source_sha256=digest)
        save(folder / ('check-%03d.json' % number), check)
        return check
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        while pending and len(results) < checks and time.monotonic() - begun < seconds:
            # Check seed alone before scheduling later candidates; a matching seed
            # should cost one official check, rather than a whole parallel batch.
            count = 1 if not results else min(jobs, checks - len(results))
            batch, pending = pending[:count], pending[count:]
            futures = [pool.submit(job, len(results) + n + 1, value) for n, value in enumerate(batch)]
            results.extend(future.result() for future in futures)
            best = min(results, key=score)
            save(folder / 'progress.json', dict(attempts=len(results), best=best, elapsed_seconds=time.monotonic() - begun))
            if score(best)[0] == 0: break
            if len(results) == 1 and checks > 1 and engine in ('upstream', 'hybrid') and best.get('status') == 'wip':
                upstream_seed = folder / 'upstream-input.cpp'
                upstream_seed.write_text(seed, encoding='utf-8')
                remaining = seconds - (time.monotonic() - begun)
                if remaining > 4:
                    # Reserve one plain-check timeout within the overall budget.
                    solver_seconds = max(1, remaining - min(45, remaining / 3))
                    upstream_result = upstream_finish(pack, upstream_seed, worker + '_' + run_id + '_upstream', checks, jobs, solver_seconds)
                    save(folder / 'upstream.json', upstream_result)
                    if upstream_result.get('candidate'):
                        new_source = Path(upstream_result['candidate']).read_text(encoding='utf-8-sig')
                        try:
                            guarded_source(new_source, seed)
                            variant = dict(source=new_source, label='official_permute')
                            results.append(job(len(results) + 1, variant))
                        except ValueError as error:
                            upstream_result['source_rejected'] = str(error)
                            save(folder / 'upstream.json', upstream_result)
                    best = min(results, key=score)
                    if score(best)[0] == 0: break
                if engine == 'upstream': break
            if engine == 'upstream': break
            pending = prioritize(pending, best)
    best = min(results, key=score) if results else None
    stable = sha(candidate) == source_hash and sha(pack / 'pack.json') == metadata_hash
    # Rehash dependencies before calling a result confirmed; cached WIP is never
    # proof. Compiler inputs changing mid-run invalidates even a fresh MATCH.
    dependencies_stable = all(Path(path).is_file() and sha(path) == digest for path, digest in dependencies.items())
    confirmed = bool(best and score(best)[0] == 0 and stable and dependencies_stable and sha(best['candidate']) == best['source_sha256'])
    provenance = None
    if confirmed:
        provenance = best['candidate'] + '.provenance.json'
        save(provenance, dict(model=model.strip() + '; non-AI CPU source finishing', source_sha256=best['source_sha256'], generator='cpu-finish', original_source_sha256=source_hash, llm_calls=0))
    record.update(outcome='match' if confirmed else 'blocked', confirmed_match=confirmed, inputs_stable=stable and dependencies_stable,
                  attempted=len(results), official_checks=sum(not check.get('cache_hit') and check.get('status') != 'budget_exhausted' for check in results),
                  cache_hits=sum(bool(check.get('cache_hit')) for check in results), best=best, provenance=provenance,
                  upstream=upstream_result, elapsed_seconds=time.monotonic() - begun, ended_utc=datetime.now(timezone.utc).isoformat(), results=results)
    save(folder / 'result.json', record)
    save(pack / worker / 'latest.json', dict(result=str(folder / 'result.json'), **{k: record[k] for k in ('outcome', 'confirmed_match', 'best', 'elapsed_seconds')}))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pack', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--model', required=True, help='Actual authors/tools for the supplied source')
    parser.add_argument('--checks', type=int, default=48)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--seconds', type=int, default=180)
    parser.add_argument('--worker', default='cpu_finish')
    parser.add_argument('--alternatives', type=Path)
    parser.add_argument('--no-cache', action='store_true')
    parser.add_argument('--engine', choices=['local', 'upstream', 'hybrid'], default='hybrid', help='Use official permuter first, local bounded variants, or both')
    args = parser.parse_args()
    result = search(args.pack, args.candidate, args.model, args.checks, args.jobs, args.seconds,
                    read(args.alternatives) if args.alternatives else None, args.worker, not args.no_cache, args.engine)
    print(json.dumps({key: result[key] for key in ('outcome', 'confirmed_match', 'attempted', 'official_checks', 'cache_hits', 'best', 'elapsed_seconds')}, indent=2))


if __name__ == '__main__': main()
