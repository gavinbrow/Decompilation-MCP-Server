"""Private, bounded Ghidra drafts for local agent handoffs; never matching proof.

No service requests, model calls or binary changes. Ghidra's inferred C is an
analysis artifact only: an author must reconstruct readable packet-compatible
C++ and pass the unchanged official compiler/checker before any upload.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/ghidra/FnvPrepare.java'

class GhidraBusyError(RuntimeError):
    """Advisory project is in use; caller may retain CPU/compiler evidence."""


def project_cache(identity, project_lane=''):
    name=identity['image_sha256'][:24]+'-'+str(identity['ghidra_version'])+('-'+project_lane if project_lane else '')
    generation_path=ROOT/'local/ghidra/project-generation.json'
    if generation_path.exists():
        generation=read(generation_path).get('generation')
        if not isinstance(generation,str) or not re.fullmatch(r'[a-z0-9-]{1,40}',generation):
            raise ValueError('Invalid Ghidra project generation; old project not replaced')
        name+='-'+generation
    return private(ROOT/'local/ghidra/projects'/name)

def shared_draft_cache():
    spec=importlib.util.spec_from_file_location('_fnv_draft_cache',ROOT/'scripts/ghidra-draft-cache.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()


def private(path, root=None):
    root = root or ROOT
    path = Path(path).resolve()
    if not any(path.is_relative_to((root / folder).resolve()) for folder in ('work', 'local')):
        raise ValueError('Artifacts must remain under ignored work/ or local/')
    return path


def save(path, value):
    path = private(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2), encoding='utf-8')
    temporary.replace(path)


def discover(ghidra_home=None, java_home=None):
    candidates = ([Path(ghidra_home)] if ghidra_home else [])
    if os.environ.get('GHIDRA_HOME'): candidates.append(Path(os.environ['GHIDRA_HOME']))
    candidates.extend(sorted((ROOT / 'tools/ghidra').glob('ghidra_*_PUBLIC'), reverse=True))
    home = next((p.resolve() for p in candidates if (p / 'support/analyzeHeadless.bat').is_file()), None)
    java_candidates = ([Path(java_home)] if java_home else [])
    if os.environ.get('JAVA_HOME'): java_candidates.append(Path(os.environ['JAVA_HOME']))
    java_candidates.extend(sorted(Path('C:/Program Files/Java').glob('jdk-*'), reverse=True))
    java_candidates.extend(sorted((ROOT / 'tools').glob('jdk*'), reverse=True))
    java = next((p.resolve() for p in java_candidates if (p / 'bin/javac.exe').is_file()), None)
    version = None
    minimum = 21
    if home:
        props = (home / 'Ghidra/application.properties').read_text(encoding='utf-8')
        match = re.search(r'^application.version=(.+)$', props, re.M)
        version = match.group(1).strip() if match else 'unknown'
        match = re.search(r'^application.java.min=(\d+)$', props, re.M)
        minimum = int(match.group(1)) if match else minimum
    java_version = None
    if java:
        process = subprocess.run([str(java / 'bin/java.exe'), '-version'], capture_output=True,
                                 text=True, timeout=15)
        match = re.search(r'version "(\d+)', process.stderr + process.stdout)
        java_version = int(match.group(1)) if match else None
    return dict(ready=bool(home and java_version and java_version >= minimum),
                ghidra_home=str(home) if home else None, ghidra_version=version,
                java_home=str(java) if java else None, java_version=java_version,
                required_java=minimum,
                install_command='.\\scripts\\install-ghidra.ps1' if not home else None)


def packet_context(pack, meta):
    """Keep actual declarations for agents; infer only explicit ABI spelling."""
    sources = []
    headers = meta.get('headers', [])
    if not isinstance(headers, list) or len(headers) > 128:
        raise ValueError('Packet headers must be a bounded list')
    for relative in [meta.get('source'), *headers]:
        if not relative or not isinstance(relative, str): continue
        file = (pack / relative).resolve()
        if not file.is_relative_to(pack) or not file.is_file():
            raise ValueError('Packet source/header escapes its original pack or is missing')
        with file.open('r', encoding='utf-8', errors='replace') as source:
            excerpt = source.read(24000)
        sources.append(dict(path=str(file), sha256=digest(file), excerpt=excerpt))
    packet = read(pack / 'packet.json') if (pack / 'packet.json').is_file() else {}
    signature = str(packet.get('signature') or '')[:2000]
    target_convention = next((cc for cc in ('__thiscall', '__fastcall', '__stdcall', '__cdecl')
                              if cc in signature), None)
    calls = []
    for source in sources:
        # Only declarations with explicit ABI and a named FUN_<address> target.
        # C++ object layouts/types are deliberately not invented from this regex.
        for match in re.finditer(r'(__cdecl|__stdcall|__fastcall|__thiscall)\s+(FUN_([0-9a-fA-F]{8}))\s*\(', source['excerpt']):
            calls.append(dict(name=match[2], address='0x' + match[3], convention=match[1]))
    return dict(signature=signature, target_convention=target_convention,
                declarations=sources, explicit_call_conventions=calls[:128],
                type_import='Source/header declarations retained for author; C++ types are not automatically imported')


def validate_pack(pack):
    pack = private(pack)
    if not pack.is_relative_to((ROOT / 'work').resolve()) or not (pack / 'pack.json').is_file():
        raise ValueError('Use an existing original work/<claim-id> pack')
    meta = read(pack / 'pack.json')
    if not 1 <= int(meta['size']) <= 16384: raise ValueError('Ghidra preparation supports 1..16384-byte spans')
    address = int(meta['address'], 16)
    if not 0 <= address <= 0xffffffff or address + int(meta['size']) > 0x100000000:
        raise ValueError('Invalid x86 function span')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$@?]*', str(meta['symbol'])):
        raise ValueError('Unexpected packet symbol spelling')
    return pack, meta


def command(runtime, cache, image, request, output, seconds, existing):
    launcher = Path(runtime['ghidra_home']) / 'support/analyzeHeadless.bat'
    result = [str(launcher), str(cache), 'fnv_reference']
    result += ['-process', image.name] if existing else ['-import', str(image), '-overwrite']
    result += ['-noanalysis', '-max-cpu', '2', '-scriptPath', str(SCRIPT.parent),
               '-postScript', SCRIPT.name, str(request), str(output),
               '-log', str(output.parent / 'ghidra.log'),
               '-scriptlog', str(output.parent / 'script.log')]
    return result


def cached_result(result_path, output, identity):
    if not result_path.is_file() or not output.is_file(): return None
    previous = read(result_path)
    draft = output.parent / 'draft.c'
    if (previous.get('identity') == identity and previous.get('outcome') == 'draft'
            and previous.get('draft') == str(draft)
            and draft.is_file() and previous.get('draft_sha256') == digest(draft)
            and previous.get('analysis_sha256') == digest(output)):
        return dict(previous, cache_hit=True)
    return None


def prepare(pack, *, seconds=120, ghidra_home=None, java_home=None, force=False, project_lane='', lock_wait_seconds=90):
    if project_lane not in ('','minimax'):raise ValueError('Unknown isolated Ghidra project lane')
    if not 15 <= seconds <= 600: raise ValueError('Ghidra time budget must be 15..600 seconds')
    if not 0<=lock_wait_seconds<=90:raise ValueError('Ghidra lock wait must be0..90 seconds')
    pack, meta = validate_pack(pack)
    runtime = discover(ghidra_home, java_home)
    if not runtime['ready']: raise RuntimeError('Ghidra/JDK unavailable: ' + json.dumps(runtime))
    image = Path(read(ROOT / 'local/settings.json')['checker_image']).resolve()
    if not image.is_file(): raise ValueError('Private checker_image is missing')
    # Refuse truncated packet spans before a disassembler can read across them.
    import capstone
    import pefile
    reference = pefile.PE(str(image), fast_load=True)
    try:
        data = reference.get_data(int(meta['address'], 16) - reference.OPTIONAL_HEADER.ImageBase, int(meta['size']))
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        if len(data) != int(meta['size']) or sum(i.size for i in decoder.disasm(data, int(meta['address'], 16))) != len(data):
            raise ValueError('Packet span does not decode completely; preparation refused')
    finally: reference.close()
    context = packet_context(pack, meta)
    identity = dict(pack=str(pack), pack_metadata_sha256=digest(pack / 'pack.json'), image_sha256=digest(image),
                    ghidra_version=runtime['ghidra_version'], script_sha256=digest(SCRIPT),
                    context_hashes=[item['sha256'] for item in context['declarations']],
                    packet_signature=context['signature'])
    folder = private(pack / 'cpu_assist/ghidra')
    folder.mkdir(parents=True, exist_ok=True)
    output = folder / 'analysis.json'
    result_path = folder / 'result.json'
    if not force:
        cached = cached_result(result_path, output, identity)
        if cached: return cached
        cache_started=time.monotonic()
        cached = shared_draft_cache().restore(ROOT, identity, folder)
        if cached:
            cached['elapsed_seconds']=time.monotonic()-cache_started
            save(result_path,cached)
            return cached
    cache = project_cache(identity,project_lane)
    cache.mkdir(parents=True, exist_ok=True)
    lock = cache / 'prep.lock'
    lock_deadline = time.monotonic() + lock_wait_seconds
    while True:
        try:
            descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL); break
        except FileExistsError:
            if time.monotonic() >= lock_deadline:
                raise GhidraBusyError('Ghidra reference cache busy; bounded advisory wait ended')
            time.sleep(0.5)
    os.write(descriptor, str(os.getpid()).encode('ascii')); os.close(descriptor)
    started = time.monotonic()
    try:
        request = folder / 'request.json'
        save(request, dict(address=meta['address'], size=int(meta['size']), symbol=meta['symbol'],
                           seconds=max(5, seconds - 20), context=context, identity=identity))
        # Remove only stale *outputs*, never the input image/project or author source.
        for file in (output, folder / 'draft.c'):
            if file.is_file(): file.unlink()
        environment = dict(os.environ, JAVA_HOME=runtime['java_home'],
                           GHIDRA_HEADLESS_MAXMEM='2G')
        runtime_folder = private(ROOT / 'local/ghidra/runtime')
        runtime_folder.mkdir(parents=True, exist_ok=True)
        for key, directory in [('XDG_CONFIG_HOME', 'settings'), ('XDG_CACHE_HOME', 'cache'),
                               ('TEMP', 'temp'), ('TMP', 'temp')]:
            location = runtime_folder / directory
            location.mkdir(parents=True, exist_ok=True)
            environment[key] = str(location)
        environment['PATH'] = str(Path(runtime['java_home']) / 'bin') + os.pathsep + environment.get('PATH', '')
        # Environment applies to this subprocess only; no global Java settings.
        args = command(runtime, cache, image, request, output, seconds,
                       (cache / 'fnv_reference.gpr').is_file())
        with (folder / 'launcher.log').open('w', encoding='utf-8') as log:
            try:
                process = subprocess.Popen(args, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL, stdout=log,
                                           stderr=subprocess.STDOUT)
                returncode = process.wait(timeout=seconds + 30)
            except subprocess.TimeoutExpired:
                # A Windows .bat launcher owns a Java/decompiler process tree.
                # Terminate only this launched tree, rather than orphaning Java.
                subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                process.wait(timeout=15)
                returncode = None
        analysis = read(output) if output.is_file() else {}
        success = bool(returncode == 0 and analysis.get('decompile_completed')
                       and (folder / 'draft.c').is_file())
        if digest(image) != identity['image_sha256'] or digest(pack / 'pack.json') != identity['pack_metadata_sha256']:
            raise RuntimeError('Reference/pack changed during Ghidra preparation')
        result = dict(outcome='draft' if success else 'blocked', cache_hit=False, identity=identity,
                      pack=str(pack), symbol=meta['symbol'], address=meta['address'], size=meta['size'],
                      ghidra_version=runtime['ghidra_version'], elapsed_seconds=time.monotonic() - started,
                      returncode=returncode, analysis=str(output) if output.is_file() else None,
                      reason='' if success else ('Ghidra timed out; launched process tree stopped' if returncode is None
                                                 else 'No bounded draft produced; inspect launcher.log and analysis.json'),
                      analysis_sha256=digest(output) if output.is_file() else None,
                      draft=str(folder / 'draft.c') if success else None,
                      draft_sha256=digest(folder / 'draft.c') if success else None,
                      confirmed_match=False, llm_calls=0, service_calls=0, upload_authorized=False,
                      warnings=['Untrusted decompiler draft; inferred types and calling conventions need review',
                                'No full-program autoanalysis; only original packet span is decoded',
                                'Address-like Ghidra names/constants must be replaced with packet symbols before checking',
                                context['type_import'], *analysis.get('warnings', [])],
                      utc=datetime.now(timezone.utc).isoformat())
        save(result_path, result)
        if success:
            try: shared_draft_cache().register(ROOT, result_path)
            except OSError: pass # An optional index failure cannot stop preparation.
        return result
    finally:
        lock.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pack', type=Path)
    parser.add_argument('--doctor', action='store_true')
    parser.add_argument('--seconds', type=int, default=120)
    parser.add_argument('--ghidra-home', type=Path)
    parser.add_argument('--java-home', type=Path)
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()
    if args.doctor: value = discover(args.ghidra_home, args.java_home)
    elif args.pack: value = prepare(args.pack, seconds=args.seconds, ghidra_home=args.ghidra_home,
                                   java_home=args.java_home, force=args.force)
    else: parser.error('Choose --doctor or --pack')
    print(json.dumps(value, indent=2))


if __name__ == '__main__': main()
