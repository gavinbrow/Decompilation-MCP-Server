"""Install an authenticated staged checker with Windows execution/lock adapters only."""
import argparse,hashlib,json,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest().lower()
def install(stage):
    stage=stage.resolve()
    if not stage.is_relative_to((ROOT/'tools/checker-staging').resolve()): raise ValueError('Expected authenticated private staging path')
    report=json.loads((ROOT/'local/checker-capabilities.json').read_text(encoding='utf-8-sig'))
    if Path(report['stage']).resolve()!=stage: raise ValueError('Wrong stage')
    source=Path(report['entrypoint']).parent.resolve()
    if not source.is_relative_to(stage): raise ValueError('Checker entry escaped stage')
    for item in report['files']:
        p=(source/item['path']).resolve()
        if not p.is_relative_to(source) or digest(p)!=item['sha256'].lower(): raise ValueError('Staged checker changed')
    target=ROOT/'tools/fnvcheck/fnvcheck'
    if target.exists(): raise ValueError('Installed checker retained. Use a new workspace or review an upgrade explicitly.')
    compiler=(source/'msvc9.py').read_text(encoding='utf-8')
    anchor='def run(tool, arguments):\n'
    if compiler.count(anchor)!=1: raise ValueError('Upstream adapter changed; manual review required')
    adapter='''    if os.name == 'nt':
        root = Path(os.environ['FNV_MSVC9_ROOT'])
        env = os.environ.copy()
        env['PATH'] = os.pathsep.join(str(p) for p in (root/'VC/bin', root/'VC/redist/x86/Microsoft.VC90.CRT', root/'Common7/IDE')) + os.pathsep + env.get('PATH', '')
        env['INCLUDE'] = ';'.join(str(p) for p in (root/'VC/include', root/'VC/PlatformSDK/include'))
        env['LIB'] = ';'.join(str(p) for p in (root/'VC/lib', root/'VC/PlatformSDK/lib'))
        command = [str(root/'VC/bin'/(tool + '.exe'))] + list(arguments)
        wrapper = os.environ.get('FNV_MSVC9_WRAPPER')
        if wrapper: command = [os.environ.get('COMSPEC', 'cmd.exe'), '/d', '/c', wrapper] + command
        return subprocess.run(command, env=env, stdin=subprocess.DEVNULL).returncode
'''
    shutil.copytree(source,target,ignore=shutil.ignore_patterns('__pycache__'))
    (target/'msvc9.py').write_text(compiler.replace(anchor,anchor+adapter),encoding='utf-8')
    (target/'fcntl.py').write_text('''import os,msvcrt
LOCK_EX=2
LOCK_NB=4
LOCK_UN=8
def flock(fd,operation):
    os.lseek(fd,0,os.SEEK_SET)
    if operation==LOCK_UN: msvcrt.locking(fd,msvcrt.LK_UNLCK,1)
    elif operation==(LOCK_EX|LOCK_NB): msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
    else: raise ValueError('Unsupported lock operation')
''',encoding='utf-8')
    print('Checker installed privately. Comparison, source rules, spans and fingerprints unchanged.')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--stage',type=Path,required=True);a=p.parse_args();install(a.stage)
