"""Select an immutable assistance checker; preserve the official MATCH gate.

The installed official checker is never replaced. Every assistance MATCH is
plain-rechecked by it before returning MATCH, including solver output. Only
local compilation occurs here: no claim, submission, service or model calls.
"""
import argparse, hashlib, json, os, subprocess, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def official_checker(root=ROOT):
    pointer=root/'local/checker-official.json'
    if not pointer.exists():return root/'tools/fnvcheck/fnvcheck'
    p=json.loads(pointer.read_text(encoding='utf-8-sig'));release=Path(p['release']).resolve()
    if not release.is_relative_to((root/'tools/checker-releases').resolve()):raise ValueError('Official release escapes workspace')
    manifest=release/'official-release.json'
    if sha(manifest)!=p['manifest_sha256']:raise ValueError('Official manifest changed')
    data=json.loads(manifest.read_text())
    if data.get('kind')!='authenticated_official':raise ValueError('Not an authenticated official release')
    for name,digest in data['release_hashes'].items():
        if Path(name).name!=name or sha(release/name)!=digest:raise ValueError('Official checker changed')
    return release

OFFICIAL=official_checker()

def select_checker(root=ROOT, official=False):
    base=official_checker(root);pointer=root/'local/checker-assistance.json'
    if official or not pointer.is_file():return base,None
    try:
        p=json.loads(pointer.read_text())
        if not p.get('enabled',True):return base,None
        release=Path(p['release']).resolve()
        if not release.is_relative_to((root/'tools/checker-releases').resolve()):raise ValueError('Release escapes workspace')
        manifest=release/'reviewed-release.json'
        if sha(manifest)!=p['manifest_sha256']:raise ValueError('Release manifest changed')
        data=json.loads(manifest.read_text())
        for name,digest in data['release_hashes'].items():
            if Path(name).name!=name or sha(release/name)!=digest:raise ValueError('Release file changed')
        for name,digest in data['official_hashes'].items():
            if Path(name).name!=name or sha(base/name)!=digest:raise ValueError('Official checker changed; revalidate assistance')
        return release,None
    except (OSError,ValueError,KeyError,TypeError) as error:
        return base,'Assistance unavailable; using unchanged official checker: '+str(error)

def invoke(checker, args, env=None):
    child=(env or os.environ).copy();child['FNVCHECK_TOOLS']=str(checker)
    return subprocess.run([sys.executable,str(checker/'fnvcheck.py'),*args],env=child,cwd=ROOT,capture_output=True,text=True)

def parse_json(run):
    try:return json.loads(run.stdout.lstrip('\ufeff'))
    except ValueError:return dict(status='checker_error',errors=['Checker did not return JSON'],detail=run.stdout[-1000:])

def gated_plain(args, checker, diagnostic_args=(), run=invoke):
    candidate=Path(args[args.index('--pack')+2])
    before=sha(candidate)
    enhanced=run(checker,[*args,*diagnostic_args]);data=parse_json(enhanced)
    code=enhanced.returncode
    if data.get('status')=='match' and code!=0:
        return dict(status='checker_error',errors=['Assistance checker reported MATCH with a failing exit code']),1
    if data.get('status')=='match' and code==0:
        original=run(OFFICIAL,args);official=parse_json(original)
        if sha(candidate)!=before:
            return dict(status='source_changed',errors=['Candidate changed during official recheck']),1
        if official.get('status')!='match' or original.returncode!=0:
            if official.get('status')=='match':official['status']='checker_error'
            official.update(assistance_status='match',official_upload_recheck_required=True,
                            checker_variant='reviewed_assistance_with_official_gate')
            official['errors']=['Assistance comparison matches, but the unchanged official checker does not. No upload authorized; retain this evidence for the service maintainer.',*(official.get('errors') or [])]
            return official,1
        data.update(official_plain_recheck='match',official_upload_recheck_required=True)
    elif sha(candidate)!=before:
        return dict(status='source_changed',errors=['Candidate changed during checking']),1
    return data,code

def main():
    p=argparse.ArgumentParser(add_help=False);p.add_argument('--official',action='store_true');p.add_argument('--diff-lines',type=int,default=70);p.add_argument('--score',action='store_true')
    options,args=p.parse_known_args()
    checker,warning=select_checker(official=options.official)
    if warning:print(warning,file=sys.stderr)
    if checker==OFFICIAL:
        result=invoke(checker,args);sys.stdout.write(result.stdout);sys.stderr.write(result.stderr);return result.returncode
    extras=['--diff-lines',str(options.diff_lines)]
    if options.score:extras.append('--score')
    if '--solve-slots' in args or '--permute' in args:
        result=invoke(checker,[*args,*extras]);sys.stdout.write(result.stdout.replace('MATCH: written','ASSISTANCE CANDIDATE: written'));sys.stderr.write(result.stderr)
        if result.returncode!=0:return result.returncode
        source=Path(args[args.index('--pack')+2]);suffix='.permuted.cpp' if '--permute' in args else '.solved.cpp'
        finished=source.with_name(source.stem+suffix)
        plain=['--pack',args[args.index('--pack')+1],str(finished),'--json']
        original=invoke(OFFICIAL,plain);data=parse_json(original)
        if original.returncode==0 and data.get('status')=='match':print('MATCH: unchanged official plain recheck passed for '+str(finished));return 0
        print('NO OFFICIAL MATCH: assistance output retained for further work; no upload authorized.');return 1
    # Keep JSON and text paths under the same official result gate.
    json_args=args if '--json' in args else [*args,'--json']
    data,code=gated_plain(json_args,checker,extras)
    if '--json' in args:print(json.dumps(data))
    else:
        print(str(data.get('status','checker_error')).upper())
        if options.score and data.get('diagnostic_score') is not None:print('SCORE %d (diagnostic only; not a percentage or proof)'%data['diagnostic_score'])
        for line in data.get('errors',[])[:30]:print(line)
        diff=data.get('diff')
        if diff:print(diff if isinstance(diff,str) else '\n'.join(map(str,diff)))
    return code

if __name__=='__main__':sys.exit(main())
