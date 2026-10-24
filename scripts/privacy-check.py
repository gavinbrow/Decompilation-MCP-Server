"""Audit Git-indexed text only; never enumerate private runtime directories."""
import json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BLOCKED={'local','work','tools','contributions','.venv','.env'}
def inspect(paths):
    problems=[]
    patterns=[('provider credential',r'(?:sk-or-v1-|gh[pousr]_)[A-Za-z0-9_-]{20,}'),('FNV credential',r'\bfnv_[A-Za-z0-9_-]{40,}\b'),('private GPU identity',r'GPU-[0-9a-f]{8}-(?:[0-9a-f-]{20,})'),('private claim identity',r'\bclm_[0-9a-f]{20,}\b'),('private Windows profile',r'(?i)[a-z]:[/\\]Users[/\\][^/\\\s"\']+')]
    for path in paths:
        relative=Path(path)
        if relative.is_absolute() or '..' in relative.parts or relative.parts[0] in BLOCKED:
            problems.append(dict(path=path,reason='private/runtime path'));continue
        p=ROOT/relative
        if p.suffix.lower() in {'.exe','.dll','.obj','.pdb','.dpapi','.asm','.disasm','.iso','.cab','.msi','.gz','.zip','.bin'}:
            problems.append(dict(path=path,reason='binary/private artifact'));continue
        try:text=p.read_text(encoding='utf-8-sig')
        except (UnicodeError,OSError):problems.append(dict(path=path,reason='not readable UTF-8 text'));continue
        for label,pattern in patterns:
            if re.search(pattern,text): problems.append(dict(path=path,reason=label))
    return problems
def main():
    paths=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0');paths=[p for p in paths if p]
    if not paths: raise SystemExit('Stage the explicit public allowlist before auditing')
    issues=inspect(paths)
    print(json.dumps(dict(files=len(paths),passed=not issues,issues=issues),indent=2))
    return bool(issues)
if __name__=='__main__':raise SystemExit(main())
