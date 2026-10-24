"""Private context/preparation helpers. No model calls or scheduler."""
import json,os,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def read(path):
    path=Path(path)
    if path.name=='trial.json' and (path.with_name(path.name+'.checkpoints')/'HEAD.json').exists():return load('coordinator-json','_recovery').load_checkpoint(path)
    return json.loads(path.read_text(encoding='utf-8-sig'))

def save(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    temporary.write_text(json.dumps(value, indent=2), encoding='utf-8')
    for attempt in range(12):
        try:
            temporary.replace(path); return
        except PermissionError:
            if attempt == 11: raise
            time.sleep(0.05*(attempt+1))

def prepare(pack, helpers):
    value = helpers.cpu_prepare(pack)
    # Deliberately run Ghidra even on CPU-resolved benchmark targets. They remain
    # separately labeled CPU-pre-solved, rather than credited as model-only wins.
    try:
        value['ghidra'] = helpers.add_ghidra(pack)
    except ValueError as exc:
        # Preserve validation; unavailable drafts are not fatal to other targets.
        value['ghidra'] = dict(outcome='refused', reason=str(exc)[:250])
        value['preparation_refused'] = str(exc)[:250]
    path = Path(pack)/'cpu_assist/handoff.json'
    handoff = read(path)
    handoff['ghidra'] = value['ghidra']
    # Model prompts contain observations/drafts/check diagnostics, not prior source files.
    handoff['evidence'] = dict(candidate_paths=[], latest_checks=[])
    handoff.pop('cpu_best_candidate', None)
    save(path, handoff)
    return value
