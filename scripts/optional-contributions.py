"""Bounded optional contribution operations, called only by the service writer.

Failures never turn into claim mutations or block ordinary release/submission.
Local receipts retain uncertain optional saves; they are never blindly replayed.
"""
import hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path

OPERATIONS = ('checkpoint', 'function_history', 'context_mode')
def normalize(r):
    r = dict(r); reason = r.get('reason', '')
    if r.get('operation') == 'giveup':
        if reason.startswith('[CHECKPOINT] '):
            r.update(operation='checkpoint', note=reason[13:])
        elif (m := re.fullmatch(r'\[CHECKPOINT ([0-9a-f]{32}) ([0-9a-f]{64})\] (.+)', reason, re.S)):
            r.update(operation='checkpoint', candidate_id=m[1], source_sha256=m[2], note=m[3])
        elif (m := re.fullmatch(r'\[HISTORY (brief|list|entry|source)(?: ([A-Za-z0-9_-]{1,128}))?\]', reason)):
            r.update(operation='function_history', view=m[1], checkpoint_id=m[2] or '')
        elif (m := re.fullmatch(r'\[CONTEXT_MODE (lean|resume|classic)\]', reason)):
            r.update(operation='context_mode', context_mode=m[1])
        elif (m := re.fullmatch(r'\[USE_CHECKPOINT ([A-Za-z0-9_-]{1,128})\] (.+)',reason,re.S)):
            r.update(checkpoint_id=m[1],reason=m[2])
        elif reason.startswith(('[CHECKPOINT','[HISTORY','[CONTEXT_MODE')):
            raise ValueError('Invalid optional command; claim retained, use exact documented syntax')
    if r.get('operation') == 'checkpoint':
        note = r.get('note', '')
        if len(note.encode()) > 2048 or (not note.strip() and not r.get('candidate_id')):
            raise ValueError('Checkpoint needs a note (<=2KiB) or a checked candidate')
    if r.get('operation') == 'function_history':
        if r.get('view', 'brief') not in ('brief','list','entry','source'): raise ValueError('Invalid history view')
        cid = r.get('checkpoint_id', '')
        if cid and not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', cid): raise ValueError('Invalid checkpoint ID')
        if r.get('view') in ('entry','source') and not cid: raise ValueError('History entry/source needs checkpoint_id')
        if type(r.get('include_stale', False)) is not bool: raise ValueError('include_stale must be boolean')
        if type(r.get('limit',5)) is not int or not 1<=r.get('limit',5)<=20: raise ValueError('History limit 1..20')
    if r.get('context_mode') not in (None,'','classic','lean','resume'): raise ValueError('Invalid context_mode')
    return r

def saved_checkpoint(row,checkpoint_id):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',checkpoint_id):raise ValueError('Invalid checkpoint ID')
    for path in (Path(row['pack'])/'optional-contributions').glob('*.json'):
        saved=json.loads(path.read_text(encoding='utf-8-sig'));answer=saved.get('answer',{})
        if saved.get('operation')=='checkpoint' and answer.get('state')=='checkpoint_saved' and answer.get('result',{}).get('checkpoint_id')==checkpoint_id:
            return checkpoint_id
    raise ValueError('Checkpoint must have a saved receipt on this same claim; use ordinary BEST_CODE release if unavailable')

def run(root, row, request, service, features):
    """Return a terminal optional result; no release, submit, or new claim calls."""
    root=Path(root);op=request['operation'];rid=request['request_id']
    policy=root/'local/optional-features.json'
    if policy.exists() and json.loads(policy.read_text(encoding='utf-8-sig')).get(op+'_enabled') is False:
        return dict(state='optional_unavailable',feature=op,reason='Optional feature disabled; continue normal work',claim_released=False)
    base=Path(row['pack'])/'optional-contributions';receipt=base/(rid+'.json')
    if receipt.exists(): return json.loads(receipt.read_text(encoding='utf-8-sig'))['answer']
    if op=='context_mode':
        mode=request['context_mode']
        features.durable(root/'local/mcp/context-preferences'/(request['agent_id']+'.json'),dict(context_mode=mode))
        return dict(state='context_mode_set', context_mode=mode, claim_released=False,
                    note='Applies to future claims. Current compiler/pack context is unchanged.')
    payload=dict(claim_id=row['claim_id']); now=datetime.now(timezone.utc).isoformat()
    if op=='checkpoint':
        previous=list(base.glob('*.local.json')) if base.exists() else []
        saves=sum(json.loads(p.read_text()).get('operation')=='checkpoint' for p in previous)
        if saves>=4: return dict(state='optional_unavailable', feature=op, claim_released=False, reason='Fleet limit: four optional saves per claim; keep working or release normally.')
        payload.update(request_id=rid, note=request.get('note',''))
        if request.get('candidate_id'):
            best=features.best_source(row,request)
            if len(best['source'].encode())>65536: raise ValueError('Checkpoint source exceeds64KiB; use note only or ordinary BEST_CODE giveup')
            payload['source']=best['source']
        # Local copy is durable BEFORE sending. It is unverified WIP, never MATCH.
        features.durable(base/(rid+'.local.json'),dict(operation=op,request_id=rid,payload=payload,model=row['external_model'],unverified=True,utc=now))
    else:
        payload.update(view=request.get('view','brief'),include_stale=request.get('include_stale',False),limit=request.get('limit',5))
        if request.get('checkpoint_id'): payload['checkpoint_id']=request['checkpoint_id']
        key=hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()
        cache=base/('history-'+key+'.cache')
        if cache.exists():
            saved=json.loads(cache.read_text()); age=datetime.now(timezone.utc).timestamp()-saved['time']
            if age<120: return dict(state='history', feature=op, result=saved['result'], cached=True, claim_released=False)
    try:
        result=service('fnv.ps1',op,'-Json',json.dumps(payload))
        if result.get('optional_unavailable'):
            answer=dict(state='optional_unavailable',feature=op,reason=result.get('reason','Optional service unavailable'),retry_at_utc=result.get('retry_at_utc'),claim_released=False)
        else:
            answer=dict(state='checkpoint_saved' if op=='checkpoint' else 'history',feature=op,result=result,claim_released=False,unverified=True)
            if op=='function_history': features.durable(cache,dict(time=datetime.now(timezone.utc).timestamp(),result=result))
    except Exception:
        answer=dict(state='optional_unavailable',feature=op,claim_released=False,uncertain_optional_save=op=='checkpoint',
                    reason='Optional response unavailable; saved identity retained, never replay blindly. Continue normal work/release.')
    features.durable(receipt,dict(operation=op,request_id=rid,utc=now,answer=answer))
    return answer
