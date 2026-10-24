"""Finite rolling CPU-first/Luna trial. This process alone owns service mutations."""
import argparse
from collections import Counter
import concurrent.futures
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
QUEUE=ROOT/'local/benchmark/coordinator'
SKIP_GHIDRA=False
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def save(p,v):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
    t=p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp');t.write_text(json.dumps(v,indent=2))
    for attempt in range(10):
        try:t.replace(p);return
        except PermissionError:
            if attempt==9:raise
            time.sleep(0.05*(attempt+1))
def utc():return datetime.now(timezone.utc).isoformat()
def load(name):
    s=importlib.util.spec_from_file_location('priority_'+name.replace('-','_'),ROOT/'scripts'/(name+'.py'))
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def event(kind,**fields):
    v=dict(utc=utc(),event=kind,**fields)
    with (QUEUE/'events.jsonl').open('a')as f:f.write(json.dumps(v)+'\n')
    print(json.dumps(v),flush=True)
def ps(script,*args):
    r=subprocess.run([shutil.which('pwsh.exe'),'-NoProfile','-File',str(ROOT/'scripts'/script),*map(str,args)],cwd=ROOT,capture_output=True,text=True,timeout=180)
    if r.returncode:
        save(QUEUE/'helper-error.json',dict(script=script,args=list(map(str,args)),stdout=r.stdout,stderr=r.stderr))
        raise RuntimeError(f'{script} failed; inspect private helper-error before another mutation')
    return json.loads(r.stdout.lstrip('\ufeff'))

def routing(check,instructions):
    """Conservative diagnostic similarity, never a percentage correctness proof."""
    if check.get('status')=='match'and check.get('return_code')==0:
        return dict(route='cpu_match',priority=-1,similarity_percent=100,instruction_differences=0)
    n=check.get('ndiff_insn')
    if check.get('status')=='wip'and type(n)is int and n>=0 and instructions>0:
        percent=max(0.0,100*(1-n/instructions))
        route,priority=('near_90_or_5',0)if percent>=90 or n<=5 else (('near_80',1)if percent>=80 else ('partial_below_80',2))
        return dict(route=route,priority=priority,similarity_percent=round(percent,2),instruction_differences=n)
    return dict(route='partial_unsupported',priority=3,similarity_percent=None,instruction_differences=None)

def cpu_prepare(pack):
    """One short CPU candidate attempt plus recoverable observations; no service."""
    started=time.monotonic();pack=Path(pack)
    cpu=load('cpu-template-worker');pipeline=load('decomp-assist');assist=load('cpu-assist')
    candidates,reason=cpu.templates(pack,255)
    screening=assist.classify(pack,cpu=cpu,template_result=(candidates,reason))
    preparation=pipeline.prepare(pack,ghidra='off',seconds=30,screening=screening)
    result=dict(outcome='unsupported',reason=reason,checker_attempts=0,llm_calls=0)
    check={};candidate=None
    if candidates:
        folder=pack/'cpu_priority';folder.mkdir(exist_ok=True)
        core=cpu.search_engine();checks=[];pattern=candidates[0][0]
        families={'integer_symbolic_search':'integer-search','structured_record_selector':'record-selector-search',
                  'structured_member_dispatch':'dispatch-search','structured_memory_destructor':'destructor-search','bounded_loop_search':'loop-search'}
        if pattern in families:
            # Family engines reserve 45 seconds for an in-progress official check.
            # Permit 30 seconds of scheduling, rather than accidentally no checks.
            family=cpu.search_engine()if pattern=='integer_symbolic_search'else cpu.family_engine(families[pattern])
            native=family.search(pack,'cpu_priority_native',max_checks=12,jobs=1,seconds=max(46,75-(time.monotonic()-started)))
            for path in (pack/'cpu_priority_native').rglob('check-*.json'):
                value=read(path)
                if 'status'in value:checks.append(value)
            result['native_search']=native
        else:
            # Check every generalized template/ABI alternative, not just its preview.
            for number,(_,source)in enumerate(candidates[:8],1):
                if time.monotonic()-started>=30:break
                value=core.check_candidate(pack,folder,number,source,'cpu_priority_generator')
                checks.append(value)
                if core.score(value)[0]==0:break
        if checks:
            check=min(checks,key=core.score);candidate=check.get('candidate')
        if candidate and core.score(check)[0]!=0 and 30-(time.monotonic()-started)>=6:
            finished=load('cpu-finish').search(pack,candidate,'Non-AI CPU C++ generator and source finishing',checks=12,jobs=1,
                         seconds=min(24,30-(time.monotonic()-started)),worker='cpu_priority_finish',engine='hybrid')
            checks.extend(finished.get('results',[]))
            check=min(checks,key=core.score);candidate=check.get('candidate')
        confirmed=bool(check and core.score(check)[0]==0)
        result.update(outcome='match'if confirmed else'blocked',pattern=pattern,checker_attempts=len(checks),
                      reason=''if confirmed else'Bounded improved CPU search ended without official MATCH')
        if candidate:result['candidate']=str(candidate)
    partial=preparation.get('partial')or{}
    observations=read(partial['path'])if partial.get('path')else{}
    instructions=int(observations.get('decoded_instructions',0))
    route=routing(check,instructions)
    result.update(elapsed_seconds=time.monotonic()-started,**route)
    if candidate:preparation['cpu_candidate']=str(candidate)
    preparation['cpu_routing']=route
    # Refresh check evidence only. Re-running full template/partial analysis
    # here repeats the same CPU work and discards family/workflow context.
    handoff=read(pack/'cpu_assist/handoff.json')
    handoff['evidence']=assist.evidence(pack)
    handoff['cpu_routing']=route;handoff['cpu_best_candidate']=str(candidate)if candidate else None
    save(pack/'cpu_assist/handoff.json',handoff)
    save(pack/'cpu_priority/result.json',result)
    return dict(cpu=result,preparation=preparation,routing=route)

def add_ghidra(pack):
    """One serialized Ghidra project worker; no model/service actions."""
    if SKIP_GHIDRA:return dict(outcome='skipped',reason='CPU-only assistance measurement; Ghidra excluded')
    result=load('ghidra-prep').prepare(Path(pack),seconds=45)
    return result
