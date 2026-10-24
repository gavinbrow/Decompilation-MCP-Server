import importlib.util,json,tempfile,unittest,hashlib,threading,time
from types import SimpleNamespace
from pathlib import Path
from datetime import datetime,timezone,timedelta
S=importlib.util.spec_from_file_location('bridge',Path(__file__).resolve().parents[1]/'scripts/mcp-live-bridge.py')
B=importlib.util.module_from_spec(S);S.loader.exec_module(B)

class BridgeTests(unittest.TestCase):
 def test_duplicate_reservation_can_publish_without_hydrated_pack(self):
  row=self.claim();row.update(stage='ready',batch_reserved_duplicate=True)
  (Path(row['pack'])/'pack.json').unlink()
  self.bridge.publish(row,lambda *args:(_ for _ in ()).throw(AssertionError('Duplicate must not load context')))
  self.assertEqual(self.answer()['state'],'preparing')
  self.assertEqual(row['stage'],'ready')

 def test_duplicate_unhydrated_reservation_is_released_at_deadline(self):
  row=self.claim();row.update(stage='ready',batch_reserved_duplicate=True,external_work_until=(B.now()-timedelta(seconds=1)).isoformat())
  (Path(row['pack'])/'pack.json').unlink()
  self.tick()
  self.assertTrue(row['released']);self.assertTrue(row['done'])
  self.assertEqual(self.answer()['state'],'released')

 def test_reload_preserves_cpu_acquisition_hold_before_dispatch(self):
  from unittest.mock import patch
  loader=SimpleNamespace(cpu_sweep_runtime=SimpleNamespace(uncertain=True))
  with patch.object(self.bridge,'prepare_web'),patch.object(self.bridge,'install_transport'),patch.object(self.bridge,'install_checkpoints'):
   self.bridge.tick(self.trial,self.status,self.service,self.finish,lambda:None,loader)
  self.assertTrue(self.bridge.uncertain);self.assertFalse(self.trial['rows'])
  self.assertEqual(self.answer()['reason'],'mutation_reconciliation_required')
 def test_single_claim_failure_registers_durable_reconciliation_source(self):
  def fail(script,*args):raise RuntimeError('lost claim response')
  self.bridge.tick(self.trial,self.status,fail,self.finish,lambda:None,None)
  self.assertTrue(self.bridge.uncertain);self.assertIn(self.req['request_id'],self.bridge.unresolved_acquisitions)
 def test_granite_is_local_pool_for_web_priority(self):
  self.assertEqual(B.claim_group({'agent_id':'granite_001'}),'local_pool')
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.bridge=B.Bridge(self.root)
  self.trial={'rows':[]};self.calls=[]
  self.status=dict(submissions_paused=False,submissions_today=0,awaiting_verification=0,limits=dict(claims=20,subsPerDay=1000,pending=1000),open_claims=[])
  self.req=dict(operation='claim',request_id='1'*32,band='<=255',model='Gemini Argon (exact model unknown); CPU/Ghidra')
  B.save(self.root/'local/opencode/control.json',{'mcp_claim_burst':1})
  self.put(self.req)
 def tearDown(self):self.tmp.cleanup()
 def put(self,r):B.save(self.bridge.base/'requests'/f"{r['request_id']}.json",r)
 def service(self,script,*args):
  self.calls.append((script,args))
  if script=='fnv.ps1':return self.status
  n=len(self.trial['rows']);cid='clm_abc' if n==0 else 'clm_'+format(0xabc+n,'x');address=0x400000+n*16
  claim=dict(claim_id=cid,address=f'0x{address:08x}',symbol=f'FUN_{address:08x}',size=12,expires=(B.now()+timedelta(hours=2)).isoformat(),pack=str(self.root/'work'/cid))
  B.save(Path(claim['pack'])/'pack.json',{k:claim[k] for k in ('address','symbol','size')})
  self.status['open_claims'].append(dict(claim_id=cid,address=claim['address'],this_key=True))
  return claim
 def finish(self,row,report):
  self.calls.append(('finish',report))
  if report['outcome']=='match':row['submission']={'submission_id':'sub_test'}
  else:row['released']=True
 def tick(self,**kw):self.bridge.tick(self.trial,self.status,self.service,self.finish,lambda:None,None,**kw)
 def answer(self,id='1'*32):return B.read(self.bridge.base/'responses'/f'{id}.json')
 def claim(self):self.tick();return self.trial['rows'][0]
 def submit(self,valid=True):
  row=self.claim();folder=Path(row['pack'])/'mcp_candidates'/('a'*32);source=b'int f(){return 1;}';sha=hashlib.sha256(source).hexdigest()
  folder.mkdir(parents=True);(folder/'candidate.cpp').write_bytes(source)
  B.save(folder/'check.json',dict(status='match' if valid else 'wip',source_sha256=sha))
  B.save(folder/'candidate.cpp.provenance.json',dict(model=row['external_model'],source_sha256=sha))
  r=dict(operation='submit',request_id='2'*32,target_id='web_clm_abc',candidate_id='a'*32,source_sha256=sha)
  self.put(r);return row,r
 def test_service_pause_is_reported_without_claim_or_false_uncertainty(self):
  B.save(self.root/'local/service-limit.json',dict(retry_at_utc=(B.now()+timedelta(hours=1)).isoformat(),reason='Daily infrastructure limit'))
  self.tick();answer=self.answer()
  self.assertEqual(answer['reason'],'service_paused');self.assertIn('Daily infrastructure',answer['service_reason'])
  self.assertFalse(self.bridge.uncertain);self.assertFalse(self.calls);self.assertFalse(self.trial['rows'])
  self.assertIsNotNone(B.read(self.bridge.base/'coordinator.json')['service_pause'])
 def test_batch_preflight_failure_does_not_latch_uncertainty(self):
  def failed(script,*args):
   directory=Path(args[-1]).parent
   B.save(directory/'started.json',dict(phase='before_status'))
   raise RuntimeError('status refused before claim')
  result=self.bridge.reserve_batch([self.req],self.trial,failed,self.finish,lambda:None,None)
  self.assertEqual(result,0);self.assertFalse(self.bridge.uncertain)
  self.assertEqual(self.answer()['state'],'queued');self.assertFalse(self.trial['rows'])
 def test_batch_claiming_failure_remains_uncertain(self):
  def failed(script,*args):
   B.save(Path(args[-1]).parent/'started.json',dict(phase='claiming'))
   raise RuntimeError('lost claim response')
  self.bridge.reserve_batch([self.req],self.trial,failed,self.finish,lambda:None,None)
  self.assertTrue(self.bridge.uncertain)
  self.assertIn(self.req['request_id'],self.bridge.unresolved_acquisitions)
  self.assertEqual(self.answer()['state'],'needs_reconciliation')
 def test_flag_compat_keeps_claim_active(self):
  row=self.claim();r=dict(operation='giveup',request_id='2'*32,target_id=B.target_name(row),reason='[FLAG_ONLY] index_problem: indexed entry starts inside another function')
  self.put(r);self.tick();self.assertEqual(self.answer('2'*32)['state'],'flagged');self.assertFalse(row.get('done'));self.assertFalse(row.get('released'))
  self.assertEqual(sum(c[0]=='fnv.ps1' and c[1][0]=='flag' for c in self.calls),1)
  self.tick();self.assertEqual(sum(c[0]=='fnv.ps1' and c[1][0]=='flag' for c in self.calls),1)
 def test_owner_disabled_flags_refuse_both_routes_without_service_calls(self):
  row=self.claim();B.save(self.root/'local/contribution-policy.json',dict(flag_enabled=False));self.calls.clear()
  requests=[dict(operation='flag',category='index_problem',note='wrong span'),dict(operation='giveup',reason='[FLAG_ONLY] index_problem: wrong span')]
  for i,request in enumerate(requests,2):
   rid=str(i)*32;self.put(dict(request,request_id=rid,target_id=B.target_name(row)));self.tick()
   self.assertEqual(self.answer(rid)['state'],'refused');self.assertFalse(self.answer(rid)['claim_released'])
  self.assertFalse(self.calls);self.assertFalse(row.get('done'));self.assertFalse(self.bridge.uncertain)
  self.put(dict(operation='giveup',reason='Cannot establish correct function span',request_id='4'*32,target_id=B.target_name(row)));self.tick()
  self.assertEqual(self.answer('4'*32)['state'],'released')
 def test_flag_wrong_agent_refused(self):
  row=self.claim();row.update(external_explicit_agent=True,external_agent_id='owner')
  self.put(dict(operation='flag',request_id='2'*32,target_id=B.target_name(row),agent_id='other',category='pack_problem',note='missing signature'))
  self.tick();self.assertEqual(self.answer('2'*32)['state'],'refused');self.assertFalse(any(c[0]=='fnv.ps1' and c[1][0]=='flag' for c in self.calls))
 def test_bad_flag_category_never_sent(self):
  row=self.claim();self.put(dict(operation='giveup',request_id='2'*32,target_id=B.target_name(row),reason='[FLAG_ONLY] difficult: hard to solve'))
  self.tick();self.assertEqual(self.answer('2'*32)['state'],'refused')
 def test_lost_flag_reply_not_replayed_and_not_released(self):
  row=self.claim();self.put(dict(operation='flag',request_id='2'*32,target_id=B.target_name(row),category='checker_problem',note='reproducible checker crash'))
  original=self.service
  def service(script,*args):
   if script=='fnv.ps1' and args[0]=='flag':self.calls.append((script,args));raise RuntimeError('lost reply')
   return original(script,*args)
  self.bridge.tick(self.trial,self.status,service,self.finish,lambda:None,None);self.tick()
  self.assertEqual(self.answer('2'*32)['state'],'optional_unavailable');self.assertFalse(row.get('done'));self.assertFalse(row.get('released'))
  self.assertEqual(sum(c[0]=='fnv.ps1' and c[1][0]=='flag' for c in self.calls),1)
 def test_best_code_wip_shared_hash_bound(self):
  row,request=self.submit(valid=False);request.update(operation='giveup',reason='stack layout differs');self.put(request)
  self.tick();self.assertEqual(self.answer('2'*32)['state'],'released')
  payload=[json.loads(c[1][-1]) for c in self.calls if c[0]=='fnv.ps1' and c[1][0]=='giveup'][0]
  self.assertEqual(payload['best_code'],'int f(){return 1;}');self.assertFalse(row['shared_best_source']['verified_match'])
 def test_changed_best_code_refused(self):
  row,request=self.submit(valid=False);request.update(operation='giveup',reason='stack layout differs');self.put(request)
  (Path(row['pack'])/'mcp_candidates'/('a'*32)/'candidate.cpp').write_text('different source')
  self.tick();self.assertEqual(self.answer('2'*32)['state'],'refused');self.assertFalse(row.get('released'))
 def test_claim_once(self):
  self.claim();self.tick();self.assertEqual(sum(c[0]=='claim-pack.ps1' for c in self.calls),1)
 def test_expired_inactive_quarantine_does_not_occupy_capacity(self):
  row=dict(arm='qwen',claim_id='clm_old',stage='quarantined',done=False,expires=(B.now()-timedelta(minutes=1)).isoformat())
  self.assertEqual(B.capacity_claim_ids([row],self.status),set())
  self.status['open_claims']=[dict(claim_id='clm_old')]
  self.assertEqual(B.capacity_claim_ids([row],self.status),{'clm_old'})
  self.status['open_claims']=[];row['expires']=(B.now()+timedelta(minutes=1)).isoformat()
  self.assertEqual(B.capacity_claim_ids([row],self.status),{'clm_old'})
 def test_dispatch_refreshes_stale_full_status_without_extra_writer(self):
  stale=dict(self.status,open_claims=[dict(claim_id='clm_old',address='0x00400000')],limits=dict(self.status['limits'],claims=1))
  self.bridge.prepare_web=lambda *args:None
  self.bridge.tick(self.trial,stale,self.service,self.finish,lambda:None,SimpleNamespace())
  self.assertEqual(len(self.trial['rows']),1)
  self.assertEqual(sum(script=='fnv.ps1' for script,args in self.calls),1)
  self.assertEqual(sum(script=='claim-reserve.ps1' for script,args in self.calls),1)
 def test_dispatch_read_failure_does_not_claim(self):
  self.bridge.prepare_web=lambda *args:None
  calls=[]
  def failed(script,*args):
   calls.append(script);raise RuntimeError('Read-only status unavailable')
  self.bridge.tick(self.trial,self.status,failed,self.finish,lambda:None,SimpleNamespace())
  self.assertEqual(calls,['fnv.ps1']);self.assertEqual(self.trial['rows'],[])
  self.assertEqual(self.answer()['reason'],'status_refresh_unavailable')
 def test_known_target_quarantine_does_not_stop_unrelated_claims(self):
  B.save(self.bridge.base/'responses'/('9'*32+'.json'),dict(state='needs_reconciliation',target_id='web_clm_known'))
  self.assertFalse(B.Bridge(self.root).uncertain)
  B.save(self.bridge.base/'responses'/('8'*32+'.json'),dict(state='needs_reconciliation',reason='Unknown claim acquisition'))
  self.assertTrue(B.Bridge(self.root).uncertain)
 def test_reserved_pack_hydrates_read_only_before_preparation(self):
  pack=self.root/'work/clm_reserved';pack.mkdir(parents=True)
  calls=[]
  def hydrate(*args):calls.append(args);B.save(pack/'pack.json',{})
  helpers=SimpleNamespace(ps=hydrate)
  module=SimpleNamespace(prepare=lambda p,h:dict(cpu=dict(outcome='unsupported')))
  value=self.bridge.prepare_owned(dict(pack=str(pack)),SimpleNamespace(helpers=helpers,module=module))
  self.assertEqual(calls,[('hydrate-pack.ps1','-Pack',str(pack))])
  self.assertEqual(value['web_preparation_lane'],'web')
 def test_local_preparation_uses_separate_ghidra_project(self):
  pack=self.root/'work/clm_local';pack.mkdir(parents=True);B.save(pack/'pack.json',{})
  options=[]
  ghidra=SimpleNamespace(prepare=lambda p,**kw:options.append(kw) or dict(outcome='draft'))
  helpers=SimpleNamespace(cpu_prepare=lambda p:dict(cpu={}),load=lambda name:ghidra)
  module=SimpleNamespace(prepare=lambda p,h:dict(cpu=h.cpu_prepare(p),ghidra=h.add_ghidra(p)))
  result=self.bridge.prepare_owned(dict(pack=str(pack)),SimpleNamespace(helpers=helpers,module=module),True)
  self.assertEqual(options,[dict(seconds=45,project_lane='minimax',lock_wait_seconds=2)])
  self.assertEqual(result['web_preparation_lane'],'local_pool')
 def test_busy_ghidra_keeps_cpu_evidence_without_claiming_a_draft(self):
  pack=self.root/'work/clm_busy';pack.mkdir(parents=True);B.save(pack/'pack.json',{})
  class Busy(RuntimeError):pass
  def busy(*a,**kw):raise Busy('busy')
  ghidra=SimpleNamespace(prepare=busy,GhidraBusyError=Busy)
  helpers=SimpleNamespace(cpu_prepare=lambda p:dict(outcome='unsupported'),load=lambda name:ghidra)
  module=SimpleNamespace(prepare=lambda p,h:dict(cpu=h.cpu_prepare(p),ghidra=h.add_ghidra(p)))
  result=self.bridge.prepare_owned(dict(pack=str(pack)),SimpleNamespace(helpers=helpers,module=module))
  self.assertEqual(result['cpu']['outcome'],'unsupported')
  self.assertEqual(result['ghidra']['outcome'],'unavailable')
  self.assertFalse(result['ghidra']['confirmed_match'])
 def test_reference_change_is_not_downgraded_to_busy_advice(self):
  pack=self.root/'work/clm_changed';pack.mkdir(parents=True);B.save(pack/'pack.json',{})
  class Busy(RuntimeError):pass
  def changed(*a,**kw):raise RuntimeError('Reference/pack changed')
  ghidra=SimpleNamespace(prepare=changed,GhidraBusyError=Busy)
  helpers=SimpleNamespace(cpu_prepare=lambda p:dict(outcome='unsupported'),load=lambda name:ghidra)
  module=SimpleNamespace(prepare=lambda p,h:dict(cpu=h.cpu_prepare(p),ghidra=h.add_ghidra(p)))
  with self.assertRaisesRegex(RuntimeError,'Reference/pack changed'):
   self.bridge.prepare_owned(dict(pack=str(pack)),SimpleNamespace(helpers=helpers,module=module))
 def test_long_batch_harvests_preparation_and_services_cpu(self):
  from unittest.mock import patch
  harvest=[];cpu=[];clock=[0]
  self.bridge.prepare_web=lambda *args:harvest.append(True)
  self.bridge.publish=lambda *args:None
  sweep=SimpleNamespace(uncertain=False,tick=lambda *args,**kw:cpu.append(True))
  loader=SimpleNamespace(cpu_sweep_runtime=sweep)
  def monotonic():clock[0]+=15;return clock[0]
  with patch.object(B.time,'monotonic',side_effect=monotonic):
   self.bridge.tick(self.trial,self.status,self.service,self.finish,lambda:None,loader)
  self.assertGreaterEqual(len(harvest),3)
  self.assertFalse(cpu) # web claim was still waiting when CPU turn was considered
 def test_size_bands_rotate_ahead_of_large_single_band_pool(self):
  entries=[]
  for n,band in enumerate(['<=255']*60+['512-1K','256-511']):
   r=dict(operation='claim',request_id=f'{n+100:032x}',band=band,model='test')
   self.put(r);entries.append((self.bridge.base/'requests'/f"{r['request_id']}.json",r))
  ordered=B.fair_pending(entries,'<=255')
  self.assertEqual([r['band'] for p,r in ordered[:3]],['256-511','512-1K','<=255'])
  tiny=[r['request_id'] for p,r in ordered if r['band']=='<=255']
  self.assertEqual(tiny,[r['request_id'] for p,r in entries[:60]])
 def test_web_group_not_stuck_behind_sixty_local_workers_in_same_band(self):
  entries=[]
  for n in range(61):
   r=dict(operation='claim',request_id=f'{n+100:032x}',band='<=255',model='test',agent_id=f'or_minimax_{n:02}' if n<60 else 'web_agent')
   self.put(r);entries.append((self.bridge.base/'requests'/f"{r['request_id']}.json",r))
  ordered=B.fair_pending(entries,'<=255',{'<=255':'local_pool'})
  self.assertEqual(ordered[0][1]['agent_id'],'web_agent')
 def test_overdue_tiny_request_precedes_fresh_large_band(self):
  import os
  old=dict(operation='claim',request_id='8'*32,band='<=255',model='test',agent_id='web_old')
  fresh=dict(operation='claim',request_id='9'*32,band='1K-4K',model='test',agent_id='web_fresh')
  self.put(old);self.put(fresh)
  oldpath=self.bridge.base/'requests'/('8'*32+'.json');freshpath=self.bridge.base/'requests'/('9'*32+'.json')
  os.utime(oldpath,(time.time()-600,time.time()-600))
  result=B.fair_pending([(oldpath,old),(freshpath,fresh)],'<=255')
  self.assertEqual(result[0][1]['agent_id'],'web_old')
 def test_amend_pending_band_keeps_original_identity(self):
  self.put(dict(operation='amend',request_id='0'*32,original_request_id='1'*32,agent_id=B.agent_key(self.req),band='512-1K',cancel=False))
  self.tick()
  self.assertEqual(self.answer('0'*32)['state'],'updated')
  self.assertEqual(B.read(self.bridge.base/'requests'/('1'*32+'.json'))['band'],'512-1K')
  self.assertEqual(self.calls[0],('claim-pack.ps1',('-Band','512-1K','-Prefer','any')))
 def test_cancel_pending_creates_no_claim(self):
  self.put(dict(operation='amend',request_id='0'*32,original_request_id='1'*32,agent_id=B.agent_key(self.req),cancel=True))
  self.tick()
  self.assertEqual(self.answer()['state'],'cancelled');self.assertFalse(self.calls)
 def test_cannot_amend_another_agent_or_executing_claim(self):
  self.put(dict(operation='amend',request_id='0'*32,original_request_id='1'*32,agent_id='other',cancel=True))
  self.tick();self.assertEqual(self.answer('0'*32)['state'],'refused')
  self.put(dict(operation='amend',request_id='2'*32,original_request_id='1'*32,agent_id=B.agent_key(self.req),band='512-1K',cancel=False))
  self.tick();self.assertEqual(self.answer('2'*32)['state'],'refused')
 def test_slow_finish_still_allows_one_claim_before_yielding(self):
  B.save(self.root/'local/opencode/control.json',dict(mcp_claim_burst=8))
  row=self.claim();self.calls=[]
  self.put(dict(operation='giveup',request_id='2'*32,target_id='web_clm_abc',reason='done'))
  for n in range(3,6):self.put(dict(operation='claim',request_id=str(n)*32,band='<=255',model='test',agent_id='worker_'+str(n)))
  original=self.finish
  clock=[100.0]
  def slow_finish(r,report):clock[0]+=60;original(r,report)
  self.finish=slow_finish
  from unittest.mock import patch
  with patch.object(B.time,'monotonic',side_effect=lambda:clock[0]):self.tick()
  self.assertEqual(sum(c[0]=='claim-pack.ps1' for c in self.calls),1)
  self.assertEqual(self.answer('4'*32)['state'],'queued')
 def test_cpu_near_handoff_reuses_same_claim(self):
  row=self.service('claim-pack.ps1')
  row.update(arm='qwen',stage='ready',done=False,cpu_sweep=True,cpu_sweep_route='near_review',cpu_review_until=(B.now()+timedelta(minutes=15)).isoformat())
  self.trial['rows'].append(row);self.calls=[]
  # Avoid context generation in this routing-only test.
  self.bridge.publish=lambda r,load:None
  self.tick()
  self.assertFalse(self.calls);self.assertEqual(row['external_owner'],'web_mcp');self.assertEqual(row['claim_id'],'clm_abc')
 def test_web_first_then_allow_local_spare_capacity(self):
  self.put(dict(self.req,request_id='8'*32,agent_id='web_second'))
  self.tick()
  self.assertEqual(sum(c[0]=='claim-pack.ps1' for c in self.calls),1)
  self.assertTrue(self.bridge.pending_claims)
  self.assertTrue(B.read(self.bridge.base/'coordinator.json')['pending_web_claims'])
 def test_second_request_reuses_owned_claim(self):
  self.claim();self.put(dict(self.req,request_id='3'*32));self.tick();self.assertEqual(self.answer('3'*32)['state'],'already_assigned');self.assertEqual(len(self.trial['rows']),1)
 def test_submission_requires_official_match(self):
  self.submit(False);self.tick();self.assertEqual(self.answer('2'*32)['state'],'refused');self.assertFalse(any(c[0]=='finish' for c in self.calls))
 def test_hash_change_refused(self):
  row,r=self.submit();(Path(row['pack'])/'mcp_candidates'/('a'*32)/'candidate.cpp').write_text('changed')
  self.tick();self.assertEqual(self.answer('2'*32)['state'],'refused')
 def test_match_routed_to_coordinator_once(self):
  self.submit();self.tick();self.tick();self.assertEqual(self.answer('2'*32)['state'],'submitted');self.assertEqual(sum(c[0]=='finish' for c in self.calls),1)
 def test_other_key_refused(self):
  self.submit();self.status['open_claims'][0]['this_key']=False;self.tick();self.assertEqual(self.answer('2'*32)['state'],'needs_reconciliation')
 def test_limit_never_claims(self):
  self.status['submissions_paused']=True;self.tick();self.assertEqual(self.calls,[]);self.assertEqual(self.answer()['state'],'waiting_capacity')
 def test_interrupted_claim_never_replayed(self):
  B.save(self.bridge.base/'responses'/('1'*32+'.json'),dict(state='executing'))
  self.tick();self.tick();self.assertEqual(self.calls,[]);self.assertTrue(self.bridge.uncertain)
 def test_interrupted_known_finish_does_not_block_other_workers(self):
  row=self.claim()
  req=dict(operation='giveup',request_id='4'*32,target_id='web_clm_abc',reason='No match')
  self.put(req);B.save(self.bridge.base/'responses'/('4'*32+'.json'),dict(state='executing'))
  before=len(self.calls);self.tick()
  self.assertEqual(len(self.calls),before)
  self.assertFalse(self.bridge.uncertain)
  self.assertEqual(row['stage'],'quarantined')
  self.assertEqual(self.answer('4'*32)['target_id'],'web_clm_abc')
  self.assertEqual(self.answer('4'*32)['state'],'needs_reconciliation')
 def test_interrupted_known_acquisition_uses_saved_identity_without_replay(self):
  row=self.claim()
  B.save(self.bridge.base/'responses'/('1'*32+'.json'),dict(state='executing'))
  self.bridge.completed_requests.discard('1'*32+'.json')
  self.bridge.published.clear();self.bridge.publish=lambda r,load:self.bridge.response(self.req,'preparing',target_id=B.target_name(r))
  before=len(self.calls);self.tick()
  self.assertEqual(len(self.calls),before);self.assertFalse(self.bridge.uncertain)
  self.assertEqual(self.answer()['target_id'],B.target_name(row))
 def test_giveup(self):
  self.claim();self.put(dict(operation='giveup',request_id='4'*32,target_id='web_clm_abc',reason='First instruction still differs'));self.tick();self.assertEqual(self.answer('4'*32)['state'],'released')
 def test_expired_worker_released(self):
  row=self.claim();row['stage']='external_working';row['external_work_until']=(B.now()-timedelta(seconds=1)).isoformat();self.tick();self.assertTrue(row['released'])
 def test_path_escape_rejected(self):
  with self.assertRaises(ValueError):B.live_target('../../elsewhere',self.root)
 def test_model_mismatch_refused(self):
  row,_=self.submit();B.save(Path(row['pack'])/'mcp_candidates'/('a'*32)/'candidate.cpp.provenance.json',dict(model='someone else',source_sha256='x'));self.tick();self.assertEqual(self.answer('2'*32)['state'],'refused')
 def test_distinct_agents_work_concurrently(self):
  self.req['agent_id']='argon_01';self.put(self.req);self.claim()
  self.put(dict(self.req,request_id='5'*32,agent_id='claude_01',model='Claude; CPU/Ghidra'))
  self.tick();self.assertEqual(len(self.trial['rows']),2)
  self.assertEqual({B.row_agent(r) for r in self.trial['rows']},{'argon_01','claude_01'})
 def test_same_agent_one_claim_even_if_model_changes(self):
  self.req['agent_id']='claude_01';self.put(self.req);self.claim()
  self.put(dict(self.req,request_id='5'*32,model='different model'));self.tick()
  self.assertEqual(len(self.trial['rows']),1);self.assertEqual(self.answer('5'*32)['state'],'already_assigned')
 def test_account_cap_bounds_many_agents(self):
  self.status['limits']['claims']=3
  for i in range(1,7):self.put(dict(self.req,request_id=f'{i:032x}',agent_id=f'agent_{i}'))
  for _ in range(8):self.tick()
  self.assertEqual(len(self.trial['rows']),3)
  self.assertTrue(self.bridge.pending_claims)
 def test_other_agent_cannot_release(self):
  self.req['agent_id']='claude_01';self.put(self.req);self.claim()
  self.put(dict(operation='giveup',request_id='6'*32,target_id='web_clm_abc',agent_id='argon_01',reason='wrong agent'))
  self.tick();self.assertEqual(self.answer('6'*32)['state'],'refused')
 def test_explicit_agent_required(self):
  self.req['agent_id']='claude_01';self.put(self.req);self.claim()
  self.put(dict(operation='giveup',request_id='6'*32,target_id='web_clm_abc',reason='missing agent'))
  self.tick();self.assertEqual(self.answer('6'*32)['state'],'refused')
 def test_legacy_argon_survives_migration(self):
  row=self.claim();row['external_owner']='argon_mcp';row['stage']='external_working'
  self.put(dict(self.req,request_id='7'*32,model='Claude; CPU/Ghidra'))
  self.tick();self.assertEqual(len(self.trial['rows']),2)
  self.assertEqual(B.target_name(row),'argon_clm_abc');self.assertFalse(row.get('done'))
 def test_agent_routing_identity_validation(self):
  with self.assertRaises(ValueError):B.validate_agent(dict(agent_id='claude_01',requires_agent_id=True),'argon_01')
  B.validate_agent(dict(agent_id='claude_01',requires_agent_id=True),'claude_01')
 def test_twenty_agents_are_not_artificially_capped(self):
  for i in range(20):self.put(dict(self.req,request_id=f'{i+1:032x}',agent_id=f'agent_{i}'))
  for _ in range(22):
   self.tick()
   # The real coordinator prepares packs between mailbox ticks.
   for row in self.trial['rows']:row['stage']='external_working'
  self.assertEqual(len(self.trial['rows']),20)
 def test_preparation_backlog_is_bounded(self):
  self.status['limits']['claims']=100
  B.save(self.root/'local/opencode/control.json',dict(mcp_claim_burst=8))
  for i in range(65):self.put(dict(self.req,request_id=f'{i+1:032x}',agent_id=f'agent_{i}'))
  for _ in range(10):self.tick()
  self.assertEqual(len(self.trial['rows']),64)
  answer=self.answer(f'{65:032x}')
  self.assertEqual(answer['state'],'queued');self.assertEqual(answer['reason'],'preparation_backlog')
  self.assertEqual(answer['available_claim_slots'],36)
 def test_configured_three_claim_burst(self):
  B.save(self.root/'local/opencode/control.json',{'mcp_claim_burst':3})
  for i in range(6):self.put(dict(self.req,request_id=f'{i+1:032x}',agent_id=f'agent_{i}'))
  self.tick();self.assertEqual(len(self.trial['rows']),3)
 def test_dispatch_queue_is_retried_and_not_mislabeled_capacity(self):
  self.put(dict(self.req,request_id='8'*32,agent_id='web_second'))
  self.tick();self.assertEqual(self.answer('8'*32)['state'],'queued')
  self.assertEqual(self.answer('8'*32)['reason'],'dispatch_budget')
  self.tick();self.assertEqual(len(self.trial['rows']),2)
 def test_reload_indexes_terminal_requests_without_republishing_history(self):
  row=self.claim();row.update(done=True,stage='done',released=True)
  self.bridge.publish(row,None)
  response=self.bridge.base/'responses'/('1'*32+'.json')
  stamp=response.stat().st_mtime_ns
  self.bridge=B.Bridge(self.root);self.calls=[]
  self.assertIn(response.name,self.bridge.completed_requests)
  self.tick()
  self.assertEqual(response.stat().st_mtime_ns,stamp)
  self.assertFalse(self.calls)
 def test_release_is_served_before_new_claim(self):
  self.claim();self.calls=[]
  self.put(dict(self.req,request_id='8'*32,agent_id='web_second'))
  self.put(dict(operation='giveup',request_id='9'*32,target_id='web_clm_abc',reason='Done'))
  self.tick();self.assertEqual(self.calls[1][0],'finish')
 def test_large_finish_queue_does_not_put_claims_last(self):
  finishing=[(Path(str(i)),dict(operation='giveup')) for i in range(30)]
  claims=[(Path('c'+str(i)),dict(operation='claim')) for i in range(30)]
  finishing.append((Path('match'),dict(operation='submit')))
  result=B.interleave_operations(finishing+claims)
  self.assertEqual([r['operation'] for p,r in result[:4]],['submit','claim','giveup','claim'])
 def test_waiting_web_claims_precede_new_local_claims_but_not_finishes(self):
  items=[(Path('local'),dict(operation='claim',agent_id='fnvqwen_01')),
         (Path('web'),dict(operation='claim',agent_id='web_agent')),
         (Path('finish'),dict(operation='giveup',agent_id='fnvqwen_02'))]
  result=B.interleave_operations(items)
  self.assertEqual([p.name for p,r in result],['finish','web','local'])
 def batch_service(self,script,*args):
  if script!='claim-batch-reserve.ps1':return self.service(script,*args)
  self.calls.append((script,args));manifest=Path(args[1]);requests=B.read(manifest)['requests']
  for n,request in enumerate(requests):
   cid=f'clm_{n+200:04x}';pack=self.root/'work'/cid
   claim=dict(claim_id=cid,pack=str(pack),address=f'0x{0x500000+n*16:08x}',symbol='FUN_batch',size=12,expires=(B.now()+timedelta(hours=2)).isoformat())
   B.save(pack/'claim-state.json',claim)
   B.save(manifest.parent/(request['request_id']+'.json'),dict(request_id=request['request_id'],state='reserved',claim=claim))
 def test_four_pending_requests_share_one_batch_and_keep_unique_claims(self):
  B.save(self.root/'local/opencode/control.json',dict(mcp_claim_burst=16,fast_claim_batches=True))
  for n in range(1,5):self.put(dict(self.req,request_id=str(n)*32,agent_id='web_'+str(n)))
  self.bridge.tick(self.trial,self.status,self.batch_service,self.finish,lambda:None,None)
  self.assertEqual(len({r['claim_id'] for r in self.trial['rows']}),4)
  self.assertEqual(sum(c[0]=='claim-batch-reserve.ps1' for c in self.calls),1)
  self.assertTrue(all(self.answer(str(n)*32)['state']=='preparing' for n in range(1,5)))
 def test_partial_batch_failure_preserves_known_claim_and_never_replays(self):
  requests=[dict(self.req,agent_id='web_a'),dict(self.req,request_id='2'*32,agent_id='web_b')]
  def partial(script,*args):
   self.calls.append((script,args));manifest=Path(args[1]);claim=dict(claim_id='clm_abc',symbol='FUN_a',address='0x00500000',size=12,expires=(B.now()+timedelta(hours=2)).isoformat(),pack=str(self.root/'work/clm_abc'))
   B.save(Path(claim['pack'])/'claim-state.json',claim)
   B.save(manifest.parent/('1'*32+'.json'),dict(request_id='1'*32,state='reserved',claim=claim))
   raise RuntimeError('connection lost during second reservation')
  count=self.bridge.reserve_batch(requests,self.trial,partial,self.finish,lambda:None,None)
  self.assertEqual(count,1);self.assertTrue(self.bridge.uncertain)
  self.assertEqual(self.answer('2'*32)['state'],'needs_reconciliation');self.assertEqual(len(self.calls),1)
 def test_batch_respects_last_free_account_slot(self):
  self.status['limits']['claims']=1
  B.save(self.root/'local/opencode/control.json',dict(mcp_claim_burst=16,fast_claim_batches=True))
  self.put(dict(self.req,request_id='2'*32,agent_id='web_b'))
  self.bridge.tick(self.trial,self.status,self.batch_service,self.finish,lambda:None,None)
  self.assertEqual(len(self.trial['rows']),1)
  self.assertFalse(any(c[0]=='claim-batch-reserve.ps1' for c in self.calls))
 def test_writer_turn_is_bounded_even_with_large_configured_claim_burst(self):
  self.status['limits']['claims']=100
  B.save(self.root/'local/opencode/control.json',dict(mcp_claim_burst=16))
  for i in range(20):self.put(dict(self.req,request_id=f'{i+1:032x}',agent_id=f'agent_{i}'))
  self.tick()
  self.assertEqual(len(self.trial['rows']),16)
  health=B.read(self.bridge.base/'coordinator.json')
  self.assertEqual(health['writer_operations'],16)
  self.assertEqual(health['claimed_this_tick'],16)
 def test_web_preparation_has_four_parallel_non_service_jobs(self):
  for _ in range(6):
   row=self.service('claim-pack.ps1');row.update(arm='qwen',stage='waiting',done=False,external_owner='web_mcp',external_model='test')
   self.trial['rows'].append(row)
  release=threading.Event();started=[];context_threads=[];main_thread=threading.get_ident()
  def prepare(pack,helpers):
   started.append(threading.get_ident());release.wait(2)
   return dict(cpu=dict(outcome='unsupported'),ghidra=dict(outcome='draft'))
  def context(pack):context_threads.append(threading.get_ident());return 'exact compiler and target evidence'
  def loader(name,suffix=''):
   if name=='free-model-trial':return SimpleNamespace(prepare=prepare)
   if name=='local-qwen-worker':return SimpleNamespace(context=context)
   if name=='agent-evidence':return SimpleNamespace(prompt_evidence=lambda pack:'CPU/Ghidra assistance')
   return object()
  try:
   self.bridge.prepare_web(self.trial,loader,self.finish,lambda:None)
   for _ in range(100):
    if len(started)==4:break
    time.sleep(.005)
   self.assertEqual(len(started),4);self.assertNotIn(main_thread,started)
   self.assertEqual(sum(r['stage']=='web_preparing' for r in self.trial['rows']),4)
   self.assertEqual(sum(r['stage']=='web_packet_waiting' for r in self.trial['rows']),2)
   self.assertFalse(any(r['stage']=='waiting' for r in self.trial['rows']))
   release.set()
   for future in list(loader.web_prep_runtime.jobs):future.result(2)
   self.bridge.prepare_web(self.trial,loader,self.finish,lambda:None)
   self.assertEqual(sum(r['stage']=='ready' for r in self.trial['rows']),4)
   self.assertTrue(context_threads);self.assertNotIn(main_thread,context_threads)
  finally:release.set();loader.web_prep_runtime.pool.shutdown()

 def test_operator_reconciled_acquisition_adopted_without_mutation(self):
  cid='clm_recovered';rid=self.req['request_id'];claim=dict(claim_id=cid,address='0x00400000',symbol='FUN_00400000',size=12,expires=(B.now()+timedelta(hours=1)).isoformat(),pack=str(self.root/'work'/cid))
  self.status['open_claims']=[dict(claim_id=cid,address=claim['address'],expires=claim['expires'],this_key=True)]
  B.save(Path(claim['pack'])/'claim-state.json',claim)
  B.save(self.bridge.base/'reconciled-acquisitions'/(rid+'.json'),dict(request_id=rid,claim=claim))
  self.bridge.unresolved_acquisitions={rid};self.bridge.uncertain=True
  self.bridge.reconcile_saved_acquisitions(self.trial,self.status,lambda:None,None)
  self.assertFalse(self.bridge.uncertain);self.assertEqual(len(self.trial['rows']),1);self.assertFalse(self.calls)
  self.assertEqual(self.answer()['target_id'],'web_'+cid)
 def test_unknown_acquisition_not_cleared_without_owned_identity(self):
  self.bridge.unresolved_acquisitions={self.req['request_id']};self.bridge.uncertain=True
  self.bridge.reconcile_saved_acquisitions(self.trial,self.status,lambda:None,None)
  self.assertTrue(self.bridge.uncertain);self.assertFalse(self.trial['rows'])
 def expired_proof(self):
  rid=self.req['request_id'];batch=self.root/'local/mcp/batches/test';checked=B.now()-timedelta(seconds=2)
  B.save(batch/'requests.json',dict(requests=[self.req]));B.save(batch/(rid+'.json'),dict(state='uncertain'))
  B.save(batch/'completed.json',dict(utc=(checked-timedelta(hours=1,minutes=2)).isoformat(),uncertain=True))
  evidence=self.bridge.base/'reconciled-acquisitions'/(rid+'-status.json');self.status['limits']['claimMs']=3600000
  B.save(evidence,dict(checked_utc=checked.isoformat(),status=self.status))
  original=self.bridge.base/'requests'/(rid+'.json');completed=batch/'completed.json'
  proof=dict(kind='expired_acquisition_no_live_identity',request_id=rid,maximum_claim_ms=3600000,
   request_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),batch_completed=str(completed.relative_to(self.root)),batch_completed_sha256=hashlib.sha256(completed.read_bytes()).hexdigest(),
   status_evidence=str(evidence.relative_to(self.root)),status_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest())
  B.save(evidence.with_name(rid+'.json'),proof);self.bridge.unresolved_acquisitions={rid};self.bridge.uncertain=True
  return proof,evidence,completed
 def test_expired_unknown_acquisition_closes_without_claim_or_verdict(self):
  self.expired_proof();self.bridge.reconcile_saved_acquisitions(self.trial,self.status,lambda:None,None)
  self.assertFalse(self.bridge.uncertain);self.assertFalse(self.calls);self.assertFalse(self.trial['rows'])
  self.assertEqual(self.answer()['state'],'closed_unreconciled');self.assertEqual(self.answer()['historical_outcome'],'unknown')
  self.assertFalse(B.Bridge(self.root).uncertain)
 def test_automatic_expiry_requires_lifetime_before_fresh_status(self):
  proof,evidence,completed=self.expired_proof()
  B.save(completed,dict(utc=B.now().isoformat(),uncertain=True))
  self.bridge.prepare_expired_acquisition_proofs(self.trial,self.status,self.service)
  self.assertFalse(self.calls);self.assertTrue(self.bridge.uncertain)
 def test_automatic_expiry_produces_proof_without_replaying_claim(self):
  proof,evidence,completed=self.expired_proof()
  evidence.with_name(self.req['request_id']+'.json').unlink()
  receipt=completed.with_name(self.req['request_id']+'.json');original=receipt.read_bytes()
  self.bridge.prepare_expired_acquisition_proofs(self.trial,self.status,self.service)
  self.assertEqual(self.calls,[('fnv.ps1',('status',))])
  self.bridge.reconcile_saved_acquisitions(self.trial,self.status,lambda:None,None)
  self.assertFalse(self.bridge.uncertain);self.assertEqual(receipt.read_bytes(),original)
  self.assertEqual(self.answer()['state'],'closed_unreconciled')
  audit=self.trial['expired_acquisition_reconciliations'][0]
  self.assertEqual(hashlib.sha256((self.root/audit['proof_path']).read_bytes()).hexdigest(),audit['proof_sha256'])
 def test_automatic_expiry_respects_global_hold_and_longer_live_limit(self):
  self.expired_proof()
  B.save(self.root/'local/service-limit.json',dict(retry_at_utc=(B.now()+timedelta(hours=1)).isoformat()))
  self.bridge.prepare_expired_acquisition_proofs(self.trial,self.status,self.service);self.assertFalse(self.calls)
  (self.root/'local/service-limit.json').unlink()
  def longer(script,*args):return dict(self.status,limits=dict(self.status['limits'],claimMs=7200000))
  (self.bridge.base/'reconciled-acquisitions'/(self.req['request_id']+'.json')).unlink()
  self.bridge.prepare_expired_acquisition_proofs(self.trial,self.status,longer)
  self.assertFalse((self.bridge.base/'reconciled-acquisitions'/(self.req['request_id']+'.json')).exists())
 def test_automatic_expiry_rejects_untracked_owned_identity(self):
  self.expired_proof()
  proof=self.bridge.base/'reconciled-acquisitions'/(self.req['request_id']+'.json');proof.unlink()
  self.status['open_claims']=[dict(claim_id='unknown',this_key=True)]
  self.bridge.prepare_expired_acquisition_proofs(self.trial,self.status,self.service)
  self.assertFalse(proof.exists());self.assertTrue(self.bridge.uncertain)
 def test_web_expiry_recovery_does_not_clear_independent_cpu_hold(self):
  from unittest.mock import patch
  self.expired_proof()
  loader=SimpleNamespace(cpu_sweep_runtime=SimpleNamespace(uncertain=True))
  with patch.object(self.bridge,'prepare_web'),patch.object(self.bridge,'install_transport'),patch.object(self.bridge,'install_checkpoints'):
   self.bridge.tick(self.trial,self.status,self.service,self.finish,lambda:None,loader)
  self.assertTrue(self.bridge.uncertain);self.assertFalse(self.trial['rows'])
  self.assertFalse(any(c[0]=='claim-pack.ps1' for c in self.calls))
 def test_expired_acquisition_proof_rejects_untracked_owned_claim(self):
  self.expired_proof();self.status['open_claims']=[dict(claim_id='clm_untracked',this_key=True)]
  self.bridge.reconcile_saved_acquisitions(self.trial,self.status,lambda:None,None)
  self.assertTrue(self.bridge.uncertain);self.assertFalse(self.calls)
 def test_expired_acquisition_proof_rejects_too_early_and_stale_status(self):
  proof,evidence,completed=self.expired_proof()
  for age in (300,-10):
   body=B.read(evidence);body['checked_utc']=(B.now()-timedelta(seconds=age)).isoformat();B.save(evidence,body)
   proof['status_sha256']=hashlib.sha256(evidence.read_bytes()).hexdigest();B.save(evidence.with_name(self.req['request_id']+'.json'),proof)
   self.bridge.reconcile_saved_acquisitions(self.trial,self.status,lambda:None,None);self.assertTrue(self.bridge.uncertain)
  self.expired_proof();B.save(completed,dict(utc=B.now().isoformat(),uncertain=True))
  proof['batch_completed_sha256']=hashlib.sha256(completed.read_bytes()).hexdigest();B.save(evidence.with_name(self.req['request_id']+'.json'),proof)
  self.bridge.reconcile_saved_acquisitions(self.trial,self.status,lambda:None,None);self.assertTrue(self.bridge.uncertain)
 def test_expired_acquisition_proof_rejects_changed_request(self):
  self.expired_proof();changed=dict(self.req,model='different');self.put(changed)
  self.bridge.reconcile_saved_acquisitions(self.trial,self.status,lambda:None,None);self.assertTrue(self.bridge.uncertain)
 def test_cloud_first_reserves_a_turn_before_slow_finishing(self):
  from tempfile import TemporaryDirectory
  with TemporaryDirectory() as d:
   p=Path(d);fin=(p/'f',dict(operation='submit',target_id='not_urgent'));web=(p/'w',dict(operation='claim',agent_id='web_a'));local=(p/'l',dict(operation='claim',agent_id='fnvqwen_01'))
   ordered=B.interleave_operations([fin,local,web],True)
   self.assertEqual(ordered[0],web);self.assertEqual(ordered[1],fin)
   self.assertEqual(B.interleave_operations([fin,web],True,{'not_urgent'})[0],fin)
 def test_response_index_observes_changed_and_new_uncertain_records(self):
  rid='a'*32;p=self.bridge.base/'responses'/(rid+'.json')
  B.save(p,dict(state='released',target_id='web_clm_a'))
  first=B.Bridge(self.root);self.assertFalse(first.uncertain)
  B.save(p,dict(state='needs_reconciliation',reason='unknown acquisition'))
  second=B.Bridge(self.root);self.assertTrue(second.uncertain);self.assertIn(rid,second.unresolved_acquisitions)
 def test_corrupt_response_index_is_not_recovery_authority(self):
  rid='b'*32;p=self.bridge.base/'responses'/(rid+'.json');B.save(p,dict(state='needs_reconciliation'))
  B.Bridge(self.root);index_path=self.bridge.base/'response-index.json';index=B.read(index_path)
  index['entries'][rid+'.json'][2]='released';B.save(index_path,index)
  self.assertTrue(B.Bridge(self.root).uncertain)
 def test_unchanged_response_cache_avoids_reopening_historical_records(self):
  from unittest.mock import patch
  p=self.bridge.base/'responses'/('c'*32+'.json');B.save(p,dict(state='released',target_id='web_clm_c'));B.Bridge(self.root)
  original=B.read;opened=[]
  def counted(path):
   if Path(path).parent.name=='responses':opened.append(path)
   return original(path)
  with patch.object(B,'read',side_effect=counted):B.Bridge(self.root)
  self.assertEqual(opened,[])
 def test_publish_reuses_only_identity_and_hash_bound_prepared_context(self):
  from unittest.mock import patch
  row=self.claim();row['stage']='ready';target=B.target_name(row);path=self.root/'local/mcp/contexts'/(target+'.json');B.save(path,{'evidence':'original'})
  row['mcp_context_ready']=dict(target_id=target,agent_id=B.row_agent(row),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
  with patch.object(self.bridge,'context_value',side_effect=AssertionError('should not rebuild')):self.bridge.publish(row,None)
  self.assertEqual(row['stage'],'external_working')
  row['stage']='ready';self.bridge.published.pop(target,None);B.save(path,{'evidence':'tampered'})
  with patch.object(self.bridge,'context_value',return_value={'evidence':'rebuilt'}) as rebuild:self.bridge.publish(row,None)
  self.assertEqual(rebuild.call_count,1);self.assertEqual(B.read(path)['evidence'],'rebuilt');self.assertIn('previous_attempts',B.read(path))
class OptionalBridgeTests(unittest.TestCase):
 setUp=BridgeTests.setUp
 tearDown=BridgeTests.tearDown
 put=BridgeTests.put
 service=BridgeTests.service
 finish=BridgeTests.finish
 tick=BridgeTests.tick
 answer=BridgeTests.answer
 claim=BridgeTests.claim
 def test_optional_save_failure_is_terminal_without_release_or_global_uncertainty(self):
  row=self.claim();self.put(dict(operation='giveup',request_id='2'*32,target_id=B.target_name(row),reason='[CHECKPOINT] useful spill observation'))
  original=self.service
  def service(script,*args):
   if script=='fnv.ps1' and args[0]=='checkpoint':raise RuntimeError('optional timeout')
   return original(script,*args)
  self.bridge.tick(self.trial,self.status,service,self.finish,lambda:None,None)
  self.assertEqual(self.answer('2'*32)['state'],'optional_unavailable');self.assertFalse(self.bridge.uncertain);self.assertFalse(row.get('done'));self.assertFalse(row.get('released'))
 def test_history_preserves_stale_and_unverified_source(self):
  row=self.claim();self.put(dict(operation='giveup',request_id='2'*32,target_id=B.target_name(row),reason='[HISTORY source cp_a]'))
  original=self.service
  def service(script,*args):return dict(stale=True,source='int f(){}',model='Prior') if args[0]=='function_history' else original(script,*args)
  self.bridge.tick(self.trial,self.status,service,self.finish,lambda:None,None)
  a=self.answer('2'*32);self.assertEqual(a['state'],'history');self.assertTrue(a['result']['stale']);self.assertFalse(row.get('released'))
 def test_optional_operations_share_one_turn_and_normal_claim_gets_first_turn(self):
  row=self.claim()
  for n in range(2,12):self.put(dict(operation='giveup',request_id=f'{n:032x}',target_id=B.target_name(row),reason='[HISTORY brief]'))
  self.put(dict(operation='claim',request_id='e'*32,band='256-511',model='Another',agent_id='web_other'))
  self.tick();self.assertEqual(len(self.trial['rows']),2)
  states=[self.answer(f'{n:032x}')['state'] for n in range(2,12)]
  self.assertLessEqual(sum(s=='history' for s in states),1);self.assertFalse(self.bridge.uncertain)
 def test_flag_explicit_keep_claim_true(self):
  row=self.claim();self.put(dict(operation='flag',request_id='2'*32,target_id=B.target_name(row),category='index_problem',note='wrong span'));self.tick()
  payload=next(json.loads(c[1][-1]) for c in self.calls if c[0]=='fnv.ps1' and c[1][0]=='flag');self.assertTrue(payload['keep_claim']);self.assertEqual(payload['scope'],'function')
 def test_context_preference_never_replaces_active_compiler_context(self):
  row=self.claim();self.put(dict(operation='giveup',request_id='2'*32,target_id=B.target_name(row),agent_id='web_owner',reason='[CONTEXT_MODE resume]'));self.tick()
  self.assertEqual(self.answer('2'*32)['state'],'context_mode_set');self.assertFalse(row.get('released'));self.assertFalse(row.get('done'))
 def test_restarted_optional_with_unknown_target_does_not_block_dispatch(self):
  r=dict(operation='checkpoint',request_id='2'*32,target_id='web_clm_fff',note='observation');self.put(r);B.save(self.bridge.base/'responses'/('2'*32+'.json'),dict(state='executing'))
  self.tick();self.assertFalse(self.bridge.uncertain);self.assertEqual(self.answer('2'*32)['state'],'optional_unavailable');self.assertEqual(len(self.trial['rows']),1)
 def test_damaged_optional_preference_cannot_quarantine_claim_dispatch(self):
  key=B.agent_key(self.req);p=self.root/'local/mcp/context-preferences'/(key+'.json');p.parent.mkdir(parents=True);p.write_text('{')
  self.tick();self.assertFalse(self.bridge.uncertain);self.assertEqual(len(self.trial['rows']),1)
if __name__=='__main__':unittest.main()
