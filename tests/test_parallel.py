"""Concurrency isolation of the MCP compiler scheduler; no service/compiler calls."""
import asyncio,importlib.util,threading,time,unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
S=importlib.util.spec_from_file_location('mcp_parallel_server',Path(__file__).resolve().parents[1]/'scripts/fnv-mcp-server.py')
M=importlib.util.module_from_spec(S);S.loader.exec_module(M)
class Checks(unittest.TestCase):
 def test_saturated_default_executor_cannot_starve_status(self):
  release=threading.Event()
  async def check():
   loop=asyncio.get_running_loop();pool=ThreadPoolExecutor(max_workers=1)
   loop.set_default_executor(pool)
   busy=asyncio.create_task(asyncio.to_thread(release.wait,3))
   try:
    await asyncio.sleep(.03)
    await asyncio.wait_for(M.mcp._tool_manager.call_tool('get_work_status',{}),.5)
   finally:release.set();await busy
  asyncio.run(check())
 def test_list_targets_uses_only_active_catalog(self):
  import tempfile,json
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as folder:
   base=Path(folder);(base/'targets').mkdir()
   name='web_clm_abcd'
   (base/'active-targets.json').write_text(json.dumps({'targets':[name]}))
   (base/'targets'/(name+'.json')).write_text(json.dumps({'target_id':name,'state':'working'}))
   with patch.object(M.live,'BASE',base),patch.object(Path,'glob',side_effect=AssertionError('No archive enumeration')):
    result=M.list_targets()
   self.assertIn(name,result['targets'])
 def test_forty_queued_checks_leave_status_responsive(self):
  release=threading.Event();state={'active':0,'peak':0};lock=threading.Lock()
  @M.background_tool(name='load_test_check')
  def check_candidate(target_id:str)->dict:
   with lock:state['active']+=1;state['peak']=max(state['peak'],state['active'])
   release.wait(3)
   with lock:state['active']-=1
   return {'ok':True}
  async def check():
   tasks=[asyncio.create_task(M.mcp._tool_manager.call_tool('load_test_check',{'target_id':str(n)})) for n in range(40)]
   try:
    for _ in range(100):
     if state['peak']==8:break
     await asyncio.sleep(.01)
    self.assertEqual(state['peak'],8)
    await asyncio.wait_for(M.mcp._tool_manager.call_tool('get_work_status',{}),.5)
   finally:release.set();await asyncio.gather(*tasks)
  asyncio.run(check());self.assertLessEqual(state['peak'],8)
 def test_sdk_slow_tool_does_not_block_status(self):
  started=threading.Event();release=threading.Event()
  @M.background_tool()
  def slow_test_tool()->dict:
   started.set();release.wait(3);return {'ok':True}
  async def check():
   slow=asyncio.create_task(M.mcp._tool_manager.call_tool('slow_test_tool',{}))
   try:
    for _ in range(100):
     if started.is_set():break
     await asyncio.sleep(.01)
    self.assertTrue(started.is_set())
    self.assertFalse(slow.done())
    await asyncio.wait_for(M.mcp._tool_manager.call_tool('get_work_status',{}),.5)
    self.assertFalse(slow.done())
   finally:
    release.set();await slow
  asyncio.run(check())
 def test_separate_targets_parallel_bounded(self):
  state={'active':0,'peak':0};lock=threading.Lock()
  def job(n):
   with M.checking('target_'+str(n)):
    with lock:state['active']+=1;state['peak']=max(state['peak'],state['active'])
    time.sleep(.03)
    with lock:state['active']-=1
  with ThreadPoolExecutor(max_workers=20) as pool:list(pool.map(job,range(20)))
  self.assertGreater(state['peak'],1);self.assertLessEqual(state['peak'],8)
 def test_same_target_serial(self):
  state={'active':0,'peak':0};lock=threading.Lock()
  def job(n):
   with M.checking('same_target'):
    with lock:state['active']+=1;state['peak']=max(state['peak'],state['active'])
    time.sleep(.01)
    with lock:state['active']-=1
  with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(job,range(8)))
  self.assertEqual(state['peak'],1)
if __name__=='__main__':unittest.main()
