import ast
import asyncio
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def module(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/'scripts'/(name+'.py'))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

class PackageTests(unittest.TestCase):
    def test_all_python_syntax(self):
        for path in (ROOT/'scripts').glob('*.py'): ast.parse(path.read_text(encoding='utf-8'),filename=str(path))

    def test_source_attribution_bound_to_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            candidate=Path(folder)/'candidate.cpp';candidate.write_text('int sample(){return 1;}')
            resolver=module('submission-attribution')
            with self.assertRaises(ValueError):resolver.resolve(candidate)
            value=resolver.resolve(candidate,model='Synthetic test author')
            candidate.with_suffix('.cpp.provenance.json').write_text(json.dumps(value))
            self.assertEqual(resolver.resolve(candidate)['source_sha256'],value['source_sha256'])
            candidate.write_text('int sample(){return 2;}')
            with self.assertRaises(ValueError):resolver.resolve(candidate)

    def test_safe_archive_roundtrip(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);archive=base/'pack.tar.gz';out=base/'out';out.mkdir()
            with tarfile.open(archive,'w:gz') as stream:
                info=tarfile.TarInfo('pack.json');data=b'{"synthetic":true}';info.size=len(data);stream.addfile(info,io.BytesIO(data))
            module('safe-extract').extract(archive,out)
            self.assertTrue(json.loads((out/'pack.json').read_text())['synthetic'])

    def test_archive_rejects_escape_and_links(self):
        for name,kind in [('../escape',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),('link',tarfile.SYMTYPE)]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as folder:
                base=Path(folder);archive=base/'pack.tar.gz';out=base/'out';out.mkdir()
                with tarfile.open(archive,'w:gz') as stream:
                    info=tarfile.TarInfo(name);info.type=kind;info.linkname='../escape';stream.addfile(info)
                with self.assertRaises(ValueError):module('safe-extract').extract(archive,out)
                self.assertFalse((base/'escape').exists())

    def test_cpu_pattern_from_synthetic_instructions(self):
        import capstone
        decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);decoder.detail=True
        # Synthetic nested scalar getter, not bytes from any game executable.
        code=list(decoder.disasm(bytes.fromhex('8b018b00c3'),0))
        result=module('cpu-template-worker').scalar_memory_templates(code,'SyntheticGetter',0)
        self.assertEqual(result[0][0],'nested_scalar_member_getter')
        self.assertIn('return value->value;',result[0][1])

    def test_unsupported_cpu_pattern_is_not_match(self):
        import capstone
        decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);decoder.detail=True
        code=list(decoder.disasm(bytes.fromhex('90c3'),0))
        self.assertEqual(module('cpu-template-worker').scalar_memory_templates(code,'SyntheticUnsupported',0),[])

    def test_no_private_historical_targets(self):
        self.assertEqual(module('fnv-mcp-server').TARGETS,{})

    def test_missing_optional_ghidra_preserves_cpu_evidence(self):
        from types import SimpleNamespace
        bridge_module=module('mcp-live-bridge')
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);pack=base/'work/synthetic';pack.mkdir(parents=True);(pack/'pack.json').write_text('{}')
            ghidra=SimpleNamespace(discover=lambda:dict(ready=False),prepare=lambda *a,**kw:self.fail('Missing Ghidra must not start'))
            helpers=SimpleNamespace(cpu_prepare=lambda p:dict(outcome='unsupported'),load=lambda name:ghidra)
            prep=SimpleNamespace(prepare=lambda p,h:dict(cpu=h.cpu_prepare(p),ghidra=h.add_ghidra(p)))
            value=bridge_module.Bridge(base).prepare_owned(dict(pack=str(pack)),SimpleNamespace(helpers=helpers,module=prep))
            self.assertEqual(value['cpu']['outcome'],'unsupported')
            self.assertEqual(value['ghidra']['outcome'],'unavailable')
            self.assertFalse(value.get('preparation_refused'))

    def test_windows_powershell_syntax(self):
        if os.name!='nt':self.skipTest('Windows PowerShell parser')
        command="$bad=@(); Get-ChildItem scripts -File -Filter *.ps1 | ForEach-Object {$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors);if($errors){$bad+=$_.Name}};if($bad){$bad;exit 1}"
        result=subprocess.run(['powershell.exe','-NoProfile','-Command',command],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_stdio_mcp_discovery_and_status_without_service(self):
        from mcp import ClientSession,StdioServerParameters
        from mcp.client.stdio import stdio_client
        async def check():
            params=StdioServerParameters(command=sys.executable,args=[str(ROOT/'scripts/fnv-mcp-server.py')])
            async with stdio_client(params) as (reader,writer):
                async with ClientSession(reader,writer) as session:
                    await session.initialize()
                    tools=await session.list_tools()
                    names={t.name for t in tools.tools}
                    self.assertTrue({'request_function','get_work_status','check_candidate','submit_function','give_up_function'}.issubset(names))
                    result=await session.call_tool('get_work_status',{})
                    self.assertFalse(result.isError)
        asyncio.run(asyncio.wait_for(check(),timeout=25))

    def test_clean_checkout_is_not_ready_without_private_inputs(self):
        result=subprocess.run([sys.executable,str(ROOT/'scripts/coordinator.py'),'--check'],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(result.returncode,1)
        data=json.loads(result.stdout);self.assertFalse(data['ready']);self.assertEqual(data['service_calls'],0)

    def test_standalone_coordinator_tick_and_uncertain_submit_is_not_replayed(self):
        if os.name!='nt': self.skipTest('Windows writer lock')
        from types import SimpleNamespace
        for lost_submit in (False,True):
            with self.subTest(lost_submit=lost_submit),tempfile.TemporaryDirectory() as folder:
                base=Path(folder);(base/'local').mkdir();(base/'local/submissions.json').write_text('[]')
                coord=module('coordinator');coord.ROOT=base;coord.QUEUE=base/'local/benchmark/coordinator'
                calls=[];saves=[]
                status=dict(open_claims=[],limits=dict(claims=2),submissions_paused=False)
                def ps(script,*args):
                    calls.append((script,args))
                    if script=='submit-match.ps1':raise RuntimeError('Synthetic lost response')
                    return status
                class FakeBridge:
                    uncertain=False
                    def __init__(self,root):self.base=root/'local/mcp/live'
                    def tick(self,trial,status,service,finish,save_trial,loader,stopping=False):
                        if not trial['rows']:
                            row=dict(claim_id='synthetic',pack=str(base/'work/synthetic'),done=not lost_submit)
                            trial['rows'].append(row)
                            if lost_submit:finish(row,dict(outcome='match',candidate='synthetic.cpp',model='Synthetic test'))
                        (base/'local/stop.request').write_text('test stop');save_trial()
                helper=SimpleNamespace(ps=ps)
                cp=SimpleNamespace(checkpoint=lambda path,trial:saves.append(json.loads(json.dumps(trial))))
                bridge=SimpleNamespace(Bridge=FakeBridge,save=lambda *args:None)
                def load(name,*args):return {'cpu-priority-trial':helper,'coordinator-json':cp,'mcp-live-bridge':bridge}[name]
                with patch.object(coord,'load',load),patch.object(coord.time,'sleep',lambda _:None):coord.run()
                self.assertTrue(saves)
                self.assertEqual(sum(name=='submit-match.ps1' for name,args in calls),int(lost_submit))
                if lost_submit:self.assertEqual(saves[-1]['rows'][0]['finalization_error'],'RuntimeError')

if __name__=='__main__': unittest.main()
