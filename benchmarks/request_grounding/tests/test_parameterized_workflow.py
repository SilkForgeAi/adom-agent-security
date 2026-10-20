import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor'))
from adom.enforcement.workflow_compiler import Compiler,sha,exact_plan
from adom.enforcement.parameterized_workflow import compile_program,ParameterizedCompiler


class ParameterizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.source=self.root/'source';self.source.mkdir()
        (self.source/'seed.py').write_text('def foo(x):\n    return bar(x)\n')
        self.c={'version':1,'task_id':'seed','epoch':0,'sources':{'seed.py':sha((self.source/'seed.py').read_bytes())},
          'requirements':[{'kind':'defines_function','symbol':'foo'},{'kind':'direct_call','symbol':'foo','target':'bar'}],
          'cardinality':'all','artifact':'release.zip','unresolved':[]}
        self.program,self.pin=compile_program(self.source,self.c,exact_plan(['seed.py']))
    def tearDown(self):self.tmp.cleanup()
    def run_program(self):
        self.runner=ParameterizedCompiler(self.source,self.root/'output')
        return self.runner.run_program(self.program,self.pin,self.c)
    def refresh(self):self.c['sources']={p.name:sha(p.read_bytes()) for p in self.source.iterdir()}
    def test_seed_filename_absent_from_ir(self):self.assertNotIn('seed.py',json.dumps(self.program))
    def test_new_filename(self):
        (self.source/'seed.py').rename(self.source/'unseen.py');self.refresh()
        r=self.run_program();self.assertEqual(r['status'],'EXECUTED');self.assertEqual(r['bound_selection'],['unseen.py'])
    def test_new_quantity(self):
        (self.source/'second.py').write_bytes((self.source/'seed.py').read_bytes());self.refresh()
        r=self.run_program();self.assertEqual(r['bound_selection'],['second.py','seed.py'])
    def test_new_valid_output_parameter(self):
        self.c['artifact']='different.zip';self.assertEqual(self.run_program()['status'],'EXECUTED')
    def test_new_source_bytes(self):
        with (self.source/'seed.py').open('a') as f:f.write('# distinct input bytes\n')
        self.refresh();self.assertEqual(self.run_program()['status'],'EXECUTED')
    def test_material_change_requires_recompilation(self):
        self.c['cardinality']='one';self.assertEqual(self.run_program()['status'],'RECOMPILE_REQUIRED')
        self.assertFalse(list(self.runner.engine.output.iterdir()))
    def test_recompiled_program_works(self):
        self.c['cardinality']='one';p,pin=compile_program(self.source,self.c,exact_plan(['seed.py']))
        runner=ParameterizedCompiler(self.source,self.root/'new-output');self.assertEqual(runner.run_program(p,pin,self.c)['status'],'EXECUTED')
        self.assertNotEqual(pin,self.pin)
    def test_stale_hash(self):
        (self.source/'seed.py').write_text('def other(): pass\n')
        self.assertEqual(self.run_program()['status'],'REVIEW_REQUIRED')
    def test_fresh_hash_but_missing_obligation(self):
        (self.source/'seed.py').write_text('def other(): pass\n');self.refresh()
        self.assertEqual(self.run_program()['status'],'REVIEW_REQUIRED')
    def test_unresolved(self):
        self.c['unresolved']=['choose the best files'];self.assertEqual(self.run_program()['status'],'REVIEW_REQUIRED')
    def test_corrupt_program(self):
        self.program['nodes'][-1]['needs']=[];self.assertEqual(self.run_program()['status'],'DENIED')
    def test_literal_path_injection(self):
        next(n for n in self.program['nodes'] if n['op']=='select')['paths']=['seed.py']
        self.assertEqual(self.run_program()['status'],'DENIED')
    def test_stale_epoch(self):
        self.c['epoch']=1;self.assertEqual(self.run_program()['status'],'DENIED')
    def test_revoked_runner(self):
        self.runner=ParameterizedCompiler(self.source,self.root/'output');self.runner.revoke()
        self.assertEqual(self.runner.run_program(self.program,self.pin,self.c)['status'],'DENIED')
    def test_nested_relative_filename_unsupported(self):
        self.c['sources']={'nested/seed.py':next(iter(self.c['sources'].values()))}
        self.assertEqual(self.run_program()['status'],'DENIED')
    def test_bad_destination(self):
        self.c['artifact']='../out.zip';self.assertEqual(self.run_program()['status'],'DENIED')
    def test_existing_literal_plan_cannot_handle_renaming(self):
        old=Compiler(self.source,self.root/'old-output');old.run(self.c,exact_plan(['seed.py']))
        (self.source/'seed.py').rename(self.source/'unseen.py');self.refresh();self.c['task_id']='new'
        self.assertEqual(old.run(self.c)['status'],'DENIED')

if __name__=='__main__':unittest.main()
