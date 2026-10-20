import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor'))
from adom.enforcement.workflow_compiler import Compiler,sha,exact_plan,compile_bundle,inspect_sources,validate_contract,select_evidence


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.source=self.root/'source';self.source.mkdir()
        (self.source/'implementation.py').write_text('def check(x):\n    return snapshot(x)\n')
        (self.source/'caller.py').write_text('from implementation import check\ndef invoke(x):\n    return check(x)\n')
        self.contract={'version':1,'task_id':'release-001','epoch':0,
          'sources':{p.name:sha(p.read_bytes()) for p in self.source.iterdir()},
          'requirements':[{'kind':'defines_function','symbol':'check'},{'kind':'direct_call','symbol':'check','target':'snapshot'}],
          'cardinality':'one','artifact':'release.zip','unresolved':[]}
        self.plan=exact_plan(['implementation.py'])
        self.engine=Compiler(self.source,self.root/'output')

    def tearDown(self):self.temp.cleanup()

    def assert_no_effect(self):self.assertEqual(list(self.engine.output.iterdir()),[])

    def test_legitimate_bundle(self):
        result=self.engine.run(self.contract,self.plan)
        self.assertEqual(result['status'],'EXECUTED',result)
        with zipfile.ZipFile(self.engine.output/result['receipt']['artifact']) as z:
            self.assertEqual(z.namelist(),['evidence.json','manifest.json','sources.zip'])
            m=json.loads(z.read('manifest.json'));self.assertEqual(m['files'][0]['path'],'implementation.py')
            with zipfile.ZipFile(io.BytesIO(z.read('sources.zip'))) as src:
                self.assertEqual(src.read('implementation.py'),(self.source/'implementation.py').read_bytes())

    def test_import_is_not_definition(self):
        p=exact_plan(['caller.py']);self.assertEqual(self.engine.run(self.contract,p)['status'],'DENIED');self.assert_no_effect()

    def test_missing_selected_file(self):
        self.plan['nodes'][1]['paths']=[]
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'DENIED');self.assert_no_effect()

    def test_extra_selected_file(self):
        self.plan['nodes'][1]['paths']=['caller.py','implementation.py']
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'DENIED');self.assert_no_effect()

    def test_dependency_skip(self):
        self.plan['nodes'][-1]['needs']=['select']
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'DENIED');self.assert_no_effect()

    def test_omit_evidence(self):
        self.plan['nodes']=[n for n in self.plan['nodes'] if n['op']!='evidence']
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'DENIED');self.assert_no_effect()

    def test_extra_operation(self):
        self.plan['nodes'].append({'id':'other','op':'upload','needs':[],'paths':[]})
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'DENIED');self.assert_no_effect()

    def test_cycle(self):
        self.plan['nodes'][0]['needs']=['publish']
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'DENIED');self.assert_no_effect()

    def test_same_op_repeated(self):
        self.plan['nodes'][-1]['op']='manifest'
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'DENIED');self.assert_no_effect()

    def test_changed_source(self):
        (self.source/'implementation.py').write_text('def other():pass\n')
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'REVIEW_REQUIRED');self.assert_no_effect()

    def test_unresolved_semantics(self):
        self.contract['unresolved']=['decide if code is safe']
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'REVIEW_REQUIRED');self.assert_no_effect()

    def test_unsupported_obligation(self):
        self.contract['requirements']=[{'kind':'detect_deception','symbol':'check'}]
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'REVIEW_REQUIRED');self.assert_no_effect()

    def test_revocation(self):
        self.engine.revoke()
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'DENIED');self.assert_no_effect()

    def test_stale_epoch(self):
        self.contract['epoch']=1
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'DENIED');self.assert_no_effect()

    def test_replay(self):
        a=self.engine.run(self.contract,self.plan);b=self.engine.run(self.contract,self.plan)
        self.assertEqual(a['status'],'EXECUTED');self.assertTrue(b['receipt']['replay']);self.assertEqual(len(self.engine.effects),1)

    def test_revocation_denies_cached_success(self):
        self.engine.run(self.contract,self.plan);self.engine.revoke()
        self.assertEqual(self.engine.run(self.contract)['status'],'DENIED');self.assertEqual(len(self.engine.effects),1)

    def test_cache_revalidates_changed_input_set(self):
        self.engine.run(self.contract,self.plan)
        (self.source/'unrelated.py').write_text('def unrelated():pass\n')
        self.contract['task_id']='release-002';self.contract['sources']['unrelated.py']=sha((self.source/'unrelated.py').read_bytes())
        r=self.engine.run(self.contract)
        self.assertEqual(r['status'],'EXECUTED');self.assertTrue(r['cache_hit'])

    def test_cache_does_not_reuse_selection_after_semantic_change(self):
        self.engine.run(self.contract,self.plan)
        (self.source/'implementation.py').write_text('def other():pass\n')
        (self.source/'caller.py').write_text('def check(x):\n    return snapshot(x)\n')
        self.contract.update(task_id='release-002',sources={p.name:sha(p.read_bytes()) for p in self.source.iterdir()})
        self.assertEqual(self.engine.run(self.contract)['status'],'DENIED');self.assertEqual(len(self.engine.effects),1)

    def test_nested_call_not_outer_function_evidence(self):
        (self.source/'implementation.py').write_text('def check(x):\n    def nested():\n        return snapshot(x)\n    return x\n')
        self.contract['sources']['implementation.py']=sha((self.source/'implementation.py').read_bytes())
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'REVIEW_REQUIRED');self.assert_no_effect()

    def test_symlink_input(self):
        (self.source/'implementation.py').unlink();(self.source/'implementation.py').symlink_to(self.source/'caller.py')
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'REVIEW_REQUIRED');self.assert_no_effect()

    def test_wrong_existing_output_preserved(self):
        p=self.engine.output/'release-001-release.zip';p.write_bytes(b'preserve')
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'UNKNOWN');self.assertEqual(p.read_bytes(),b'preserve')

    def test_node_order_need_not_be_literal(self):
        self.plan['nodes'].reverse()
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'EXECUTED')

    def test_traversal_contract(self):
        self.contract['artifact']='../release.zip'
        self.assertEqual(self.engine.run(self.contract,self.plan)['status'],'DENIED');self.assert_no_effect()

if __name__=='__main__':unittest.main()
