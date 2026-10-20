import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor'))
from adom.enforcement.workflow_compiler import sha
from adom.enforcement.request_grounding import ground,GroundedExecutor


class GroundingDevelopmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.source=self.root/'source';self.source.mkdir()
        (self.source/'dev.py').write_text('class Sample:\n    pass\ndef check(x):\n    return snapshot(x)\n')
        self.context={'request_id':'dev-001','authority':{'epoch':0,'ops':['release_bundle'],'read_paths':['dev.py'],
          'artifacts':['release.zip','second.zip']},'resources':{'dev.py':{'sha256':sha((self.source/'dev.py').read_bytes())}}}
        self.req='Build a release package from ["dev.py"], selecting all files that define class Sample, as "release.zip".'
        self.engine=GroundedExecutor(self.source,self.root/'out')
    def tearDown(self):self.tmp.cleanup()
    def test_derive_contract_without_label(self):
        r=ground(self.req,self.context);self.assertEqual(r['route'],'GROUNDED')
        self.assertEqual(r['contract']['requirements'],[{'kind':'defines_class','symbol':'Sample'}]);self.assertTrue(r['parse_trace']['whole_request_matched'])
    def test_form_two(self):
        self.assertEqual(ground('Package all files that define class Sample from ["dev.py"] into "release.zip" as a release evidence bundle.',self.context)['route'],'GROUNDED')
    def test_form_three(self):
        self.assertEqual(ground('Using ["dev.py"], create a release evidence bundle for all files that define class Sample and save it as "release.zip".',self.context)['route'],'GROUNDED')
    def test_case_sensitive_identifier(self):
        r=ground(self.req.replace('Sample','sample'),self.context);self.assertEqual(r['contract']['requirements'][0]['symbol'],'sample')
        result=self.engine.handle(self.req.replace('Sample','sample'),self.context);self.assertEqual(result['route'],'REVIEW_REQUIRED')
    def test_backtick_symbol(self):
        self.assertEqual(ground(self.req.replace('Sample','`Sample`'),self.context)['route'],'GROUNDED')
    def test_unbalanced_backtick(self):
        self.assertEqual(ground(self.req.replace('Sample','`Sample'),self.context)['route'],'MODEL_REQUIRED')
    def test_extra_deliverable_not_dropped(self):
        r=self.engine.handle(self.req+' Also email the result.',self.context)
        self.assertEqual(r['route'],'MODEL_REQUIRED');self.assertFalse(list(self.engine.runtime.engine.output.iterdir()))
    def test_condition_not_dropped(self):
        self.assertEqual(ground(self.req.replace(', as',', but only if the code is secure, as'),self.context)['route'],'MODEL_REQUIRED')
    def test_negation_not_dropped(self):
        self.assertEqual(ground(self.req.replace('define class','do not define class'),self.context)['route'],'MODEL_REQUIRED')
    def test_exception_not_dropped(self):
        self.assertEqual(ground(self.req.replace(', as',', except the safest file, as'),self.context)['route'],'MODEL_REQUIRED')
    def test_missing_parameters(self):
        self.assertEqual(ground('Build a release package.',self.context)['route'],'CLARIFY')
    def test_duplicate_sources(self):
        self.assertEqual(ground(self.req.replace('["dev.py"]','["dev.py", "dev.py"]'),self.context)['route'],'CLARIFY')
    def test_unknown_source_denied(self):
        self.assertEqual(ground(self.req.replace('dev.py','private.env'),self.context)['route'],'DENY')
    def test_unknown_destination_denied(self):
        self.assertEqual(ground(self.req.replace('release.zip','other.zip'),self.context)['route'],'DENY')
    def test_missing_authority_denied(self):
        self.context['authority']['ops']=[];self.assertEqual(ground(self.req,self.context)['route'],'DENY')
    def test_gold_labels_not_accepted(self):
        self.context['gold']='GROUNDED';self.assertEqual(ground(self.req,self.context)['route'],'DENY')
    def test_conjunction_is_not_partial(self):
        r=ground(self.req.replace('define class Sample','define function check and where function check directly calls snapshot'),self.context)
        self.assertEqual(len(r['contract']['requirements']),2)
    def test_conjunction_order_same_contract(self):
        a='define function check and where function check directly calls snapshot'
        b='where function check directly calls snapshot and define function check'
        x=ground(self.req.replace('define class Sample',a),self.context)
        y=ground(self.req.replace('define class Sample',b),self.context)
        self.assertEqual(x['contract'],y['contract'])
    def test_complete_pipeline(self):
        r=self.engine.handle(self.req,self.context);self.assertEqual(r['execution']['status'],'EXECUTED')
        with zipfile.ZipFile(self.engine.runtime.engine.output/r['execution']['receipt']['artifact']) as z:
            self.assertEqual(json.loads(z.read('manifest.json'))['files'][0]['path'],'dev.py')
    def test_reuse_with_new_identity_and_output(self):
        r=self.engine.handle(self.req,self.context);self.assertTrue(r['compiled_new_program'])
        c=copy.deepcopy(self.context);c['request_id']='dev-002'
        r2=self.engine.handle(self.req.replace('release.zip','second.zip'),c)
        self.assertFalse(r2['compiled_new_program']);self.assertEqual(r['program_sha256'],r2['program_sha256'])
    def test_revocation(self):
        self.engine.revoke();self.assertEqual(self.engine.handle(self.req,self.context)['route'],'DENY')
        self.assertFalse(list(self.engine.runtime.engine.output.iterdir()))
    def test_source_mutation_before_effect(self):
        (self.source/'dev.py').write_text('class Other:pass\n')
        r=self.engine.handle(self.req,self.context);self.assertEqual(r['route'],'REVIEW_REQUIRED')
        self.assertFalse(list(self.engine.runtime.engine.output.iterdir()))

if __name__=='__main__':unittest.main()
