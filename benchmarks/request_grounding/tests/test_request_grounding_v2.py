import copy
from test_request_grounding import GroundingDevelopmentTests
from adom.enforcement.request_grounding import ground

class V2Tests(GroundingDevelopmentTests):
    def forms(self):
        return ['Gather a release evidence bundle of all modules in ["dev.py"] that define class Sample; put it in "release.zip".', 'I need a release evidence bundle named "release.zip" containing all files from ["dev.py"] that define class Sample.']
    def test_new_contracts(self):
        for text in self.forms():
            self.assertEqual(ground(text,self.context)['contract'],ground(self.req,self.context)['contract'])
    def test_material_clauses(self):
        for text in self.forms():
            for altered in [text+' Also email it.',text.replace('define class Sample','do not define class Sample'),text.replace('define class Sample','define class Sample and determine whether it is secure'),text+' Only if production ready.']:
                with self.subTest(text=altered):self.assertEqual(self.engine.handle(altered,self.context)['route'],'MODEL_REQUIRED')
        self.assertFalse(list(self.engine.runtime.engine.output.iterdir()))
    def test_new_authority(self):
        for text in self.forms():
            for altered in [text.replace('dev.py','private.env'),text.replace('release.zip','forbidden.zip')]:
                self.assertEqual(ground(altered,self.context)['route'],'DENY')
    def test_missing_destination(self):
        self.assertEqual(ground(self.req.replace(', as "release.zip"',''),self.context)['route'],'CLARIFY')
    def test_incomplete_reasoning(self):
        text=self.req.replace(', as "release.zip"','').replace('define class Sample','are safe for production')
        self.assertEqual(ground(text,self.context)['route'],'MODEL_REQUIRED')
    def test_effect_and_reuse(self):
        first=self.engine.handle(self.forms()[0],self.context)
        self.assertEqual(first['execution']['status'],'EXECUTED')
        other=copy.deepcopy(self.context);other['request_id']='new-form-2'
        second=self.engine.handle(self.forms()[1],other)
        self.assertEqual(second['execution']['status'],'EXECUTED')
        self.assertFalse(second['compiled_new_program'])
