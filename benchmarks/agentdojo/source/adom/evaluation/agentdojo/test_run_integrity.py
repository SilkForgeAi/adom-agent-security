import copy,unittest
from adom.evaluation.agentdojo.run_integrity import digest,validate_freeze,validate_utility,validate_gate
class IntegrityTests(unittest.TestCase):
 def setUp(self):
  self.f={'adapter_code_sha256':'code','agentdojo_version':'pkg','benchmark_version':'bench'};self.f['freeze_sha256']=digest(self.f)
  self.u={c:{'freeze_sha256':self.f['freeze_sha256'],'model':'m','tasks':{'t':True},'passed':1,'total':1,'rate':1.0} for c in ['adom','baseline']}
  self.g={'freeze_sha256':self.f['freeze_sha256'],'utility_sha256':digest(self.u),'passed':True,'drop':0,'max_drop':.1}
 def test_valid(self):validate_freeze(self.f,'code','pkg','bench');validate_gate(self.g,self.u,self.f['freeze_sha256'],'m',.1)
 def test_code_change(self):
  with self.assertRaises(ValueError):validate_freeze(self.f,'new','pkg','bench')
 def test_forged_freeze(self):
  self.f['agentdojo_version']='other'
  with self.assertRaises(ValueError):validate_freeze(self.f,'code','other','bench')
 def test_utility_changed(self):
  self.u['adom']['tasks']['t']=False;self.u['adom'].update(passed=0,rate=0)
  with self.assertRaises(ValueError):validate_gate(self.g,self.u,self.f['freeze_sha256'],'m',.1)
 def test_task_set_changed(self):
  self.u['adom']['tasks']={'other':True}
  with self.assertRaises(ValueError):validate_utility(self.u,self.f['freeze_sha256'],'m')
 def test_legacy_no_provenance(self):
  del self.u['baseline']['freeze_sha256']
  with self.assertRaises(ValueError):validate_utility(self.u,self.f['freeze_sha256'],'m')
if __name__=='__main__':unittest.main()
