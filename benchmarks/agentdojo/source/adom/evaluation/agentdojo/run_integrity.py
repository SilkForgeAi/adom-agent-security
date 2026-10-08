"""Reject stale benchmark freezes and gates before model calls."""
import hashlib,json

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()
def validate_freeze(record,code_hash,package_version,benchmark_version):
 body={k:v for k,v in record.items() if k!='freeze_sha256'}
 if record.get('freeze_sha256')!=digest(body):raise ValueError('freeze digest mismatch')
 if record.get('adapter_code_sha256')!=code_hash:raise ValueError('adapter changed; create a fresh run directory')
 if record.get('agentdojo_version')!=package_version:raise ValueError('AgentDojo package changed')
 if record.get('benchmark_version')!=benchmark_version:raise ValueError('benchmark changed')
 return record

def validate_utility(data,freeze_sha,model):
 sets=[]
 for condition in ('adom','baseline'):
  r=data[condition]
  if r.get('freeze_sha256')!=freeze_sha or r.get('model')!=model:raise ValueError('utility provenance mismatch')
  tasks=r['tasks']
  if not tasks or any(type(v) is not bool for v in tasks.values()):raise ValueError('invalid utility records')
  if r['total']!=len(tasks) or r['passed']!=sum(tasks.values()) or abs(r['rate']-sum(tasks.values())/len(tasks))>1e-12:raise ValueError('utility summary mismatch')
  sets.append(set(tasks))
 if sets[0]!=sets[1]:raise ValueError('utility task sets differ')

def validate_gate(gate,utility,freeze_sha,model,max_drop):
 validate_utility(utility,freeze_sha,model)
 if gate.get('freeze_sha256')!=freeze_sha or gate.get('utility_sha256')!=digest(utility):raise ValueError('stale utility gate')
 drop=utility['baseline']['rate']-utility['adom']['rate']
 if gate.get('passed') is not True or gate.get('max_drop')!=max_drop or abs(gate.get('drop',999)-drop)>1e-12 or drop>max_drop:raise ValueError('utility gate has not passed')
