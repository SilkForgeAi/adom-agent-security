"""Read-only evidence audit after the frozen live campaign. No API calls."""
import json,zipfile,statistics
from pathlib import Path
import campaign as c
from adom.enforcement.request_grounding import ground
from api_client import estimated_cost
P=c.P
c.frozen()
rows=json.loads((P/'results.json').read_text());cases={x['id']:x for x in json.loads((P/'requests.json').read_text())};gold=json.loads((P/'gold.json').read_text())
assert len(rows)==48 and len({(r['id'],r['arm']) for r in rows})==48
usage={a:{'prompt_tokens':0,'cached_tokens':0,'completion_tokens':0,'uncached_cost_usd':0} for a in ['always_model','adom']}
verified=0;exact_semantic_mismatches=[];models=set();failures=[]
for r in rows:
 folder=P/'raw'/r['id']/r['arm'];g=gold[r['id']];result=r['result']
 assert c.verify(folder/'artifacts',result,g)==r['correct']
 if r['actual_artifacts']:
  for name in r['actual_artifacts']:
   artifact=P/r['arm']/name;assert artifact.read_bytes()==(folder/'artifacts'/name).read_bytes()
   assert c.sha(artifact.read_bytes())==result['receipt']['sha256'];verified+=1
   with zipfile.ZipFile(artifact) as z:
    ev=json.loads(z.read('evidence.json'))
    assert all(c.sha((P/'inputs'/n).read_bytes())==h for n,h in ev['source_pins'].items())
 if r['api_calls']:
  resp=json.loads((folder/'response-00.json').read_text());u=resp['usage'];models.add(resp['model'])
  assert abs(estimated_cost(u)-r['cost_usd'])<1e-10
  if g['family']!='control':
   a=usage[r['arm']];a['prompt_tokens']+=u['prompt_tokens'];a['cached_tokens']+=u.get('prompt_tokens_details',{}).get('cached_tokens',0);a['completion_tokens']+=u['completion_tokens'];a['uncached_cost_usd']+=(u['prompt_tokens']*5+u['completion_tokens']*30)/1e6
  if g['family']=='exact' and result.get('status')=='EXECUTED':
   v=json.loads(resp['choices'][0]['message']['content']);expected=ground(cases[r['id']]['request'],cases[r['id']]['context'])['contract']
   req=[{k:x for k,x in t.items() if k!='target' or t['kind']=='direct_call'} for t in v['requirements']]
   if sorted(req,key=lambda x:json.dumps(x,sort_keys=True))!=expected['requirements'] or v['cardinality']!=expected['cardinality'] or set(v['sources'])!=set(expected['sources']) or v['artifact']!=expected['artifact']:exact_semantic_mismatches.append(r['id'])
 if not r['correct']:failures.append({'id':r['id'],'arm':r['arm'],'result':result})
assert len(list((P/'adom').glob('*.zip')))+len(list((P/'always_model').glob('*.zip')))==verified==40
spend=json.loads((P/'spend.json').read_text());assert abs(spend['accounted_usd']-c.PRIOR-sum(r['cost_usd'] for r in rows))<1e-9
out={'verified_artifacts':verified,'api_responses':sum(r['api_calls'] for r in rows),'returned_models':sorted(models),'legitimate_usage':usage,'uncached_cost_savings':1-usage['adom']['uncached_cost_usd']/usage['always_model']['uncached_cost_usd'],'exact_model_contract_mismatches':exact_semantic_mismatches,'failures':failures,'combined_spend_usd':spend['accounted_usd'],'new_spend_usd':spend['accounted_usd']-c.PRIOR}
c.write(P/'verification.json',out);print(json.dumps(out,indent=2))
