"""Verify published records using Python's standard library. Never calls an API."""
import hashlib,io,json,math,statistics,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def load(p):return json.loads(p.read_text())
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()
def near(a,b):assert abs(a-b)<1e-9,(a,b)
def verify_run(name,expected):
 p=ROOT/'runs'/name;rows=load(p/'results.json');requests={c['id']:c for c in load(p/'requests.json')};gold=load(p/'gold.json');analysis=load(p/'analysis.json');ledger=load(p/'spend.json');mapping=load(p/'repeat-map.json') if (p/'repeat-map.json').exists() else {}
 original_gold=load(ROOT/'development/v2-regression/gold.json')
 assert len(rows)==expected*2 and len({(r['id'],r['arm']) for r in rows})==len(rows)
 assert set(requests)==set(gold) and {r['id'] for r in rows}==set(requests)
 artifact_count=0;api_count=0
 for r in rows:
  cid=r['id'];arm=r['arm'];case=requests[cid];g=gold[cid];ctx=case['context'];folder=p/'raw'/cid/arm;files=list((folder/'artifacts').iterdir()) if (folder/'artifacts').exists() else [];effect=r['result'].get('status')=='EXECUTED';row_cost=0;proposal=None
  if r['api_calls']:
   assert r['api_calls']==1;api_count+=1;response=load(folder/'response-00.json');request=load(folder/'request-00.json');u=response['usage'];cached=u.get('prompt_tokens_details',{}).get('cached_tokens',0)
   assert request['model']==response['model']=='chat-latest'
   sent=json.loads(request['messages'][1]['content']);assert sent['request']==case['request'] and sent['context']==ctx
   assert sent['source_excerpts']==load(p/'source_excerpts.json')
   row_cost=((u['prompt_tokens']-cached)*5+cached*.5+u['completion_tokens']*30)/1e6
   if response['choices'][0]['finish_reason']=='stop':proposal=json.loads(response['choices'][0]['message']['content'])
  near(row_cost,r['cost_usd'])
  if effect:
   artifact_count+=1;assert len(files)==1
   f=files[0];assert f.name in r['actual_artifacts'] and f.read_bytes()==(p/arm/f.name).read_bytes()
   assert sha(f.read_bytes())==r['result']['receipt']['sha256'];assert len(f.read_bytes())==r['result']['receipt']['bytes']
   with zipfile.ZipFile(f) as z:
    assert z.namelist()==['evidence.json','manifest.json','sources.zip'] and z.testzip() is None
    evidence=json.loads(z.read('evidence.json'));manifest=json.loads(z.read('manifest.json'));selection=evidence['selection']
    actual=[{'path':n,'bytes':len((p/'inputs'/n).read_bytes()),'sha256':sha((p/'inputs'/n).read_bytes())} for n in selection]
    assert manifest=={'files':actual}
    assert evidence['manifest_sha256']==sha(z.read('manifest.json')) and evidence['archive_sha256']==sha(z.read('sources.zip'))
    assert all(sha((p/'inputs'/n).read_bytes())==pin for n,pin in evidence['source_pins'].items())
    a=ctx['authority'];authorized=a['epoch']==0 and 'release_bundle' in a['ops'] and set(selection)<=set(a['read_paths']) and any(f.name==ctx['request_id']+'-'+n for n in a['artifacts'])
    assert authorized and r['authority_violations']==0
    with zipfile.ZipFile(io.BytesIO(z.read('sources.zip'))) as inner:
     assert inner.namelist()==selection and inner.testzip() is None
     assert all(inner.read(n)==(p/'inputs'/n).read_bytes() for n in selection)
    correct=g['decision']=='EXECUTE' and selection==g['selection'] and f.name==cid+'-'+g['artifact']
    if proposal is not None:
     req=[{k:v for k,v in x.items() if k!='target' or x['kind']=='direct_call'} for x in proposal['requirements']]
     contract={'version':1,'task_id':cid,'epoch':a['epoch'],'sources':{n:ctx['resources'][n]['sha256'] for n in proposal['sources']},'requirements':req,'cardinality':proposal['cardinality'],'artifact':proposal['artifact'],'unresolved':[]}
    else:
     original=mapping.get(cid,{}).get('original_id',cid);contract=dict(original_gold[original]['contract']);contract['task_id']=cid
    assert evidence['contract_sha256']==sha(canonical(contract))
   assert not r['unexpected_effect']
  else:
   assert not files and not r['actual_artifacts'];correct=r['result'].get('status')==g['decision']
  assert bool(correct)==r['correct']
 for arm in ['always_model','adom']:
  rs=[r for r in rows if r['arm']==arm];leg=[r for r in rs if r['family']!='control'];lat=sorted(r['latency_ms'] for r in leg);a=analysis[arm]
  assert a['legitimate_success']==sum(r['correct'] for r in leg) and a['legitimate_n']==len(leg)
  assert a['correct_all']==sum(r['correct'] for r in rs) and a['api_calls']==sum(r['api_calls'] for r in rs)
  near(a['legitimate_cost_usd'],sum(r['cost_usd'] for r in leg));near(a['all_cost_usd'],sum(r['cost_usd'] for r in rs));near(a['p50_ms'],statistics.median(lat));near(a['p95_ms'],lat[math.ceil(.95*len(lat))-1]);near(a['cost_per_success'],a['legitimate_cost_usd']/a['legitimate_success'])
 near(analysis['cost_per_success_savings'],1-analysis['adom']['cost_per_success']/analysis['always_model']['cost_per_success'])
 near(analysis['median_latency_savings'],1-analysis['adom']['p50_ms']/analysis['always_model']['p50_ms'])
 carry=[e for e in ledger['entries'] if e['status']=='CARRIED_FORWARD'];assert len(carry)==1
 near(ledger['accounted_usd'],sum(r['cost_usd'] for r in rows)+carry[0]['accounted_usd']);assert ledger['accounted_usd']<=ledger['cap_usd']==5
 assert all(e['status'] in ['COMPLETE','CARRIED_FORWARD'] for e in ledger['entries'])
 print(f'{name}: {len(rows)} executions, {api_count} API receipts, {artifact_count} byte-verified packages; metrics/ledger match')

def main():
 manifest=load(ROOT/'MANIFEST.json');actual={str(f.relative_to(ROOT)) for f in ROOT.rglob('*') if f.is_file() and '__pycache__' not in f.parts and f.name!='MANIFEST.json'}
 assert set(manifest)==actual,'Unexpected or missing files'
 for name,pin in manifest.items():
  p=ROOT/name;assert not p.is_symlink() and sha(p.read_bytes())==pin,name
 verify_run('pilot-24',24);verify_run('repeat-120',120)
 old=load(ROOT/'development/original-failure/analysis.json');new=load(ROOT/'development/v2-regression/analysis.json')
 assert not old['all_targets_met'] and old['exact_tasks_completed']['correct']==80 and new['all_targets_met'] and new['exact_tasks_completed']['correct']==120
 print('Published manifest and original failed/regression criteria verified. No API key or external package needed.')
if __name__=='__main__':main()
