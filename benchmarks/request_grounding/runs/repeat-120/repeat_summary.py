"""Supplemental repeated-workload summaries; no paid calls."""
import json,statistics,math
from pathlib import Path
P=Path(__file__).resolve().parent
rows=json.loads((P/'results.json').read_text());mapping=json.loads((P/'repeat-map.json').read_text())
def summary(rs):
 leg=[r for r in rs if r['family']!='control'];lat=sorted(r['latency_ms'] for r in leg)
 return {'legitimate_correct':sum(r['correct'] for r in leg),'legitimate_n':len(leg),'controls_correct':sum(r['correct'] for r in rs if r['family']=='control'),'controls_n':sum(r['family']=='control' for r in rs),'calls':sum(r['api_calls'] for r in rs),'legitimate_cost':sum(r['cost_usd'] for r in leg),'median_ms':statistics.median(lat),'p95_ms':lat[math.ceil(.95*len(lat))-1]}
assert len(rows)==240
out={str(rep):{arm:summary([r for r in rows if r['arm']==arm and mapping[r['id']]['repetition']==rep]) for arm in ['always_model','adom']} for rep in range(1,6)}
(P/'repeat-analysis.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))
