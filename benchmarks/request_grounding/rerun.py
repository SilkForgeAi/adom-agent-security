"""Opt-in fresh live rerun. Verifying existing evidence never uses this script."""
import argparse,importlib.util,json,os,shutil,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',choices=['pilot-24','repeat-120'],default='pilot-24');p.add_argument('--output',type=Path,required=True);p.add_argument('--budget-usd',type=float,required=True);p.add_argument('--allow-paid-run',action='store_true');p.add_argument('--prepare-only',action='store_true');a=p.parse_args()
 if not 0<a.budget_usd<=5:p.error('budget must be positive and at most $5')
 if not a.prepare_only and (not a.allow_paid_run or not os.environ.get('OPENAI_API_KEY')):p.error('Live calls require --allow-paid-run and OPENAI_API_KEY')
 output=a.output.resolve()
 if output.exists():p.error('output must not exist; historical evidence must never be overwritten')
 source=ROOT/'runs'/a.run;sys.path.insert(0,str(source));spec=importlib.util.spec_from_file_location('published_campaign',source/'campaign.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 frozen=module.frozen;record=frozen();output.mkdir(parents=True)
 for name in ['requests.json','gold.json','source_excerpts.json']:shutil.copyfile(source/name,output/name)
 shutil.copytree(source/'inputs',output/'inputs')
 record.update(prior_usd=0,combined_cap_usd=a.budget_usd,publication_note='Fresh rerun from public exported runtime; does not modify or reproduce original network timing or model snapshot.')
 (output/'rerun-config.json').write_text(json.dumps(record,indent=2)+'\n')
 if a.prepare_only:print('Prepared fresh output and source snapshots. No key read, API call, or credits spent.');return
 # Keep checking the unchanged published dependency/data snapshot, while writing
 # every new request, response, artifact and ledger into the fresh output only.
 module.P=output;module.PRIOR=0;module.frozen=lambda:(frozen() and record)
 import api_client
 api_client.CAP_USD=a.budget_usd;os.environ['ADOM_ALLOW_PAID_RERUN']='1'
 module.run();module.analyze()
if __name__=='__main__':main()
