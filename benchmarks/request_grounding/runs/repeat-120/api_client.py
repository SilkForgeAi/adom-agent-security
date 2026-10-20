"""Small accounted API transport. No retries; conservative reservations first."""
import json
from pathlib import Path
import time
import urllib.request

MODEL = 'chat-latest'
CAP_USD = 5.0
MAX_OUTPUT = 1000
RATES = {'input': 5.0, 'cached_input': 0.5, 'output': 30.0}


def write(path, value):
    path = Path(path); temp = path.with_suffix(path.suffix+'.tmp')
    temp.write_text(json.dumps(value, indent=2)+'\n'); temp.replace(path)


def key_from_file(path):
    for line in Path(path).read_text().splitlines():
        if line.startswith('OPENAI_API_KEY='):
            key = line.split('=', 1)[1].strip().strip('\"\'')
            if key and not any(c.isspace() for c in key): return key
    raise RuntimeError('project credential unavailable')


def estimated_cost(usage):
    p = usage['prompt_tokens']; o = usage['completion_tokens']
    c = usage.get('prompt_tokens_details', {}).get('cached_tokens', 0)
    if any(type(v) is not int or v < 0 for v in (p, o, c)) or c > p:
        raise ValueError('invalid usage')
    return ((p-c)*RATES['input']+c*RATES['cached_input']+o*RATES['output'])/1e6


class Spend:
    def __init__(self, path):
        self.path = Path(path); self.entries = []
        if self.path.exists(): raise ValueError('fresh ledger required; no implicit reset')
        self.save()

    def save(self):
        write(self.path, {'cap_usd': CAP_USD, 'accounted_usd': sum(e['accounted_usd'] for e in self.entries), 'entries': self.entries})

    def reserve(self, payload, episode, turn):
        bound = (2*len(json.dumps(payload).encode())+4096)*RATES['input']/1e6 + payload['max_completion_tokens']*RATES['output']/1e6
        if sum(e['accounted_usd'] for e in self.entries)+bound > CAP_USD:
            raise RuntimeError('LOCAL_SPEND_CAP')
        entry = {'episode': episode, 'turn': turn, 'status': 'RESERVED', 'accounted_usd': bound}
        self.entries.append(entry); self.save(); return entry

    def finish(self, entry, response):
        actual = estimated_cost(response['usage'])
        if actual > entry['accounted_usd']: raise RuntimeError('usage exceeds reservation')
        entry.update(status='COMPLETE', accounted_usd=actual, usage=response['usage']); self.save()


def chat(key, payload, spend, folder, turn, episode):
    import os
    if os.environ.get('ADOM_ALLOW_PAID_RERUN') != '1': raise RuntimeError('Explicit ADOM_ALLOW_PAID_RERUN=1 required')
    write(folder/f'request-{turn:02d}.json', payload)
    entry = spend.reserve(payload, episode, turn); start = time.perf_counter_ns()
    req = urllib.request.Request('https://api.openai.com/v1/chat/completions',
        data=json.dumps(payload).encode(), headers={'Authorization': 'Bearer '+key, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=45) as stream: response = json.load(stream)
    except Exception as exc:
        entry.update(status='UNKNOWN_API_OUTCOME', error_type=type(exc).__name__); spend.save()
        raise RuntimeError('API_FAILURE_'+type(exc).__name__) from None
    elapsed = time.perf_counter_ns()-start
    write(folder/f'response-{turn:02d}.json', response)
    spend.finish(entry, response)
    return response, elapsed
