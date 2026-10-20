"""Bounded release DAG compiler with syntax evidence and pre-effect validation.

Trusted host code, not a sandbox. Callers authenticate and approve contracts.
Static syntax facts are not runtime behavior proofs or natural-language semantics.
"""
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import threading
import tempfile
import zipfile

from adom.api.model_proxy import ModelProxyPolicy
from adom.enforcement.mediated_gateway import MediatedAgentGateway
from adom.enforcement.workflow_authority import strict_json, canonical

OPS = ('inspect', 'select', 'manifest', 'archive', 'evidence', 'publish')
NEEDS = {'inspect': set(), 'select': {'inspect'}, 'manifest': {'select'}, 'archive': {'select'},
         'evidence': {'inspect','select','manifest','archive'}, 'publish': {'manifest','archive','evidence'}}


class Rejected(ValueError): pass
class Unresolved(ValueError): pass


def sha(raw): return hashlib.sha256(raw).hexdigest()


def json_bytes(value): return (canonical(value)+'\n').encode()


def flat(name):
    return type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,180}',name) is not None and name not in ('.','..')


def snapshot(value, limit=50000):
    raw=canonical(value)
    if len(raw.encode())>limit: raise Rejected('oversize JSON')
    return strict_json(raw)


def validate_contract(value):
    c=snapshot(value)
    if type(c) is not dict or set(c)!={'version','task_id','epoch','sources','requirements','cardinality','artifact','unresolved'}:
        raise Rejected('contract schema')
    if type(c['version']) is not int or c['version']!=1 or not flat(c['task_id']): raise Rejected('contract identity')
    if type(c['epoch']) is not int or c['epoch']<0: raise Rejected('contract epoch')
    if not flat(c['artifact']) or not c['artifact'].endswith('.zip'): raise Rejected('artifact scope')
    if type(c['sources']) is not dict or not 1<=len(c['sources'])<=64: raise Rejected('source count')
    for name,pin in c['sources'].items():
        if not flat(name) or name==c['artifact'] or type(pin) is not str or re.fullmatch('[0-9a-f]{64}',pin) is None:
            raise Rejected('source pin')
    if type(c['unresolved']) is not list or any(type(x) is not str for x in c['unresolved']): raise Rejected('unresolved schema')
    if c['unresolved']: raise Unresolved('material requirement unresolved')
    if c['cardinality'] not in ('one','all'): raise Rejected('cardinality')
    if type(c['requirements']) is not list or not 1<=len(c['requirements'])<=8: raise Rejected('requirements')
    for req in c['requirements']:
        if type(req) is not dict: raise Rejected('requirement schema')
        kind=req.get('kind')
        expected={'kind','symbol','target'} if kind=='direct_call' else {'kind','symbol'}
        if set(req)!=expected: raise Rejected('requirement fields')
        if kind not in ('defines_function','defines_class','direct_call'): raise Unresolved('unsupported evidence obligation')
        if any(type(v) is not str or re.fullmatch('[A-Za-z_][A-Za-z0-9_.]{0,180}',v) is None for k,v in req.items() if k!='kind'):
            raise Rejected('symbol schema')
    return c


def expr_name(node):
    if isinstance(node,ast.Name): return node.id
    if isinstance(node,ast.Attribute):
        base=expr_name(node.value)
        return base+'.'+node.attr if base else None
    return None


def definitions(nodes,prefix=''):
    for node in nodes:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
            symbol=prefix+node.name
            yield symbol,node
            yield from definitions(node.body,symbol+'.')


def direct_calls(node):
    found=set()
    def visit(n):
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):
            return
        if isinstance(n,ast.Call):
            name=expr_name(n.func)
            if name: found.add(name)
        for child in ast.iter_child_nodes(n): visit(child)
    for item in node.body: visit(item)
    return sorted(found)


def inspect_sources(source,contract):
    contents={};facts=[]
    for name,pin in sorted(contract['sources'].items()):
        fd=os.open(Path(source)/name,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f: raw=f.read(1000001)
        if len(raw)>1000000 or sha(raw)!=pin: raise Unresolved('input snapshot changed or too large')
        contents[name]=raw
        try: tree=ast.parse(raw,filename=name)
        except (SyntaxError,ValueError): raise Unresolved('source cannot be parsed') from None
        lines=raw.splitlines(keepends=True)
        for symbol,node in definitions(tree.body):
            is_class=isinstance(node,ast.ClassDef)
            facts.append({'path':name,'source_sha256':pin,'symbol':symbol,
              'kind':'defines_class' if is_class else 'defines_function',
              'line_start':node.lineno,'line_end':node.end_lineno,
              'span_sha256':sha(b''.join(lines[node.lineno-1:node.end_lineno])),
              'direct_calls':[] if is_class else direct_calls(node)})
    return contents,facts


def satisfies(fact,requirement):
    if fact['symbol']!=requirement['symbol']: return False
    if requirement['kind']=='direct_call':
        return fact['kind']=='defines_function' and requirement['target'] in fact['direct_calls']
    return fact['kind']==requirement['kind']


def select_evidence(contract,facts):
    selected=[];proofs={}
    for name in sorted(contract['sources']):
        evidence=[]
        for req in contract['requirements']:
            candidates=[f for f in facts if f['path']==name and satisfies(f,req)]
            if not candidates: break
            evidence.append({'requirement':req,'fact':candidates[0]})
        else:
            selected.append(name);proofs[name]=evidence
    if not selected or (contract['cardinality']=='one' and len(selected)!=1):
        raise Unresolved('selection obligation not uniquely satisfied')
    return selected,proofs


def validate_plan(value,selected):
    p=snapshot(value)
    if type(p) is not dict or set(p)!={'version','nodes'} or type(p['version']) is not int or p['version']!=1:
        raise Rejected('plan schema')
    if type(p['nodes']) is not list or len(p['nodes'])!=len(OPS): raise Rejected('plan must cover entire workflow')
    by_id={};by_op={}
    for node in p['nodes']:
        if type(node) is not dict or set(node)!={'id','op','needs','paths'}: raise Rejected('node schema')
        if not flat(node['id']) or node['id'] in by_id or node['op'] not in OPS or node['op'] in by_op:
            raise Rejected('unknown or repeated operation')
        if type(node['needs']) is not list or any(type(n) is not str for n in node['needs']) or len(set(node['needs']))!=len(node['needs']):
            raise Rejected('dependency schema')
        if type(node['paths']) is not list or any(type(n) is not str for n in node['paths']): raise Rejected('path schema')
        if node['op']=='select':
            if node['paths']!=selected: raise Rejected('selection does not satisfy trusted evidence obligation')
        elif node['paths']: raise Rejected('paths belong only on selection node')
        by_id[node['id']]=node;by_op[node['op']]=node
    for op,node in by_op.items():
        if any(n not in by_id for n in node['needs']): raise Rejected('unknown dependency')
        if {by_id[n]['op'] for n in node['needs']}!=NEEDS[op]: raise Rejected('dependency closure mismatch')
    order=[];done=set()
    while len(done)<len(OPS):
        ready=[n for n in p['nodes'] if n['id'] not in done and set(n['needs'])<=done]
        if not ready: raise Rejected('cycle')
        for n in ready: order.append(n['op']);done.add(n['id'])
    return p,order


def exact_plan(selected):
    return {'version':1,'nodes':[{'id':op,'op':op,'needs':sorted(NEEDS[op]),'paths':selected if op=='select' else []} for op in OPS]}


def zipped(entries):
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for name,data in sorted(entries.items()):
            info=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100644<<16;z.writestr(info,data)
    return buffer.getvalue()


def compile_bundle(source,raw_contract,raw_plan):
    c=validate_contract(raw_contract)
    contents,facts=inspect_sources(source,c)
    selected,proofs=select_evidence(c,facts)
    p,order=validate_plan(raw_plan,selected)
    manifest={'files':[{'path':n,'bytes':len(contents[n]),'sha256':sha(contents[n])} for n in selected]}
    manifest_bytes=json_bytes(manifest)
    archive_bytes=zipped({n:contents[n] for n in selected})
    evidence={'version':1,'contract_sha256':sha(json_bytes(c)),'source_pins':c['sources'],
      'selection':selected,'proofs':proofs,'manifest_sha256':sha(manifest_bytes),'archive_sha256':sha(archive_bytes),
      'checked_properties':['complete_selection','syntax_obligations','source_pins','dependency_closure','bounded_outputs'],
      'claim_boundary':'Static syntax evidence, not runtime behavior or natural-language intent proof.'}
    payload=zipped({'manifest.json':manifest_bytes,'sources.zip':archive_bytes,'evidence.json':json_bytes(evidence)})
    return c,p,payload,{'selection':selected,'order':order,'proofs':proofs,'sha256':sha(payload),'bytes':len(payload)}


class Compiler:
    """Private plan cache; every hit is fully revalidated. In-process epoch only."""
    def __init__(self,source,output):
        self.source=Path(source);self.output=Path(output)
        self.output.mkdir(parents=True,exist_ok=True)
        self.epoch=0;self.revoked=False;self.cache={};self.lock=threading.RLock()
        self.effects=[]
        self.gateway=MediatedAgentGateway(ModelProxyPolicy(allowed_tools=('commit_release_bundle',)),executor=self._write)

    def revoke(self):
        with self.lock: self.revoked=True;self.epoch+=1

    def inspect(self,contract):
        c=validate_contract(contract)
        return inspect_sources(self.source,c)[1]

    def key(self,c):
        return sha(json_bytes({k:c[k] for k in ('requirements','cardinality','artifact')}))

    def cached(self,c):
        return copy.deepcopy(self.cache.get(self.key(validate_contract(c))))

    def run(self,contract,plan=None):
        with self.lock:
            try:
                c=validate_contract(contract)
                if self.revoked or c['epoch']!=self.epoch: raise Rejected('revoked or stale epoch')
                hit=plan is None
                candidate=self.cached(c) if hit else plan
                if candidate is None: return {'status':'NEEDS_PLAN','cache_hit':False}
                c,p,payload,proof=compile_bundle(self.source,c,candidate)
                # Re-read every relevant input immediately before effect dispatch.
                inspect_sources(self.source,c)
                args={'task_id':c['task_id'],'artifact':c['artifact'],'sha256':sha(payload),'content':payload.hex()}
                decision=self.gateway.run_tool('commit_release_bundle',args)
                if decision.execution_status!='succeeded':
                    return {'status':'UNKNOWN' if decision.execution_status=='unknown' else 'DENIED','reason':decision.reason}
                self.cache[self.key(c)]=copy.deepcopy(p)
                return {'status':'EXECUTED','cache_hit':hit,'proof':proof,'receipt':decision.result}
            except Unresolved as exc:
                return {'status':'REVIEW_REQUIRED','reason':str(exc),'effect_started':False}
            except (Rejected,ValueError,TypeError,KeyError,RecursionError) as exc:
                return {'status':'DENIED','reason':str(exc),'effect_started':False}
            except OSError as exc:
                return {'status':'REVIEW_REQUIRED','reason':'source access unavailable: '+type(exc).__name__,'effect_started':False}

    def _write(self,name,args):
        if name!='commit_release_bundle' or set(args)!={'task_id','artifact','sha256','content'}: raise Rejected('executor schema')
        if self.revoked or not flat(args['task_id']) or not flat(args['artifact']): raise Rejected('executor authority')
        payload=bytes.fromhex(args['content'])
        if sha(payload)!=args['sha256']: raise Rejected('payload binding')
        # One create-only local artifact is the effect. It is not external delivery.
        target=self.output/(args['task_id']+'-'+args['artifact'])
        fd,staged=tempfile.mkstemp(prefix='.compiler-stage-',dir=self.output)
        try:
            with os.fdopen(fd,'wb') as f: f.write(payload);f.flush();os.fsync(f.fileno())
            try: os.link(staged,target,follow_symlinks=False)
            except FileExistsError:
                if target.is_symlink() or target.read_bytes()!=payload: raise Rejected('existing artifact differs')
                return {'artifact':target.name,'sha256':sha(payload),'replay':True}
        finally:
            os.unlink(staged)
        dfd=os.open(self.output,os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
        receipt={'artifact':target.name,'sha256':sha(payload),'bytes':len(payload)}
        self.effects.append(receipt)
        return receipt
