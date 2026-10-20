"""Complete-request recognizer for a published controlled language, not arbitrary prose.

The authenticated request is text, not a caller-supplied task-kind label. Authority
and resource snapshots are independent trusted host inputs. No model is used.
"""
import copy
import json
import re
import threading
from adom.enforcement.workflow_compiler import (
 sha,json_bytes,flat,validate_contract,inspect_sources,select_evidence,exact_plan,Unresolved,Rejected)
from adom.enforcement.parameterized_workflow import ParameterizedCompiler,compile_program,semantic_contract

GRAMMAR_VERSION='release-request-grounding-v2'
ARRAY=r'(\[[^\n]{1,4096}\])'
STRING=r'("(?:[^"\\\n]|\\.){1,180}")'
BUNDLE=r'(?:a |the )?(?:release evidence bundle|release package|verified release archive)'
VERB=r'(?:create|build|generate|prepare|produce|assemble)'
FORMATS=[
 re.compile(rf'gather {BUNDLE} of (?P<selection_count>all modules) in (?P<sources>{ARRAY}) that (?P<selection_predicate>.+?); put it in (?P<artifact>{STRING})\.?',re.I),
 re.compile(rf'I need {BUNDLE} named (?P<artifact>{STRING}) containing (?P<selection_count>all files) from (?P<sources>{ARRAY}) that (?P<selection_predicate>.+?)\.?',re.I),
 re.compile(rf'(?:please )?{VERB} {BUNDLE} (?:from|using) (?P<sources>{ARRAY})[,;]? (?P<selection>.+?),? (?:as|named|and save it as|and write it to) (?P<artifact>{STRING})\.?',re.I),
 re.compile(rf'(?:please )?package (?P<selection>.+?) (?:from|using) (?P<sources>{ARRAY}) into (?P<artifact>{STRING}) as {BUNDLE}\.?',re.I),
 re.compile(rf'(?:using|from) (?P<sources>{ARRAY}), {VERB} {BUNDLE} for (?P<selection>.+?) and save it as (?P<artifact>{STRING})\.?',re.I),
]
SYMBOL=r'(`[A-Za-z_][A-Za-z0-9_.]{0,180}`|[A-Za-z_][A-Za-z0-9_.]{0,180})'
CARDINALITY=re.compile(r'(?:(?:selecting|containing|for) )?(all (?:matching )?files|every file|exactly one file|the single file) (?:that|which) (.+)',re.I)
DEFINITION=re.compile(rf'(?:define|defines|declare|declares) (?:a |the )?(class|function) {SYMBOL}',re.I)
DIRECT_CALL=re.compile(rf'(?:where )?(?:the )?function {SYMBOL} directly calls {SYMBOL}',re.I)


def validate_context(context):
    if type(context) is not dict or set(context)!={'request_id','authority','resources'}:raise Rejected('context schema')
    if not flat(context['request_id']):raise Rejected('request identity')
    a=context['authority'];resources=context['resources']
    if type(a) is not dict or set(a)!={'epoch','ops','read_paths','artifacts'}:raise Rejected('authority schema')
    if type(a['epoch']) is not int or a['epoch']<0:raise Rejected('authority epoch')
    for k in ('ops','read_paths','artifacts'):
        if type(a[k]) is not list or any(type(v) is not str for v in a[k]):raise Rejected('authority grants')
    if type(resources) is not dict:raise Rejected('resource schema')
    return a,resources


def parse_selector(raw):
    text=raw[:-1] if raw.endswith(',') else raw
    header=CARDINALITY.fullmatch(text)
    if header is None:return None
    cardinality='one' if header[1].lower() in ('exactly one file','the single file') else 'all'
    clauses=re.split(r'\s+and\s+',header[2],flags=re.I)
    if not 1<=len(clauses)<=8:return None
    requirements=[];trace=[]
    for clause in clauses:
        match=DEFINITION.fullmatch(clause)
        if match:
            req={'kind':'defines_class' if match[1].lower()=='class' else 'defines_function','symbol':match[2].strip('`')}
        else:
            match=DIRECT_CALL.fullmatch(clause)
            if not match:return None
            req={'kind':'direct_call','symbol':match[1].strip('`'),'target':match[2].strip('`')}
        requirements.append(req);trace.append({'clause':clause,'obligation':req})
    # Conjunction is commutative and idempotent within this explicit predicate DSL.
    unique={json.dumps(r,sort_keys=True):r for r in requirements}
    return cardinality,[unique[k] for k in sorted(unique)],trace


def ground(request,context):
    """No source read or execution here. Non-grounded requests return no contract."""
    try:
        a,resources=validate_context(context)
        if type(request) is not str or not 1<=len(request.encode('utf-8'))<=8192:
            return {'route':'CLARIFY','reason':'invalid or oversized request'}
        text=request.strip()
        for pattern in FORMATS:
            match=pattern.fullmatch(text)
            if match is None:continue
            selection_text=match.groupdict().get('selection')
            if selection_text is None:
                selection_text='all files that '+match['selection_predicate']
            selector=parse_selector(selection_text)
            if selector is None:return {'route':'MODEL_REQUIRED','reason':'entire selection clause outside verified language'}
            try:paths=json.loads(match['sources']);artifact=json.loads(match['artifact'])
            except (ValueError,TypeError):return {'route':'CLARIFY','reason':'malformed explicit parameters'}
            if type(paths) is not list or not 1<=len(paths)<=64 or any(type(n) is not str for n in paths) or len(set(paths))!=len(paths):
                return {'route':'CLARIFY','reason':'source list must be explicit, bounded and unique'}
            if not flat(artifact) or not artifact.endswith('.zip') or any(not flat(n) for n in paths):
                return {'route':'DENY','reason':'outside local release filename scope'}
            if 'release_bundle' not in a['ops'] or artifact not in a['artifacts'] or not set(paths)<=set(a['read_paths']):
                return {'route':'DENY','reason':'independent authority does not permit requested effect'}
            if any(n not in resources for n in paths):return {'route':'CLARIFY','reason':'requested source snapshot unavailable'}
            pins={}
            for n in paths:
                meta=resources[n]
                pin=meta.get('sha256') if type(meta) is dict else None
                if type(pin) is not str or re.fullmatch('[0-9a-f]{64}',pin) is None:
                    return {'route':'DENY','reason':'source evidence unavailable'}
                pins[n]=pin
            cardinality,requirements,trace=selector
            contract={'version':1,'task_id':context['request_id'],'epoch':a['epoch'],'sources':dict(sorted(pins.items())),
              'requirements':requirements,'cardinality':cardinality,'artifact':artifact,'unresolved':[]}
            validate_contract(contract)
            return {'route':'GROUNDED','contract':contract,'parse_trace':{'grammar_version':GRAMMAR_VERSION,
              'request_sha256':sha(request.encode()),'whole_request_matched':True,
              'source_text':match['sources'],'selection_text':selection_text,'artifact_text':match['artifact'],
              'predicate_bindings':trace},'reason':'whole request recognized under published syntax semantics'}
        if re.fullmatch(rf'(?:please )?{VERB} {BUNDLE}\.?',text,re.I):
            return {'route':'CLARIFY','reason':'missing source, selection and destination'}
        if re.fullmatch(rf'(?:please )?{VERB} {BUNDLE} (?:from|using) {ARRAY}\.?',text,re.I):
            return {'route':'CLARIFY','reason':'missing selection and destination'}
        incomplete=re.fullmatch(rf'(?:please )?{VERB} {BUNDLE} (?:from|using) (?P<sources>{ARRAY})[,;]? (?P<selection>.+?)\.?',text,re.I)
        if incomplete is not None and parse_selector(incomplete['selection']) is not None:
            # Complete recognized selection, but no destination. Never execute or
            # infer an output name; authority is checked after a completed request.
            return {'route':'CLARIFY','reason':'missing destination'}
        return {'route':'MODEL_REQUIRED','reason':'whole request outside verified language'}
    except (Rejected,Unresolved,TypeError,ValueError,KeyError,RecursionError) as exc:
        return {'route':'DENY','reason':'invalid trusted context or contract: '+type(exc).__name__}


class GroundedExecutor:
    """Known-language requests -> derived contract -> parameterized IR -> ADOM gate.

No callback or automatic paid fallback. Caller handles MODEL_REQUIRED/CLARIFY.
Authentication of the request/context remains the host application's job.
"""
    def __init__(self,source,output):
        self.runtime=ParameterizedCompiler(source,output);self.programs={};self.lock=threading.RLock()

    def revoke(self):
        with self.lock:self.runtime.revoke()

    def handle(self,request,context):
        with self.lock:
            parsed=ground(request,context)
            if parsed['route']!='GROUNDED':return parsed
            c=parsed['contract']
            if self.runtime.engine.revoked or c['epoch']!=self.runtime.engine.epoch:
                return {'route':'DENY','reason':'revoked or stale authority','grounding':parsed}
            key=sha(json_bytes(semantic_contract(c)));compiled=False
            try:
                if key not in self.programs:
                    contents,facts=inspect_sources(self.runtime.engine.source,c)
                    selected,_=select_evidence(c,facts)
                    program,pin=compile_program(self.runtime.engine.source,c,exact_plan(selected))
                    self.programs[key]=(copy.deepcopy(program),pin);compiled=True
                program,pin=self.programs[key]
                result=self.runtime.run_program(program,pin,c)
                return {'route':'DETERMINISTIC','grounding':parsed,'compiled_new_program':compiled,
                  'program_sha256':pin,'execution':result}
            except Unresolved as exc:
                return {'route':'REVIEW_REQUIRED','reason':str(exc),'grounding':parsed}
            except (Rejected,ValueError,TypeError,KeyError,OSError) as exc:
                return {'route':'REVIEW_REQUIRED','reason':'execution evidence unavailable: '+type(exc).__name__,'grounding':parsed}
