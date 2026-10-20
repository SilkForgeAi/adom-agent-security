"""Parameterized release IR. Trusted contract and trusted IR pin are separate inputs.

No model or evaluator imports. Static syntax obligations only. Native machine
code is not generated; the IR is a validated executable workflow template.
"""
import copy
from adom.enforcement.workflow_compiler import (
 Compiler,Rejected,Unresolved,validate_contract,compile_bundle,validate_plan,
 inspect_sources,select_evidence,snapshot,sha,json_bytes)

IR_VERSION='release-ir-parameters-v1'
PARAMETERS=['task_id','epoch','sources','artifact','selected_sources']


def semantic_contract(c):
    return {'contract_version':c['version'],'requirements':c['requirements'],
            'cardinality':c['cardinality'],'source_limit':64,'artifact_suffix':'.zip'}


def compile_program(source,contract,model_plan):
    c,p,_,proof=compile_bundle(source,contract,model_plan)
    nodes=copy.deepcopy(p['nodes'])
    for n in nodes:
        n['paths']='$selected_sources' if n['op']=='select' else []
    program={'ir_version':IR_VERSION,'semantic_contract':semantic_contract(c),
             'parameters':PARAMETERS,'nodes':nodes}
    return program,sha(json_bytes(program))


def validate_program(program,trusted_pin):
    p=snapshot(program)
    if type(trusted_pin) is not str or sha(json_bytes(p))!=trusted_pin:
        raise Rejected('compiled artifact integrity mismatch')
    if type(p) is not dict or set(p)!={'ir_version','semantic_contract','parameters','nodes'}:
        raise Rejected('IR schema')
    if p['ir_version']!=IR_VERSION or p['parameters']!=PARAMETERS:raise Rejected('IR version or bindings')
    if type(p['nodes']) is not list:raise Rejected('IR nodes')
    nodes=copy.deepcopy(p['nodes'])
    for n in nodes:
        if type(n) is not dict or set(n)!={'id','op','needs','paths'}:raise Rejected('IR node schema')
        if n['op']=='select':
            if n['paths']!='$selected_sources':raise Rejected('literal selection cannot be reused as parameterized IR')
            n['paths']=['validated-binding.py']
    validate_plan({'version':1,'nodes':nodes},['validated-binding.py'])
    return p


class ParameterizedCompiler:
    def __init__(self,source,output):
        self.engine=Compiler(source,output)

    def revoke(self):self.engine.revoke()

    def run_program(self,program,trusted_pin,contract):
        with self.engine.lock:
            try:
                p=validate_program(program,trusted_pin)
                c=validate_contract(contract)
                if self.engine.revoked or c['epoch']!=self.engine.epoch:raise Rejected('revoked or stale epoch')
                if semantic_contract(c)!=p['semantic_contract']:
                    return {'status':'RECOMPILE_REQUIRED','program_reused':False,'effect_started':False,
                            'reason':'changed semantic contract'}
                # The binding is recomputed from fresh bytes, not copied from the seed plan.
                contents,facts=inspect_sources(self.engine.source,c)
                selected,_=select_evidence(c,facts)
                nodes=copy.deepcopy(p['nodes'])
                for n in nodes:
                    if n['op']=='select':n['paths']=selected
                result=self.engine.run(c,{'version':1,'nodes':nodes})
                result.update(program_reused=result['status']=='EXECUTED',program_sha256=trusted_pin,
                              bound_selection=selected)
                return result
            except Unresolved as exc:
                return {'status':'REVIEW_REQUIRED','program_reused':False,'effect_started':False,'reason':str(exc)}
            except (Rejected,TypeError,ValueError,KeyError,RecursionError) as exc:
                return {'status':'DENIED','program_reused':False,'effect_started':False,'reason':str(exc)}
            except OSError as exc:
                return {'status':'REVIEW_REQUIRED','program_reused':False,'effect_started':False,'reason':'source unavailable: '+type(exc).__name__}
