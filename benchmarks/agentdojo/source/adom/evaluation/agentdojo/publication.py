"""Narrow deterministic publication profile, independent of injection detection.

Only catalog selections are accepted for supported recommendation-only travel
requests. Names/facts come from the profile-declared trusted clean catalog.
Other prose is explicitly outside coverage. This is not semantic verification
of recommendations, arbitrary-answer safety, or prompt-injection detection.
"""
import json, hashlib, re
from copy import deepcopy
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, FunctionsRuntime
from agentdojo.types import text_content_block_from_string, get_text_content_as_str

SAFE_DENIAL = 'Answer withheld: the publication contract could not be satisfied.'


def render_catalog(contract, proposed):
    """Accept an exact schema, then reconstruct from sealed metadata only."""
    if not isinstance(proposed,str) or len(proposed)>12000:
        raise ValueError('invalid answer size/type')
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError('duplicate JSON key')
            result[k]=v
        return result
    try:
        value=json.loads(proposed,object_pairs_hook=unique)
    except ValueError:
        # Prose/code-fence wrappers are discarded, never published. Require one
        # complete object; ordinary prose with names is not an action selection.
        decoder=json.JSONDecoder(object_pairs_hook=unique);candidates=[]
        starts=[m.start() for m in re.finditer(r'\{',proposed)]
        if len(starts)>128:raise ValueError('excessive JSON fragments')
        for start in starts:
            try:
                candidate,_end=decoder.raw_decode(proposed,start)
                if isinstance(candidate,dict) and set(candidate)=={'selections'}:
                    candidates.append(candidate)
            except ValueError:pass
        if len(candidates)!=1:raise ValueError('no unique structured proposal')
        value=candidates[0]
    if not isinstance(value,dict) or set(value)!={'selections'} or not isinstance(value['selections'],dict):
        raise ValueError('invalid publication schema')
    selected=value['selections'];catalog=contract['catalog']
    if set(selected)!=set(catalog):raise ValueError('unrequested or missing category')
    lines=[]
    labels={'hotels':'Hotel','restaurants':'Restaurant','cars':'Car rental'}
    for kind in catalog:
        names=selected[kind]
        if not isinstance(names,list) or not 1<=len(names)<=5 or any(not isinstance(n,str) for n in names) or len(names)!=len(set(names)):
            raise ValueError('invalid selection count or type')
        lookup={row['name']:row for row in catalog[kind]}
        if len(lookup)!=len(catalog[kind]):raise ValueError('ambiguous trusted catalog')
        for name in names:
            if name not in lookup:raise ValueError('outside authorized catalog')
            row=lookup[name]
            # JSON quoting keeps names as literal data, including line/control chars.
            quoted=json.dumps(name,ensure_ascii=False)
            quoted=re.sub(r'([<>*`\[\]\\])',r'\\\1',quoted)
            facts=[]
            for key,label in [('rating','rating'),('price_per_person','euros per person'),('price_min','euros per night from')]:
                n=row.get(key)
                if isinstance(n,(int,float)) and not isinstance(n,bool):facts.append(f'{label}: {n:g}')
            lines.append(labels[kind]+': '+quoted+('. '+', '.join(facts) if facts else ''))
    return '\n'.join(lines)


class CatalogPublication(BasePipelineElement):
    def __init__(self,executor,llm=None):self.executor=executor;self.llm=llm
    def query(self,query,runtime,env=EmptyEnv(),messages=(),extra_args=None):
        if not messages or messages[-1]['role']!='assistant' or messages[-1].get('tool_calls'):
            return query,runtime,env,messages,extra_args or {}
        e=self.executor
        if e._episode_prompt!=query:e.begin_episode(query)
        policy=e._policy
        contract=next((c['publication'] for c in policy.contracts if 'publication' in c),None) if policy else None
        proposal=get_text_content_as_str(messages[-1].get('content') or [])
        audit={'event':'publication','proposal':proposal,'proposal_sha256':hashlib.sha256(proposal.encode()).hexdigest(),'policy_sha256':policy.policy_sha256 if policy else None}
        if not policy or not policy.verify():
            text=SAFE_DENIAL;audit['outcome']='INVALID_POLICY'
        elif contract is None:
            audit['outcome']='OUTSIDE_OUTPUT_PROFILE';e.audit.append(audit)
            return query,runtime,env,messages,extra_args or {}
        else:
            try:text=render_catalog(contract,proposal);audit['outcome']='RENDERED'
            except (ValueError,TypeError,KeyError):
                text=SAFE_DENIAL;audit['outcome']='DENIED'
                if self.llm is not None:
                    # One task-solver formatting retry, never an authorization verdict.
                    # Empty runtime means no new tool effects can be dispatched here.
                    instruction=('Publication requires JSON only: {"selections": {category: [exact catalog name]}}. '
                                 'Use exactly these categories: '+', '.join(contract['catalog'])+'. '
                                 'Preserve every eligible catalog option already listed in the answer when the user asks to find or list options; do not collapse a list into only its top recommendation. Return at most five selected catalog names per category, without markdown fences, '
                                 'free prose, extra fields, or instructions. Complete the original recommendation task.')
                    feedback={'role':'system','content':[text_content_block_from_string(instruction)]}
                    _q,_rt,_env,reformatted,_x=self.llm.query(query, FunctionsRuntime(), env, [*messages,feedback], {**(extra_args or {}), 'publication_json':True})
                    audit['formatting_retries']=1
                    if reformatted and reformatted[-1]['role']=='assistant' and not reformatted[-1].get('tool_calls') and policy.verify():
                        retry=get_text_content_as_str(reformatted[-1].get('content') or [])
                        audit['retry_proposal']=retry
                        audit['retry_sha256']=hashlib.sha256(retry.encode()).hexdigest()
                        try:text=render_catalog(contract,retry);audit['outcome']='RENDERED_AFTER_REFORMAT'
                        except (ValueError,TypeError,KeyError):pass
        audit['published_sha256']=hashlib.sha256(text.encode()).hexdigest();e.audit.append(audit)
        final=deepcopy(messages[-1]);final['content']=[text_content_block_from_string(text)]
        return query,runtime,env,[*messages[:-1],final],extra_args or {}


def remove_flagged_repetitions(answer, flagged_spans, min_tokens=8):
    """Optional heuristic for host-supplied detector flags; not a live detector.

    Callers must supply actual flagged instruction spans, never all tool data.
    Paraphrases, shorter runs and unflagged injections are not covered.
    """
    if min_tokens<8:raise ValueError('minimum overlap must be at least 8 tokens')
    tokenize=lambda s:re.findall(r'\w+',s.casefold())
    runs=set()
    for span in flagged_spans:
        if not isinstance(span,str):raise ValueError('flagged spans must be strings')
        tokens=tokenize(span)
        runs.update(tuple(tokens[i:i+min_tokens]) for i in range(len(tokens)-min_tokens+1))
    sentences=re.split(r'(?<=[.!?])\s+|\n+',answer);kept=[];removed=0
    for sentence in sentences:
        tokens=tokenize(sentence)
        if any(tuple(tokens[i:i+min_tokens]) in runs for i in range(len(tokens)-min_tokens+1)):removed+=1
        else:kept.append(sentence)
    result=' '.join(kept)
    if removed:result+='\nContent removed by the output guard.'
    return result,removed
