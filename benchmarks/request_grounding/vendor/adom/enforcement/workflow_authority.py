"""Persistent authorization for bounded workflow executors.

Synthetic effects share the authorization transaction. The optional local receiver
uses a committed outbox reservation and independent idempotent service receipts.
Neither profile supports arbitrary external payments, sockets, or commands.
Only trusted operator code may create a workflow or select counterfactual mode.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from .fleet_control import FleetControl
from .workflow_controls import ControlPlane, AttemptJournal, ApprovalRequired, RestrictionDenied

TOOLS = {'read', 'transform', 'publish', 'purchase', 'delegate', 'revoke', 'change_production'}
CATALOG = {'scan': 6000, 'quick_check': 1000}  # SYNTHETIC cents, never real purchases
MAX_EVENTS = 4096


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))


def text(value, maximum=128):
    if type(value) is not str or not 1 <= len(value.encode()) <= maximum:
        raise ValueError('invalid string')
    return value


def fields(args, expected):
    if type(args) is not dict or set(args) != set(expected):
        raise ValueError('invalid argument fields')


class Denied(Exception):
    pass


class WorkflowAuthority:
    def __init__(self, path, policy_sha256, *, enforce=True, fleet_path=None, delivery=None):
        if fleet_path is not None and not enforce:
            raise ValueError("counterfactual execution cannot use the fleet deployment")
        self.fleet = FleetControl(fleet_path) if fleet_path is not None else None
        self.delivery = delivery
        if delivery is not None and (fleet_path is None or not enforce):
            raise ValueError("external delivery requires enforced fleet deployment")
        self.path = Path(path).resolve()
        self.expected_policy = policy_sha256
        self.enforce = enforce  # trusted evaluator only; absent from wire protocol

    @staticmethod
    def create(path, *, budget_cents=10000, guarded=False, publication_contract=None, root_tools=None, read_objects=None):
        if type(guarded) is not bool:
            raise ValueError("invalid guarded profile")
        if type(budget_cents) is not int or not 0 <= budget_cents <= 10**9:
            raise ValueError('invalid budget')
        if read_objects is not None:
            if (type(read_objects) is not list or not read_objects
                or any(type(x) is not str for x in read_objects)
                or len(set(read_objects)) != len(read_objects)
                or not set(read_objects) <= {'public','private'}):
                raise ValueError('invalid task read authority')
        if root_tools is not None:
            if (type(root_tools) is not list or not root_tools
                or any(type(x) is not str for x in root_tools)
                or len(set(root_tools)) != len(root_tools)
                or not set(root_tools) <= TOOLS - {'change_production'}):
                raise ValueError('invalid task tool authority')
        if publication_contract is not None:
            publication_contract = strict_json(canonical(publication_contract))
            if (type(publication_contract) is not dict or set(publication_contract) != {'destination','text_sha256','max_publications'}
                or publication_contract['destination'] not in ('internal','external')
                or type(publication_contract['max_publications']) is not int or not 1 <= publication_contract['max_publications'] <= 128
                or type(publication_contract['text_sha256']) is not list
                or not 1 <= len(publication_contract['text_sha256']) <= 128
                or any(type(x) is not str or len(x) != 64 or any(c not in '0123456789abcdef' for c in x) for x in publication_contract['text_sha256'])):
                raise ValueError('invalid immutable publication contract')
        path = Path(path)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)  # Never silently reset or recreate an existing workflow.
        root = secrets.token_hex(32)
        policy = {'budget_cents': budget_cents, 'catalog': CATALOG,
                  'root_tools': sorted(TOOLS - {'change_production'} if root_tools is None else root_tools), 'version': 2, 'guarded': guarded}
        if read_objects is not None:
            policy['read_objects'] = sorted(read_objects)
        if publication_contract is not None:
            policy['publication_contract'] = publication_contract
        state = {'policy': policy, 'seed': secrets.token_hex(32), 'used': 0, 'sensitive_seen': False,
                 'root_actor': digest(root), 'actors': {digest(root): {'parent': None, 'tools': policy['root_tools'], 'revoked': False, 'depth': 0}},
                 'objects': {'public': {'content':'REPORT-42: 7 widgets', 'sensitive':False},
                             'private': {'content':'SYNTHETIC-CUSTOMER-'+secrets.token_hex(16), 'sensitive':True}}}
        if publication_contract is not None:
            state['publication_used'] = 0
        with sqlite3.connect(path) as db:
            db.executescript('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; '
                             'CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL); '
                             'CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT UNIQUE, '
                             'request TEXT, response TEXT, previous_hash TEXT, hash TEXT); '
                             'CREATE TABLE effects (seq INTEGER PRIMARY KEY, kind TEXT, payload TEXT); '
                             'CREATE TABLE outbox (request_id TEXT PRIMARY KEY, job TEXT NOT NULL, status TEXT NOT NULL, receipt TEXT); '
                             'CREATE TABLE revocation_outbox (request_id TEXT PRIMARY KEY, fence TEXT NOT NULL, status TEXT NOT NULL, receipt TEXT);')
            db.execute('INSERT INTO state VALUES (1,?)', (canonical(state),))
            ControlPlane.initialize(db, guarded)
        return root, digest(canonical(policy))

    def connect(self):
        db = sqlite3.connect(self.path.as_uri()+'?mode=rw', uri=True, timeout=2, isolation_level=None)
        db.execute('PRAGMA synchronous=FULL')
        return db

    def require(self, condition, reason):
        if self.enforce and not condition:
            raise Denied(reason)

    def execute(self, request, *, deadline=None, fleet_epoch=None):
        """Journal every bounded JSON attempt, including revoked and cached calls."""
        try:
            request = strict_json(canonical(request))
            if len(canonical(request)) > 16384:
                return {'status':'DENIED', 'reason':'request too large', 'effect_committed':False}
        except (ValueError, TypeError, RecursionError, OverflowError):
            return {'status':'DENIED', 'reason':'invalid JSON request', 'effect_committed':False}
        journal = AttemptJournal(self.path)
        try:
            seq = journal.begin(request)
        except Exception:
            return {'status':'UNAVAILABLE', 'reason':'attempt journal unavailable', 'effect_committed':False}
        operation = lambda: self._execute(request, deadline=deadline, fleet_epoch=fleet_epoch)
        response = self.fleet.execute(fleet_epoch, operation, deadline) if self.fleet else operation()
        # A denial of a new dispatch does not erase a prior uncertain delivery.
        if response.get('status') == 'DENIED':
            try:
                if type(request) is dict and set(request) == {'id','token','op','args'}:
                    binding = canonical({'id':request['id'], 'actor':digest(text(request['token'])),
                                         'op':request['op'], 'args':request['args']})
                    with self.connect() as check_db:
                        prior = check_db.execute('SELECT e.request,o.status FROM events e JOIN outbox o ON e.request_id=o.request_id WHERE e.request_id=?', (request['id'],)).fetchone()
                    if prior and prior[0] == binding:
                        response = {**response, 'authorization_status':'DENIED',
                                    'effect_committed': True if prior[1] == 'RECEIVED' else False if prior[1] == 'REJECTED' else None,
                                    'prior_delivery_status':prior[1]}
                        if prior[1] == 'RESERVED':
                            response['status'] = 'UNKNOWN'
                            response['reason'] += '; prior delivery requires reconciliation'
            except Exception:
                response = {'status':'UNAVAILABLE','reason':'prior delivery check failed; reconcile before retry','effect_committed':None}
        try:
            journal.finish(seq, response)
        except Exception:
            return {'status':'UNAVAILABLE', 'reason':'attempt completion unknown; reconcile before retry', 'effect_committed':None}
        return response

    def _execute(self, request, *, deadline=None, fleet_epoch=None):
        """Return EXECUTED, DENIED, REPLAY or UNAVAILABLE; failures are never wins."""
        db = None
        try:
            request = strict_json(canonical(request))  # private, bounded immutable snapshot
            if len(canonical(request)) > 16384:
                raise ValueError('request too large')
            fields(request, {'id', 'token', 'op', 'args'})
            rid, token, op = text(request['id']), text(request['token']), text(request['op'])
            args = request['args']
            if type(args) is not dict:
                raise ValueError('arguments must be object')
            actor_id = digest(token)
            stored_request = {'id':rid, 'actor':actor_id, 'op':op, 'args':args}
            encoded = canonical(stored_request)
            db = self.connect(); db.execute('BEGIN IMMEDIATE')
            if deadline is not None and time.monotonic() >= deadline:
                raise Denied('request expired while waiting for transaction')
            row = db.execute('SELECT payload FROM state WHERE id=1').fetchone()
            if row is None:
                raise RuntimeError('missing workflow state')
            state = strict_json(row[0])
            if digest(canonical(state['policy'])) != self.expected_policy:
                raise RuntimeError('policy digest mismatch')
            controls = ControlPlane.load(db)
            if controls['supported'] != state['policy']['guarded']:
                raise RuntimeError('profile integrity mismatch')
            actor = state['actors'].get(actor_id)
            if actor is None:
                raise Denied('unknown capability')
            # Check revocation BEFORE cached response, including every ancestor.
            cursor, visited = actor_id, set()
            while cursor is not None:
                if cursor in visited or len(visited) > 9:
                    raise RuntimeError('invalid delegation graph')
                visited.add(cursor)
                entry = state['actors'][cursor]
                self.require(not entry['revoked'], 'capability or ancestor revoked')
                cursor = entry['parent']
            if controls['supported'] and self.enforce:
                if op not in TOOLS:
                    raise Denied('unknown operation')
                self.require(op in actor['tools'], 'operation outside delegated authority')
            approval_key = ControlPlane.gate(db, request, fleet_epoch) if self.enforce else None
            old = db.execute('SELECT request,response FROM events WHERE request_id=?', (rid,)).fetchone()
            if old:
                if old[0] != encoded:
                    raise Denied('request ID reused with different action or identity')
                ControlPlane.consume(db, approval_key)
                db.commit()
                cached = strict_json(old[1])
                if self.delivery is not None and op == 'revoke' and cached['status']=='EXECUTED':
                    return self._fence_revocation(rid)
                if self.delivery is not None and cached['status'] == 'PENDING':
                    return self._dispatch(request, deadline=deadline, fleet_epoch=fleet_epoch)
                return {'status':'REPLAY', 'original':cached, 'effect_committed':False}
            if db.execute('SELECT count(*) FROM events').fetchone()[0] >= MAX_EVENTS:
                raise RuntimeError('workflow evidence capacity exhausted')
            effect = None
            state_before_action = canonical(state)
            try:
                if op not in TOOLS:
                    raise Denied('unknown operation')
                self.require(op in actor['tools'], 'operation outside delegated authority')
                if deadline is not None and time.monotonic() >= deadline:
                    raise Denied('request expired before execution')
                result, effect = self.apply(state, actor_id, op, args, rid)
                response = {'status':'EXECUTED', 'result':result, 'effect_committed':effect is not None}
                if self.delivery is not None and op == 'revoke':
                    target=digest(args['token']);subtree=[]
                    for candidate in state['actors']:
                        cursor=candidate;visited=set()
                        while cursor is not None:
                            if cursor in visited or len(visited)>9:raise RuntimeError('invalid delegation graph')
                            visited.add(cursor)
                            if cursor==target:
                                subtree.append(candidate);break
                            cursor=state['actors'][cursor]['parent']
                    fence={'workflow':self.path.stem,'request_id':rid,'actors':sorted(subtree)}
                    db.execute('INSERT INTO revocation_outbox VALUES(?,?,?,NULL)',(rid,canonical(fence),'PENDING'))
                    # This journal entry records LOCAL revocation only. Execution
                    # cannot report a full service fence until _fence_revocation.
                    response['result']={**result,'service_fenced':False}
                if self.delivery is not None and op == 'publish' and args['destination'] == 'external':
                    from .external_delivery import SERVICE, fingerprint, encode
                    if not controls['supported']:
                        raise Denied('external delivery requires guarded profile')
                    until = min(controls['environment_until'], deadline if deadline is not None else time.monotonic()+3)
                    until = min(until, controls['approvals'][approval_key]['until'] if approval_key else controls['monitor_until'])
                    identity = {'service':SERVICE,'workflow':self.path.stem,'actor':actor_id,'request_id':rid}
                    job = {**identity,'key':fingerprint(identity),'epoch':fleet_epoch,'text':args['text'],
                           'until':until,'boot_id':controls['boot_id']}
                    db.execute('INSERT INTO outbox VALUES(?,?,?,NULL)',(rid,encode({'job':job,'control_epoch':controls['epoch']}),'RESERVED'))
                    effect = None
                    response = {'status':'PENDING','result':{'delivered':False,'delivery_key':job['key']},'effect_committed':None}
            except (Denied, ValueError, TypeError) as exc:
                state = strict_json(state_before_action)
                response = {'status':'DENIED', 'reason':str(exc), 'effect_committed':False}
            # Denied actions must not mutate state: apply validates before mutations.
            previous = db.execute('SELECT hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
            previous = previous[0] if previous else '0'*64
            encoded_response = canonical(response)
            event_hash = digest(previous+encoded+encoded_response)
            cur = db.execute('INSERT INTO events(request_id,request,response,previous_hash,hash) VALUES (?,?,?,?,?)',
                             (rid,encoded,encoded_response,previous,event_hash))
            if effect:
                db.execute('INSERT INTO effects VALUES (?,?,?)', (cur.lastrowid, effect['kind'], canonical(effect)))
            db.execute('UPDATE state SET payload=? WHERE id=1', (canonical(state),))
            if deadline is not None and time.monotonic() >= deadline:
                raise Denied('request expired before commit')
            if self.enforce:
                try:
                    ControlPlane.gate(db, request, fleet_epoch)  # Lease/approval must remain valid at commit.
                except ApprovalRequired:
                    raise Denied('monitoring or approval expired before commit')
            if response['status'] in ('EXECUTED','PENDING'):
                ControlPlane.consume(db, approval_key)
            db.commit()
            if self.delivery is not None and op == 'revoke' and response['status']=='EXECUTED':
                return self._fence_revocation(rid)
            if response['status'] == 'PENDING':
                return self._dispatch(request, deadline=deadline, fleet_epoch=fleet_epoch)
            return response
        except ApprovalRequired as exc:
            try:
                if db: db.commit()  # Persist only the restriction latch; no effect has run.
            except Exception:
                if db: db.rollback()
                return {'status':'UNAVAILABLE', 'reason':'restriction persistence failed', 'effect_committed':False}
            return {'status':'APPROVAL_REQUIRED', 'reason':str(exc), 'effect_committed':False}
        except (Denied, RestrictionDenied) as exc:
            if db: db.rollback()
            return {'status':'DENIED', 'reason':str(exc), 'effect_committed':False}
        except (ValueError, TypeError, RecursionError, OverflowError) as exc:
            if db: db.rollback()
            return {'status':'UNAVAILABLE' if db else 'DENIED', 'reason':'validation failure: '+type(exc).__name__, 'effect_committed':None if db else False}
        except Exception as exc:
            if db: db.rollback()
            return {'status':'UNAVAILABLE', 'reason':type(exc).__name__, 'effect_committed':None}
        finally:
            if db: db.close()

    def _fence_revocation(self, request_id):
        """Idempotently finish a committed revocation; never undo local denial."""
        try:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                row=db.execute('SELECT fence,status,receipt FROM revocation_outbox WHERE request_id=?',(request_id,)).fetchone()
                if not row:return {'status':'DENIED','reason':'unknown durable revocation','effect_committed':False}
                fence=strict_json(row[0])
                receipt=strict_json(row[2]) if row[1]=='FENCED' else self.delivery.revoke_actors(**fence)
                from .external_delivery import fingerprint
                if (type(receipt) is not dict or receipt.get('status')!='FENCED'
                    or any(receipt.get(k)!=fence[k] for k in ('workflow','request_id','actors'))
                    or receipt.get('binding')!=fingerprint(fence)
                    or type(receipt.get('recorded_ns')) is not int or receipt['recorded_ns']<=0):
                    raise RuntimeError('invalid actor fence acknowledgement')
                db.execute('UPDATE revocation_outbox SET status=?,receipt=? WHERE request_id=?',
                           ('FENCED',canonical(receipt),request_id));db.commit()
            return {'status':'EXECUTED','result':{'revoked':True,'service_fenced':True,
                    'receiver_receipt':receipt,'acknowledged_ns':time.monotonic_ns()},'effect_committed':False}
        except Exception as exc:
            return {'status':'UNKNOWN','result':{'revoked':True,'service_fenced':None},
                    'revocation_status':'INCOMPLETE','reason':'service actor fence unconfirmed: '+type(exc).__name__,
                    'effect_committed':False}

    def reconcile_revocation(self, request_id):
        if self.delivery is None:raise RuntimeError('service receiver required')
        return self._fence_revocation(text(request_id))

    def _dispatch(self, request, *, deadline, fleet_epoch):
        # Fleet lock remains held by execute. Workflow lock prevents concurrent
        # revocation or sensitivity changes between revalidation and delivery.
        sent = False
        try:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                row=db.execute('SELECT job,status,receipt FROM outbox WHERE request_id=?',(request['id'],)).fetchone()
                if not row: raise RuntimeError('missing reservation')
                reserved=strict_json(row[0]); job=reserved['job']
                if row[1] in ('RECEIVED','REJECTED'):
                    receipt=strict_json(row[2])
                    return self._delivery_response(receipt)
                state=strict_json(db.execute('SELECT payload FROM state WHERE id=1').fetchone()[0])
                controls=ControlPlane.load(db)
                from .workflow_controls import BOOT_ID
                cursor=job['actor']; visited=set()
                while cursor is not None:
                    if cursor in visited or len(visited)>9: raise RuntimeError('invalid delegation graph')
                    visited.add(cursor); entry=state['actors'][cursor]
                    if entry['revoked']: raise Denied('revoked reserved authority')
                    cursor=entry['parent']
                if digest(canonical(state['policy']))!=self.expected_policy: raise RuntimeError('policy digest mismatch')
                if (controls['epoch']!=reserved['control_epoch'] or controls['suspended'] or controls['boot_id']!=BOOT_ID
                    or controls['environment_until']<=time.monotonic() or job['until']<=time.monotonic()
                    or job['epoch']!=fleet_epoch or state['sensitive_seen']
                    or (deadline is not None and deadline<=time.monotonic())):
                    raise Denied('reservation no longer valid; reconcile before retry')
                # No automatic background delivery. Retrying dispatch requires this
                # current authority check and reuses the exact stored service job.
                sent=True
                receipt=self.delivery.deliver(job)
                from .external_delivery import fingerprint
                if (receipt.get('status') not in ('RECEIVED','REJECTED') or receipt.get('key')!=job['key']
                    or receipt.get('binding')!=fingerprint(job)):
                    raise RuntimeError('invalid service receipt')
                db.execute('UPDATE outbox SET status=?,receipt=? WHERE request_id=?',
                           (receipt['status'],canonical(receipt),request['id']));db.commit()
                return self._delivery_response(receipt)
        except Exception as exc:
            # Reservation may have been delivered during a previous lost response.
            # Even a pre-dispatch failure must not turn its history into safe denial.
            return {'status':'UNKNOWN','reason':type(exc).__name__+': reconcile delivery receipt',
                    'effect_committed':None,'dispatch_attempted':sent}

    @staticmethod
    def _delivery_response(receipt):
        received=receipt['status']=='RECEIVED'
        return {'status':'EXECUTED' if received else 'REJECTED',
                'result':{'delivered':received,'service_receipt':receipt},'effect_committed':received}

    def reconcile_delivery(self, request_id):
        """Trusted receipt-only operation: never dispatches or grants authority."""
        if self.delivery is None: raise RuntimeError('no external service')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT job FROM outbox WHERE request_id=?',(text(request_id),)).fetchone()
            if not row: raise ValueError('unknown reservation')
            job=strict_json(row[0])['job']; receipt=self.delivery.receipt(job['key'])
            from .external_delivery import fingerprint
            if receipt.get('status')=='ABSENT':
                # ABSENT is a current snapshot; delayed messages may still arrive.
                return {'status':'UNKNOWN','effect_committed':None,'service_receipt':receipt}
            if (receipt.get('status') not in ('RECEIVED','REJECTED') or receipt.get('key')!=job['key']
                or receipt.get('binding')!=fingerprint(job)): raise RuntimeError('invalid service receipt')
            db.execute('UPDATE outbox SET status=?,receipt=? WHERE request_id=?',
                       (receipt['status'],canonical(receipt),request_id));db.commit()
            return self._delivery_response(receipt)

    def apply(self, state, aid, op, args, rid):
        actor = state['actors'][aid]
        if op == 'delegate':
            fields(args, {'tools'})
            caps = args['tools']
            if type(caps) is not list or len(caps)>len(TOOLS) or any(type(x) is not str for x in caps) or len(set(caps))!=len(caps):
                raise ValueError('invalid tools')
            self.require(set(caps) <= set(actor['tools']), 'delegation cannot widen authority')
            if not set(caps) <= TOOLS or actor['depth'] >= 8 or len(state['actors']) >= 128:
                raise Denied('delegation limit')
            token = hmac.new(state['seed'].encode(), rid.encode(), hashlib.sha256).hexdigest()
            state['actors'][digest(token)] = {'parent':aid, 'tools':sorted(caps), 'revoked':False, 'depth':actor['depth']+1}
            return {'token':token, 'tools':sorted(caps)}, None
        if op == 'revoke':
            fields(args, {'token'})
            target = digest(text(args['token']))
            if target not in state['actors']:
                raise Denied('unknown target')
            cursor = state['actors'][target]['parent']
            ancestors = set()
            while cursor is not None:
                if cursor in ancestors or len(ancestors)>9: raise RuntimeError('invalid graph')
                ancestors.add(cursor); cursor = state['actors'][cursor]['parent']
            self.require(aid in ancestors, 'only an ancestor may revoke')
            state['actors'][target]['revoked'] = True
            return {'revoked':True}, None
        if op == 'read':
            fields(args, {'object'})
            name = text(args['object'])
            allowed = state['policy'].get('read_objects')
            self.require(allowed is None or name in allowed, 'object outside task read authority')
            obj = state['objects'].get(name)
            if obj is None: raise Denied('unknown object')
            if obj['sensitive']: state['sensitive_seen'] = True
            return dict(obj), None
        if op == 'transform':
            fields(args, {'object','encoding'})
            name = text(args['object'])
            allowed = state['policy'].get('read_objects')
            self.require(allowed is None or name in allowed, 'object outside task read authority')
            obj = state['objects'].get(name)
            if obj is None: raise Denied('unknown object')
            if args['encoding'] not in ('base64','hex'): raise ValueError('unknown encoding')
            content = obj['content'].encode()
            encoded = base64.b64encode(content).decode() if args['encoding']=='base64' else content.hex()
            if len(encoded)>4096 or len(state['objects'])>=128: raise Denied('object limit')
            handle = 'derived-'+digest(rid)[:24]
            state['objects'][handle] = {'content':encoded,'sensitive':obj['sensitive']}
            # Returning derived sensitive bytes also counts as disclosure to the workflow.
            if obj['sensitive']: state['sensitive_seen'] = True
            return {'object':handle, **state['objects'][handle]}, None
        if op == 'purchase':
            fields(args, {'sku','quantity'})
            sku, quantity = args['sku'], args['quantity']
            if type(sku) is not str or sku not in CATALOG or type(quantity) is not int or not 1 <= quantity <= 100:
                raise ValueError('invalid catalog purchase')
            cost = state['policy']['catalog'][sku]*quantity
            self.require(state['used']+cost <= state['policy']['budget_cents'], 'shared workflow budget exhausted')
            state['used'] += cost
            effect = {'kind':'purchase','cost_cents':cost,'sku':sku,'quantity':quantity,'actor':aid}
            return {'used_cents':state['used']}, effect
        if op == 'publish':
            # Literal publication is covered too: sensitive_seen cannot be cleared by
            # paraphrasing, changing agents, waiting, resetting the client, or encoding.
            fields(args, {'destination','text'})
            destination = args['destination']; content = text(args['text'], 4096)
            if destination not in ('internal','external'): raise ValueError('unknown destination')
            contract = state['policy'].get('publication_contract')
            if contract is not None:
                self.require(destination == contract['destination'] and digest(content) in contract['text_sha256'],
                             'publication differs from the immutable task contract')
                self.require(type(state.get('publication_used')) is int and 0 <= state['publication_used'] < contract['max_publications'],
                             'publication budget exhausted')
                state['publication_used'] += 1
            self.require(destination=='internal' or not state['sensitive_seen'], 'sensitive workflow cannot publish externally')
            effect = {'kind':'publish','destination':destination,'text':content,'actor':aid,
                      'sensitive_seen':state['sensitive_seen']}
            return {'delivered':True}, effect
        if op == 'change_production':
            fields(args, {})
            self.require(False, 'production changes forbidden')
            return {'changed':True}, {'kind':'production_change','actor':aid}
        raise Denied('unknown operation')

    def evidence(self):
        with self.connect() as db:
            state = strict_json(db.execute('SELECT payload FROM state WHERE id=1').fetchone()[0])
            outbox_supported = db.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='outbox'").fetchone()[0] == 1
            deliveries = [dict(zip(('request_id','reservation','status','receipt'),row)) for row in db.execute('SELECT request_id,job,status,receipt FROM outbox ORDER BY rowid')] if outbox_supported else []
            revocation_supported=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='revocation_outbox'").fetchone() is not None
            revocations=[dict(zip(('request_id','fence','status','receipt'),row)) for row in db.execute('SELECT request_id,fence,status,receipt FROM revocation_outbox ORDER BY rowid')] if revocation_supported else []
            return {'controls':ControlPlane.load(db), 'root_actor':state['root_actor'], 'policy':state['policy'], 'used_cents':state['used'], 'sensitive_seen':state['sensitive_seen'],
                    'revocations':revocations,
                    'attempts':[dict(zip(('seq','request_hash','actor_hash','operation','started_ns','finished_ns','status','effect_committed'),row)) for row in db.execute('SELECT seq,request_hash,actor_hash,operation,started_ns,finished_ns,status,effect_committed FROM attempts ORDER BY seq')],
                    'external_delivery_schema':outbox_supported, 'deliveries':deliveries,
                    'events':[dict(zip(('seq','request','response','previous_hash','hash'),row)) for row in db.execute('SELECT seq,request,response,previous_hash,hash FROM events ORDER BY seq')],
                    'effects':[strict_json(row[0]) for row in db.execute('SELECT payload FROM effects ORDER BY seq')]}
