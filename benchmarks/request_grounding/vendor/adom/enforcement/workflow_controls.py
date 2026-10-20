"""Trusted workflow restrictions and bounded attempt evidence.

This API is operator/broker-owned. None of its mutation methods are agent operations.
Monitoring can add restrictions; only an explicit operator action can release them.
"""
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import time

MAX_ATTEMPTS = 4096
try:
    BOOT_ID = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
except OSError:
    # Offline macOS fixture only. Supported deployment uses the Linux boot ID.
    BOOT_ID = 'offline-' + str(round(time.time() - time.monotonic()))


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def request_digest(request):
    return hashlib.sha256(encode(request).encode()).hexdigest()


class ApprovalRequired(Exception):
    pass


class RestrictionDenied(Exception):
    pass


class ControlPlane:
    def __init__(self, path):
        self.path = Path(path).resolve()

    def connect(self):
        db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=2,
                             isolation_level=None)
        db.execute('PRAGMA synchronous=FULL')
        return db

    @staticmethod
    def initialize(db, supported):
        db.executescript('CREATE TABLE controls (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL); '
                         'CREATE TABLE attempts (seq INTEGER PRIMARY KEY AUTOINCREMENT, request_hash TEXT, '
                         'actor_hash TEXT, operation TEXT, started_ns INTEGER, finished_ns INTEGER, '
                         'status TEXT, effect_committed INTEGER);')
        state = {'supported': supported, 'boot_id': BOOT_ID, 'epoch': 0,
                 'environment_until': 0, 'monitor_until': 0, 'health': 'unavailable',
                 'review_required': bool(supported), 'suspended': False, 'approvals': {}}
        db.execute('INSERT INTO controls VALUES (1,?)', (encode(state),))

    @staticmethod
    def load(db):
        row = db.execute('SELECT payload FROM controls WHERE id=1').fetchone()
        if row is None:
            raise RuntimeError('missing workflow controls; initialize a new versioned fixture')
        state = json.loads(row[0])
        required = {'supported','boot_id','epoch','environment_until','monitor_until','health',
                    'review_required','suspended','approvals'}
        if set(state) != required or type(state['epoch']) is not int or state['epoch'] < 0:
            raise RuntimeError('invalid control state')
        if any(type(state[k]) is not bool for k in ('supported','review_required','suspended')):
            raise RuntimeError('invalid control state')
        if state['health'] not in ('healthy','degraded','unavailable') or type(state['approvals']) is not dict:
            raise RuntimeError('invalid control state')
        if any(type(state[k]) not in (int,float) or not math.isfinite(state[k])
               for k in ('environment_until','monitor_until')):
            raise RuntimeError('invalid lease')
        return state

    @staticmethod
    def store(db, state):
        db.execute('UPDATE controls SET payload=? WHERE id=1', (encode(state),))

    def mutate(self, fn):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            state = self.load(db)
            result = fn(state)
            self.store(db, state)
            db.commit()
            return result

    @staticmethod
    def ttl(value):
        if type(value) not in (int,float) or not math.isfinite(value) or not 0 < value <= 30:
            raise ValueError('lease must be positive and at most 30 seconds')
        return value

    def observe_environment(self, valid, ttl=4):
        if type(valid) is not bool:
            raise ValueError('expected boolean environment verdict')
        self.ttl(ttl)
        def update(s):
            if not valid or s['boot_id'] != BOOT_ID or s['environment_until'] <= time.monotonic():
                s['epoch'] += 1
                s['approvals'] = {}
            s['boot_id'] = BOOT_ID
            s['environment_until'] = time.monotonic() + ttl if valid else 0
        self.mutate(update)

    def observe_monitor(self, health, restriction='none', ttl=4):
        if health not in ('healthy','degraded','unavailable') or restriction not in ('none','review','suspend'):
            raise ValueError('invalid monitoring observation')
        self.ttl(ttl)
        def update(s):
            before = (s['health'], s['review_required'], s['suspended'])
            s['health'] = health
            s['monitor_until'] = time.monotonic() + ttl if health == 'healthy' else 0
            s['review_required'] |= health != 'healthy' or restriction in ('review','suspend')
            s['suspended'] |= restriction == 'suspend'
            if before != (s['health'],s['review_required'],s['suspended']):
                s['epoch'] += 1
                s['approvals'] = {}
        self.mutate(update)

    def release(self):
        """Explicit trusted operator release, never a monitoring result."""
        def update(s):
            now = time.monotonic()
            if s['boot_id'] != BOOT_ID or s['environment_until'] <= now or s['health'] != 'healthy' or s['monitor_until'] <= now:
                raise RestrictionDenied('healthy monitoring and verified environment required')
            s['suspended'] = False
            s['review_required'] = False
            s['epoch'] += 1
            s['approvals'] = {}
        self.mutate(update)

    def suspend(self):
        self.observe_monitor('degraded', 'suspend')

    def approve(self, request, ttl=3, fleet_epoch=None):
        self.ttl(ttl)
        key = request_digest(request if fleet_epoch is None else {"request":request,"fleet_epoch":fleet_epoch})
        def update(s):
            now = time.monotonic()
            if s['boot_id'] != BOOT_ID or s['environment_until'] <= now or s['suspended']:
                raise RestrictionDenied('approval cannot bypass failed enforcement or suspension')
            if (s['health'] != 'healthy' or s['monitor_until'] <= now) and not s['review_required']:
                s['review_required'] = True
                s['epoch'] += 1
                s['approvals'] = {}
            s['approvals'] = {k:v for k,v in s['approvals'].items() if v['until'] > now}
            if len(s['approvals']) >= 128:
                raise RuntimeError('approval capacity exhausted')
            s['approvals'][key] = {'epoch':s['epoch'], 'until':now+ttl}
        self.mutate(update)

    @classmethod
    def gate(cls, db, request, fleet_epoch=None):
        s = cls.load(db)
        if not s['supported']:
            return None
        now = time.monotonic()
        if s['boot_id'] != BOOT_ID or s['environment_until'] <= now:
            raise RestrictionDenied('enforcement environment unverified or stale')
        # Tightening authority stays possible through an authorized revoke operation.
        if request['op'] == 'revoke':
            return None
        if s['suspended']:
            raise RestrictionDenied('workflow suspended')
        stale = s['health'] != 'healthy' or s['monitor_until'] <= now
        if stale and not s['review_required']:
            s['review_required'] = True
            s['epoch'] += 1
            s['approvals'] = {}
            cls.store(db, s)
        if stale or s['review_required']:
            key = request_digest(request if fleet_epoch is None else {"request":request,"fleet_epoch":fleet_epoch})
            approval = s['approvals'].get(key)
            if not approval or approval['epoch'] != s['epoch'] or approval['until'] <= now:
                raise ApprovalRequired('exact-action approval required')
            return key
        return None

    @classmethod
    def consume(cls, db, key):
        if key:
            s = cls.load(db)
            del s['approvals'][key]
            cls.store(db, s)


class AttemptJournal(ControlPlane):
    def begin(self, request):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT count(*) FROM attempts').fetchone()[0] >= MAX_ATTEMPTS:
                raise RuntimeError('attempt evidence capacity exhausted')
            token = request.get('token','') if type(request) is dict else ''
            actor = hashlib.sha256(token.encode()).hexdigest() if type(token) is str else 'invalid'
            op = request.get('op','invalid') if type(request) is dict else 'invalid'
            op = op if type(op) is str and len(op) <= 128 else 'invalid'
            cur = db.execute('INSERT INTO attempts(request_hash,actor_hash,operation,started_ns,status) VALUES (?,?,?,?,?)',
                             (request_digest(request),actor,op,time.monotonic_ns(),'STARTED'))
            db.commit()
            return cur.lastrowid

    def finish(self, seq, response):
        with self.connect() as db:
            effect = response.get('effect_committed')
            cur = db.execute('UPDATE attempts SET finished_ns=?,status=?,effect_committed=? WHERE seq=? AND status=?',
                             (time.monotonic_ns(),response['status'],effect,seq,'STARTED'))
            if cur.rowcount != 1:
                raise RuntimeError('attempt completion mismatch')
