"""Durable, bounded publication protocol for the supported local receiver only.

Reservation is committed in the authorization database before dispatch. Receiver
receipts, including rejection, are service-owned and idempotent. Unknown outcomes
remain unknown until a trusted reconciliation query; they are never safe denials.
"""
import hashlib
import json
import math
import socket
import sqlite3
import struct
import time
from pathlib import Path

SERVICE = 'report-receiver-v1'


def encode(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'), allow_nan=False)


def fingerprint(x):
    return hashlib.sha256(encode(x).encode()).hexdigest()


class LocalReceiverClient:
    def __init__(self, data='/delivery/data.sock', admin='/delivery/admin.sock'):
        self.data, self.admin = data, admin

    def call(self, message, *, admin=False):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(1)
            sock.connect(self.admin if admin else self.data)
            uid = struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
            if uid != 10002:
                raise RuntimeError('unexpected service identity')
            sock.sendall((encode(message)+'\n').encode())
            raw = b''
            while not raw.endswith(b'\n') and len(raw) <= 20000:
                block = sock.recv(20001-len(raw))
                if not block: break
                raw += block
            if not raw.endswith(b'\n') or len(raw) > 20000:
                raise RuntimeError('invalid service response')
            from .workflow_authority import strict_json
            result = strict_json(raw)
            if not isinstance(result, dict): raise RuntimeError('invalid service response')
            return result

    def deliver(self, job): return self.call({'op':'deliver','job':job})
    def receipt(self, key): return self.call({'op':'receipt','key':key}, admin=True)
    def fence(self, epoch, stopped): return self.call({'op':'fence','epoch':epoch,'stopped':stopped}, admin=True)
    def revoke_actors(self, workflow, request_id, actors):
        return self.call({'op':'revoke_actors','workflow':workflow,'request_id':request_id,'actors':actors}, admin=True)
    def status(self): return self.call({'op':'status'}, admin=True)


class ReceiverStore:
    """Owned exclusively by the receiver. State loss never silently reinitializes."""
    def __init__(self, path): self.path = Path(path).resolve()

    @staticmethod
    def create(path):
        import os
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd)
        with sqlite3.connect(path) as db:
            db.executescript('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; '
                'CREATE TABLE control(id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL,stopped INTEGER NOT NULL); '
                'CREATE TABLE receipts(key TEXT PRIMARY KEY,binding TEXT NOT NULL,job TEXT NOT NULL,status TEXT NOT NULL,recorded_ns INTEGER NOT NULL); '
                'CREATE TABLE fences(epoch INTEGER PRIMARY KEY,stopped INTEGER NOT NULL,recorded_ns INTEGER NOT NULL); '
                'CREATE TABLE actor_revocations(workflow TEXT NOT NULL,actor TEXT NOT NULL,recorded_ns INTEGER NOT NULL,PRIMARY KEY(workflow,actor)); '
                'CREATE TABLE revocation_fences(workflow TEXT NOT NULL,request_id TEXT NOT NULL,binding TEXT NOT NULL,receipt TEXT NOT NULL,PRIMARY KEY(workflow,request_id));')
            # Fresh service is stopped. Explicit trusted synchronization is required.
            db.execute('INSERT INTO control VALUES(1,0,1)')

    def connect(self):
        db = sqlite3.connect(self.path.as_uri()+'?mode=rw', uri=True, isolation_level=None, timeout=2)
        db.execute('PRAGMA synchronous=FULL'); return db

    @staticmethod
    def state(db):
        # An old receiver must not silently start without the new fence ledger.
        for table in ('actor_revocations','revocation_fences'):
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
                raise RuntimeError('receiver actor-fence schema missing; explicit upgrade required')
        row = db.execute('SELECT epoch,stopped FROM control WHERE id=1').fetchone()
        if not row or type(row[0]) is not int or row[0] < 0 or row[1] not in (0,1):
            raise RuntimeError('invalid receiver control')
        return {'epoch':row[0], 'stopped':bool(row[1])}

    def status(self):
        with self.connect() as db: return self.state(db)

    @staticmethod
    def validate(job):
        if type(job) is not dict or set(job) != {'key','service','workflow','actor','request_id','epoch','text','until','boot_id'}:
            raise ValueError('invalid delivery contract')
        if job['service'] != SERVICE or type(job['epoch']) is not int or job['epoch'] < 0:
            raise ValueError('invalid service or epoch')
        for k, limit in [('key',64),('workflow',64),('actor',64),('request_id',128),('text',4096),('boot_id',128)]:
            if type(job[k]) is not str or not 0 < len(job[k].encode()) <= limit: raise ValueError('invalid field')
        if type(job['until']) not in (int,float) or not math.isfinite(job['until']): raise ValueError('invalid expiry')
        identity = {k:job[k] for k in ('service','workflow','actor','request_id')}
        if job['key'] != fingerprint(identity): raise ValueError('invalid request identity')

    @staticmethod
    def result(row):
        return {'status':row[0], 'key':row[1], 'binding':row[2], 'recorded_ns':row[3]}

    def receipt(self, key):
        if type(key) is not str or len(key) != 64: raise ValueError('invalid receipt key')
        with self.connect() as db:
            row=db.execute('SELECT status,key,binding,recorded_ns FROM receipts WHERE key=?',(key,)).fetchone()
            return self.result(row) if row else {'status':'ABSENT','key':key}

    def deliver(self, job):
        self.validate(job); binding=fingerprint(job)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE'); state=self.state(db)
            old=db.execute('SELECT status,key,binding,recorded_ns FROM receipts WHERE key=?',(job['key'],)).fetchone()
            if old:
                if old[2] != binding: raise ValueError('request ID binding conflict')
                return self.result(old)
            if db.execute('SELECT count(*) FROM receipts').fetchone()[0] >= 4096: raise RuntimeError('receipt capacity exhausted')
            from .workflow_controls import BOOT_ID
            revoked=db.execute('SELECT 1 FROM actor_revocations WHERE workflow=? AND actor=?',
                               (job['workflow'],job['actor'])).fetchone() is not None
            allowed = not revoked and not state['stopped'] and job['epoch']==state['epoch'] and job['until']>time.monotonic() and job['boot_id']==BOOT_ID
            status='RECEIVED' if allowed else 'REJECTED'
            ns=time.monotonic_ns()
            # For this supported service, this row IS the entire external effect.
            # No arbitrary command, downstream forwarding or external purchase.
            db.execute('INSERT INTO receipts VALUES(?,?,?,?,?)',(job['key'],binding,encode(job),status,ns)); db.commit()
            return {'status':status,'key':job['key'],'binding':binding,'recorded_ns':ns}

    def revoke_actors(self, workflow, request_id, actors):
        """Durably fence a broker-selected subtree, serialized with actual effects.

        Actor IDs are never reused. Fences are additive, survive fleet resume,
        and cannot be undone by an agent or a replayed request. Existing receipts
        remain historical facts; returning one never creates a new effect.
        """
        if (type(workflow) is not str or not 1<=len(workflow)<=64
            or type(request_id) is not str or not 1<=len(request_id)<=128
            or type(actors) is not list or not 1<=len(actors)<=128
            or any(type(a) is not str or len(a)!=64 or any(c not in '0123456789abcdef' for c in a) for a in actors)
            or actors!=sorted(set(actors))):
            raise ValueError('invalid actor fence')
        binding=fingerprint({'workflow':workflow,'request_id':request_id,'actors':actors})
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');self.state(db)
            old=db.execute('SELECT binding,receipt FROM revocation_fences WHERE workflow=? AND request_id=?',
                           (workflow,request_id)).fetchone()
            if old:
                if old[0]!=binding:raise ValueError('revocation request binding conflict')
                return json.loads(old[1])
            if db.execute('SELECT count(*) FROM revocation_fences').fetchone()[0]>=4096:
                raise RuntimeError('revocation receipt capacity exhausted')
            missing=[a for a in actors if not db.execute('SELECT 1 FROM actor_revocations WHERE workflow=? AND actor=?',(workflow,a)).fetchone()]
            if db.execute('SELECT count(*) FROM actor_revocations').fetchone()[0]+len(missing)>4096:
                raise RuntimeError('actor fence capacity exhausted')
            ns=time.monotonic_ns()
            db.executemany('INSERT INTO actor_revocations VALUES(?,?,?)',[(workflow,a,ns) for a in missing])
            receipt={'status':'FENCED','workflow':workflow,'request_id':request_id,'actors':actors,
                     'binding':binding,'recorded_ns':ns}
            db.execute('INSERT INTO revocation_fences VALUES(?,?,?,?)',(workflow,request_id,binding,encode(receipt)))
            db.commit()
            return receipt

    def fence(self, epoch, stopped):
        if type(epoch) is not int or epoch<0 or type(stopped) is not bool: raise ValueError('invalid fence')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE'); current=self.state(db)
            if epoch < current['epoch']: raise ValueError('stale fence')
            old=db.execute('SELECT stopped FROM fences WHERE epoch=?',(epoch,)).fetchone()
            if old:
                if bool(old[0]) != stopped:
                    if not stopped: raise ValueError('same-epoch authority cannot widen')
                    db.execute('UPDATE fences SET stopped=1 WHERE epoch=?',(epoch,))
            else:
                if db.execute('SELECT count(*) FROM fences').fetchone()[0]>=4096: raise RuntimeError('fence capacity exhausted')
                db.execute('INSERT INTO fences VALUES(?,?,?)',(epoch,int(stopped),time.monotonic_ns()))
            db.execute('UPDATE control SET epoch=?,stopped=? WHERE id=1',(epoch,int(stopped)));db.commit()
        return {'epoch':epoch,'stopped':stopped,'acknowledged_ns':time.monotonic_ns()}


class DeliveryCoordinator:
    def __init__(self, fleet, receiver): self.fleet,self.receiver=fleet,receiver

    def stop(self):
        requested=time.monotonic_ns();local=self.fleet.transition(True)
        try:
            ack=self.receiver.fence(local['epoch'], True)
            if ack.get('epoch') != local['epoch'] or ack.get('stopped') is not True: raise RuntimeError('invalid fence acknowledgement')
            return {'status':'STOPPED','requested_ns':requested,'fleet':local,'service':ack,'acknowledged_ns':time.monotonic_ns()}
        except Exception as exc:
            return {'status':'INCOMPLETE','requested_ns':requested,'fleet':local,'reason':type(exc).__name__,'acknowledged_ns':None}

    def synchronize(self):
        """Trusted restart reconciliation; never clears a persisted local stop."""
        with self.fleet.connect() as db:
            db.execute('BEGIN IMMEDIATE'); state=self.fleet.state(db)
            ack=self.receiver.fence(state['epoch'],state['stopped'])
            if ack.get('epoch')!=state['epoch'] or ack.get('stopped')!=state['stopped']: raise RuntimeError('fence mismatch')
            db.rollback();return ack

    def resume(self):
        # Keep broker admission stopped until the service accepts the next epoch.
        # A failure leaves local admission stopped; the service alone cannot dispatch.
        with self.fleet.connect() as db:
            db.execute('BEGIN IMMEDIATE'); state=self.fleet.state(db)
            if not state['stopped']: raise RuntimeError('stop before resume')
            epoch=state['epoch']+1
            if epoch>4096: raise RuntimeError('fleet transition evidence capacity exhausted')
            ack=self.receiver.fence(epoch,False)
            if ack.get('epoch')!=epoch or ack.get('stopped') is not False: raise RuntimeError('fence mismatch')
            ns=time.monotonic_ns()
            db.execute('UPDATE fleet SET epoch=?,stopped=0 WHERE id=1',(epoch,))
            db.execute('INSERT INTO transitions VALUES(?,?,?,?)',(epoch,0,time.time_ns(),ns));db.commit()
        return {'status':'RESUMED','epoch':epoch,'service':ack,'acknowledged_ns':time.monotonic_ns()}
