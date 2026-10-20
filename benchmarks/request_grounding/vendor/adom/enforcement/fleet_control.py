"""A trusted, persistent stop barrier for one broker deployment.

All effect transactions hold the same fleet lock. Stop acknowledgement follows
completion of those transactions; later transactions see the stopped latch.
This is synthetic-effect containment, not remote cancellation or process killing.
"""
import json
import os
from pathlib import Path
import sqlite3
import time


class FleetControl:
    def __init__(self, path):
        self.path = Path(path).resolve()

    @staticmethod
    def create(path):
        path = Path(path)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with sqlite3.connect(path) as db:
            db.executescript('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; '
                             'CREATE TABLE fleet (id INTEGER PRIMARY KEY CHECK(id=1), epoch INTEGER NOT NULL, stopped INTEGER NOT NULL); '
                             'CREATE TABLE transitions (epoch INTEGER PRIMARY KEY, stopped INTEGER, wall_ns INTEGER, monotonic_ns INTEGER);')
            db.execute('INSERT INTO fleet VALUES (1,0,0)')

    def connect(self, deadline=None):
        timeout = 2 if deadline is None else max(0, min(2, deadline-time.monotonic()))
        db = sqlite3.connect(self.path.as_uri()+'?mode=rw', uri=True, timeout=timeout,
                             isolation_level=None)
        db.execute('PRAGMA synchronous=FULL')
        return db

    @staticmethod
    def state(db):
        row = db.execute('SELECT epoch,stopped FROM fleet WHERE id=1').fetchone()
        if row is None or type(row[0]) is not int or row[0] < 0 or type(row[1]) is not int or row[1] not in (0,1):
            raise RuntimeError('invalid fleet state')
        return {'epoch':row[0], 'stopped':bool(row[1])}

    def transition(self, stopped):
        if type(stopped) is not bool:
            raise ValueError('invalid stop state')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            state = self.state(db)
            # Every explicit transition invalidates old queued request epochs.
            epoch = state['epoch']+1
            if epoch > 4096:
                raise RuntimeError('fleet transition evidence capacity exhausted')
            wall, mono = time.time_ns(), time.monotonic_ns()
            db.execute('UPDATE fleet SET epoch=?,stopped=? WHERE id=1', (epoch,int(stopped)))
            db.execute('INSERT INTO transitions VALUES (?,?,?,?)', (epoch,int(stopped),wall,mono))
            db.commit()
        return {'epoch':epoch, 'stopped':stopped, 'acknowledged_ns':time.monotonic_ns(),
                'transition_ns':mono}

    def status(self):
        with self.connect() as db:
            return self.state(db)

    def execute(self, epoch, operation, deadline=None):
        """Keep the fleet lock until the nested synthetic effect transaction ends."""
        try:
            with self.connect(deadline) as db:
                db.execute('BEGIN IMMEDIATE')
                state = self.state(db)
                if state['stopped']:
                    return {'status':'DENIED','reason':'fleet stopped','effect_committed':False,
                            'fleet_epoch':state['epoch']}
                if type(epoch) is not int or epoch != state['epoch']:
                    return {'status':'DENIED','reason':'stale or invalid fleet epoch','effect_committed':False,
                            'fleet_epoch':state['epoch']}
                if deadline is not None and time.monotonic() >= deadline:
                    return {'status':'DENIED','reason':'request expired at fleet barrier','effect_committed':False}
                # The fleet database is read-only within this transaction. Its lock
                # serializes stop acknowledgement with the workflow's effect commit.
                result = operation()
                db.rollback()
                return result
        except Exception as exc:
            return {'status':'UNAVAILABLE','reason':'fleet barrier unavailable: '+type(exc).__name__,
                    'effect_committed':None}
