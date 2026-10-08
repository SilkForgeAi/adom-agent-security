"""Durable pre-dispatch reservations at documented GPT-4o-mini token rates."""
import sqlite3
from decimal import Decimal

MODEL = 'gpt-4o-mini-2024-07-18'
INPUT_NANOUSD = 150
OUTPUT_NANOUSD = 600
CONTEXT_LIMIT = 128000
OUTPUT_LIMIT = 8192
WORST_REQUEST_NANOUSD = CONTEXT_LIMIT * INPUT_NANOUSD + OUTPUT_LIMIT * OUTPUT_NANOUSD


class BudgetExceeded(RuntimeError):
    pass


class Budget:
    def __init__(self, path, usd):
        amount = Decimal(str(usd))
        if not amount.is_finite() or amount <= 0 or amount > 3:
            raise ValueError('Budget must be positive and no greater than $3')
        self.path = str(path)
        self.limit = int(amount * 1_000_000_000)
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS config(limit_nano INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY, reserved INTEGER NOT NULL, actual INTEGER, status TEXT NOT NULL)')
            rows = db.execute('SELECT limit_nano FROM config').fetchall()
            if not rows:
                db.execute('INSERT INTO config VALUES(?)', (self.limit,))
            elif rows != [(self.limit,)]:
                raise ValueError('Existing budget limit differs')

    def reserve(self):
        with sqlite3.connect(self.path, timeout=30) as db:
            db.execute('BEGIN IMMEDIATE')
            total = db.execute('SELECT COALESCE(SUM(COALESCE(actual,reserved)),0) FROM requests').fetchone()[0]
            if total + WORST_REQUEST_NANOUSD > self.limit:
                raise BudgetExceeded('Pre-dispatch token-cost reservation ceiling reached')
            cursor = db.execute('INSERT INTO requests(reserved,status) VALUES(?,?)', (WORST_REQUEST_NANOUSD, 'OUTCOME_UNKNOWN'))
            return cursor.lastrowid

    def settle(self, request_id, prompt, completion):
        if type(prompt) is not int or type(completion) is not int or not 0 <= prompt <= CONTEXT_LIMIT or not 0 <= completion <= OUTPUT_LIMIT:
            raise ValueError('Usage exceeds reserved request bounds; retain unknown reservation')
        cost = prompt * INPUT_NANOUSD + completion * OUTPUT_NANOUSD
        with sqlite3.connect(self.path, timeout=30) as db:
            cursor = db.execute("UPDATE requests SET actual=?,status='RETURNED' WHERE id=? AND status='OUTCOME_UNKNOWN'", (cost, request_id))
            if cursor.rowcount != 1:
                raise ValueError('Missing or already settled request')
        return cost

    def summary(self):
        with sqlite3.connect(self.path) as db:
            calls, actual, reserved = db.execute('SELECT COUNT(*),COALESCE(SUM(actual),0),COALESCE(SUM(CASE WHEN actual IS NULL THEN reserved ELSE 0 END),0) FROM requests').fetchone()
        return dict(requests=calls, returned_token_estimate_usd=actual / 1e9,
                    unknown_reserved_usd=reserved / 1e9, reservation_limit_usd=self.limit / 1e9,
                    billing='Token-rate accounting, not an authoritative provider billing limit. Failed/missing-usage requests retain full reservations; no cache discounts.')
