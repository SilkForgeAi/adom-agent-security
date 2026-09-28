"""
ADOM blast-radius control — fleet circuit breakers and consequence budgets.
(OWASP Agentic Top 10: ASI08 Cascading Failures; also LLM06 Unbounded Consumption / cost
asymmetry, and the containment half of ASI10 Rogue Agents.)

The action boundary answers "is THIS action harmful?". It cannot answer "has this agent done
ten thousand individually-reasonable things in four minutes?" or "is one agent's failure now
propagating through everything that depends on it?". That is what this module bounds.

THREAT MODEL
  1. Runaway agent — a loop issues endlessly many individually-benign actions. Bounded by
     per-agent action budgets over a rolling window.
  2. Consequence blast radius — a compromised agent racks up irreversible effects (deletes,
     spend, egress volume). Bounded by SEPARATE budgets per consequence class, so a benign-
     looking action budget can't be spent on destruction.
  3. Cascading failure — agent A degrades, and everything downstream of A amplifies it
     (retries, fan-out). Contained by a dependency graph: when A's breaker opens, dependents
     are ISOLATED rather than allowed to pile on.
  4. Thundering herd on recovery — everything retries the instant a breaker closes. Contained
     by HALF-OPEN state: a limited number of probe actions before full close.
  5. Cost asymmetry — one crafted input multiplies spend across a tool chain. Bounded by the
     spend budget, which is denominated in money, not calls.

DESIGN PRINCIPLES (consistent with the rest of ADOM)
  - FAIL-CLOSED. An open breaker DENIES. An unknown agent is denied when strict. Errors deny.
  - Budgets are per consequence class, not one pooled counter — irreversibility deserves its
    own ceiling.
  - Deterministic and cheap: rolling counters + monotonic clock, no model, no I/O.
  - This is a SECOND plane. It never replaces the action boundary; a call must pass both.

HONEST SCOPE
  - This bounds and contains cascades; it does not PREDICT them. Forecasting a fleet-wide
    cascade before it starts needs fleet observability and is not claimed here.
  - Budgets are per-process state. A distributed fleet needs a shared store (Redis, etc.) for
    fleet-wide truth; the interface is designed for that but the in-memory backend is single-
    process. Stated, not hidden.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

BLAST_VERSION = "blast-2026.08.16"

CLOSED, OPEN, HALF_OPEN = "closed", "open", "half_open"


@dataclass
class Budget:
    """Ceilings for one agent over a rolling window. None = unlimited (explicit opt-out)."""
    max_actions: Optional[int] = 500          # any mediated action
    max_destructive: Optional[int] = 5        # deletes / drops / irreversible writes
    max_spend: Optional[float] = 0.0          # money moved (default: none allowed)
    max_egress_bytes: Optional[int] = 10_000_000
    max_failures: Optional[int] = 10          # consecutive-ish failures before breaker opens
    window_seconds: float = 60.0


@dataclass
class BlastVerdict:
    allowed: bool
    state: str = CLOSED
    reason: str = ""
    signals: List[str] = field(default_factory=list)
    remaining: Dict[str, Any] = field(default_factory=dict)


class _Counters:
    """SLIDING-window counters.

    The previous implementation reset every counter to zero the moment the window elapsed — a
    FIXED window, despite `Budget.window_seconds` being documented as rolling. That leaves a
    seam at every boundary: an agent could spend its entire budget at t=59.9s and its entire
    budget again at t=60.1s, i.e. 2x the stated ceiling in 200ms. For a control whose purpose
    is bounding a runaway agent, the burst at the boundary is precisely the case that matters.

    This keeps the previous window's totals and decays them by how far into the current window
    we are — the standard sliding-window-counter approximation. Memory is O(1) per agent (no
    per-event log), so it stays usable at the decision rates ADOM targets.
    """

    __slots__ = ("actions", "destructive", "spend", "egress", "failures", "window_start",
                 "_p_actions", "_p_destructive", "_p_spend", "_p_egress", "_p_failures")

    def __init__(self, now: float):
        self.actions = 0
        self.destructive = 0
        self.spend = 0.0
        self.egress = 0
        self.failures = 0
        self.window_start = now
        self._p_actions = 0
        self._p_destructive = 0
        self._p_spend = 0.0
        self._p_egress = 0
        self._p_failures = 0

    def roll(self, now: float, window: float) -> None:
        if window <= 0:
            return
        elapsed = now - self.window_start
        if elapsed < window:
            return
        if elapsed < 2 * window:
            # One window has passed: the current bucket becomes the previous one.
            self._p_actions, self._p_destructive = self.actions, self.destructive
            self._p_spend, self._p_egress = self.spend, self.egress
            self._p_failures = self.failures
            self.window_start += window
        else:
            # More than two windows idle: nothing carries over.
            self._p_actions = self._p_destructive = self._p_egress = self._p_failures = 0
            self._p_spend = 0.0
            self.window_start = now
        self.actions = self.destructive = self.egress = self.failures = 0
        self.spend = 0.0

    def _weight(self, now: float, window: float) -> float:
        """Fraction of the PREVIOUS window still inside the trailing `window` seconds."""
        if window <= 0:
            return 0.0
        frac = (now - self.window_start) / window
        return max(0.0, min(1.0, 1.0 - frac))

    def sliding(self, now: float, window: float) -> Tuple[float, float, float, float, float]:
        """(actions, destructive, spend, egress, failures) over the trailing window."""
        w = self._weight(now, window)
        return (self.actions + self._p_actions * w,
                self.destructive + self._p_destructive * w,
                self.spend + self._p_spend * w,
                self.egress + self._p_egress * w,
                self.failures + self._p_failures * w)


class BlastRadiusController:
    """Fleet circuit breakers + consequence budgets. Every mediated action should call
    `check()` before execution and `record_failure()` on error."""

    def __init__(self, default_budget: Optional[Budget] = None,
                 fleet_budget: Optional[Budget] = None,
                 strict_unknown_agents: bool = True,
                 half_open_probes: int = 3,
                 cooldown_seconds: float = 30.0,
                 clock: Callable[[], float] = time.monotonic,
                 on_trip: Optional[Callable[[str, str], None]] = None):
        self.default_budget = default_budget or Budget()
        self.fleet_budget = fleet_budget
        self.strict_unknown_agents = strict_unknown_agents
        self.half_open_probes = max(1, half_open_probes)
        self.cooldown_seconds = cooldown_seconds
        self._clock = clock
        self.on_trip = on_trip

        self._budgets: Dict[str, Budget] = {}
        self._counters: Dict[str, _Counters] = {}
        self._state: Dict[str, str] = {}
        self._opened_at: Dict[str, float] = {}
        self._probes: Dict[str, int] = {}
        self._dependents: Dict[str, Set[str]] = {}     # agent -> agents that depend on it
        self._depends_on: Dict[str, Set[str]] = {}     # agent -> its upstream dependencies
        self._isolated: Set[str] = set()               # contained due to an upstream trip
        self._fleet = _Counters(self._clock())
        self._fleet_open = False
        self._lock = threading.RLock()
        self.audit: List[Tuple[str, BlastVerdict]] = []

    # ---- configuration ----
    def register(self, agent_id: str, budget: Optional[Budget] = None,
                 depends_on: Tuple[str, ...] = ()) -> None:
        with self._lock:
            self._budgets[agent_id] = budget or self.default_budget
            self._counters.setdefault(agent_id, _Counters(self._clock()))
            self._state.setdefault(agent_id, CLOSED)
            for up in depends_on:
                self._dependents.setdefault(up, set()).add(agent_id)
                self._depends_on.setdefault(agent_id, set()).add(up)

    # ---- the gate every action passes ----
    def check(self, agent_id: str, kind: str = "action", amount: float = 0.0,
              nbytes: int = 0) -> BlastVerdict:
        """kind: action | destructive | spend | egress. Returns allow/deny, fail-closed."""
        try:
            now = self._clock()
            with self._lock:
                if agent_id not in self._budgets:
                    if self.strict_unknown_agents:
                        return self._finish(agent_id, BlastVerdict(
                            False, OPEN, f"unregistered agent '{agent_id}' (strict)",
                            ["blast:unknown_agent:denied"]))
                    self.register(agent_id)

                if self._fleet_open:
                    return self._finish(agent_id, BlastVerdict(
                        False, OPEN, "fleet kill-switch engaged", ["blast:fleet_open:critical"]))

                if agent_id in self._isolated:
                    return self._finish(agent_id, BlastVerdict(
                        False, OPEN, f"'{agent_id}' isolated: an upstream dependency tripped",
                        ["blast:cascade_isolation:high"]))

                budget = self._budgets[agent_id]
                ctr = self._counters.setdefault(agent_id, _Counters(now))
                ctr.roll(now, budget.window_seconds)
                state = self._state.get(agent_id, CLOSED)

                # breaker state machine
                if state == OPEN:
                    if now - self._opened_at.get(agent_id, now) >= self.cooldown_seconds:
                        state = HALF_OPEN
                        self._state[agent_id] = HALF_OPEN
                        self._probes[agent_id] = 0
                        # Fresh counters on entering half-open. Without this the agent is
                        # judged on the stale counters that tripped it, so it re-trips on the
                        # first probe and can NEVER recover — a permanent-denial bug. A control
                        # that can't recover gets switched off by operators, which is worse
                        # than the risk it was added to manage.
                        ctr = _Counters(now)
                        self._counters[agent_id] = ctr
                    else:
                        return self._finish(agent_id, BlastVerdict(
                            False, OPEN, f"circuit open for '{agent_id}' (cooling down)",
                            ["blast:circuit_open:high"]))
                if state == HALF_OPEN:
                    # Probe allowance is clamped to the action budget: if it could exceed the
                    # budget, the probe itself would re-trip the breaker and the agent could
                    # never recover. Recovery must always be reachable.
                    probe_cap = self.half_open_probes
                    if budget.max_actions is not None:
                        probe_cap = min(probe_cap, budget.max_actions)
                    if self._probes.get(agent_id, 0) >= probe_cap:
                        return self._finish(agent_id, BlastVerdict(
                            False, HALF_OPEN,
                            f"'{agent_id}' half-open probe limit reached (anti-thundering-herd)",
                            ["blast:half_open_limited:medium"]))
                    self._probes[agent_id] = self._probes.get(agent_id, 0) + 1

                # ---- consequence budgets (checked BEFORE incrementing; deny does not consume)
                over = self._would_exceed(ctr, budget, kind, amount, nbytes, now)
                if over:
                    self._trip(agent_id, now, f"budget exceeded: {over}")
                    return self._finish(agent_id, BlastVerdict(
                        False, OPEN, f"'{agent_id}' exceeded {over} budget",
                        [f"blast:budget_exceeded:{over}:high"]))

                if self.fleet_budget is not None:
                    self._fleet.roll(now, self.fleet_budget.window_seconds)
                    fover = self._would_exceed(self._fleet, self.fleet_budget, kind, amount, nbytes, now)
                    if fover:
                        self._fleet_open = True
                        if self.on_trip:
                            try: self.on_trip("FLEET", f"fleet {fover} budget exceeded")
                            except Exception: pass
                        return self._finish(agent_id, BlastVerdict(
                            False, OPEN, f"FLEET {fover} budget exceeded — kill-switch engaged",
                            [f"blast:fleet_budget_exceeded:{fover}:critical"]))
                    self._consume(self._fleet, kind, amount, nbytes)

                self._consume(ctr, kind, amount, nbytes)
                st = self._state.get(agent_id, CLOSED)
                return self._finish(agent_id, BlastVerdict(
                    True, st, "within budget", ["blast:ok"],
                    remaining=self._remaining(ctr, budget)))
        except Exception as e:                       # fail-CLOSED on internal error
            return self._finish(agent_id, BlastVerdict(
                False, OPEN, f"blast-radius internal error: {e}", ["blast:error_fail_closed"]))

    # ---- failure feedback (drives the breaker) ----
    def record_failure(self, agent_id: str) -> None:
        now = self._clock()
        with self._lock:
            budget = self._budgets.get(agent_id, self.default_budget)
            ctr = self._counters.setdefault(agent_id, _Counters(now))
            ctr.roll(now, budget.window_seconds)
            ctr.failures += 1
            if budget.max_failures is not None and ctr.failures >= budget.max_failures:
                self._trip(agent_id, now, "failure threshold reached")

    def record_success(self, agent_id: str) -> None:
        with self._lock:
            if self._state.get(agent_id) == HALF_OPEN:
                if self._probes.get(agent_id, 0) >= 1:
                    self._state[agent_id] = CLOSED     # recovered
                    self._probes[agent_id] = 0
                    self._counters[agent_id] = _Counters(self._clock())
                    self._isolated.discard(agent_id)
                    self._lift_isolation_from(agent_id)   # dependents recover with it

    # ---- manual controls ----
    def trip(self, agent_id: str, reason: str = "manual") -> None:
        with self._lock:
            self._trip(agent_id, self._clock(), reason)

    def trip_fleet(self, reason: str = "manual kill-switch") -> None:
        with self._lock:
            self._fleet_open = True
        if self.on_trip:
            try: self.on_trip("FLEET", reason)
            except Exception: pass

    def reset(self, agent_id: Optional[str] = None) -> None:
        with self._lock:
            if agent_id is None:
                self._state = {k: CLOSED for k in self._state}
                self._counters = {k: _Counters(self._clock()) for k in self._counters}
                self._isolated.clear(); self._probes.clear(); self._fleet_open = False
                self._fleet = _Counters(self._clock())
            else:
                self._state[agent_id] = CLOSED
                self._counters[agent_id] = _Counters(self._clock())
                self._isolated.discard(agent_id); self._probes.pop(agent_id, None)
                self._lift_isolation_from(agent_id)

    def _lift_isolation_from(self, agent_id: str) -> None:
        """Un-isolate dependents whose upstreams have all recovered (call with lock held).

        Isolation previously had no exit: once an upstream tripped, its dependents stayed OPEN
        forever, even after the upstream closed, until someone called reset() by hand. That is
        the same permanent-denial failure already fixed in the half-open breaker — and an
        operator whose fleet stays dark after the incident resolves switches the control off.
        """
        frontier = list(self._dependents.get(agent_id, ()))
        seen = set()
        while frontier:
            dep = frontier.pop()
            if dep in seen:
                continue
            seen.add(dep)
            if dep not in self._isolated:
                continue
            ups = self._depends_on.get(dep, set())
            if all(self._state.get(u, CLOSED) == CLOSED and u not in self._isolated
                   for u in ups):
                self._isolated.discard(dep)
                self._counters[dep] = _Counters(self._clock())
                frontier.extend(self._dependents.get(dep, ()))

    def state_of(self, agent_id: str) -> str:
        with self._lock:
            if self._fleet_open or agent_id in self._isolated:
                return OPEN
            return self._state.get(agent_id, CLOSED)

    def is_registered(self, agent_id: str) -> bool:
        """Whether an agent has an explicit budget registration.

        Gateways use this before auto-registering their fixed agent identity so they do not
        overwrite a caller-supplied per-agent budget. Reading private controller dictionaries
        from each integration would make registration behavior race-prone and brittle.
        """
        with self._lock:
            return agent_id in self._budgets

    # ---- internals (call with lock held) ----
    def _trip(self, agent_id: str, now: float, reason: str) -> None:
        self._state[agent_id] = OPEN
        self._opened_at[agent_id] = now
        self._probes[agent_id] = 0
        # CASCADE CONTAINMENT: isolate everything that depends on this agent, TRANSITIVELY.
        # Isolating only DIRECT dependents left a three-tier fleet still cascading: A trips,
        # B is isolated, and C — which depends on B — keeps retrying into a dead dependency,
        # which is the amplification this module exists to stop.
        frontier = list(self._dependents.get(agent_id, ()))
        seen = set()
        while frontier:
            dep = frontier.pop()
            if dep in seen:
                continue
            seen.add(dep)
            self._isolated.add(dep)
            frontier.extend(self._dependents.get(dep, ()))
        if self.on_trip:
            try: self.on_trip(agent_id, reason)
            except Exception: pass

    @staticmethod
    def _would_exceed(ctr: _Counters, b: Budget, kind: str, amount: float, nbytes: int,
                      now: Optional[float] = None):
        # Evaluate against the SLIDING totals so the boundary between windows is not a seam an
        # agent can burst through (see _Counters).
        if now is None:
            a, d, sp, eg, _f = ctr.actions, ctr.destructive, ctr.spend, ctr.egress, ctr.failures
        else:
            a, d, sp, eg, _f = ctr.sliding(now, b.window_seconds)
        if b.max_actions is not None and a + 1 > b.max_actions:
            return "actions"
        if kind == "destructive" and b.max_destructive is not None and d + 1 > b.max_destructive:
            return "destructive"
        if kind == "spend" and b.max_spend is not None and sp + amount > b.max_spend:
            return "spend"
        if kind == "egress" and b.max_egress_bytes is not None and eg + nbytes > b.max_egress_bytes:
            return "egress"
        return None

    @staticmethod
    def _consume(ctr: _Counters, kind: str, amount: float, nbytes: int) -> None:
        ctr.actions += 1
        if kind == "destructive":
            ctr.destructive += 1
        elif kind == "spend":
            ctr.spend += amount
        elif kind == "egress":
            ctr.egress += nbytes

    @staticmethod
    def _remaining(ctr: _Counters, b: Budget) -> Dict[str, Any]:
        def left(cap, used):
            return None if cap is None else max(0, cap - used)
        return {"actions": left(b.max_actions, ctr.actions),
                "destructive": left(b.max_destructive, ctr.destructive),
                "spend": None if b.max_spend is None else max(0.0, b.max_spend - ctr.spend),
                "egress_bytes": left(b.max_egress_bytes, ctr.egress)}

    def _finish(self, agent_id: str, v: BlastVerdict) -> BlastVerdict:
        with self._lock:
            self.audit.append((agent_id, v))
            if len(self.audit) > 10000:
                del self.audit[:5000]
        return v
