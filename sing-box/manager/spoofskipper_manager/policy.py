"""In-memory selector policy. Decisions request measurements; they never perform I/O."""
from dataclasses import dataclass
import statistics
import math

from .settings import HOLD, MARGIN, ACTIVE_SCORE_MAX_AGE, FRESH_SAMPLE_SECONDS


def score(sample, weight, now, max_age):
    recent = sample.scored(now, max_age)
    if not recent:
        return None
    rate = statistics.median(rate for rate, _ in recent[-3:])
    latency = statistics.median(latency for _, latency in recent[-3:])
    return weight * (min(rate, 50)/10)**.6 * (200/max(latency, 20))**.4


@dataclass
class Decision:
    target: tuple | None
    reason: str
    tests: tuple = ()  # (sample key, kind), ordered before background work


@dataclass
class EligiblePool:
    candidates: dict
    samples: dict
    now: float
    settings: object
    active: tuple | None
    members: tuple
    priorities: dict | None
    unresolved: tuple = ()

    def healthy(self, key):
        return self.samples[key].is_healthy(self.now, self.settings['gate_standby_seconds'] * 2)

    def unknown(self, key):
        return self.samples[key].healthy is not False and not self.healthy(key)

    @property
    def available(self):
        return tuple(key for key in self.members if self.healthy(key))

    def gate_tests(self, keys):
        return tuple((key, 'gate') for key in keys if self.unknown(key))

    def value(self, key, max_age=None):
        if max_age is None:
            max_age = self.settings['throughput_sweep_seconds']
        return score(self.samples[key], self.candidates[key]['weight'], self.now, max_age)

    def rank(self, key, max_age=None):
        if max_age is None:
            max_age = self.settings['throughput_sweep_seconds']
        if key == self.active and math.isfinite(max_age):
            max_age = ACTIVE_SCORE_MAX_AGE
        value = self.value(key, max_age)
        return value is not None, value or 0, -self.samples[key].latency_or_inf, key


def eligible_pool(selector, current, candidates, samples, now, settings, members):
    """One tier and fresh-health gate for decisions and observational summaries."""
    tiers = settings.get('selector_priorities', {}).get(selector)
    priorities = ({key: index for index, providers in enumerate(tiers)
                   for key, candidate in candidates.items() if candidate['provider'] in providers}
                  if tiers is not None else None)
    allowed = {key: candidate for key, candidate in candidates.items()
               if key[0] in members and (priorities is None or key in priorities)}
    active = next((key for key in allowed if key[0] == current), None)
    pool = EligiblePool(allowed, samples, now, settings, active, tuple(allowed), priorities)
    if tiers is not None:
        pool.members = ()
        for index in range(len(tiers)):
            group = tuple(key for key in allowed if priorities[key] == index)
            working = tuple(key for key in group if pool.healthy(key))
            unresolved = tuple(key for key in group if pool.unknown(key))
            if working:
                pool.members = working
                break
            if unresolved:
                pool.unresolved = unresolved
                break
    return pool


class Policy:
    def __init__(self):
        self.choices, self.switched_at, self.pending = {}, {}, {}

    def observe(self, selector, tag, now):
        # Also damps dashboard changes and the initial ownership handoff.
        if self.choices.get(selector) != tag:
            self.choices[selector], self.switched_at[selector] = tag, now
            self.pending.pop(selector, None)

    def decide(self, selector, current, candidates, samples, now, settings, members):
        self.observe(selector, current, now)
        pool = eligible_pool(selector, current, candidates, samples, now, settings, members)
        if pool.unresolved:
            return Decision(None, 'priority_health_unknown', pool.gate_tests(pool.unresolved))
        failover = self.failover(pool)
        if failover is not None:
            return failover
        if not pool.available:
            return Decision(None, 'health_unknown', pool.gate_tests(pool.members))
        return self.elective(selector, pool)

    def failover(self, pool):
        failed = pool.active is not None and pool.samples[pool.active].healthy is False
        if not failed and pool.active is not None:
            return None
        if pool.available:
            target = max(pool.available, key=lambda key: pool.rank(key, float('inf')))
            return Decision(target, 'health_failover' if failed else 'healthy_bootstrap')
        unresolved = any(pool.unknown(key) for key in pool.members)
        return Decision(None, 'health_unknown' if unresolved else 'all_paths_failed',
                        pool.gate_tests(pool.members))

    def elective(self, selector, pool):
        best = max(pool.available, key=pool.rank)
        boundary = pool.priorities is not None and pool.priorities[best] < pool.priorities[pool.active]
        if best == pool.active:
            self.pending.pop(selector, None)
            return Decision(None, 'current_best')
        if not boundary:
            current_score = pool.value(pool.active, ACTIVE_SCORE_MAX_AGE)
            challenger_score = pool.value(best)
            if challenger_score is None or (current_score is not None and challenger_score < current_score*MARGIN):
                self.pending.pop(selector, None)
                return Decision(None, 'margin_or_performance_unknown')
        if pool.now-self.switched_at[selector] < HOLD:
            return Decision(None, 'hold')
        pending = self.pending.get(selector)
        if pending is None or pending[0] != best:
            self.pending[selector] = (best, pool.now)
        since = self.pending[selector][1]
        sample = pool.samples[best]
        tests = self.challenge_tests(best, sample, since, pool.now, boundary)
        if tests:
            return Decision(None, 'priority_return_test' if boundary else 'challenger_test', tests)
        score_age = max(FRESH_SAMPLE_SECONDS, pool.now-sample.throughput_at) if boundary else FRESH_SAMPLE_SECONDS
        if sample.body_failed or pool.value(best, score_age) is None:
            return Decision(None, 'challenger_performance_unknown')
        if not boundary:
            incumbent = pool.value(pool.active, ACTIVE_SCORE_MAX_AGE)
            if incumbent is not None and pool.value(best, FRESH_SAMPLE_SECONDS) < incumbent*MARGIN:
                return Decision(None, 'fresh_challenger_margin')
        return Decision(best, 'priority_return' if boundary else 'score_improvement')

    @staticmethod
    def challenge_tests(best, sample, since, now, boundary):
        # The two serial priority-return checks share one challenge boundary.
        measured_at = max(sample.throughput_at, sample.throttle_at) if boundary else sample.throughput_at
        waiting_for_pair = boundary and sample.throttle_at < since
        fresh = sample.throughput_at >= since and (waiting_for_pair or now-measured_at <= FRESH_SAMPLE_SECONDS)
        tests = []
        if not fresh:
            tests.append((best, 'throughput'))
        throttle_stale = sample.throughput_at >= since and now-measured_at > FRESH_SAMPLE_SECONDS
        if boundary and (sample.throttle_at < since or throttle_stale):
            tests.append((best, 'throttle'))
        return tuple(tests)
