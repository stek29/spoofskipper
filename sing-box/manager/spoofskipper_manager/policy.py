"""In-memory selector policy. Decisions request measurements; they never perform I/O."""
from dataclasses import dataclass
import statistics
import math

from .probes import Probe, RATE_CAP_MBPS
from .samples import Health
from .settings import HOLD, MARGIN, ACTIVE_SCORE_MAX_AGE, FRESH_SAMPLE_SECONDS, SCORE_MAX_AGE


def score_terms(sample, now, max_age):
    """Median rate and latency of the last three samples in the window, and their factors."""
    recent = sample.scored(now, max_age)
    if not recent:
        return None
    rate = statistics.median(rate for rate, _ in recent[-3:])
    latency = statistics.median(latency for _, latency in recent[-3:])
    return rate, latency, (min(rate, RATE_CAP_MBPS)/10)**.6, (200/max(latency, 20))**.4


def score(sample, weight, now, max_age):
    terms = score_terms(sample, now, max_age)
    return None if terms is None else weight * terms[2] * terms[3]


@dataclass
class Decision:
    target: tuple | None
    reason: str
    tests: tuple = ()  # (sample key, Probe), ordered before background work
    since: float = float('-inf')  # tests are wanted unless already submitted after this


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
        return self.samples[key].is_healthy(self.now, self.settings.gate_standby_seconds * 2)

    def unknown(self, key):
        return self.samples[key].health is not Health.FAILED and not self.healthy(key)

    @property
    def available(self):
        return tuple(key for key in self.members if self.healthy(key))

    def gate_tests(self, keys):
        return tuple((key, Probe.GATE) for key in keys if self.unknown(key))

    def value(self, key, max_age=None):
        if max_age is None:
            max_age = SCORE_MAX_AGE
        return score(self.samples[key], self.candidates[key].weight, self.now, max_age)

    def rank(self, key, max_age=None):
        if max_age is None:
            max_age = SCORE_MAX_AGE
        if key == self.active and math.isfinite(max_age):
            max_age = ACTIVE_SCORE_MAX_AGE
        value = self.value(key, max_age)
        return value is not None, value or 0, -self.samples[key].latency_or_inf, key


def eligible_pool(selector, current, candidates, samples, now, settings, members):
    """One tier and fresh-health gate for decisions and observational summaries."""
    tiers = settings.selector_priorities.get(selector)
    priorities = ({key: index for index, providers in enumerate(tiers)
                   for key, candidate in candidates.items() if candidate.provider in providers}
                  if tiers is not None else None)
    allowed = {key: candidate for key, candidate in candidates.items()
               if key.tag in members and (priorities is None or key in priorities)}
    active = next((key for key in allowed if key.tag == current), None)
    pool = EligiblePool(allowed, samples, now, settings, active, tuple(allowed), priorities)
    if tiers is not None:
        # A lower tier is eligible only once every member above it has failed.
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
        """Leave a failed (or ineligible) route immediately, bypassing hold and margin."""
        failed = pool.active is not None and pool.samples[pool.active].health is Health.FAILED
        if not failed and pool.active is not None:
            return None
        if not pool.available:
            unresolved = any(pool.unknown(key) for key in pool.members)
            return Decision(None, 'health_unknown' if unresolved else 'all_paths_failed',
                            pool.gate_tests(pool.members))
        # Switch only to a path that read past the throttling threshold after
        # the active one failed: a standby's earlier proof may be hours old, and
        # a tiny gate response passes throttling middleboxes. Candidates are
        # checked best first. When the probe endpoint itself is down, none
        # qualifies and the current route is kept instead of hopping between paths.
        since = pool.samples[pool.active].failed_at if failed else float('-inf')
        best = max(pool.available, key=lambda key: pool.rank(key, float('inf')))
        if pool.samples[best].threshold_at < since:
            return Decision(None, 'failover_verify', ((best, Probe.THROTTLE),), since)
        return Decision(best, 'health_failover' if failed else 'healthy_bootstrap')

    def elective(self, selector, pool):
        """Switch a working route only for a fresh, clearly better measurement."""
        best = max(pool.available, key=pool.rank)
        if best == pool.active:
            self.pending.pop(selector, None)
            return Decision(None, 'current_best')
        # Returning to a higher priority tier needs no score margin.
        priority_return = pool.priorities is not None and pool.priorities[best] < pool.priorities[pool.active]
        incumbent = pool.value(pool.active, ACTIVE_SCORE_MAX_AGE)
        if not priority_return:
            challenger = pool.value(best)
            if challenger is None or (incumbent is not None and challenger < incumbent*MARGIN):
                self.pending.pop(selector, None)
                return Decision(None, 'margin_or_performance_unknown')
        if pool.now-self.switched_at[selector] < HOLD:
            return Decision(None, 'hold')
        if self.pending.get(selector, (None,))[0] != best:
            self.pending[selector] = (best, pool.now)
        since = self.pending[selector][1]
        # The switch itself is justified only by a throughput result taken after
        # the challenge started; it also proves the throttling threshold.
        # A priority return skips the margin, so any fresh threshold proof will do,
        # including one from a fallback endpoint while the primary is down.
        measured_at = pool.samples[best].threshold_at if priority_return else pool.samples[best].throughput_at
        if measured_at < since or pool.now-measured_at > FRESH_SAMPLE_SECONDS:
            return Decision(None, 'priority_return_test' if priority_return else 'challenger_test',
                            ((best, Probe.THROUGHPUT),), since)
        if not priority_return and incumbent is not None and \
                pool.value(best, FRESH_SAMPLE_SECONDS) < incumbent*MARGIN:
            return Decision(None, 'fresh_challenger_margin')
        return Decision(best, 'priority_return' if priority_return else 'score_improvement')
