"""In-memory selector policy. Decisions request measurements; they never perform I/O."""
from dataclasses import dataclass
import statistics
import math

HOLD = 300
MARGIN = 1.15


def score(sample, weight, now, max_age):
    recent = [(rate, latency) for at, rate, latency in sample.successes if 0 <= now-at <= max_age]
    if not recent or sample.healthy is not True or sample.body_failed:
        return None
    rate = statistics.median(rate for rate, _ in recent[-3:])
    latency = statistics.median(latency for _, latency in recent[-3:])
    return weight * (min(rate, 50)/10)**.6 * (200/max(latency, 20))**.4


@dataclass
class Decision:
    target: tuple | None
    reason: str
    tests: tuple = ()  # (sample key, kind), ordered before background work


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
        tiers = settings.get('selector_priorities', {}).get(selector)
        def priority(k):
            return next((i for i, providers in enumerate(tiers or [])
                         if candidates[k]['provider'] in providers), None)
        allowed = {k: c for k, c in candidates.items() if k[0] in members and
                   (tiers is None or priority(k) is not None)}
        active = next((k for k in allowed if k[0] == current), None)
        age = settings['throughput_sweep_seconds']
        health_age = settings['gate_standby_seconds'] * 2
        def healthy(k):
            s = samples[k]
            return s.healthy is True and now-s.healthy_at <= health_age
        def value(k, maximum=age):
            return score(samples[k], allowed[k]['weight'], now, maximum)
        def rank(k, maximum=age):
            v = value(k, 7200 if k == active and math.isfinite(maximum) else maximum)
            return (v is not None, v or 0, -(samples[k].latency or float('inf')), k)
        def unknown(k):
            return samples[k].healthy is not False and not healthy(k)
        def gate_tests(keys):
            return tuple((k, 'gate') for k in keys if unknown(k))
        pool = list(allowed)
        if tiers is not None:
            pool = []
            for tier in range(len(tiers)):
                group = [k for k in allowed if priority(k) == tier]
                working = [k for k in group if healthy(k)]
                unresolved = [k for k in group if unknown(k)]
                if working:
                    pool = working
                    break
                if unresolved:
                    return Decision(None, 'priority_health_unknown', gate_tests(unresolved))
        available = [k for k in pool if healthy(k)]
        failed = active is not None and samples[active].healthy is False
        if failed or active is None:
            if available:
                target = max(available, key=lambda k: rank(k, float('inf')))
                # No downloads on the failover path; active warmup tests follow.
                return Decision(target, 'health_failover' if failed else 'healthy_bootstrap')
            return Decision(None, 'all_paths_failed' if not any(unknown(k) for k in pool)
                            else 'health_unknown', gate_tests(pool))
        if not available:
            return Decision(None, 'health_unknown', gate_tests(pool))
        best = max(available, key=rank)
        boundary = tiers is not None and priority(best) < priority(active)
        if best == active:
            self.pending.pop(selector, None)
            return Decision(None, 'current_best')
        if not boundary:
            current_score, challenger_score = value(active, 7200), value(best)
            if challenger_score is None or (current_score is not None and challenger_score < current_score*MARGIN):
                self.pending.pop(selector, None)
                return Decision(None, 'margin_or_performance_unknown')
        if now-self.switched_at[selector] < HOLD:
            return Decision(None, 'hold')
        # A new challenge starts only after the hold expires. Earlier recovery
        # observations never authorize return to a preferred tier.
        pending = self.pending.get(selector)
        if pending is None or pending[0] != best:
            self.pending[selector] = (best, now)
            pending = self.pending[selector]
        since = pending[1]
        s = samples[best]
        # Priority checks share a challenge boundary. Serial downloads may take
        # longer than the freshness window; use the later completion for the pair.
        measured_at = max(s.throughput_at, s.throttle_at) if boundary else s.throughput_at
        waiting_for_pair = boundary and s.throttle_at < since
        fresh = s.throughput_at >= since and (waiting_for_pair or now-measured_at <= 30)
        tests = []
        if not fresh:
            tests.append((best, 'throughput'))
        if boundary and (s.throttle_at < since or (s.throughput_at >= since and now-measured_at > 30)):
            tests.append((best, 'throttle'))
        if tests:
            return Decision(None, 'priority_return_test' if boundary else 'challenger_test', tuple(tests))
        score_age = max(30, now-s.throughput_at) if boundary else 30
        if s.body_failed or value(best, score_age) is None:
            return Decision(None, 'challenger_performance_unknown')
        if not boundary:
            incumbent = value(active, 7200)
            if incumbent is not None and value(best, 30) < incumbent*MARGIN:
                return Decision(None, 'fresh_challenger_margin')
        return Decision(best, 'priority_return' if boundary else 'score_improvement')
