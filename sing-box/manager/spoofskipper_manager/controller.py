"""Selector observation, policy decisions and verified API writes."""
from . import clash_api
from .clash_api import resolve
from .compiler import selectors, selector_members
from .policy import Policy, score, eligible_pool
from .settings import ACTIVE_SCORE_MAX_AGE


class SelectorController:
    def __init__(self, measurements, log):
        self.measurements, self.log = measurements, log
        self.policy = Policy()
        self.last_decisions = {}
        self.decisions = {}

    def revoke(self, selectors):
        for tag in selectors:
            self.policy.choices.pop(tag, None)
            self.policy.switched_at.pop(tag, None)
            self.policy.pending.pop(tag, None)
            self.last_decisions.pop(tag, None)
            self.decisions.pop(tag, None)

    def inspect(self):
        measurements = self.measurements
        proxies = clash_api.proxies(measurements.config)
        measurements.active = {tag: resolve(proxies, tag) for tag in selectors(measurements.config) if tag in proxies}
        measurements.update_paths(proxies)
        measurements.proxy_choices = proxies
        return proxies

    def apply_policy(self, now):
        measurements = self.measurements
        measurements.requested = {}
        managed = measurements.settings.get('managed_selectors', [])
        for selector in selectors(measurements.config):
            if selector not in managed or selector not in measurements.active:
                continue
            members = selector_members(measurements.config, selector)
            decision = self.policy.decide(selector, measurements.active[selector], measurements.candidates,
                measurements.samples, now, measurements.settings, members)
            self.decisions[selector] = decision
            pending = self.policy.pending.get(selector)
            for key, kind in decision.tests:
                last = measurements.samples[key].last.get(kind, float('-inf'))
                # Retry failed/unknown challenges at the early-test cadence,
                # rather than hammering an unscored or unreachable candidate.
                since = pending[1] if pending and pending[0] == key else now
                interval = measurements.settings['gate_active_seconds'] if kind == 'gate' else measurements.settings['early_test_seconds']
                if (kind != 'gate' and last < since) or now-last >= interval:
                    measurements.requested.setdefault(key, kind)
            target = decision.target
            compared = []
            for tag in (measurements.active[selector], target[0] if target else
                        pending[0][0] if pending else None):
                key = next((k for k in measurements.candidates if k[0] == tag), None)
                if key:
                    sample = measurements.samples[key]
                    compared.append({'candidate': tag, 'score': score(sample, measurements.candidates[key]['weight'], now,
                        ACTIVE_SCORE_MAX_AGE if tag == measurements.active[selector] else measurements.settings['throughput_sweep_seconds']),
                        'sample_age': now-sample.throughput_at if sample.successes else None})
            signature = (decision.reason, target, pending)
            if self.last_decisions.get(selector) != signature:
                self.log('selector_decision', selector=selector, reason=decision.reason, compared=compared)
                self.last_decisions[selector] = signature
            if target is None or target[0] == measurements.active[selector]:
                continue
            try:
                measurements.invalidate()
                measurements.restart_client()
                clash_api.select(measurements.config, selector, target[0], managed)
                self.policy.observe(selector, target[0], now)
                self.log('selector_switched', selector=selector, candidate=target[0], reason=decision.reason,
                         compared=compared)
                self.inspect()  # Invalidate samples whose effective paths changed.
            except Exception as exc:
                self.log('selector_write_failed', selector=selector, error=type(exc).__name__)

    def summary_choice(self, selector, now):
        measurements = self.measurements
        current = measurements.active.get(selector)
        members = selector_members(measurements.config, selector)
        pool = eligible_pool(selector, current, measurements.candidates, measurements.samples,
                             now, measurements.settings, members)
        if selector in measurements.settings.managed_selectors:
            decision = self.decisions.get(selector)
            proposed = decision.target if decision else None
            if decision and proposed is None:
                proposed = pool.active  # The policy keeps the current route.
            reason = decision.reason if decision else 'awaiting_policy'
        else:
            proposed = max(pool.available, key=pool.rank) if pool.available and not pool.unresolved else None
            reason = ('priority_health_unknown' if pool.unresolved else
                      'observed_ranking' if proposed else 'health_or_performance_unknown')
        choice = {'active': current, 'proposed': proposed[0] if proposed else None,
                  'proposed_score': pool.value(proposed, ACTIVE_SCORE_MAX_AGE if proposed == pool.active
                                              else None) if proposed else None, 'reason': reason}
        if selector in measurements.settings.managed_selectors:
            choice['decision_reason'] = reason
        if pool.active:
            sample = measurements.samples[pool.active]
            choice.update(score=pool.value(pool.active, ACTIVE_SCORE_MAX_AGE),
                          sample_age=now-sample.throughput_at if sample.successes else None)
        return choice

    def summary(self, now):
        choices = {selector: self.summary_choice(selector, now)
                   for selector in selectors(self.measurements.config)}
        self.log('observe_summary', selectors=choices,
                 application_bytes=self.measurements.accounting.summary(reset=True))
