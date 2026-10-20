"""Selector observation, policy decisions and verified API writes."""
from . import clash_api
from .clash_api import resolve
from .compiler import selectors, selector_members
from .policy import Policy, score
from .settings import ACTIVE_SCORE_MAX_AGE


class SelectorController:
    def __init__(self, measurements, log):
        self.measurements, self.log = measurements, log
        self.policy = Policy()
        self.last_decisions = {}

    def revoke(self, selectors):
        for tag in selectors:
            self.policy.choices.pop(tag, None)
            self.policy.switched_at.pop(tag, None)
            self.policy.pending.pop(tag, None)
            self.last_decisions.pop(tag, None)

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

    def summary(self, now):
        measurements = self.measurements
        choices = {}
        for selector in selectors(measurements.config):
            members = selector_members(measurements.config, selector)
            tiers = measurements.settings.get('selector_priorities', {}).get(selector)
            allowed = [(k, c) for k, c in measurements.candidates.items() if k[0] in members]
            if tiers is not None:
                for tier in tiers:
                    group = [(k, c) for k, c in allowed if c['provider'] in tier]
                    if any(measurements.samples[k].healthy is not False for k, _ in group):
                        allowed = group
                        break
                else:
                    allowed = []
            ranked = []
            for key, c in allowed:
                sample = measurements.samples[key]
                if sample.healthy and not sample.body_failed:
                    value = score(sample, c['weight'], now, ACTIVE_SCORE_MAX_AGE if key[0] in measurements.active.values() else measurements.settings['throughput_sweep_seconds'])
                    ranked.append((value is not None, value or 0, -(sample.latency_or_inf), key[0]))
            best = max(ranked) if ranked else None
            choices[selector] = {'active': measurements.active.get(selector), 'proposed': best[3] if best else None,
                                 'proposed_score': best[1] if best and best[0] else None,
                                 'reason': 'observed_ranking' if best else 'health_or_performance_unknown'}
            for key, c in measurements.candidates.items():
                if key[0] == measurements.active.get(selector):
                    sample = measurements.samples[key]
                    choices[selector].update(score=score(sample, c['weight'], now, ACTIVE_SCORE_MAX_AGE),
                        sample_age=now-sample.throughput_at if sample.successes else None)
        for selector, signature in self.last_decisions.items():
            if selector in measurements.settings.get('managed_selectors', []):
                choices[selector]['decision_reason'] = signature[0]
        self.log('observe_summary', selectors=choices, application_bytes=measurements.accounting.summary())
