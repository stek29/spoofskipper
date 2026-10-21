"""Selector observation, policy decisions and verified API writes."""
from . import clash_api
from .clash_api import resolve
from .compiler import selectors
from .policy import Policy, score
from .probes import Probe
from .settings import ACTIVE_SCORE_MAX_AGE, CHALLENGE_RETRY_SECONDS, SCORE_MAX_AGE


def retry_in(last, probe, since, now, settings):
    """Seconds until a requested test may be submitted again; at most 0 means now."""
    # Run each requested test once per decision; retry failed or
    # unknown results at the normal cadence rather than every tick.
    if last < since:
        return 0
    return (settings.gate_active_seconds if probe is Probe.GATE else CHALLENGE_RETRY_SECONDS) - (now-last)


class SelectorController:
    def __init__(self, measurements, log):
        self.measurements, self.log = measurements, log
        self.policy = Policy()
        self.last_decisions = {}
        self.decisions = {}
        self.decided_at = {}  # when each selector's current decision signature began

    def revoke(self, selectors):
        for tag in selectors:
            self.policy.choices.pop(tag, None)
            self.policy.switched_at.pop(tag, None)
            self.policy.pending.pop(tag, None)
            self.last_decisions.pop(tag, None)
            self.decisions.pop(tag, None)
            self.decided_at.pop(tag, None)

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
        managed = measurements.settings.managed_selectors
        for selector in selectors(measurements.config):
            if selector not in managed or selector not in measurements.active:
                continue
            members = measurements.selector_members(selector)
            decision = self.policy.decide(selector, measurements.active[selector], measurements.candidates,
                measurements.samples, now, measurements.settings, members)
            self.decisions[selector] = decision
            pending = self.policy.pending.get(selector)
            for key, probe in decision.tests:
                last = measurements.samples[key].last.get(probe, float('-inf'))
                if retry_in(last, probe, decision.since, now, measurements.settings) <= 0:
                    measurements.requested.setdefault(key, probe)
            target = decision.target
            compared = []
            for tag in (measurements.active[selector], target.tag if target else
                        pending[0].tag if pending else None):
                key = next((k for k in measurements.candidates if k.tag == tag), None)
                if key:
                    sample = measurements.samples[key]
                    compared.append({'candidate': tag, 'score': score(sample, measurements.candidates[key].weight, now,
                        ACTIVE_SCORE_MAX_AGE if tag == measurements.active[selector] else SCORE_MAX_AGE,
                        measurements.settings.rate_cap_mbps),
                        'sample_age': now-sample.throughput_at if sample.successes else None})
            signature = (decision.reason, target, pending)
            if self.last_decisions.get(selector) != signature:
                self.log('selector_decision', selector=selector, reason=decision.reason, compared=compared)
                self.last_decisions[selector], self.decided_at[selector] = signature, now
            if target is None or target.tag == measurements.active[selector]:
                continue
            try:
                measurements.invalidate()
                measurements.restart_client()
                clash_api.select(measurements.config, selector, target.tag, managed)
                self.policy.observe(selector, target.tag, now)
                self.log('selector_switched', selector=selector, candidate=target.tag, reason=decision.reason,
                         compared=compared)
                self.inspect()  # Invalidate samples whose effective paths changed.
            except Exception as exc:
                self.log('selector_write_failed', selector=selector, error=type(exc).__name__)
