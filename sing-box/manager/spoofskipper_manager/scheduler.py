"""Bounded measurements and serialized policy writes; no catch-up ticks."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import time
import weakref
from . import clash_api
from .probes import Accounting, DEFAULTS, THROTTLE, ProbeClient, sample_key
from .policy import Policy, score
from .compiler import probe_outbounds, selectors, selector_members


@dataclass
class Sample:
    latency: float | None = None
    healthy: bool | None = None
    healthy_at: float = float('-inf')
    throttle_at: float = float('-inf')
    failures: int = 0
    body_failed: bool = False
    corroborate: str | None = None
    successes: list[tuple[float, float, float]] = field(default_factory=list)
    last: dict[str, float] = field(default_factory=dict)

    @property
    def throughput_at(self):
        return self.successes[-1][0] if self.successes else float('-inf')


def resolve(proxies, tag):
    seen = set()
    while tag in proxies and proxies[tag].get('now'):
        if tag in seen:
            raise ValueError('API selector cycle')
        seen.add(tag)
        tag = proxies[tag]['now']
    return tag


def path_identity(config, proxies, tag):
    """Rendered candidate identity including selected groups and recursive detours."""
    entries = {o['tag']: o for o in config.get('outbounds', []) + config.get('endpoints', [])}
    def visit(tag, seen):
        if tag in seen or tag not in entries:
            raise ValueError('invalid upstream dependency')
        entry = entries[tag]
        dependencies = []
        if entry.get('type') in ('selector', 'urltest'):
            selected = proxies.get(tag, {}).get('now')
            if selected not in entry['outbounds']:
                raise ValueError('upstream selection unavailable')
            dependencies.append(selected)
        if entry.get('detour'):
            dependencies.append(entry['detour'])
        return sample_key(entry), tuple(visit(member, seen | {tag}) for member in dependencies)
    return visit(tag, set())


class Scheduler:
    def __init__(self, log, clock=time.monotonic):
        self.log, self.clock = log, clock
        self.pool = ThreadPoolExecutor(max_workers=5, thread_name_prefix='probe')
        self.samples, self.candidates, self.jobs = {}, {}, {}
        self.epoch, self.config, self.settings = 0, None, dict(DEFAULTS)
        self.started = clock()
        self.paths, self.path_versions, self.proxy_choices = {}, {}, {}
        self.active, self.last_inspect, self.last_summary = {}, float('-inf'), clock()
        self.accounting = Accounting()
        self.client = None
        self.clients = weakref.WeakSet()
        self.policy = Policy()
        self.requested = {}
        self.last_decisions = {}

    def configure(self, config, candidates, settings):
        self.epoch += 1
        self.config, self.settings = config, {**DEFAULTS, **settings}
        enabled = settings.get('probes_enabled', False)
        subscribed = {c['outbound']['tag']: c for c in candidates}
        entries = []
        if enabled:
            for outbound in probe_outbounds(config):
                tag = outbound['tag']
                entry = dict(subscribed.get(tag, {'provider': tag,
                    'weight': settings.get('provider_weights', {}).get(tag, 1.0)}))
                entry['outbound'] = outbound
                entries.append(entry)
        self.candidates = {sample_key(c['outbound']): c for c in entries}
        self.samples = {k: self.samples.get(k, Sample()) for k in self.candidates}
        self.update_paths(self.proxy_choices)
        self.client = ProbeClient(self.settings, accounting=self.accounting) if enabled else None
        if self.client:
            self.clients.add(self.client)
        self.last_inspect = float('-inf')

    def restrict(self, settings):
        """Apply revocations now; new ownership/probes require a checked render."""
        old = self.settings.get('managed_selectors', [])
        allowed = [tag for tag in old if tag in settings.get('managed_selectors', [])]
        self.settings = {**self.settings, 'managed_selectors': allowed}
        for tag in set(old) - set(allowed):
            self.policy.choices.pop(tag, None)
            self.policy.switched_at.pop(tag, None)
            self.policy.pending.pop(tag, None)
            self.last_decisions.pop(tag, None)
        if not settings.get('probes_enabled', False):
            if self.client is not None or self.jobs:
                self.invalidate()
            self.client = None
            self.settings['probes_enabled'] = False
        self.requested = {}

    def update_paths(self, proxies):
        paths = {}
        for key in self.candidates:
            try:
                path = path_identity(self.config, proxies, key[0])
            except ValueError:
                path = None  # Unknown selection cannot retain trusted evidence.
            if key in self.paths and (path is None or path != self.paths[key]):
                self.samples[key] = Sample()
                self.path_versions[key] = self.path_versions.get(key, 0) + 1
            paths[key] = path
        self.paths = paths
        self.path_versions = {k: self.path_versions.get(k, 0) for k in paths}

    def invalidate(self):
        # Quiesce before core reloads or dependent selector writes. Cancellation
        # closes active sockets; wait for workers before touching their routes.
        self.epoch += 1
        for client in self.clients:
            client.cancel()
        for future in self.jobs:
            future.cancel()
        for future in self.jobs:
            try:
                future.result()
            except Exception:
                pass
        self.jobs.clear()

    def restart_client(self):
        self.client = ProbeClient(self.settings, accounting=self.accounting)
        self.clients.add(self.client)

    def close(self):
        self.invalidate()
        for client in self.clients:
            client.cancel()
        self.pool.shutdown(wait=True, cancel_futures=True)

    def shortlist(self, now):
        groups = {}
        for key, candidate in self.candidates.items():
            sample = self.samples[key]
            if sample.healthy and not sample.body_failed and now-sample.throughput_at <= self.settings['throughput_sweep_seconds']:
                groups.setdefault(candidate['provider'], []).append(key)
        return {p: sorted(keys, key=lambda k: self.samples[k].latency or float('inf'))[:3] for p, keys in groups.items()}

    def inspect(self):
        proxies = clash_api.proxies(self.config)
        self.active = {tag: resolve(proxies, tag) for tag in selectors(self.config) if tag in proxies}
        self.update_paths(proxies)
        self.proxy_choices = proxies
        return proxies

    def perform(self, client, config, candidate, kind):
        outbound = candidate['outbound']
        key = sample_key(outbound)
        version = self.path_versions.get(key, 0)
        dependent = bool(outbound.get('detour'))
        before = path_identity(config, clash_api.proxies(config), outbound['tag']) if dependent else key
        result = client.corroborate(outbound, body=kind == 'corroborate_body') if kind.startswith('corroborate') else client.run(outbound, kind)
        after = path_identity(config, clash_api.proxies(config), outbound['tag']) if dependent else key
        result['completed_at'] = self.clock()
        return result, before == after and version == self.path_versions.get(key, 0)

    def accept(self, key, kind, result, now):
        sample = self.samples[key]
        if kind == 'corroborate_gate' or kind == 'corroborate_body':
            if not result['ok']:
                sample.healthy = False
            elif kind == 'corroborate_body' or not sample.body_failed:
                sample.healthy = True
                sample.healthy_at = now
            self.log('probe_corroboration', candidate=key[0], kind=kind, ok=result['ok'])
            return
        if result.get('latency_ms') is not None:
            sample.latency = result['latency_ms']
        if result['ok']:
            sample.failures = 0
            body_ok = kind == 'throttle' or (kind == 'throughput' and
                (result.get('mbps') is not None or result.get('bytes', 0) >= THROTTLE))
            if not sample.body_failed or body_ok:
                sample.healthy = True
                sample.healthy_at = now
            if kind == 'throttle':
                sample.throttle_at = now
                sample.body_failed = False
            if kind == 'throughput' and result.get('mbps') is not None:
                sample.body_failed = False
                sample.successes = (sample.successes + [(now, result['mbps'], sample.latency)])[-3:]
        else:
            sample.failures += 1
            if kind != 'gate':
                sample.body_failed = True
                sample.healthy = None
                sample.corroborate = 'corroborate_body'
            elif sample.failures >= 3:
                sample.corroborate = 'corroborate_gate'
            self.log('probe_failed', candidate=key[0], kind=kind, error=result.get('error'),
                     bytes=result['bytes'], burst_seconds=result.get('burst_seconds'))
        self.log('probe_sample', candidate=key[0], **result)

    def collect(self, now):
        for future, (key, kind, epoch) in list(self.jobs.items()):
            if not future.done():
                continue
            del self.jobs[future]
            try:
                result, valid = future.result()
                if epoch == self.epoch and key in self.samples and valid:
                    self.accept(key, kind, result, result.pop('completed_at', now))
                    self.samples[key].last[kind] = now  # Never catch up missed runs.
                else:
                    self.log('probe_discarded', candidate=key[0], reason='reload_or_upstream_change')
            except Exception as exc:
                self.log('probe_discarded', candidate=key[0], reason=type(exc).__name__)

    def next_test(self, key, peers, now):
        sample, settings = self.samples[key], self.settings
        active = key[0] in self.active.values()
        if sample.corroborate:
            return sample.corroborate
        gate_interval = settings['gate_active_seconds' if active else 'gate_standby_seconds']
        if now >= sample.last.get('gate', float('-inf')) + gate_interval:
            return 'gate'
        if (active or sample.body_failed) and now >= sample.last.get('throttle', float('-inf')) + settings['throttle_seconds']:
            return 'throttle'
        if not sample.healthy or sample.body_failed:
            return None
        cadence = settings['throughput_active_seconds' if active else
                           'throughput_shortlist_seconds' if key in peers else 'throughput_sweep_seconds']
        # Spread first sweeps across the interval; shortlist bootstrap bypasses this.
        first_sweep = self.started + cadence * int(key[1][:8], 16) / 0xffffffff
        due = sample.last['throughput'] + cadence if 'throughput' in sample.last else first_sweep
        early = key not in peers and (len(peers) < 3 or sample.latency < max(self.samples[k].latency for k in peers))
        if now >= due or (early and now-sample.last.get('throughput', float('-inf')) >= settings['early_test_seconds']):
            return 'throughput'
        return None

    def tick(self):
        now = self.clock()
        self.collect(now)
        if not self.client:
            return
        if now-self.last_inspect >= 5:
            try:
                self.inspect()
            except Exception as exc:
                self.log('probe_inspection_failed', error=type(exc).__name__)
            self.last_inspect = now
        self.apply_policy(now)
        if now-self.last_summary >= 3600:
            self.summary(now)
            self.last_summary = now
        busy = {key for key, _, _ in self.jobs.values()}
        gates = sum(kind == 'gate' for _, kind, _ in self.jobs.values())
        downloading = any(kind != 'gate' for _, kind, _ in self.jobs.values())
        shortlists = self.shortlist(now)
        ordered = sorted(self.candidates, key=lambda k: (k not in self.requested, k[0] not in self.active.values(), self.samples[k].latency or float('inf'), k))
        for key in ordered:
            if key in busy:
                continue
            candidate, sample = self.candidates[key], self.samples[key]
            kind = self.requested.get(key) or self.next_test(key, shortlists.get(candidate['provider'], []), now)
            if kind is None or (kind == 'gate' and gates >= self.settings['probe_workers']) or (kind != 'gate' and downloading):
                continue
            if kind == 'gate':
                gates += 1
            else:
                downloading = True
            sample.last[kind] = now
            if key in self.requested:
                self.accounting.add(policy_tests=1, **({'challenger_tests': 1} if kind == 'throughput' else {}))
            if kind.startswith('corroborate'):
                sample.corroborate = None
            future = self.pool.submit(self.perform, self.client, self.config, candidate, kind)
            self.jobs[future] = (key, kind, self.epoch)

    def apply_policy(self, now):
        self.requested = {}
        managed = self.settings.get('managed_selectors', [])
        for selector in selectors(self.config):
            if selector not in managed or selector not in self.active:
                continue
            members = selector_members(self.config, selector)
            decision = self.policy.decide(selector, self.active[selector], self.candidates,
                self.samples, now, self.settings, members)
            pending = self.policy.pending.get(selector)
            for key, kind in decision.tests:
                last = self.samples[key].last.get(kind, float('-inf'))
                # Retry failed/unknown challenges at the early-test cadence,
                # rather than hammering an unscored or unreachable candidate.
                since = pending[1] if pending and pending[0] == key else now
                interval = self.settings['gate_active_seconds'] if kind == 'gate' else self.settings['early_test_seconds']
                if (kind != 'gate' and last < since) or now-last >= interval:
                    self.requested.setdefault(key, kind)
            target = decision.target
            compared = []
            for tag in (self.active[selector], target[0] if target else
                        pending[0][0] if pending else None):
                key = next((k for k in self.candidates if k[0] == tag), None)
                if key:
                    sample = self.samples[key]
                    compared.append({'candidate': tag, 'score': score(sample, self.candidates[key]['weight'], now,
                        7200 if tag == self.active[selector] else self.settings['throughput_sweep_seconds']),
                        'sample_age': now-sample.throughput_at if sample.successes else None})
            signature = (decision.reason, target, pending)
            if self.last_decisions.get(selector) != signature:
                self.log('selector_decision', selector=selector, reason=decision.reason, compared=compared)
                self.last_decisions[selector] = signature
            if target is None or target[0] == self.active[selector]:
                continue
            try:
                self.invalidate()
                self.restart_client()
                clash_api.select(self.config, selector, target[0], managed)
                self.policy.observe(selector, target[0], now)
                self.log('selector_switched', selector=selector, candidate=target[0], reason=decision.reason,
                         compared=compared)
                self.inspect()  # Invalidate samples whose effective paths changed.
            except Exception as exc:
                self.log('selector_write_failed', selector=selector, error=type(exc).__name__)

    def summary(self, now):
        choices = {}
        for selector in selectors(self.config):
            members = selector_members(self.config, selector)
            tiers = self.settings.get('selector_priorities', {}).get(selector)
            allowed = [(k, c) for k, c in self.candidates.items() if k[0] in members]
            if tiers is not None:
                for tier in tiers:
                    group = [(k, c) for k, c in allowed if c['provider'] in tier]
                    if any(self.samples[k].healthy is not False for k, _ in group):
                        allowed = group
                        break
                else:
                    allowed = []
            ranked = []
            for key, c in allowed:
                sample = self.samples[key]
                if sample.healthy and not sample.body_failed:
                    value = score(sample, c['weight'], now, 7200 if key[0] in self.active.values() else self.settings['throughput_sweep_seconds'])
                    ranked.append((value is not None, value or 0, -(sample.latency or float('inf')), key[0]))
            best = max(ranked) if ranked else None
            choices[selector] = {'active': self.active.get(selector), 'proposed': best[3] if best else None,
                                 'proposed_score': best[1] if best and best[0] else None,
                                 'reason': 'observed_ranking' if best else 'health_or_performance_unknown'}
            for key, c in self.candidates.items():
                if key[0] == self.active.get(selector):
                    sample = self.samples[key]
                    choices[selector].update(score=score(sample, c['weight'], now, 7200),
                        sample_age=now-sample.throughput_at if sample.successes else None)
        for selector, signature in self.last_decisions.items():
            if selector in self.settings.get('managed_selectors', []):
                choices[selector]['decision_reason'] = signature[0]
        self.log('observe_summary', selectors=choices, application_bytes=self.client.accounting.summary())
