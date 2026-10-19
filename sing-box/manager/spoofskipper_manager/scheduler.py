"""Observe-only scheduling. Work is in memory and never catches up missed ticks."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import statistics
import time
import weakref
from . import clash_api
from .probes import Accounting, DEFAULTS, ProbeClient, sample_key

SELECTORS = ('proxy_main', 'proxy_deepmind', 'warp_upstream')


@dataclass
class Sample:
    latency: float | None = None
    healthy: bool | None = None
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


def score(sample, weight, now, max_age):
    recent = [(rate, latency) for at, rate, latency in sample.successes if now-at <= max_age]
    if not recent or sample.healthy is not True or sample.body_failed:
        return None
    rate = statistics.median(rate for rate, _ in recent[-3:])
    latency = statistics.median(latency for _, latency in recent[-3:])
    return weight * (min(rate, 50)/10)**.6 * (200/max(latency, 20))**.4


class Scheduler:
    def __init__(self, log, clock=time.monotonic):
        self.log, self.clock = log, clock
        self.pool = ThreadPoolExecutor(max_workers=5, thread_name_prefix='probe')
        self.samples, self.candidates, self.jobs = {}, {}, {}
        self.epoch, self.config, self.settings = 0, None, dict(DEFAULTS)
        self.started = clock()
        self.warp_version, self.warp_upstream = 0, None
        self.active, self.last_inspect, self.last_summary = {}, float('-inf'), clock()
        self.accounting = Accounting()
        self.client = None
        self.clients = weakref.WeakSet()

    def configure(self, config, candidates, settings):
        self.epoch += 1
        self.config, self.settings = config, {**DEFAULTS, **settings}
        enabled = settings.get('probes_enabled', False)
        entries = list(candidates) if enabled else []
        warp = next((o for o in config.get('endpoints', []) + config.get('outbounds', []) if o.get('detour') == 'warp_upstream'), None)
        if warp and enabled:
            entries.append({'provider': 'WARP', 'weight': 1.0, 'outbound': warp})
        self.candidates = {sample_key(c['outbound']): c for c in entries}
        self.samples = {k: self.samples.get(k, Sample()) for k in self.candidates}
        self.client = ProbeClient(self.settings, accounting=self.accounting) if enabled else None
        if self.client:
            self.clients.add(self.client)
        self.last_inspect = float('-inf')

    def invalidate(self):
        # Called before HUP/restart; even rollback must discard crossing probes.
        self.epoch += 1

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
        self.active = {tag: resolve(proxies, tag) for tag in SELECTORS if tag in proxies}
        upstream = self.active.get('warp_upstream')
        if self.warp_upstream is not None and upstream != self.warp_upstream:
            self.warp_version += 1
            for key, candidate in self.candidates.items():
                if candidate['provider'] == 'WARP':
                    self.samples[key] = Sample()
        self.warp_upstream = upstream
        return proxies

    def perform(self, client, config, candidate, kind):
        outbound = candidate['outbound']
        warp = candidate['provider'] == 'WARP'
        version = self.warp_version
        before = resolve(clash_api.proxies(config), 'warp_upstream') if warp else None
        result = client.corroborate(outbound, body=kind == 'corroborate_body') if kind.startswith('corroborate') else client.run(outbound, kind)
        after = resolve(clash_api.proxies(config), 'warp_upstream') if warp else None
        result['completed_at'] = self.clock()
        return result, before == after and (not warp or version == self.warp_version)

    def accept(self, key, kind, result, now):
        sample = self.samples[key]
        if kind == 'corroborate_gate' or kind == 'corroborate_body':
            if not result['ok']:
                sample.healthy = False
            else:
                sample.healthy = True
            self.log('probe_corroboration', candidate=key[0], kind=kind, ok=result['ok'])
            return
        if result.get('latency_ms') is not None:
            sample.latency = result['latency_ms']
        if result['ok']:
            sample.failures = 0
            if not sample.body_failed or kind in ('throttle', 'throughput'):
                sample.healthy = True
            if kind == 'throttle':
                sample.body_failed = False
            if kind == 'throughput' and result.get('mbps') is not None:
                sample.body_failed = False
                sample.successes = (sample.successes + [(now, result['mbps'], sample.latency)])[-3:]
        else:
            sample.failures += 1
            if kind != 'gate':
                sample.body_failed = True
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
        if now-self.last_summary >= 3600:
            self.summary(now)
            self.last_summary = now
        busy = {key for key, _, _ in self.jobs.values()}
        gates = sum(kind == 'gate' for _, kind, _ in self.jobs.values())
        downloading = any(kind != 'gate' for _, kind, _ in self.jobs.values())
        shortlists = self.shortlist(now)
        ordered = sorted(self.candidates, key=lambda k: (k[0] not in self.active.values(), self.samples[k].latency or float('inf'), k))
        for key in ordered:
            if key in busy:
                continue
            candidate, sample = self.candidates[key], self.samples[key]
            kind = self.next_test(key, shortlists.get(candidate['provider'], []), now)
            if kind is None or (kind == 'gate' and gates >= self.settings['probe_workers']) or (kind != 'gate' and downloading):
                continue
            if kind == 'gate':
                gates += 1
            else:
                downloading = True
            sample.last[kind] = now
            if kind.startswith('corroborate'):
                sample.corroborate = None
            future = self.pool.submit(self.perform, self.client, self.config, candidate, kind)
            self.jobs[future] = (key, kind, self.epoch)

    def summary(self, now):
        choices = {}
        for selector in SELECTORS:
            allowed = [(k, c) for k, c in self.candidates.items() if c['provider'] != 'WARP' or selector != 'warp_upstream']
            if selector == 'proxy_deepmind':
                blanc = [(k, c) for k, c in allowed if c['provider'] == 'blanc']
                allowed = blanc if any(self.samples[k].healthy is not False for k, _ in blanc) else [(k, c) for k, c in allowed if c['provider'] == 'WARP']
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
        self.log('observe_summary', selectors=choices, application_bytes=self.client.accounting.summary())
