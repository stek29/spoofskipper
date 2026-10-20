"""Bounded measurements and serialized policy writes; no catch-up ticks."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
import time
import weakref
from . import clash_api
from .probes import Accounting, THROTTLE, ProbeClient, sample_key
from .controller import SelectorController
from .settings import (Settings, INSPECT_SECONDS, SUMMARY_SECONDS,
                       GATE_FAILURE_THRESHOLD)
from .compiler import probe_outbounds
from .graph import OutboundGraph


class Health(Enum):
    UNKNOWN = 'unknown'
    HEALTHY = 'healthy'
    BODY_ONLY_BACKUP = 'body_only_backup'
    SUSPECT_BODY = 'suspect_body'
    FAILED_GATE = 'failed_gate'
    FAILED_BODY = 'failed_body'


@dataclass
class Sample:
    latency: float | None = None
    health: Health = Health.UNKNOWN
    healthy_at: float = float('-inf')
    throttle_at: float = float('-inf')
    unknown_throughput: int = 0
    failures: int = 0
    corroborate: str | None = None
    successes: list[tuple[float, float, float]] = field(default_factory=list)
    last: dict[str, float] = field(default_factory=dict)

    @property
    def healthy(self):
        if self.health in (Health.HEALTHY, Health.BODY_ONLY_BACKUP):
            return True
        if self.health in (Health.FAILED_GATE, Health.FAILED_BODY):
            return False
        return None

    @property
    def body_failed(self):
        return self.health in (Health.SUSPECT_BODY, Health.FAILED_BODY, Health.BODY_ONLY_BACKUP)

    @property
    def latency_or_inf(self):
        return self.latency if self.latency is not None else float('inf')

    def is_healthy(self, now, max_age):
        return self.healthy is True and 0 <= now-self.healthy_at <= max_age

    def scored(self, now, max_age):
        if self.healthy is not True or self.body_failed:
            return []
        return [(rate, latency) for at, rate, latency in self.successes
                if 0 <= now-at <= max_age]

    def record(self, kind, result, now):
        """Own health transitions; HEAD and tiny bodies never erase body failure."""
        if kind.startswith('corroborate'):
            if not result['ok']:
                self.health = Health.FAILED_BODY if self.body_failed else Health.FAILED_GATE
            elif kind == 'corroborate_body' or not self.body_failed:
                self.health = Health.BODY_ONLY_BACKUP if self.body_failed else Health.HEALTHY
                self.healthy_at = now
            return
        if result.get('latency_ms') is not None:
            self.latency = result['latency_ms']
        if kind == 'throughput':
            self.unknown_throughput = self.unknown_throughput + 1 if result.get('mbps') is None else 0
        if not result['ok']:
            self.failures += 1
            if kind != 'gate':
                self.health = Health.SUSPECT_BODY
                self.corroborate = 'corroborate_body'
            elif self.failures >= GATE_FAILURE_THRESHOLD:
                self.corroborate = 'corroborate_gate'
            return
        self.failures = 0
        body_ok = kind == 'throttle' or (kind == 'throughput' and
            (result.get('mbps') is not None or result.get('bytes', 0) >= THROTTLE))
        if not self.body_failed or body_ok:
            self.health = Health.BODY_ONLY_BACKUP if self.body_failed else Health.HEALTHY
            self.healthy_at = now
        if kind == 'throttle':
            self.throttle_at = now
            self.health = Health.HEALTHY
        if kind == 'throughput' and result.get('mbps') is not None:
            self.health = Health.HEALTHY
            self.successes = (self.successes + [(now, result['mbps'], self.latency)])[-3:]

    @property
    def throughput_at(self):
        return self.successes[-1][0] if self.successes else float('-inf')


def path_identity(config, proxies, tag):
    return OutboundGraph(config).path_identity(tag, proxies)


class Scheduler:
    def __init__(self, log, clock=time.monotonic):
        self.log, self.clock = log, clock
        self.pool = ThreadPoolExecutor(max_workers=5, thread_name_prefix='probe')
        self.samples, self.candidates, self.jobs = {}, {}, {}
        self.epoch, self.config, self.settings = 0, None, Settings()
        self.started = clock()
        self.paths, self.path_versions, self.proxy_choices = {}, {}, {}
        self.active, self.last_inspect, self.last_summary = {}, float('-inf'), clock()
        self.accounting = Accounting()
        self.client = None
        self.clients = weakref.WeakSet()
        self.controller = SelectorController(self, log)
        self.requested = {}

    def configure(self, config, candidates, settings):
        self.epoch += 1
        self.config, self.settings = config, Settings.from_mapping(settings)
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
        self.settings = self.settings.with_changes(managed_selectors=allowed)
        self.controller.revoke(set(old) - set(allowed))
        if not settings.get('probes_enabled', False):
            if self.client is not None or self.jobs:
                self.invalidate()
            self.client = None
            self.settings = self.settings.with_changes(probes_enabled=False)
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
        for key, kind, _ in self.jobs.values():
            self.rearm_cancelled(key, kind)
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
            if sample.scored(now, self.settings['throughput_sweep_seconds']):
                groups.setdefault(candidate['provider'], []).append(key)
        return {p: sorted(keys, key=lambda k: self.samples[k].latency_or_inf)[:3] for p, keys in groups.items()}

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
        self.samples[key].record(kind, result, now)
        if kind.startswith('corroborate'):
            self.log('probe_corroboration', candidate=key[0], kind=kind, ok=result['ok'])
            return
        if not result['ok']:
            self.log('probe_failed', candidate=key[0], kind=kind, error=result.get('error'),
                     bytes=result['bytes'], burst_seconds=result.get('burst_seconds'))
        self.log('probe_sample', candidate=key[0], **result)

    def rearm_cancelled(self, key, kind):
        """Cancellation did not complete an attempt; permit its replacement now."""
        if key in self.samples:
            self.samples[key].last.pop(kind, None)
            if kind.startswith('corroborate'):
                self.samples[key].corroborate = kind

    def collect(self, now):
        for future, (key, kind, epoch) in list(self.jobs.items()):
            if not future.done():
                continue
            del self.jobs[future]
            if epoch != self.epoch:
                self.rearm_cancelled(key, kind)
                self.log('probe_discarded', candidate=key[0], reason='reload_or_upstream_change')
                continue
            # Ordinary discards consumed an attempt: retain its submission cadence.
            try:
                result, valid = future.result()
                if key in self.samples and valid:
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
        early = (sample.unknown_throughput < 2 and key not in peers and
                 (len(peers) < 3 or (sample.latency_or_inf) <
                  max(self.samples[k].latency_or_inf for k in peers)))
        if now >= due or (early and now-sample.last.get('throughput', float('-inf')) >= settings['early_test_seconds']):
            return 'throughput'
        return None

    def tick(self):
        now = self.clock()
        self.collect(now)
        if not self.client:
            return
        if now-self.last_inspect >= INSPECT_SECONDS:
            try:
                self.controller.inspect()
            except Exception as exc:
                self.log('probe_inspection_failed', error=type(exc).__name__)
            self.last_inspect = now
        self.controller.apply_policy(now)
        if now-self.last_summary >= SUMMARY_SECONDS:
            self.controller.summary(now)
            self.last_summary = now
        busy = {key for key, _, _ in self.jobs.values()}
        gates = sum(kind == 'gate' for _, kind, _ in self.jobs.values())
        downloading = any(kind != 'gate' for _, kind, _ in self.jobs.values())
        shortlists = self.shortlist(now)
        ordered = sorted(self.candidates, key=lambda k: (k not in self.requested, k[0] not in self.active.values(), self.samples[k].latency_or_inf, k))
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
