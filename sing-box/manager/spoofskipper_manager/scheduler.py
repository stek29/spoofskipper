"""Bounded measurements and serialized policy writes; no catch-up ticks."""
from concurrent.futures import ThreadPoolExecutor
import time
import weakref
from .controller import SelectorController
from .compiler import probe_outbounds
from .graph import OutboundGraph
from .identity import Candidate, sample_key
from .probes import Probe, ProbeClient
from .samples import FAILURES_TO_FAIL, Health, Sample
from .policy import score
from .settings import (Settings, INSPECT_SECONDS, SCORE_MAX_AGE, SHORTLIST_SIZE,
                       UPLINK_FRESH_SECONDS, UPLINK_RETRY_SECONDS)


class Scheduler:
    def __init__(self, log, clock=time.monotonic):
        self.log, self.clock = log, clock
        self.pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix='probe')  # 4 gates, a download, an uplink check
        self.samples, self.candidates, self.jobs = {}, {}, {}
        self.epoch, self.config, self.settings = 0, None, Settings()
        self.paths, self.path_versions, self.proxy_choices = {}, {}, {}
        self.active, self.last_inspect = {}, float('-inf')
        self.client = None
        self.clients = weakref.WeakSet()
        self.controller = SelectorController(self, log)
        self.requested = {}
        self.job_versions = {}
        self.configured = None
        self.graph, self.members = None, {}
        self.rotated_at = {}
        # Failures wait for a direct uplink check; while it is down they are dropped.
        self.held, self.uplink, self.uplink_down, self.uplink_checked_at = [], None, False, float('-inf')

    def configure(self, config, candidates, settings):
        settings = Settings.from_mapping(settings)
        enabled = settings.probes_enabled
        live_client = self.client is not None and not self.client.cancelled.is_set()
        if (config == self.config and settings == self.settings and list(candidates) == self.configured
                and live_client == enabled):
            return  # Unchanged reloads keep in-flight probes and their results.
        self.configured = list(candidates)
        self.epoch += 1
        self.config, self.settings = config, settings
        self.graph, self.members = OutboundGraph(config), {}
        # Subscription leaves carry their provider; local leaves are their own provider.
        subscribed = {c['outbound']['tag']: c for c in candidates}
        entries = []
        if enabled:
            for outbound in probe_outbounds(config):
                tag = outbound['tag']
                provider = subscribed[tag]['provider'] if tag in subscribed else tag
                weight = subscribed[tag]['weight'] if tag in subscribed else settings.provider_weights.get(tag, 1.0)
                entries.append(Candidate(outbound, provider, weight))
        self.candidates = {sample_key(c.outbound): c for c in entries}
        self.samples = {k: self.samples.get(k, Sample()) for k in self.candidates}
        self.update_paths(self.proxy_choices)
        self.client = ProbeClient(self.settings) if enabled else None
        if self.client:
            self.clients.add(self.client)
        self.last_inspect = float('-inf')

    def restrict(self, settings):
        """Apply revocations now; new ownership/probes require a checked render."""
        settings = Settings.from_mapping(settings)
        old = self.settings.managed_selectors
        allowed = [tag for tag in old if tag in settings.managed_selectors]
        self.settings = self.settings.with_changes(managed_selectors=allowed)
        self.controller.revoke(set(old) - set(allowed))
        if not settings.probes_enabled:
            if self.client is not None or self.jobs:
                self.invalidate()
            self.client = None
            self.settings = self.settings.with_changes(probes_enabled=False)
        self.requested = {}

    def update_paths(self, proxies):
        paths = {}
        for key in self.candidates:
            try:
                path = self.graph.path_identity(key.tag, proxies)
            except ValueError:
                path = None  # Unknown selection cannot retain trusted evidence.
            if key in self.paths and (path is None or path != self.paths[key]):
                self.samples[key] = Sample()
                self.path_versions[key] = self.path_versions.get(key, 0) + 1
            paths[key] = path
        self.paths = paths
        self.path_versions = {k: self.path_versions.get(k, 0) for k in paths}

    def selector_members(self, selector):
        if selector not in self.members:
            self.members[selector] = self.graph.leaves(selector)
        return self.members[selector]

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
        for key, probe, _ in self.jobs.values():
            self.rearm_cancelled(key, probe)
        self.jobs.clear()
        self.job_versions.clear()
        if self.uplink is not None:
            self.uplink.cancel()
            self.uplink = None  # A cancelled check says nothing about the uplink.
        self.held = []

    def restart_client(self):
        self.client = ProbeClient(self.settings)
        self.clients.add(self.client)

    def close(self):
        self.invalidate()
        for client in self.clients:
            client.cancel()
        self.pool.shutdown(wait=True, cancel_futures=True)

    def standbys(self):
        groups = {}
        for key, candidate in self.candidates.items():
            if self.samples[key].health is Health.HEALTHY and key.tag not in self.active.values():
                groups.setdefault(candidate.provider, []).append(key)
        return groups

    def shortlist(self, now=None):
        """The best-scored healthy standbys of each provider get regular throughput tests."""
        now = self.clock() if now is None else now
        def rank(key):
            value = score(self.samples[key], self.candidates[key].weight, now, SCORE_MAX_AGE)
            return value is None, -(value or 0), self.samples[key].latency_or_inf
        return {key for keys in self.standbys().values() for key in sorted(keys, key=rank)[:SHORTLIST_SIZE]}

    def rotation(self, shortlisted, now):
        """One more standby per provider and interval, least recently tested first, so every path gets scored."""
        chosen = {}
        for provider, keys in self.standbys().items():
            rest = [key for key in keys if key not in shortlisted]
            if rest and now - self.rotated_at.get(provider, float('-inf')) >= self.settings.throughput_rotation_seconds:
                sample = lambda key: self.samples[key]
                key = min(rest, key=lambda k: (sample(k).last.get(Probe.THROUGHPUT, float('-inf')), sample(k).latency_or_inf))
                chosen[key] = provider
        return chosen

    def perform(self, client, candidate, endpoint, probe):
        result = client.run(candidate.outbound, probe, endpoint)
        result.completed_at = self.clock()
        return result

    def accept(self, key, result, now):
        self.samples[key].record(result, now, max(FAILURES_TO_FAIL, len(self.settings.probe_urls)))
        if not result.ok:
            self.log('probe_failed', candidate=key.tag, probe=result.probe, error=result.error,
                     bytes=result.bytes, burst_seconds=result.burst_seconds)
        self.log('probe_sample', candidate=key.tag, **result.fields())

    def rearm_cancelled(self, key, probe):
        """Cancellation did not complete an attempt; permit its replacement now."""
        sample = self.samples.get(key)
        if sample is None:
            return
        sample.last.pop(probe, None)
        if sample.failed_probe is probe and 0 < sample.failures and sample.health is not Health.FAILED:
            sample.confirm = probe  # The cancelled attempt was a confirmation.

    def collect(self, now):
        for future, (key, probe, epoch) in list(self.jobs.items()):
            if not future.done():
                continue
            del self.jobs[future]
            version = self.job_versions.pop(future, None)
            if epoch != self.epoch:
                self.rearm_cancelled(key, probe)
                self.log('probe_discarded', candidate=key.tag, reason='reload_or_upstream_change')
                continue
            # Inspection changed the path (e.g. an upstream selector) while the
            # probe ran: the result belongs to neither path. Ordinary discards
            # consumed an attempt, so they retain their submission cadence.
            try:
                result = future.result()
                if key in self.samples and version in (None, self.path_versions.get(key, 0)):
                    self.accept_or_hold(key, result, now)
                    self.samples[key].last[probe] = now  # Never catch up missed runs.
                else:
                    self.log('probe_discarded', candidate=key.tag, reason='reload_or_upstream_change')
            except Exception as exc:
                self.log('probe_discarded', candidate=key.tag, reason=type(exc).__name__)

    def accept_or_hold(self, key, result, now):
        at = result.completed_at or now
        if result.ok or not self.settings.uplink_urls:
            self.accept(key, result, at)
        elif self.uplink_down:
            self.log('probe_discarded', candidate=key.tag, reason='uplink_down')
        elif self.uplink is None and now - self.uplink_checked_at < UPLINK_FRESH_SECONDS:
            self.accept(key, result, at)
        else:
            self.held.append((key, result, at))

    def check_uplink(self, now):
        """Tell a dead path from a dead uplink before failures count."""
        if self.uplink is not None and self.uplink.done():
            future, self.uplink = self.uplink, None
            try:
                up = future.result()
            except Exception:
                up = False
            self.uplink_checked_at = now
            if up == self.uplink_down:
                self.uplink_down = not up
                self.log('uplink_down' if self.uplink_down else 'uplink_restored')
            held, self.held = self.held, []
            for key, result, at in held:
                if key in self.samples:
                    self.accept_or_hold(key, result, now)
        if self.uplink is None and (self.held or self.uplink_down and now - self.uplink_checked_at >= UPLINK_RETRY_SECONDS):
            self.uplink = self.pool.submit(self.client.uplink_up)

    def next_test(self, key, shortlisted, now, rotation=()):
        sample, settings = self.samples[key], self.settings
        last = lambda probe: sample.last.get(probe, float('-inf'))
        active = key.tag in self.active.values()
        if sample.confirm:
            return sample.confirm
        if now >= last(Probe.GATE) + (settings.gate_active_seconds if active else settings.gate_standby_seconds):
            return Probe.GATE
        if sample.health is not Health.HEALTHY:
            # Reachable but unproven (or failed): check the threshold once per gate success.
            return Probe.THROTTLE if sample.reachable_at > last(Probe.THROTTLE) else None
        if active and now >= last(Probe.THROTTLE) + settings.throttle_seconds:
            return Probe.THROTTLE
        if key in rotation:
            return Probe.THROUGHPUT
        if active or key in shortlisted:
            cadence = settings.throughput_active_seconds if active else settings.throughput_shortlist_seconds
            if now >= last(Probe.THROUGHPUT) + cadence:
                return Probe.THROUGHPUT
        return None

    def tick(self):
        now = self.clock()
        self.collect(now)
        if not self.client:
            return
        if self.settings.uplink_urls:
            self.check_uplink(now)
            if self.uplink_down:
                return  # Paused: measurements and decisions resume with the uplink.
        if now-self.last_inspect >= INSPECT_SECONDS:
            try:
                self.controller.inspect()
            except Exception as exc:
                self.log('probe_inspection_failed', error=type(exc).__name__)
            self.last_inspect = now
        try:
            self.controller.apply_policy(now)
            policy_error = None
        except Exception as exc:
            # A policy fault must not stop measurements; it is re-raised below for logging.
            self.requested, policy_error = {}, exc
        busy = {key for key, _, _ in self.jobs.values()}
        gates = sum(probe is Probe.GATE for _, probe, _ in self.jobs.values())
        # Gates run in parallel; body probes download one at a time.
        downloading = any(probe is not Probe.GATE for _, probe, _ in self.jobs.values())
        shortlisted = self.shortlist(now)
        rotation = self.rotation(shortlisted, now)
        ordered = sorted(self.candidates, key=lambda k: (k not in self.requested, k.tag not in self.active.values(),
                                                         self.samples[k].latency_or_inf, k))
        for key in ordered:
            if key in busy:
                continue
            candidate, sample = self.candidates[key], self.samples[key]
            probe = self.requested.get(key) or self.next_test(key, shortlisted, now, rotation)
            if probe is None:
                continue
            if probe is Probe.GATE:
                if gates >= self.settings.probe_workers:
                    continue
                gates += 1
            else:
                if downloading:
                    continue
                downloading = True
            sample.last[probe] = now
            if probe is Probe.THROUGHPUT and key in rotation:
                self.rotated_at[rotation[key]] = now
            if sample.confirm is probe:
                sample.confirm = None
            # The n-th consecutive failure is confirmed against the next endpoint.
            future = self.pool.submit(self.perform, self.client, candidate, sample.failures, probe)
            self.jobs[future] = (key, probe, self.epoch)
            self.job_versions[future] = self.path_versions.get(key, 0)
        if policy_error is not None:
            raise policy_error
