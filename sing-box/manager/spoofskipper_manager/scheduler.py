"""Bounded measurements and serialized policy writes; no catch-up ticks."""
from concurrent.futures import ThreadPoolExecutor
import time
import weakref
from . import clash_api
from .controller import SelectorController
from .compiler import probe_outbounds
from .graph import OutboundGraph
from .identity import Candidate, sample_key
from .probes import Probe, ProbeClient
from .samples import Health, Sample
from .settings import Settings, INSPECT_SECONDS, SHORTLIST_SIZE


def path_identity(config, proxies, tag):
    return OutboundGraph(config).path_identity(tag, proxies)


class Scheduler:
    def __init__(self, log, clock=time.monotonic):
        self.log, self.clock = log, clock
        self.pool = ThreadPoolExecutor(max_workers=5, thread_name_prefix='probe')
        self.samples, self.candidates, self.jobs = {}, {}, {}
        self.epoch, self.config, self.settings = 0, None, Settings()
        self.paths, self.path_versions, self.proxy_choices = {}, {}, {}
        self.active, self.last_inspect = {}, float('-inf')
        self.client = None
        self.clients = weakref.WeakSet()
        self.controller = SelectorController(self, log)
        self.requested = {}
        self.configured = None
        self.graph, self.members = None, {}

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

    def restart_client(self):
        self.client = ProbeClient(self.settings)
        self.clients.add(self.client)

    def close(self):
        self.invalidate()
        for client in self.clients:
            client.cancel()
        self.pool.shutdown(wait=True, cancel_futures=True)

    def shortlist(self):
        """The lowest-latency healthy standbys of each provider get throughput tests."""
        groups = {}
        for key, candidate in self.candidates.items():
            if self.samples[key].health is Health.HEALTHY:
                groups.setdefault(candidate.provider, []).append(key)
        return {key for keys in groups.values()
                for key in sorted(keys, key=lambda k: self.samples[k].latency_or_inf)[:SHORTLIST_SIZE]}

    def perform(self, client, config, candidate, probe):
        outbound = candidate.outbound
        key = sample_key(outbound)
        version = self.path_versions.get(key, 0)
        dependent = bool(outbound.get('detour'))
        before = path_identity(config, clash_api.proxies(config), outbound['tag']) if dependent else key
        result = client.run(outbound, probe)
        after = path_identity(config, clash_api.proxies(config), outbound['tag']) if dependent else key
        result.completed_at = self.clock()
        return result, before == after and version == self.path_versions.get(key, 0)

    def accept(self, key, result, now):
        self.samples[key].record(result, now)
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
            if epoch != self.epoch:
                self.rearm_cancelled(key, probe)
                self.log('probe_discarded', candidate=key.tag, reason='reload_or_upstream_change')
                continue
            # Ordinary discards consumed an attempt: retain its submission cadence.
            try:
                result, valid = future.result()
                if key in self.samples and valid:
                    self.accept(key, result, result.completed_at or now)
                    self.samples[key].last[probe] = now  # Never catch up missed runs.
                else:
                    self.log('probe_discarded', candidate=key.tag, reason='reload_or_upstream_change')
            except Exception as exc:
                self.log('probe_discarded', candidate=key.tag, reason=type(exc).__name__)

    def next_test(self, key, shortlisted, now):
        sample, settings = self.samples[key], self.settings
        last = lambda probe: sample.last.get(probe, float('-inf'))
        active = key.tag in self.active.values()
        if sample.confirm:
            return sample.confirm
        if now >= last(Probe.GATE) + settings['gate_active_seconds' if active else 'gate_standby_seconds']:
            return Probe.GATE
        if sample.health is not Health.HEALTHY:
            # Reachable but unproven (or failed): check the threshold once per gate success.
            return Probe.THROTTLE if sample.reachable_at > last(Probe.THROTTLE) else None
        if active and now >= last(Probe.THROTTLE) + settings['throttle_seconds']:
            return Probe.THROTTLE
        if active or key in shortlisted:
            cadence = settings['throughput_active_seconds' if active else 'throughput_shortlist_seconds']
            if now >= last(Probe.THROUGHPUT) + cadence:
                return Probe.THROUGHPUT
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
        shortlisted = self.shortlist()
        ordered = sorted(self.candidates, key=lambda k: (k not in self.requested, k.tag not in self.active.values(),
                                                         self.samples[k].latency_or_inf, k))
        for key in ordered:
            if key in busy:
                continue
            candidate, sample = self.candidates[key], self.samples[key]
            probe = self.requested.get(key) or self.next_test(key, shortlisted, now)
            if probe is None:
                continue
            if probe is Probe.GATE:
                if gates >= self.settings['probe_workers']:
                    continue
                gates += 1
            else:
                if downloading:
                    continue
                downloading = True
            sample.last[probe] = now
            if sample.confirm is probe:
                sample.confirm = None
            future = self.pool.submit(self.perform, self.client, self.config, candidate, probe)
            self.jobs[future] = (key, probe, self.epoch)
        if policy_error is not None:
            raise policy_error
