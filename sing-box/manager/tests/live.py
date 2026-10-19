#!/usr/bin/env python3
"""Explicit live validation against private subscriptions; never part of discovery.

Run in a disposable development container with read-only /config, writable /tmp,
no published ports and this script mounted read-only. Uses real clocks, HTTPS
measurements and Clash writes. Reports contain metrics, never connection secrets.
"""
import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time

from spoofskipper_manager import clash_api, compiler, service
from spoofskipper_manager.policy import HOLD, MARGIN, score
from spoofskipper_manager.probes import ProbeClient, identity, sample_key
from spoofskipper_manager.subscriptions import Providers


class LiveRun:
    def __init__(self, config_dir, artifacts, endpoint_file, preferred_provider):
        self.source, self.artifacts = Path(config_dir), Path(artifacts)
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='manager-live-')
        self.root = Path(self.temp.name)
        self.started = time.monotonic()
        self.labels, self.events, self.checks = {}, [], {}
        self.preferred_provider = preferred_provider
        self.settings = {**service.load_settings(self.source),
                         'probes_enabled': True, 'managed_selectors': [],
                         'probe_port': 19091, 'probe_timeout': 15, 'probe_stall_timeout': 2}
        service.log = self.log
        self.manager = service.Manager(self.source, self.root/'data')
        self.manager.settings.update(self.settings)
        self.scheduler = self.manager.scheduler
        self.scheduler.log = self.log
        self.candidates = []
        self.chained = json.loads(Path(endpoint_file).read_text())
        self.settings['selector_priorities'] = {'priority_traffic': [[preferred_provider], [self.chained['tag']]]}
        self.chained.update(detour='transport', domain_resolver={'server': 'default', 'strategy': 'ipv4_only'})
        self.labels[self.chained['tag']] = 'local/endpoint'

    def safe(self, obj):
        if isinstance(obj, dict):
            return {k: self.safe(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.safe(v) for v in obj]
        if isinstance(obj, str):
            return self.labels.get(obj, obj)
        return obj

    def log(self, event, **fields):
        row = self.safe({'event': event, 'elapsed': round(time.monotonic()-self.started, 3), **fields})
        self.events.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)

    def save(self, error=None):
        report = {'checks': self.checks, 'application_bytes': self.scheduler.accounting.summary(),
                  'elapsed_seconds': time.monotonic()-self.started, 'error': error}
        (self.artifacts/'summary.json').write_text(json.dumps(report, indent=2))
        (self.artifacts/'events.json').write_text(json.dumps(self.events, indent=2, ensure_ascii=False))
        self.log('live_report', **report)

    def key(self, tag):
        return next(k for k in self.scheduler.candidates if k[0] == tag)

    def api(self):
        return clash_api.proxies(self.manager.current)

    def choice(self, selector):
        return self.api()[selector]['now']

    def set_choice(self, selector, tag):
        # Test control, equivalent to an operator choosing the initial state.
        # Never used to fulfill a policy-switch assertion.
        self.scheduler.invalidate()
        self.scheduler.restart_client()
        clash_api.select(self.manager.current, selector, tag, [selector])
        self.scheduler.inspect()
        self.log('test_setup_choice', selector=selector, candidate=tag)

    def build(self, candidates, chained, priority_members=None):
        leaves = [copy.deepcopy(c['outbound']) for c in candidates]
        tags = [o['tag'] for o in leaves]
        endpoint = chained and chained.get('type') in ('wireguard', 'tailscale')
        config = {'log': {'disabled': True},
                  'dns': {'servers': [{'type': 'local', 'tag': 'default'}]},
                  'outbounds': leaves + ([copy.deepcopy(chained)] if chained and not endpoint else []) + [
                      {'type': 'selector', 'tag': tag, 'outbounds':
                       (priority_members if tag == 'priority_traffic' and priority_members is not None else
                        tags + ([chained['tag']] if chained and tag != 'transport' else []))}
                      for tag in ('traffic', 'priority_traffic', 'transport')],
                  'endpoints': [copy.deepcopy(chained)] if endpoint else [],
                  'route': {'final': 'traffic', 'default_domain_resolver': {'server': 'default', 'strategy': 'ipv4_only'}},
                  'experimental': {'cache_file': {'enabled': True, 'path': str(self.root/'cache.db')},
                                   'clash_api': {'external_controller': '127.0.0.1:19092'}}}
        if chained and chained.get('detour') == '__live_offline':
            config['outbounds'].append({'type': 'socks', 'tag': '__live_offline',
                'server': '127.0.0.1', 'server_port': 1})
        compiler.add_probe_routes(config, self.settings, candidates)
        # Independent, authenticated routes through the selectors themselves
        # verify actual post-switch traffic, beyond direct candidate probing.
        selectors = [o for o in config['outbounds'] if o.get('type') == 'selector']
        inbound = '__live_selected_traffic'
        config['inbounds'].append({'type': 'mixed', 'tag': inbound, 'listen': '127.0.0.1',
            'listen_port': 19093, 'users': [{'username': identity(o)[0], 'password': identity(o)[1]}
                                           for o in selectors]})
        rules = [{'inbound': [inbound], 'auth_user': [identity(o)[0]], 'action': 'route',
                  'outbound': o['tag']} for o in selectors]
        config['route']['rules'] = rules + [{'inbound': [inbound], 'action': 'reject'}] + config['route']['rules']
        compiler.validate(config)
        digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        config['outbounds'].append({'type': 'direct', 'tag': compiler.REVISION_PREFIX+digest})
        return config

    def install(self, candidates, chained, priority_members=None, managed=()):
        self.settings['managed_selectors'] = list(managed)
        self.manager.settings.update(self.settings)
        self.manager.activate(self.build(candidates, chained, priority_members))
        self.scheduler.configure(self.manager.current, candidates, self.settings)
        self.scheduler.inspect()
        self.candidates = candidates

    def measure(self, key, kind):
        result, valid = self.scheduler.perform(self.scheduler.client, self.manager.current,
                                               self.scheduler.candidates[key], kind)
        assert valid, 'measurement crossed upstream change'
        at = result.pop('completed_at')
        self.scheduler.accept(key, kind, result, at)
        self.scheduler.samples[key].last[kind] = self.scheduler.clock()
        self.check_budget()
        return result

    def verify_selected_traffic(self, selector):
        entry = next(o for o in self.manager.current['outbounds'] if o['tag'] == selector)
        before = self.choice(selector)
        client = ProbeClient({**self.settings, 'probe_port': 19093}, accounting=self.scheduler.accounting)
        result = client.run(entry, 'gate')
        assert result['ok'], 'real traffic through selected route failed'
        assert self.choice(selector) == before, 'selector changed during traffic verification'
        self.log('real_selected_traffic_passed', selector=selector, candidate=before,
                 bytes=result['bytes'], latency_ms=result.get('latency_ms'))
        return before

    def check_budget(self):
        # A test-run ceiling only, not a production budget subsystem.
        received = self.scheduler.accounting.summary()['today'].get('received', 0)
        assert received <= 384*1024*1024, 'live test received-byte ceiling reached'

    def pump(self, seconds, assertion=None):
        until = time.monotonic()+seconds
        next_progress = time.monotonic()
        while time.monotonic() < until:
            self.scheduler.tick()
            self.check_budget()
            if assertion:
                assertion()
            if time.monotonic() >= next_progress:
                self.log('live_progress', choices=self.scheduler.active,
                         application_bytes=self.scheduler.accounting.summary())
                self.save()
                next_progress = time.monotonic()+30
            time.sleep(.2)

    def await_switch(self, selector, previous, timeout, reason):
        until = time.monotonic()+timeout
        next_progress = 0
        while time.monotonic() < until:
            self.scheduler.tick()
            self.check_budget()
            switched = [e for e in self.events if e['event'] == 'selector_switched' and
                        e['selector'] == selector and e.get('reason') == reason]
            if switched and self.choice(selector) != previous:
                return switched[-1]
            if time.monotonic() >= next_progress:
                self.log('waiting_for_switch', selector=selector, reason=reason,
                         candidate=self.scheduler.active.get(selector),
                         remaining_seconds=round(until-time.monotonic()))
                self.save()
                next_progress = time.monotonic()+30
            time.sleep(.2)
        raise AssertionError('live switch timeout: '+reason)

    def discovery(self):
        providers = Providers(self.source, self.root, self.settings, self.log)
        snapshots = providers.refresh()
        assert len(snapshots) == len(providers.config['subscriptions']), 'subscription fetch incomplete'
        self.all_candidates = providers.candidates(snapshots)
        for index, c in enumerate(self.all_candidates):
            self.labels[c['outbound']['tag']] = f"{c['provider']}/{c['outbound']['type']}/{index}"
        self.install(self.all_candidates, self.chained)
        self.log('real_subscription_sweep', providers=len(snapshots), candidates=len(self.all_candidates))
        queue = list(self.scheduler.candidates)
        queue = [k for k in queue if self.scheduler.candidates[k]['outbound']['tag'] != self.chained['tag']]
        completed, next_progress = 0, 0
        while queue or self.scheduler.jobs:
            while queue and len(self.scheduler.jobs) < 4:
                key = queue.pop(0)
                future = self.scheduler.pool.submit(self.scheduler.perform, self.scheduler.client,
                    self.manager.current, self.scheduler.candidates[key], 'gate')
                self.scheduler.jobs[future] = (key, 'gate', self.scheduler.epoch)
            before = len(self.scheduler.jobs)
            self.scheduler.collect(time.monotonic())
            completed += before-len(self.scheduler.jobs)
            if time.monotonic() >= next_progress:
                self.log('gate_sweep_progress', completed=completed, total=len(self.all_candidates))
                self.save()
                next_progress = time.monotonic()+20
            time.sleep(.1)
        healthy = Counter(c['provider'] for k, c in self.scheduler.candidates.items()
                          if self.scheduler.samples[k].healthy is True)
        self.checks['gate_sweep'] = {'total': len(self.all_candidates), 'healthy_by_provider': dict(healthy)}
        self.log('gate_sweep_complete', **self.checks['gate_sweep'])
        # Three scored candidates per provider, latency ordered, bounded backfill.
        self.scored = []
        for provider in snapshots:
            keys = sorted((k for k, c in self.scheduler.candidates.items() if c['provider'] == provider
                           and self.scheduler.samples[k].healthy is True),
                          key=lambda k: self.scheduler.samples[k].latency)
            successes = 0
            for key in keys[:10]:
                throttle = self.measure(key, 'throttle')
                if not throttle['ok']:
                    continue
                result = self.measure(key, 'throughput')
                if result['ok'] and result.get('mbps'):
                    self.scored.append(key)
                    successes += 1
                if successes == 3:
                    break
            self.log('provider_bandwidth_complete', provider=provider, scored=successes)
            assert successes, 'no measured throughput for provider '+provider
        self.checks['bandwidth'] = [{'candidate': self.labels[k[0]],
            'weight': self.scheduler.candidates[k]['weight'],
            'unweighted_score': score(self.scheduler.samples[k], 1., time.monotonic(), 7200),
            'weighted_score': score(self.scheduler.samples[k], self.scheduler.candidates[k]['weight'],
                                    time.monotonic(), 7200)} for k in self.scored]
        for row in self.checks['bandwidth']:
            assert abs(row['weighted_score']-row['unweighted_score']*row['weight']) < 1e-8
        self.save()

    def chained_connectivity(self):
        key = self.key(self.chained['tag'])
        # Try measured healthy subscription paths in latency order.
        choices = sorted(self.scored, key=lambda k: (
            self.scheduler.samples[k].latency))
        for upstream in choices[:9]:
            self.set_choice('transport', upstream[0])
            for attempt in range(2):
                result = self.measure(key, 'gate')
                self.log('real_chained_attempt', upstream=upstream[0], attempt=attempt+1, ok=result['ok'])
                if result['ok']:
                    throttle = self.measure(key, 'throttle')
                    throughput = self.measure(key, 'throughput')
                    assert throttle['ok'], 'chained endpoint throttle failed'
                    self.transport = upstream
                    self.checks['chained_real_path'] = {'upstream': self.labels[upstream[0]],
                        'throughput_mbps': throughput.get('mbps'), 'throttle_ok': True}
                    self.save()
                    return
        raise AssertionError('real chained endpoint unreachable through tested subscription paths')

    def elective(self):
        now = time.monotonic()
        ranked = sorted(self.scored, key=lambda k: score(self.scheduler.samples[k],
            self.scheduler.candidates[k]['weight'], now, 7200) or 0)
        first, best = ranked[0], ranked[-1]
        low = score(self.scheduler.samples[first], self.scheduler.candidates[first]['weight'], now, 7200)
        high = score(self.scheduler.samples[best], self.scheduler.candidates[best]['weight'], now, 7200)
        assert high >= low*MARGIN, 'real scores do not offer an elective challenger'
        self.set_choice('traffic', first[0])
        # Keep the discovery result set for actual background shortlist scheduling.
        self.scheduler.settings['managed_selectors'] = ['traffic']
        self.scheduler.policy.observe('traffic', first[0], time.monotonic())
        held_since = self.scheduler.policy.switched_at['traffic']
        self.log('elective_hold_started', incumbent=first[0], low_score=low, best_score=high,
                 hold_seconds=HOLD, actual_weights=self.settings.get('provider_weights', {}))
        before = self.api()
        def retained():
            if time.monotonic() < held_since+HOLD:
                assert self.scheduler.active['traffic'] == first[0], 'incumbent changed before real hold elapsed'
        self.pump(max(0, held_since+HOLD-time.monotonic()-.3), retained)
        event = self.await_switch('traffic', first[0], 180, 'score_improvement')
        now = time.monotonic()
        elapsed = now-held_since
        assert elapsed >= HOLD, 'elective hold bypassed'
        key = self.key(self.choice('traffic'))
        since = self.scheduler.samples[key].throughput_at
        assert since >= held_since+HOLD-.3, 'earlier throughput reused for promotion'
        after = self.api()
        for selector in ('priority_traffic', 'transport'):
            assert after[selector]['now'] == before[selector]['now'], 'unlisted selector changed'
        self.verify_selected_traffic('traffic')
        self.checks['live_elective_switch'] = {'held_seconds': elapsed,
            'target': self.labels[key[0]], 'fresh_throughput_age': now-since,
            'compared': event['compared'], 'unlisted_preserved': True}
        self.save()

    def preferred_chained_transitions(self):
        now = time.monotonic()
        preferred = max((k for k in self.scored if self.scheduler.candidates[k]['provider'] == self.preferred_provider),
                    key=lambda k: score(self.scheduler.samples[k], self.scheduler.candidates[k]['weight'], now, 7200) or 0)
        # A real single-preferred provider topology makes its outage deterministic without
        # altering any provider server or manufacturing health/score evidence.
        keep = {preferred[0], self.transport[0]}
        candidates = [c for c in self.all_candidates if c['outbound']['tag'] in keep]
        self.settings.update(gate_active_seconds=5, gate_standby_seconds=15)
        members = [preferred[0], self.chained['tag']]
        self.install(candidates, self.chained, members)
        self.set_choice('transport', self.transport[0])
        self.set_choice('priority_traffic', preferred[0])
        for tag in members:
            result = self.measure(self.key(tag), 'gate')
            assert result['ok'], 'reduced topology path failed'
        self.scheduler.settings['managed_selectors'] = ['priority_traffic']
        self.scheduler.policy.observe('priority_traffic', preferred[0], time.monotonic())
        self.log('strict_topology', preferred=preferred[0], chained=self.chained['tag'],
                 upstream=self.transport[0])
        broken = copy.deepcopy(candidates)
        for c in broken:
            if c['outbound']['tag'] == preferred[0]:
                c['outbound'].update(server='127.0.0.1', server_port=1)
        began = time.monotonic()
        self.install(broken, self.chained, members, ['priority_traffic'])
        self.await_switch('priority_traffic', preferred[0], 120, 'health_failover')
        assert self.choice('priority_traffic') == self.chained['tag'], 'preferred provider outage did not choose working chained endpoint'
        chained_since = self.scheduler.policy.switched_at['priority_traffic']
        self.verify_selected_traffic('priority_traffic')
        self.checks['preferred_to_chained'] = {'seconds': time.monotonic()-began, 'confirmed_real_probe_failures': True}
        # Restore the actual subscribed definition. Early successful real
        # throughput and throttle must not permit return before five minutes.
        self.install(candidates, self.chained, members, ['priority_traffic'])
        preferred = self.key(preferred[0])
        for kind in ('gate', 'throughput', 'throttle'):
            assert self.measure(preferred, kind)['ok'], 'restored preferred provider probe failed'
        early_at = time.monotonic()
        def retained():
            if time.monotonic() < chained_since+HOLD:
                assert self.scheduler.active['priority_traffic'] == self.chained['tag'], 'early preferred provider return before real hold'
        self.pump(max(0, chained_since+HOLD-time.monotonic()-.3), retained)
        self.await_switch('priority_traffic', self.chained['tag'], 180, 'priority_return')
        now = time.monotonic()
        s = self.scheduler.samples[preferred]
        assert s.throughput_at >= chained_since+HOLD-.3, 'earlier preferred provider throughput reused'
        assert s.throttle_at >= chained_since+HOLD-.3 and now-s.throttle_at <= 30, 'preferred provider throttle not fresh'
        assert s.throughput_at > early_at, 'recovery observation reused'
        self.verify_selected_traffic('priority_traffic')
        self.checks['chained_to_preferred'] = {'held_seconds': now-chained_since,
            'fresh_throughput_age': now-s.throughput_at, 'fresh_throttle_age': now-s.throttle_at}
        self.save()
        # Confirmed chained endpoint failure bypasses a newly started hold and downloads.
        self.set_choice('priority_traffic', self.chained['tag'])
        self.scheduler.policy.observe('priority_traffic', self.chained['tag'], time.monotonic())
        dead_chained = copy.deepcopy(self.chained)
        dead_chained['detour'] = '__live_offline'
        began = time.monotonic()
        self.install(candidates, dead_chained, members, ['priority_traffic'])
        self.await_switch('priority_traffic', self.chained['tag'], 120, 'health_failover')
        assert self.choice('priority_traffic') == preferred[0], 'failed chained endpoint did not choose healthy preferred provider'
        self.verify_selected_traffic('priority_traffic')
        self.checks['failed_chained_bypasses_hold'] = {'seconds': time.monotonic()-began}
        self.save()

    def full_provider_outage(self, candidates, preferred, upstream):
        """Real policy over the complete subscription graph, with scratch faults."""
        self.settings.update(gate_active_seconds=5, gate_standby_seconds=60)
        self.install(candidates, self.chained)
        self.set_choice('transport', upstream)
        self.set_choice('priority_traffic', preferred)
        assert self.measure(self.key(preferred), 'gate')['ok']
        assert self.measure(self.key(self.chained['tag']), 'gate')['ok']
        broken = copy.deepcopy(candidates)
        count = 0
        for candidate in broken:
            if candidate['provider'] == self.preferred_provider:
                candidate['outbound'].update(server='127.0.0.1', server_port=1)
                count += 1
        self.log('full_provider_outage_started', candidates=len(candidates), failed_preferred_routes=count)
        self.install(broken, self.chained, managed=['priority_traffic'])
        began = time.monotonic()
        self.await_switch('priority_traffic', preferred, 180, 'health_failover')
        assert self.choice('priority_traffic') == self.chained['tag']
        assert all(self.scheduler.samples[k].healthy is False for k, c in self.scheduler.candidates.items()
                   if c['provider'] == self.preferred_provider), 'chained endpoint chosen before all preferred provider failures confirmed'
        self.verify_selected_traffic('priority_traffic')
        self.checks['full_provider_outage'] = {'total_candidates': len(candidates),
            'confirmed_failed_preferred': count, 'seconds': time.monotonic()-began}
        self.save()
        # Restore actual provider definitions, then really fail chained endpoint. Gate-only
        # recovery must suffice for immediate fallback with unknown preferred provider rates.
        self.install(candidates, self.chained, managed=['priority_traffic'])
        assert self.measure(self.key(preferred), 'gate')['ok']
        assert not self.scheduler.samples[self.key(preferred)].successes, 'expected unknown restored preferred provider throughput'
        self.scheduler.policy.observe('priority_traffic', self.chained['tag'], time.monotonic())
        dead_chained = copy.deepcopy(self.chained)
        dead_chained['detour'] = '__live_offline'
        self.install(candidates, dead_chained, managed=['priority_traffic'])
        began = time.monotonic()
        # Gate-only test driver: obtain real confirmed failure while preserving
        # unknown throughput. Production policy must select before any download.
        chained_key = self.key(self.chained['tag'])
        for _ in range(3):
            assert not self.measure(chained_key, 'gate')['ok']
        assert not self.measure(chained_key, 'corroborate_gate')['ok']
        assert not self.scheduler.samples[self.key(preferred)].successes
        self.scheduler.inspect()
        self.scheduler.apply_policy(time.monotonic())
        assert self.choice('priority_traffic') == preferred
        assert time.monotonic()-began < HOLD
        self.verify_selected_traffic('priority_traffic')
        self.checks['full_graph_unknown_score_fallback'] = {'seconds': time.monotonic()-began,
            'throughput_downloads_before_choice': 0}
        self.save()
        # With both eligible path classes genuinely broken, retain the choice;
        # neither the policy nor selector membership may introduce direct routing.
        prior = self.choice('priority_traffic')
        self.install(broken, dead_chained, managed=['priority_traffic'])
        until = time.monotonic()+180
        progress = 0
        while time.monotonic() < until:
            self.scheduler.tick()
            self.check_budget()
            reason = self.scheduler.last_decisions.get('priority_traffic', (None,))[0]
            if reason == 'all_paths_failed':
                break
            if time.monotonic() >= progress:
                self.log('waiting_for_all_path_failure', reason=reason)
                progress = time.monotonic()+30
            time.sleep(.2)
        else:
            raise AssertionError('all-path failure confirmation timed out')
        assert self.choice('priority_traffic') == prior
        entry = next(o for o in self.manager.current['outbounds'] if o['tag'] == 'priority_traffic')
        client = ProbeClient({**self.settings, 'probe_port': 19093}, accounting=self.scheduler.accounting)
        assert not client.run(entry, 'gate')['ok'], 'unexpected successful route after all paths failed'
        assert not any(tag.startswith(compiler.REVISION_PREFIX) or tag == 'direct' for tag in entry['outbounds'])
        self.checks['full_graph_all_paths_failed_without_direct'] = True
        self.save()

    def resume_chained_checks(self, report_path):
        """Resume with fresh real measurements after a passed elective checkpoint."""
        previous = json.loads(Path(report_path).read_text())
        assert previous['checks'].get('live_elective_switch'), 'real elective checkpoint is required'
        try:
            providers = Providers(self.source, self.root, self.settings, self.log)
            snapshots = providers.refresh()
            assert len(snapshots) == len(providers.config['subscriptions'])
            self.all_candidates = providers.candidates(snapshots)
            for index, c in enumerate(self.all_candidates):
                self.labels[c['outbound']['tag']] = f"{c['provider']}/{c['outbound']['type']}/{index}"
            ranked = sorted(previous['checks']['bandwidth'], key=lambda row: row['weighted_score'], reverse=True)
            preferred = next(row['candidate'] for row in ranked if row['candidate'].startswith(self.preferred_provider+'/'))
            upstream = previous['checks']['chained_real_path']['upstream']
            selected = [c for c in self.all_candidates if self.labels[c['outbound']['tag']] in (preferred, upstream)]
            assert len(selected) == 2, 'live subscription candidates changed; rerun discovery'
            self.install(selected, self.chained)
            upstream_tag = next(c['outbound']['tag'] for c in selected if self.labels[c['outbound']['tag']] == upstream)
            self.set_choice('transport', upstream_tag)
            self.scored = []
            for c in selected:
                key = self.key(c['outbound']['tag'])
                assert self.measure(key, 'gate')['ok']
                assert self.measure(key, 'throttle')['ok']
                for attempt in range(3):
                    result = self.measure(key, 'throughput')
                    if result['ok'] and result.get('mbps'):
                        self.scored.append(key)
                        break
                else:
                    raise AssertionError('fresh real throughput unavailable')
            self.chained_connectivity()
            self.preferred_chained_transitions()
            self.checks['resumed_real_chained_checks_passed'] = True
            self.checks['prior_live_elective_checkpoint'] = previous['checks']['live_elective_switch']
            self.save()
        except BaseException as exc:
            self.save(error=type(exc).__name__+': '+str(exc))
            raise
        finally:
            self.scheduler.close()
            self.manager.stop_child()
            self.temp.cleanup()

    def selected_traffic_smoke(self, report_path):
        """Additional end-to-end requests through the selectors themselves."""
        previous = json.loads(Path(report_path).read_text())
        assert previous['checks'].get('live_elective_switch'), 'real elective checkpoint must pass first'
        try:
            providers = Providers(self.source, self.root, self.settings, self.log)
            snapshots = providers.refresh()
            assert len(snapshots) == len(providers.config['subscriptions'])
            candidates = providers.candidates(snapshots)
            for index, c in enumerate(candidates):
                self.labels[c['outbound']['tag']] = f"{c['provider']}/{c['outbound']['type']}/{index}"
            reverse = {v: k for k, v in self.labels.items()}
            self.install(candidates, self.chained)
            ranked = sorted(previous['checks']['bandwidth'], key=lambda row: row['weighted_score'], reverse=True)
            preferred = next(row for row in ranked if row['candidate'].startswith(self.preferred_provider+'/'))
            best = ranked[0]
            for selector, row in [('traffic', best), ('priority_traffic', preferred)]:
                self.set_choice(selector, reverse[row['candidate']])
                self.verify_selected_traffic(selector)
            upstream = reverse[previous['checks']['chained_real_path']['upstream']]
            self.set_choice('transport', upstream)
            key = self.key(self.chained['tag'])
            for attempt in range(2):
                if self.measure(key, 'gate')['ok']:
                    break
            else:
                raise AssertionError('chained endpoint failed selected-traffic warmup')
            self.set_choice('priority_traffic', self.chained['tag'])
            self.verify_selected_traffic('priority_traffic')
            self.checks['selected_traffic_smoke_passed'] = True
            self.save()
            self.full_provider_outage(candidates, reverse[preferred['candidate']], upstream)
            self.checks['full_provider_live_checks_passed'] = True
            self.save()
        except BaseException as exc:
            self.save(error=type(exc).__name__+': '+str(exc))
            raise
        finally:
            self.scheduler.close()
            self.manager.stop_child()
            self.temp.cleanup()

    def run(self):
        try:
            self.discovery()
            self.chained_connectivity()
            self.elective()
            self.preferred_chained_transitions()
            ranked = sorted(self.checks['bandwidth'], key=lambda row: row['weighted_score'], reverse=True)
            label = next(row['candidate'] for row in ranked if row['candidate'].startswith(self.preferred_provider+'/'))
            preferred = next(c['outbound']['tag'] for c in self.all_candidates
                         if self.labels[c['outbound']['tag']] == label)
            self.full_provider_outage(self.all_candidates, preferred, self.transport[0])
            self.checks['all_requested_live_checks_passed'] = True
            self.save()
        except BaseException as exc:
            self.save(error=type(exc).__name__+': '+str(exc))
            raise
        finally:
            self.scheduler.close()
            self.manager.stop_child()
            self.temp.cleanup()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config-dir', default='/config')
    parser.add_argument('--artifacts-dir', default='/artifacts')
    parser.add_argument('--endpoint-file', required=True, help='JSON outbound or endpoint to test through a selected transport')
    parser.add_argument('--preferred-provider', required=True, help='subscription prefix used for strict priority tests')
    parser.add_argument('--resume-chained-report', help='resume chained endpoint checks with fresh measurements from a live elective checkpoint')
    parser.add_argument('--selected-traffic-report', help='run additional selector traffic checks using a passed full-run report')
    args = parser.parse_args()
    run = LiveRun(args.config_dir, args.artifacts_dir, args.endpoint_file, args.preferred_provider)
    if args.resume_chained_report:
        run.resume_chained_checks(args.resume_chained_report)
    elif args.selected_traffic_report:
        run.selected_traffic_smoke(args.selected_traffic_report)
    else:
        run.run()
