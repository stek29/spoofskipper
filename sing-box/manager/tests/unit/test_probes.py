import copy
import sys
import unittest
from concurrent.futures import Future
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import compiler
from spoofskipper_manager.probes import SKIP, THROTTLE, Probe, ProbeResult
from spoofskipper_manager.identity import sample_key
from spoofskipper_manager.scheduler import Health, Scheduler
from spoofskipper_manager.policy import score


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.
        self.logs = []
        self.scheduler = Scheduler(lambda event, **kw: self.logs.append((event, kw)), clock=lambda: self.now)
        self.candidates = [{'provider': 'p', 'weight': 1.25, 'outbound': {'type': 'trojan', 'tag': 'c'+str(i)}} for i in range(6)]
        self.config = {'outbounds': [c['outbound'] for c in self.candidates]}
        self.scheduler.configure(self.config, self.candidates, {'probes_enabled': True})
        self.scheduler.last_inspect = self.now
        self.submissions = []
        def submit(*args):
            future = Future()
            self.submissions.append((future, args))
            return future
        self.patch = patch.object(self.scheduler.pool, 'submit', side_effect=submit)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.scheduler.close()

    def complete(self, **extra):
        for future, args in self.submissions:
            if not future.done():
                probe = Probe(args[-1])
                size = {Probe.GATE: 1, Probe.THROTTLE: THROTTLE, Probe.THROUGHPUT: THROTTLE + SKIP}[probe]
                fields = {'bytes': size, 'latency_ms': 30, **extra}
                if probe is not Probe.THROUGHPUT:
                    fields.pop('mbps', None)
                future.set_result(ProbeResult(probe, ok=True, **fields))

    def test_bounded_gates_dedup_and_no_catchup(self):
        self.scheduler.tick()
        self.assertEqual(len(self.scheduler.jobs), 4)
        self.scheduler.tick()
        self.assertEqual(len(self.scheduler.jobs), 4)
        self.complete()
        self.scheduler.tick()
        self.assertLessEqual(len(self.scheduler.jobs), 3)  # two gates + one download
        self.assertLessEqual(sum(k != 'gate' for _, k, _ in self.scheduler.jobs.values()), 1)
        self.complete(mbps=10)
        self.now += 100000
        self.scheduler.last_inspect = self.now
        self.scheduler.tick()
        self.assertLessEqual(len(self.scheduler.jobs), 5)
        for sample in self.scheduler.samples.values():
            if 'gate' in sample.last:
                self.assertEqual(sample.last['gate'], self.now)
        self.complete()

    def test_reload_retention_and_crossing_discard(self):
        key = sample_key(self.candidates[0]['outbound'])
        self.scheduler.samples[key].successes = [(self.now, 10, 30)]
        self.scheduler.tick()
        # An identical reload keeps in-flight probes and accepts their results.
        self.scheduler.configure(self.config, self.candidates, {'probes_enabled': True})
        self.assertEqual(self.scheduler.samples[key].successes, [(self.now, 10, 30)])
        self.complete()
        self.scheduler.last_inspect = self.now
        self.scheduler.tick()
        self.assertFalse(any(e == 'probe_discarded' for e, _ in self.logs))
        self.assertTrue(any(e == 'probe_sample' for e, _ in self.logs))
        # A changed reload discards work that crossed it.
        self.assertTrue(self.scheduler.jobs)
        changed = copy.deepcopy(self.candidates)
        changed[0]['outbound']['bind_interface'] = 'new'
        self.scheduler.configure({'outbounds': [c['outbound'] for c in changed]}, changed, {'probes_enabled': True})
        self.assertNotIn(key, self.scheduler.samples)
        self.complete()
        self.scheduler.tick()
        self.assertTrue(any(e == 'probe_discarded' for e, _ in self.logs))

    def test_only_the_lowest_latency_standbys_get_throughput_tests(self):
        for i, sample in enumerate(self.scheduler.samples.values()):
            sample.health, sample.latency = Health.HEALTHY, 10+i
            sample.last['gate'] = self.now
        shortlisted = self.scheduler.shortlist()
        self.assertEqual(sorted(k.tag for k in shortlisted), ['c0', 'c1', 'c2'])
        self.scheduler.tick()
        self.assertEqual(len(self.scheduler.jobs), 1)  # Downloads run one at a time.
        key, kind, _ = next(iter(self.scheduler.jobs.values()))
        self.assertEqual((key.tag, kind), ('c0', 'throughput'))
        self.complete(mbps=20)
        self.scheduler.samples[key].health = Health.FAILED  # A failed path drops out; c3 moves up.
        self.assertIn('c3', {k.tag for k in self.scheduler.shortlist()})
        self.assertIsNone(self.scheduler.next_test(sample_key({'type': 'trojan', 'tag': 'c5'}), shortlisted, self.now))

    def test_failure_confirmation_is_scheduled_first_and_survives_cancellation(self):
        key = next(iter(self.scheduler.samples))
        sample = self.scheduler.samples[key]
        sample.health, sample.healthy_at = Health.HEALTHY, self.now
        sample.last.update(gate=self.now, throttle=self.now, throughput=self.now)
        self.scheduler.accept(key, ProbeResult(Probe.THROTTLE, error='TimeoutError'), self.now)
        self.assertEqual(self.scheduler.next_test(key, [], self.now), Probe.THROTTLE)
        self.scheduler.tick()
        self.assertIn((key, Probe.THROTTLE, self.scheduler.epoch), self.scheduler.jobs.values())
        endpoints = [args[-2] for _, args in self.submissions if args[2] is self.scheduler.candidates[key]]
        self.assertEqual(endpoints, [1])  # Confirmed against the fallback endpoint.
        self.assertIsNone(sample.confirm)
        self.scheduler.invalidate()  # A reload cancels the confirmation; it is re-armed.
        self.assertEqual(sample.confirm, Probe.THROTTLE)
        self.scheduler.accept(key, ProbeResult(Probe.THROTTLE, error='TimeoutError'), self.now)
        self.assertFalse(sample.healthy)
        self.assertIsNone(score(sample, 1, self.now, 7200))

    def test_failed_path_rechecks_threshold_once_per_gate_success(self):
        key = next(iter(self.scheduler.samples))
        sample = self.scheduler.samples[key]
        sample.health, sample.failures = Health.FAILED, 2
        sample.last.update(gate=self.now, throttle=self.now)
        self.assertIsNone(self.scheduler.next_test(key, [], self.now))
        self.scheduler.accept(key, ProbeResult(Probe.GATE, ok=True, bytes=1), self.now + 1)
        self.assertEqual(self.scheduler.next_test(key, [], self.now + 1), Probe.THROTTLE)
        sample.last[Probe.THROTTLE] = self.now + 1
        self.assertIsNone(self.scheduler.next_test(key, [], self.now + 2))

    def test_routes_do_not_change_selectors_and_are_first(self):
        config = {'outbounds': self.config['outbounds'] + [{'type': 'selector', 'tag': 'proxy_main', 'outbounds': ['c0']}],
                  'route': {'rules': [{'outbound': 'proxy_main'}]}}
        before = copy.deepcopy(config['outbounds'])
        compiler.add_probe_routes(config, {'probes_enabled': True}, self.candidates)
        self.assertEqual(config['outbounds'], before)
        self.assertEqual(config['route']['rules'][0]['auth_user'][0][:6], 'probe_')
        self.assertEqual(config['route']['rules'][-2]['action'], 'reject')
        self.assertEqual(config['inbounds'][0]['listen'], '127.0.0.1')


    def test_active_warmup_does_not_wait_after_throttle(self):
        self.scheduler.active = {'proxy_main': 'c0'}
        self.scheduler.tick()
        self.complete()
        self.scheduler.tick()
        key = sample_key(self.candidates[0]['outbound'])
        self.assertIn((key, 'throttle', self.scheduler.epoch), self.scheduler.jobs.values())
        self.complete()
        self.scheduler.tick()
        self.assertIn((key, 'throughput', self.scheduler.epoch), self.scheduler.jobs.values())
        self.complete(mbps=10)
