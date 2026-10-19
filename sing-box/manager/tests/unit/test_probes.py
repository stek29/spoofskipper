import copy
import sys
import unittest
from concurrent.futures import Future
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import compiler
from spoofskipper_manager.probes import Accounting, sample_key
from spoofskipper_manager.scheduler import Scheduler, Sample, score


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.
        self.logs = []
        self.scheduler = Scheduler(lambda event, **kw: self.logs.append((event, kw)), clock=lambda: self.now)
        self.candidates = [{'provider': 'p', 'weight': 1.25, 'outbound': {'type': 'direct', 'tag': 'c'+str(i)}} for i in range(6)]
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
                future.set_result(({'ok': True, 'kind': args[-1], 'bytes': 1, 'latency_ms': 30, **extra}, True))

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
        self.scheduler.configure(self.config, self.candidates, {'probes_enabled': True})
        self.assertEqual(self.scheduler.samples[key].successes, [(self.now, 10, 30)])
        self.complete()
        self.scheduler.last_inspect = self.now
        self.scheduler.tick()
        self.assertTrue(any(e == 'probe_discarded' for e, _ in self.logs))
        changed = copy.deepcopy(self.candidates)
        changed[0]['outbound']['bind_interface'] = 'new'
        self.scheduler.configure(self.config, changed, {'probes_enabled': True})
        self.assertNotIn(key, self.scheduler.samples)
        self.complete()

    def test_shortlist_warmup_backfill_and_freshness(self):
        for i, (key, sample) in enumerate(self.scheduler.samples.items()):
            sample.healthy, sample.latency = True, 10+i
            sample.last['gate'] = self.now
            if i < 3:
                sample.successes = [(self.now, 20, 10+i)]
        peers = self.scheduler.shortlist(self.now)['p']
        self.assertEqual(len(peers), 3)
        self.scheduler.tick()
        self.assertEqual(len(self.scheduler.jobs), 0)  # no full-pool startup downloads
        self.scheduler.samples[peers[0]].body_failed = True
        self.scheduler.samples[peers[0]].last['throttle'] = self.now
        self.scheduler.tick()
        self.assertEqual(len(self.scheduler.jobs), 1)  # latency-ranked replacement
        key, kind, _ = next(iter(self.scheduler.jobs.values()))
        self.assertEqual(kind, 'throughput')
        self.assertNotIn(key, peers)
        self.complete(mbps=20)
        sample = self.scheduler.samples[peers[1]]
        self.assertIsNotNone(score(sample, 1, self.now, 7200))
        self.assertIsNone(score(sample, 1, self.now+7201, 7200))

    def test_failure_corroboration_and_tiny_success(self):
        key = next(iter(self.scheduler.samples))
        failure = {'ok': False, 'bytes': 0}
        for _ in range(2):
            self.scheduler.accept(key, 'gate', failure, self.now)
        sample = self.scheduler.samples[key]
        self.assertIsNone(sample.corroborate)
        self.scheduler.accept(key, 'gate', failure, self.now)
        self.assertEqual(sample.corroborate, 'corroborate_gate')
        self.scheduler.accept(key, 'corroborate_gate', failure, self.now)
        self.assertFalse(sample.healthy)
        self.scheduler.accept(key, 'throttle', failure, self.now)
        self.scheduler.accept(key, 'gate', {'ok': True}, self.now)
        self.assertTrue(sample.body_failed)
        self.scheduler.accept(key, 'corroborate_body', {'ok': True}, self.now)
        self.assertTrue(sample.body_failed)
        self.scheduler.accept(key, 'throttle', {'ok': True}, self.now)
        self.assertFalse(sample.body_failed)
        self.assertIsNone(score(sample, 1, self.now, 7200))

    def test_warp_changed_upstream_discards(self):
        class Client:
            def run(self, *_):
                return {'ok': True}
        with patch('spoofskipper_manager.scheduler.clash_api.proxies', side_effect=[{'warp_upstream': {'now': 'a'}}, {'warp_upstream': {'now': 'b'}}]):
            _, valid = self.scheduler.perform(Client(), {}, {'provider': 'WARP', 'outbound': {}}, 'gate')
        self.assertFalse(valid)

    def test_accounting_hour_today(self):
        account = Accounting(clock=lambda: self.now)
        account.add(sent=1, received=2, skipped=1)
        self.now += 3600
        account.add(received=3)
        self.assertEqual(account.summary()['hour'], {'received': 3})
        self.assertEqual(account.summary()['today']['received'], 5)

    def test_routes_do_not_change_selectors_and_are_first(self):
        config = {'outbounds': self.config['outbounds'] + [{'type': 'selector', 'tag': 'proxy_main', 'outbounds': ['c0']}],
                  'route': {'rules': [{'outbound': 'proxy_main'}]}}
        before = copy.deepcopy(config['outbounds'])
        compiler.add_probe_routes(config, {'probes_enabled': True}, self.candidates)
        self.assertEqual(config['outbounds'], before)
        self.assertEqual(config['route']['rules'][0]['auth_user'][0][:6], 'probe_')
        self.assertEqual(config['route']['rules'][-2]['action'], 'reject')
        self.assertEqual(config['inbounds'][0]['listen'], '127.0.0.1')


    def test_active_cadence_change_and_median_score(self):
        sample = Sample(latency=999, healthy=True,
                        successes=[(100, 10, 20), (101, 20, 40), (102, 50, 80)])
        expected = (20/10)**.6 * (200/40)**.4
        self.assertAlmostEqual(score(sample, 1, 103, 7200), expected)
        key = next(iter(self.scheduler.samples))
        self.scheduler.samples[key] = sample
        sample.last['gate'] = sample.last['throughput'] = self.now
        self.now += 61
        self.scheduler.active = {'proxy_main': key[0]}
        self.assertEqual(self.scheduler.next_test(key, [], self.now), 'gate')
        sample.last['gate'] = self.now
        self.assertEqual(self.scheduler.next_test(key, [], self.now), 'throttle')
        sample.last['throttle'] = self.now
        self.assertIsNone(self.scheduler.next_test(key, [], self.now))


    def test_proposed_main_includes_warp_but_upstream_excludes_it(self):
        warp = {'type': 'wireguard', 'tag': 'warp', 'detour': 'warp_upstream'}
        config = {'outbounds': self.config['outbounds'], 'endpoints': [warp]}
        self.scheduler.configure(config, self.candidates, {'probes_enabled': True})
        for key, sample in self.scheduler.samples.items():
            sample.healthy, sample.latency = True, 20
            sample.successes = [(self.now, 50 if key[0] == 'warp' else 1, 20)]
        self.scheduler.summary(self.now)
        choices = self.logs[-1][1]['selectors']
        self.assertEqual(choices['proxy_main']['proposed'], 'warp')
        self.assertNotEqual(choices['warp_upstream']['proposed'], 'warp')


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
