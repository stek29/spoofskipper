import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import clash_api, compiler
from spoofskipper_manager.identity import Candidate, SampleKey
from spoofskipper_manager.policy import Policy, score
from spoofskipper_manager.scheduler import Health, Sample, Scheduler
from spoofskipper_manager.probes import SKIP, THROTTLE, Probe, ProbeResult
from spoofskipper_manager.settings import SCORE_MAX_AGE, Settings


def key(tag):
    return SampleKey(tag, tag)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.p = Policy()
        self.candidates = {key(tag): Candidate({}, provider, weight) for tag, provider, weight in
                           [('a', 'preferred', 1.25), ('b', 'preferred', 1.25), ('c', 'other', 1), ('chained', 'chained', 1)]}
        self.samples = {k: Sample(health=Health.HEALTHY, healthy_at=1000, latency=50,
                                  successes=[(1000, 10, 50)]) for k in self.candidates}
        self.members = [k.tag for k in self.candidates]

    def sample(self, tag):
        return self.samples[key(tag)]

    def decide(self, tag='a', selector='proxy_main'):
        return self.p.decide(selector, tag, self.candidates, self.samples, self.now, Settings(selector_priorities={'proxy_deepmind': [['preferred'], ['chained']]}),
                             [m for m in self.members if selector != 'chained_upstream' or m != 'chained'])

    def test_score_tradeoff_cap_weight_median_and_freshness(self):
        s = self.sample('a')
        s.successes = [(100, 1, 1000), (900, 10, 50), (950, 100, 50), (999, 20, 50)]
        expected = 1.25 * 2**.6 * 4**.4
        self.assertAlmostEqual(score(s, 1.25, 1000, 200), expected)
        s.successes = [(1000, 100, 50)]
        capped = score(s, 1, 1000, 7200)
        s.successes = [(1000, 50, 50)]
        self.assertEqual(score(s, 1, 1000, 7200), capped)
        self.assertIsNone(score(s, 1, 8201, 7200))
        self.assertIsNotNone(score(s, 1, 8201, SCORE_MAX_AGE))
        s.health = Health.FAILED
        self.assertIsNone(score(s, 1, 1000, 7200))

    def test_hold_margin_and_mandatory_fresh_challenger(self):
        self.sample('b').successes = [(1000, 11, 50)]
        self.assertEqual(self.decide().reason, 'margin_or_performance_unknown')

    def test_fresh_switch_and_failed_fresh_margin(self):
        self.sample('b').successes = [(1000, 40, 50)]
        self.assertEqual(self.decide().reason, 'hold')
        self.now = 1300
        d = self.decide()
        self.assertEqual(d.tests, ((key('b'), Probe.THROUGHPUT),))
        self.assertEqual(d.since, 1300)
        self.sample('b').successes = [(1301, 40, 50)]
        self.now = 1301
        self.assertEqual(self.decide().target, key('b'))
        self.sample('b').successes = [(1301, 1, 50)]
        self.assertIsNone(self.decide().target)

    def test_challenger_result_older_than_freshness_is_retested(self):
        self.sample('b').successes = [(1000, 40, 50)]
        self.decide()
        self.now = 1300
        self.decide()
        self.sample('b').successes = [(1301, 40, 50)]
        self.now = 1332
        d = self.decide()
        self.assertIsNone(d.target)
        self.assertEqual(d.reason, 'challenger_test')
        self.assertEqual(d.since, 1300)  # The controller retries at the early cadence.

    def test_immediate_failure_last_score_unknown_fallback_and_all_failed(self):
        self.decide()
        self.sample('a').health = Health.FAILED
        self.sample('b').successes = [(0, 40, 50)]
        self.now += 1
        d = self.decide()
        self.assertEqual(d.reason, 'health_failover')
        self.assertEqual(d.target, key('b'))
        self.assertFalse(d.tests)
        for s in self.samples.values():
            s.successes = []
        self.sample('c').latency = 10
        self.assertEqual(self.decide().target, key('c'))
        for s in self.samples.values():
            s.health = Health.FAILED
        self.assertEqual(self.decide().reason, 'all_paths_failed')
        self.assertIsNone(self.decide().target)

    def test_failover_needs_a_threshold_pass_after_the_failure(self):
        self.sample('a').health, self.sample('a').failed_at = Health.FAILED, 1000
        self.sample('b').successes = [(1000, 40, 50)]  # Best ranked, then c.
        self.sample('c').successes = [(1000, 20, 50)]
        for tag in ('b', 'c', 'chained'):
            self.sample(tag).healthy_at = 1001  # Gates answered after the failure...
            self.sample(tag).threshold_at = 900  # ...but the threshold was last passed before it.
        self.now = 1001
        d = self.decide()
        self.assertIsNone(d.target)
        self.assertEqual(d.reason, 'failover_verify')
        self.assertEqual((d.tests, d.since), (((key('b'), Probe.THROTTLE),), 1000))
        self.sample('b').health = Health.FAILED  # b stalls too; the next best is checked.
        self.assertEqual(self.decide().tests, ((key('c'), Probe.THROTTLE),))
        self.sample('c').threshold_at = 1002
        self.assertEqual(self.decide().target, key('c'))

    def test_preferred_unknown_before_chained_and_strict_boundary(self):
        self.sample('a').health = Health.UNKNOWN
        self.sample('b').health = Health.FAILED
        d = self.decide(selector='proxy_deepmind')
        self.assertEqual(d.reason, 'priority_health_unknown')
        self.assertEqual(d.tests, ((key('a'), Probe.GATE),))
        self.sample('a').health = Health.FAILED
        self.assertEqual(self.decide(selector='proxy_deepmind').target, key('chained'))
        self.sample('chained').health = Health.FAILED
        self.sample('a').health = Health.HEALTHY
        self.sample('a').successes = []
        self.assertEqual(self.decide('chained', 'proxy_deepmind').target, key('a'))

    def test_unknown_preferred_incumbent_is_not_a_provider_boundary(self):
        self.sample('a').health = Health.UNKNOWN
        d = self.decide(selector='proxy_deepmind')
        self.assertEqual(d.reason, 'hold')
        self.assertIsNone(d.target)
        self.sample('a').health = Health.FAILED
        self.assertEqual(self.decide(selector='proxy_deepmind').reason, 'health_failover')

    def test_return_to_preferred_needs_one_post_hold_throughput_and_no_margin(self):
        self.sample('b').health = Health.FAILED
        self.sample('a').successes = [(1000, .1, 500)]  # Far below the chained path's score.
        self.assertEqual(self.decide('chained', 'proxy_deepmind').reason, 'hold')
        self.now = 1300
        d = self.decide('chained', 'proxy_deepmind')
        self.assertEqual(d.reason, 'priority_return_test')
        self.assertEqual(d.tests, ((key('a'), Probe.THROUGHPUT),))
        self.sample('a').successes = [(1301, .1, 500)]
        self.now = 1301
        d = self.decide('chained', 'proxy_deepmind')
        self.assertEqual((d.target, d.reason), (key('a'), 'priority_return'))

    def test_upstream_excludes_chained_and_stale_health_needs_gate(self):
        self.sample('a').health = Health.FAILED
        self.sample('chained').successes = [(1000, 50, 20)]
        self.assertNotEqual(self.decide(selector='chained_upstream').target, key('chained'))
        self.now = 10000
        self.assertEqual(self.decide().reason, 'health_unknown')
        self.assertTrue(all(probe is Probe.GATE for _, probe in self.decide().tests))

    def test_failure_uses_last_known_score_even_beyond_sweep(self):
        self.sample('a').health = Health.FAILED
        self.sample('b').successes = [(-1000000, 40, 50)]
        self.sample('c').successes = [(1000, 1, 50)]
        self.sample('chained').successes = []
        self.assertEqual(self.decide().target, key('b'))

    def test_stale_active_score_does_not_block_fresh_challenger(self):
        self.sample('a').successes = [(-7000, 50, 20)]
        self.sample('b').successes = [(1000, 2, 50)]
        self.sample('c').health = self.sample('chained').health = Health.FAILED
        self.assertEqual(self.decide().reason, 'hold')
        self.now = 1300
        self.assertEqual(self.decide().reason, 'challenger_test')


class OwnershipTests(unittest.TestCase):
    def config(self):
        leaves = [{'type': 'trojan', 'tag': tag, 'server': '127.0.0.1', 'server_port': 1, 'password': 'fixture'} for tag in ('a', 'b')]
        c = {'outbounds': leaves + [{'type': 'urltest', 'tag': 'p_best', 'outbounds': ['a', 'b']}] +
            [{'type': 'selector', 'tag': tag, 'outbounds': ['p_best', 'a', 'b']} for tag in
             ('proxy_main', 'proxy_deepmind', 'chained_upstream')],
             'experimental': {'clash_api': {'external_controller': '127.0.0.1:9090'}}}
        return c, [{'outbound': o} for o in leaves]

    def test_handoff_flattens_only_owned_selectors(self):
        native, candidates = self.config()
        c = copy.deepcopy(native)
        compiler.handoff_selectors(c, ['proxy_main'], candidates)
        entries = {o['tag']: o for o in c['outbounds']}
        self.assertEqual(entries['proxy_main']['outbounds'], ['a', 'b'])
        self.assertEqual(entries['proxy_deepmind']['outbounds'], ['p_best', 'a', 'b'])
        c = copy.deepcopy(native)
        compiler.handoff_selectors(c, [], candidates)
        self.assertEqual(c, native)

    def test_handoff_rejects_incompatible_members_and_cycles(self):
        c, candidates = self.config()
        c['outbounds'].append({'type': 'direct', 'tag': 'bypass'})
        c['outbounds'][2]['outbounds'].append('bypass')
        with self.assertRaises(ValueError):
            compiler.handoff_selectors(c, ['proxy_main'], [])
        c['outbounds'][-1]['outbounds'] = ['chained_upstream']
        with self.assertRaises(ValueError):
            compiler.handoff_selectors(c, ['proxy_main'], candidates)

    def test_write_verification_rolls_back_only_failed_selector(self):
        c, _ = self.config()
        with patch.object(clash_api, 'proxies', side_effect=[{'proxy_main': {'now': 'a'}},
                {'proxy_main': {'now': 'a'}}, {'proxy_main': {'now': 'a'}}]), \
                patch.object(clash_api.urllib.request, 'build_opener') as opener:
            with self.assertRaises(ValueError):
                clash_api.select(c, 'proxy_main', 'b', ['proxy_main'])
            calls = opener.return_value.open.call_args_list
            self.assertEqual(len(calls), 2)
            self.assertTrue(all(call.args[0].full_url.endswith('/proxies/proxy_main') for call in calls))
            self.assertIn(b'"name": "b"', calls[0].args[0].data)
            self.assertIn(b'"name": "a"', calls[1].args[0].data)
            self.assertIsNone(calls[0].args[0].get_header('Authorization'))
        with patch.object(clash_api, 'proxies') as inspect:
            with self.assertRaises(ValueError):
                clash_api.select(c, 'proxy_main', 'b', [])
            inspect.assert_not_called()


class PolicySchedulingTests(unittest.TestCase):
    def setUp(self):
        from concurrent.futures import Future
        self.now = 1000.
        self.scheduler = Scheduler(lambda *args, **kw: None, clock=lambda: self.now)
        self.candidates = [{'provider': 'preferred', 'weight': 1.25,
                            'outbound': {'type': 'trojan', 'tag': tag}} for tag in ('a', 'b')]
        self.chained = {'type': 'wireguard', 'tag': 'chained', 'detour': 'chained_upstream'}
        self.config = {'outbounds': [c['outbound'] for c in self.candidates]+[
            {'type': 'selector', 'tag': 'proxy_main', 'outbounds': ['a', 'b', 'chained']},
            {'type': 'selector', 'tag': 'proxy_deepmind', 'outbounds': ['a', 'b', 'chained']},
            {'type': 'selector', 'tag': 'chained_upstream', 'outbounds': ['a', 'b']}], 'endpoints': [self.chained]}
        self.api = {tag: {'now': value} for tag, value in
                    [('proxy_main', 'a'), ('proxy_deepmind', 'chained'), ('chained_upstream', 'a')]}
        self.scheduler.configure(self.config, self.candidates,
                                 {'probes_enabled': True, 'managed_selectors': ['proxy_main'],
                                  'selector_priorities': {'proxy_deepmind': [['preferred'], ['chained']]}})
        for key, sample in self.scheduler.samples.items():
            sample.health, sample.healthy_at, sample.latency = Health.HEALTHY, self.now, 50
            sample.successes = [(self.now, 40 if key[0] == 'b' else 1, 50)]
            sample.last = {'gate': self.now, 'throttle': self.now, 'throughput': self.now}
        self.submitted = []
        def submit(*args):
            future = Future()
            self.submitted.append((future, args))
            return future
        self.submit_patch = patch.object(self.scheduler.pool, 'submit', side_effect=submit)
        self.api_patch = patch.object(clash_api, 'proxies', side_effect=lambda *args, **kw: copy.deepcopy(self.api))
        def select(config, selector, target, managed):
            self.assertIn(selector, managed)
            self.api[selector]['now'] = target
        self.write_patch = patch.object(clash_api, 'select', side_effect=select)
        self.submit_patch.start()
        self.api_patch.start()
        self.write = self.write_patch.start()

    def tearDown(self):
        self.scheduler.close()
        self.submit_patch.stop()
        self.api_patch.stop()
        self.write_patch.stop()

    def key(self, tag):
        return next(k for k in self.scheduler.samples if k[0] == tag)

    def finish(self, kind, **kw):
        self.now += 1
        for future, args in self.submitted:
            if not future.done() and args[-1] == kind:
                size = {'gate': 1, 'throttle': THROTTLE, 'throughput': THROTTLE + SKIP}[kind]
                future.set_result(ProbeResult(Probe(kind), ok=True, **{'bytes': size, 'latency_ms': 50,
                                   'completed_at': self.now, **kw}))

    def test_elective_test_priority_and_real_completion_before_write(self):
        self.scheduler.tick()
        self.write.assert_not_called()
        self.now += 300
        for s in self.scheduler.samples.values():
            s.last['gate'] = s.last['throttle'] = self.now-1
        self.scheduler.tick()
        self.assertIn((self.key('b'), 'throughput', self.scheduler.epoch), self.scheduler.jobs.values())
        self.write.assert_not_called()
        self.finish('throughput', mbps=40)
        self.scheduler.tick()
        self.assertEqual(self.api['proxy_main']['now'], 'b')
        self.assertEqual(self.api['proxy_deepmind']['now'], 'chained')

    def test_preferred_return_executes_post_hold_throughput(self):
        self.scheduler.settings = self.scheduler.settings.with_changes(managed_selectors=['proxy_deepmind'])
        self.scheduler.tick()
        self.now += 300
        for s in self.scheduler.samples.values():
            s.last['gate'] = s.last['throttle'] = self.now-1
        self.scheduler.tick()
        self.assertIn((self.key('b'), 'throughput', self.scheduler.epoch), self.scheduler.jobs.values())
        self.assertEqual(self.api['proxy_deepmind']['now'], 'chained')
        self.finish('throughput', mbps=40)
        self.scheduler.tick()
        self.assertEqual(self.api['proxy_deepmind']['now'], 'b')
        self.assertEqual(self.api['proxy_main']['now'], 'a')

    def test_cancelled_challenger_throughput_is_requested_immediately(self):
        for discard in ('epoch_change', 'reload'):
            with self.subTest(discard=discard):
                self.scheduler.invalidate()
                self.scheduler.restart_client()
                self.scheduler.controller.policy = Policy()
                self.scheduler.settings = self.scheduler.settings.with_changes(managed_selectors=['proxy_deepmind'])
                self.api['proxy_deepmind']['now'] = 'chained'
                self.scheduler.tick()
                self.now += 300
                for sample in self.scheduler.samples.values():
                    sample.last['gate'] = sample.last['throttle'] = self.now-1
                self.scheduler.tick()
                key = self.key('b')
                future = next(future for future, (candidate, kind, _) in self.scheduler.jobs.items()
                              if candidate == key and kind == 'throughput')
                previous = self.scheduler.samples[key].last['throughput']
                if discard == 'reload':
                    self.scheduler.invalidate()
                    self.scheduler.restart_client()
                else:
                    self.scheduler.epoch += 1
                    future.set_exception(OSError('old epoch worker'))
                self.now += .1
                self.scheduler.tick()
                self.assertEqual(self.api['proxy_deepmind']['now'], 'chained')
                self.assertIn((key, 'throughput', self.scheduler.epoch), self.scheduler.jobs.values())
                self.assertGreater(self.scheduler.samples[key].last['throughput'], previous)
                self.write.assert_not_called()

    def test_unknown_challenger_result_does_not_cause_download_loop(self):
        self.scheduler.tick()
        self.now += 300
        for s in self.scheduler.samples.values():
            s.last['gate'] = s.last['throttle'] = self.now-1
        self.scheduler.tick()
        self.finish('throughput', bytes=1)  # Valid bounded result, insufficient scored bytes.
        self.scheduler.tick()
        count = len(self.submitted)
        for _ in range(5):
            self.now += .1
            self.scheduler.tick()
        self.assertEqual(len(self.submitted), count)
        self.write.assert_not_called()

    def test_upstream_write_drains_and_invalidates_chained_samples(self):
        from concurrent.futures import Future
        self.scheduler.settings = self.scheduler.settings.with_changes(managed_selectors=['chained_upstream'])
        self.scheduler.controller.inspect()
        chained = self.key('chained')
        future = Future()
        self.scheduler.jobs[future] = (chained, Probe.THROUGHPUT, self.scheduler.epoch)
        self.scheduler.samples[self.key('a')].health = Health.FAILED
        old_client = self.scheduler.client
        self.scheduler.controller.apply_policy(self.now)
        self.assertTrue(future.cancelled())
        self.assertTrue(old_client.cancelled.is_set())
        self.assertEqual(self.api['chained_upstream']['now'], 'b')
        self.assertIsNone(self.scheduler.samples[chained].healthy)
        self.assertEqual(self.scheduler.samples[chained].successes, [])
        self.assertFalse(self.scheduler.client.cancelled.is_set())


if __name__ == '__main__':
    unittest.main()
