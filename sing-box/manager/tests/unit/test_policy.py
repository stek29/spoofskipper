import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import clash_api, compiler
from spoofskipper_manager.policy import Policy, score
from spoofskipper_manager.scheduler import Health, Sample, Scheduler
from spoofskipper_manager.probes import DEFAULTS, sample_key
from spoofskipper_manager.service import load_settings
from spoofskipper_manager.state import write_json


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.p = Policy()
        self.candidates = {(tag, tag): {'provider': provider, 'weight': weight} for tag, provider, weight in
                           [('a', 'preferred', 1.25), ('b', 'preferred', 1.25), ('c', 'other', 1), ('chained', 'chained', 1)]}
        self.samples = {k: Sample(health=Health.HEALTHY, healthy_at=1000, latency=50,
                                successes=[(1000, 10, 50)]) for k in self.candidates}
        self.members = [k[0] for k in self.candidates]

    def sample(self, tag):
        return self.samples[(tag, tag)]

    def decide(self, tag='a', selector='proxy_main'):
        return self.p.decide(selector, tag, self.candidates, self.samples, self.now, {**DEFAULTS, 'selector_priorities': {'proxy_deepmind': [['preferred'], ['chained']]}},
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
        self.assertIsNotNone(score(s, 1, 8201, DEFAULTS['throughput_sweep_seconds']))
        s.health = Health.SUSPECT_BODY
        self.assertIsNone(score(s, 1, 1000, 7200))

    def test_hold_margin_and_mandatory_fresh_challenger(self):
        self.sample('b').successes = [(1000, 11, 50)]
        self.assertEqual(self.decide().reason, 'margin_or_performance_unknown')

    def test_fresh_switch_and_failed_fresh_margin(self):
        self.sample('b').successes = [(1000, 40, 50)]
        self.assertEqual(self.decide().reason, 'hold')
        self.now = 1300
        d = self.decide()
        self.assertEqual(d.tests, ((('b', 'b'), 'throughput'),))
        self.sample('b').successes = [(1301, 40, 50)]
        self.now = 1301
        self.assertEqual(self.decide().target, ('b', 'b'))
        self.sample('b').successes = [(1301, 1, 50)]
        self.assertIsNone(self.decide().target)

    def test_immediate_failure_last_score_unknown_fallback_and_all_failed(self):
        self.decide()
        self.sample('a').health = Health.FAILED_GATE
        self.sample('b').successes = [(0, 40, 50)]
        self.now += 1
        d = self.decide()
        self.assertEqual(d.reason, 'health_failover')
        self.assertEqual(d.target, ('b', 'b'))
        self.assertFalse(d.tests)
        for s in self.samples.values():
            s.successes = []
        self.sample('c').latency = 10
        self.assertEqual(self.decide().target, ('c', 'c'))
        for s in self.samples.values():
            s.health = Health.FAILED_GATE
        self.assertEqual(self.decide().reason, 'all_paths_failed')
        self.assertIsNone(self.decide().target)

    def test_preferred_unknown_before_chained_and_strict_boundary(self):
        self.sample('a').health = Health.UNKNOWN
        self.sample('b').health = Health.FAILED_GATE
        d = self.decide(selector='proxy_deepmind')
        self.assertEqual(d.reason, 'priority_health_unknown')
        self.assertEqual(d.tests, ((('a', 'a'), 'gate'),))
        self.sample('a').health = Health.FAILED_GATE
        self.assertEqual(self.decide(selector='proxy_deepmind').target, ('chained', 'chained'))
        self.sample('chained').health = Health.FAILED_GATE
        self.sample('a').health = Health.HEALTHY
        self.sample('a').successes = []
        self.assertEqual(self.decide('chained', 'proxy_deepmind').target, ('a', 'a'))

    def test_unknown_preferred_incumbent_is_not_a_provider_boundary(self):
        self.sample('a').health = Health.UNKNOWN
        d = self.decide(selector='proxy_deepmind')
        self.assertEqual(d.reason, 'hold')
        self.assertIsNone(d.target)
        self.sample('a').health = Health.FAILED_GATE
        self.assertEqual(self.decide(selector='proxy_deepmind').reason, 'health_failover')

    def test_return_to_preferred_retests_at_hold_and_requires_recent_throttle(self):
        self.sample('b').health = Health.FAILED_GATE
        self.sample('a').successes = [(1000, .1, 500)]  # no boundary margin
        self.sample('a').throttle_at = 1000
        self.assertEqual(self.decide('chained', 'proxy_deepmind').reason, 'hold')
        self.now = 1300
        d = self.decide('chained', 'proxy_deepmind')
        self.assertEqual({kind for _, kind in d.tests}, {'throughput', 'throttle'})
        self.sample('a').successes = [(1301, .1, 500)]
        self.now = 1301
        self.assertEqual(self.decide('chained', 'proxy_deepmind').tests, ((('a', 'a'), 'throttle'),))
        self.sample('a').throttle_at = 1302
        self.now = 1302
        self.assertEqual(self.decide('chained', 'proxy_deepmind').target, ('a', 'a'))
        self.now = 1333
        self.assertIsNone(self.decide('chained', 'proxy_deepmind').target)

    def test_priority_return_pair_can_complete_more_than_thirty_seconds_apart(self):
        self.sample('b').health = Health.FAILED_GATE
        self.decide('chained', 'proxy_deepmind')
        self.now = 1300
        self.decide('chained', 'proxy_deepmind')
        self.sample('a').successes = [(1301, 10, 50)]
        self.now = 1335
        self.assertEqual(self.decide('chained', 'proxy_deepmind').tests,
                         ((('a', 'a'), 'throttle'),))
        self.sample('a').throttle_at = 1336
        self.now = 1336
        self.assertEqual(self.decide('chained', 'proxy_deepmind').target, ('a', 'a'))

    def test_upstream_excludes_chained_and_stale_health_needs_gate(self):
        self.sample('a').health = Health.FAILED_GATE
        self.sample('chained').successes = [(1000, 50, 20)]
        self.assertNotEqual(self.decide(selector='chained_upstream').target, ('chained', 'chained'))
        self.now = 10000
        self.assertEqual(self.decide().reason, 'health_unknown')
        self.assertTrue(all(kind == 'gate' for _, kind in self.decide().tests))

    def test_failure_uses_last_known_score_even_beyond_sweep(self):
        self.sample('a').health = Health.FAILED_GATE
        self.sample('b').successes = [(-1000000, 40, 50)]
        self.sample('c').successes = [(1000, 1, 50)]
        self.sample('chained').successes = []
        self.assertEqual(self.decide().target, ('b', 'b'))

    def test_stale_active_score_does_not_block_fresh_challenger(self):
        self.sample('a').successes = [(-7000, 50, 20)]
        self.sample('b').successes = [(1000, 2, 50)]
        self.sample('c').health = self.sample('chained').health = Health.FAILED_GATE
        self.assertEqual(self.decide().reason, 'hold')
        self.now = 1300
        self.assertEqual(self.decide().reason, 'challenger_test')

    def test_new_health_evidence_does_not_clear_body_failure(self):
        scheduler = Scheduler(lambda *args, **kw: None)
        try:
            key = ('a', 'a')
            scheduler.samples[key] = Sample(health=Health.HEALTHY)
            scheduler.accept(key, 'throttle', {'ok': False, 'bytes': 0}, 1000)
            self.assertIsNone(scheduler.samples[key].healthy)
            scheduler.accept(key, 'gate', {'ok': True}, 1001)
            self.assertIsNone(scheduler.samples[key].healthy)
            scheduler.accept(key, 'corroborate_body', {'ok': True}, 1002)
            self.assertTrue(scheduler.samples[key].healthy)
            self.assertTrue(scheduler.samples[key].body_failed)
            self.assertEqual(scheduler.samples[key].healthy_at, 1002)
            scheduler.accept(key, 'throttle', {'ok': True}, 1003)
            self.assertFalse(scheduler.samples[key].body_failed)
            self.assertEqual(scheduler.samples[key].throttle_at, 1003)
        finally:
            scheduler.close()


class OwnershipTests(unittest.TestCase):
    def config(self):
        leaves = [{'type': 'trojan', 'tag': tag, 'server': '127.0.0.1', 'server_port': 1, 'password': 'fixture'} for tag in ('a', 'b')]
        c = {'outbounds': leaves + [{'type': 'urltest', 'tag': 'p_best', 'outbounds': ['a', 'b']}] +
            [{'type': 'selector', 'tag': tag, 'outbounds': ['p_best', 'a', 'b']} for tag in
             ('proxy_main', 'proxy_deepmind', 'chained_upstream')],
             'experimental': {'clash_api': {'external_controller': '127.0.0.1:9090'}}}
        return c, [{'outbound': o} for o in leaves]

    def test_partial_handoff_shared_groups_last_reference_and_reversal(self):
        native, candidates = self.config()
        c = copy.deepcopy(native)
        compiler.handoff_selectors(c, ['proxy_main'], candidates)
        entries = {o['tag']: o for o in c['outbounds']}
        self.assertEqual(entries['proxy_main']['outbounds'], ['a', 'b'])
        self.assertEqual(entries['proxy_deepmind']['outbounds'], ['p_best', 'a', 'b'])
        self.assertIn('p_best', entries)
        c = copy.deepcopy(native)
        compiler.handoff_selectors(c, ['proxy_main', 'proxy_deepmind', 'chained_upstream'], candidates)
        self.assertNotIn('p_best', {o['tag'] for o in c['outbounds']})
        c = copy.deepcopy(native)
        compiler.handoff_selectors(c, [], candidates)
        self.assertEqual(c, native)

    def test_route_reference_retained_incompatible_members_and_cycles_rejected(self):
        c, candidates = self.config()
        c['route'] = {'final': 'p_best'}
        compiler.handoff_selectors(c, ['proxy_main', 'proxy_deepmind', 'chained_upstream'], candidates)
        self.assertIn('p_best', {o['tag'] for o in c['outbounds']})
        c, candidates = self.config()
        c['outbounds'].append({'type': 'direct', 'tag': 'bypass'})
        c['outbounds'][2]['outbounds'].append('bypass')
        with self.assertRaises(ValueError):
            compiler.handoff_selectors(c, ['proxy_main'], [])
        c['outbounds'][-1]['outbounds'] = ['chained_upstream']
        with self.assertRaises(ValueError):
            compiler.handoff_selectors(c, ['proxy_main'], candidates)

    def test_managed_settings_allowlist_and_probe_dependency(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'local-manager.json'
            for managed in ('proxy_main', [''], ['proxy_main']*2, [1], None):
                write_json(path, {'probes_enabled': True, 'managed_selectors': managed})
                with self.assertRaises(ValueError):
                    load_settings(temp)
            write_json(path, {'probes_enabled': True, 'managed_selectors': ['proxy_main']})
            self.assertEqual(load_settings(temp).managed_selectors, ('proxy_main',))

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
                future.set_result(({'ok': True, 'kind': kind, 'bytes': 1, 'latency_ms': 50,
                                   'completed_at': self.now, **kw}, True))

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
        self.assertEqual(self.scheduler.accounting.summary()['today']['challenger_tests'], 1)

    def test_preferred_return_executes_both_post_hold_tests(self):
        self.scheduler.settings = self.scheduler.settings.with_changes(managed_selectors=['proxy_deepmind'])
        self.scheduler.tick()
        self.now += 300
        for s in self.scheduler.samples.values():
            s.last['gate'] = s.last['throttle'] = self.now-1
        self.scheduler.tick()
        self.finish('throughput', mbps=40)
        self.scheduler.tick()
        self.assertEqual(self.api['proxy_deepmind']['now'], 'chained')
        self.assertIn((self.key('b'), 'throttle', self.scheduler.epoch), self.scheduler.jobs.values())
        self.finish('throttle')
        self.scheduler.tick()
        self.assertEqual(self.api['proxy_deepmind']['now'], 'b')
        self.assertEqual(self.api['proxy_main']['now'], 'a')

    def test_unknown_challenger_result_does_not_cause_download_loop(self):
        self.scheduler.tick()
        self.now += 300
        for s in self.scheduler.samples.values():
            s.last['gate'] = s.last['throttle'] = self.now-1
        self.scheduler.tick()
        self.finish('throughput')  # Valid bounded result, insufficient scored bytes.
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
        self.scheduler.inspect()
        chained = self.key('chained')
        future = Future()
        self.scheduler.jobs[future] = (chained, 'throughput', self.scheduler.epoch)
        self.scheduler.samples[self.key('a')].health = Health.FAILED_GATE
        old_client = self.scheduler.client
        self.scheduler.apply_policy(self.now)
        self.assertTrue(future.cancelled())
        self.assertTrue(old_client.cancelled.is_set())
        self.assertEqual(self.api['chained_upstream']['now'], 'b')
        self.assertIsNone(self.scheduler.samples[chained].healthy)
        self.assertEqual(self.scheduler.samples[chained].successes, [])
        self.assertFalse(self.scheduler.client.cancelled.is_set())


if __name__ == '__main__':
    unittest.main()
