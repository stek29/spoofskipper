"""Names and protocols do not determine policy or dependency handling."""
import copy
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import compiler, clash_api
from spoofskipper_manager.policy import Policy
from spoofskipper_manager.probes import DEFAULTS, sample_key
from spoofskipper_manager.scheduler import Health, Scheduler, Sample
from spoofskipper_manager.service import load_settings
from spoofskipper_manager.state import write_json


class GenericPolicyTests(unittest.TestCase):
    def test_three_configured_tiers_and_unconfigured_score_policy(self):
        candidates = {(x, x): {'provider': x, 'weight': 1} for x in ('first', 'second', 'third')}
        samples = {k: Sample(health=Health.HEALTHY, healthy_at=1000, latency=20,
                            successes=[(1000, 1 if k[0] == 'first' else 50, 20)]) for k in candidates}
        settings = {**DEFAULTS, 'selector_priorities': {'arbitrary': [['first'], ['second'], ['third']]}}
        policy = Policy()
        decide = lambda: policy.decide('arbitrary', 'third', candidates, samples, 1000, settings, ['first', 'second', 'third'])
        self.assertEqual(decide().reason, 'hold')
        samples[('third', 'third')].health = Health.FAILED_GATE
        self.assertEqual(decide().target, ('first', 'first'))
        samples[('first', 'first')].health = Health.UNKNOWN
        self.assertEqual(decide().reason, 'priority_health_unknown')
        samples[('first', 'first')].health = Health.FAILED_GATE
        self.assertEqual(decide().target, ('second', 'second'))
        settings.pop('selector_priorities')
        self.assertEqual(decide().target, ('second', 'second'))

    def test_arbitrary_static_proxy_chain_and_dependency_invalidation(self):
        config = {'experimental': {'clash_api': {'external_controller': '127.0.0.1:9090'}}, 'outbounds': [
            {'type': 'socks', 'tag': 'one', 'server': 'old', 'server_port': 1080},
            {'type': 'socks', 'tag': 'two', 'server': 'other', 'server_port': 1080},
            {'type': 'selector', 'tag': 'hop', 'outbounds': ['one', 'two']},
            {'type': 'http', 'tag': 'chained-a', 'server': 'proxy', 'server_port': 8080, 'detour': 'hop'},
            {'type': 'trojan', 'tag': 'chained-b', 'server': 'proxy', 'server_port': 443, 'detour': 'chained-a'},
            {'type': 'selector', 'tag': 'arbitrary', 'outbounds': ['chained-a', 'chained-b']},
            {'type': 'direct', 'tag': 'bypass'}]}
        scheduler = Scheduler(lambda *args, **kw: None)
        settings = {'probes_enabled': True, 'provider_weights': {'chained-b': 2.5}}
        api = {'hop': {'now': 'one'}, 'arbitrary': {'now': 'chained-a'}}
        try:
            scheduler.configure(config, [], settings)
            self.assertEqual({k[0] for k in scheduler.candidates}, {'one', 'two', 'chained-a', 'chained-b'})
            self.assertEqual(scheduler.candidates[sample_key(config['outbounds'][4])]['weight'], 2.5)
            compiler.handoff_selectors(copy.deepcopy(config), ['arbitrary'], [])
            with patch.object(clash_api, 'proxies', return_value=api):
                scheduler.controller.inspect()
                for sample in scheduler.samples.values():
                    sample.health = Health.HEALTHY
                api['hop']['now'] = 'two'
                scheduler.controller.inspect()
            for tag in ('chained-a', 'chained-b'):
                self.assertIsNone(scheduler.samples[sample_key(next(o for o in config['outbounds'] if o['tag'] == tag))].healthy)
            self.assertTrue(scheduler.samples[sample_key(config['outbounds'][0])].healthy)
        finally:
            scheduler.close()

    def test_priorities_validation_and_arbitrary_selector_names(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'local-manager.json'
            for priorities in ([], {'x': []}, {'x': [['a'], ['a']]}, {'x': ['a']}, {'x': [[1]]}):
                write_json(path, {'selector_priorities': priorities})
                with self.assertRaises(ValueError):
                    load_settings(temp)
            write_json(path, {'probes_enabled': True, 'managed_selectors': ['arbitrary'],
                              'selector_priorities': {'arbitrary': [['provider-a', 'provider-b'], ['local-proxy']]}})
            self.assertEqual(load_settings(temp).managed_selectors, ('arbitrary',))
