"""Dependency identity."""
import copy
from concurrent.futures import Future
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import clash_api, compiler, service
from spoofskipper_manager.settings import Settings
from spoofskipper_manager.probes import THROTTLE, Probe, ProbeResult
from spoofskipper_manager.identity import sample_key
from spoofskipper_manager.scheduler import Health, Sample, Scheduler
from spoofskipper_manager.state import write_json


class DependencyIdentityTests(unittest.TestCase):
    def setUp(self):
        self.scheduler = Scheduler(lambda *args, **kw: None, clock=lambda: 100.)
        self.config = {'outbounds': [
            {'type': 'trojan', 'tag': 'a', 'password': 'old', 'server': 'old', 'detour': 'transport'},
            {'type': 'trojan', 'tag': 'b', 'password': 'old'},
            {'type': 'urltest', 'tag': 'group', 'outbounds': ['a', 'b']},
            {'type': 'selector', 'tag': 'chained_upstream', 'outbounds': ['group']},
            {'type': 'selector', 'tag': 'transport', 'outbounds': ['t1', 't2']},
            {'type': 'direct', 'tag': 't1', 'bind_interface': 'old'}, {'type': 'direct', 'tag': 't2'}],
            'endpoints': [{'type': 'wireguard', 'tag': 'chained', 'detour': 'chained_upstream'}]}
        self.api = {'chained_upstream': {'now': 'group'}, 'group': {'now': 'a'}, 'transport': {'now': 't1'}}
        self.settings = {'probes_enabled': True}
        self.key = sample_key(self.config['endpoints'][0])
        self.configure(self.config)
        with patch.object(clash_api, 'proxies', return_value=self.api):
            self.scheduler.controller.inspect()

    def configure(self, config):
        self.scheduler.configure(config, [{'provider': 'p', 'weight': 1, 'outbound': o}
                                         for o in config['outbounds'][:2]], self.settings)

    def seed(self):
        self.scheduler.samples[self.key] = sample = Sample(health=Health.HEALTHY, healthy_at=100,
                                                          successes=[(100, 40, 20)])
        return sample

    def tearDown(self):
        self.scheduler.close()

    def test_unchanged_path_and_unselected_credentials_retain_samples(self):
        sample = self.seed()
        changed = copy.deepcopy(self.config)
        changed['outbounds'][1]['password'] = 'rotated'
        self.configure(changed)
        with patch.object(clash_api, 'proxies', return_value=self.api):
            self.scheduler.controller.inspect()
        self.assertIs(self.scheduler.samples[self.key], sample)

    def test_selected_credentials_server_tls_and_detour_changes_drop_samples(self):
        for index, field, value in ((0, 'password', 'rotated'), (0, 'server', 'new'),
                                     (0, 'tls', {'server_name': 'new'}), (5, 'bind_interface', 'new')):
            with self.subTest(field=field):
                self.configure(self.config)
                with patch.object(clash_api, 'proxies', return_value=self.api):
                    self.scheduler.controller.inspect()
                self.seed()
                changed = copy.deepcopy(self.config)
                changed['outbounds'][index][field] = value
                self.configure(changed)
                self.assertIsNone(self.scheduler.samples[self.key].healthy)
                self.assertEqual(self.scheduler.samples[self.key].successes, [])

    def test_nested_detour_selection_change_discards_crossing_probe(self):
        after = copy.deepcopy(self.api)
        after['transport']['now'] = 't2'
        client = Mock()
        client.run.return_value = ProbeResult(Probe.GATE, ok=True)
        with patch.object(clash_api, 'proxies', side_effect=[self.api, after]):
            _, valid = self.scheduler.perform(client, self.config,
                self.scheduler.candidates[self.key], 'gate')
        self.assertFalse(valid)
