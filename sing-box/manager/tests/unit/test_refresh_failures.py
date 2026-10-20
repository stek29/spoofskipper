"""Refresh failures."""
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
from spoofskipper_manager.probes import THROTTLE, sample_key
from spoofskipper_manager.scheduler import Health, Sample, Scheduler
from spoofskipper_manager.state import write_json


class RefreshFailureTests(unittest.TestCase):
    def exercise(self, case):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_json(root/'local-manager.json', {'probes_enabled': True, 'managed_selectors': ['proxy_main']})
            manager = service.Manager(root, root/'state')
            old = {'outbounds': [{'type': 'trojan', 'tag': 'a', 'password': 'old'},
                {'type': 'trojan', 'tag': 'b'}, {'type': 'selector', 'tag': 'proxy_main', 'outbounds': ['a', 'b']},
                {'type': 'direct', 'tag': compiler.REVISION_PREFIX+'old'}],
                'experimental': {'clash_api': {'external_controller': '127.0.0.1:9090'}}}
            new = copy.deepcopy(old)
            new['outbounds'][0]['password'] = 'rotated'
            new['outbounds'][-1]['tag'] = compiler.REVISION_PREFIX+'new'
            write_json(manager.live, old)
            candidates = [{'provider': 'p', 'weight': 1, 'outbound': o} for o in old['outbounds'][:2]]
            providers = Mock(snapshots={'p': {}}, candidates=Mock(return_value=candidates))
            providers.refresh.return_value = {'p': {}}
            settings = dict(manager.settings)
            if case not in ('commit', 'stage'):
                settings['managed_selectors'] = []
            if case == 'disable':
                settings['probes_enabled'] = False
            if case == 'commit':
                providers.commit.side_effect = OSError('snapshot write failed')
            clients, configure = [], manager.configure_probes
            def configured(*args):
                configure(*args)
                clients.append(manager.scheduler.client)
            real_tick = manager.scheduler.tick
            failures = []
            def tick():
                scheduler = manager.scheduler
                if case in ('commit', 'stage'):
                    expected = new if case == 'commit' else old
                    self.assertEqual(manager.current, expected)
                    self.assertEqual(scheduler.config, expected)
                    self.assertFalse(scheduler.client.cancelled.is_set())
                    self.assertIn(sample_key(expected['outbounds'][0]), scheduler.samples)
                    if case == 'commit':
                        self.assertNotIn(sample_key(old['outbounds'][0]), scheduler.samples)
                    else:
                        providers.commit.assert_not_called()
                    real_tick()
                    self.assertTrue(submit.called)
                    self.assertTrue(all(call.args[2] == expected for call in submit.call_args_list))
                else:
                    self.assertEqual(scheduler.settings['managed_selectors'], ())
                    if case == 'disable':
                        self.assertIsNone(scheduler.client)
                        self.assertTrue(clients[0].cancelled.is_set())
                        real_tick()
                        submit.assert_not_called()
                    else:
                        scheduler.active = {'proxy_main': 'a'}
                        for key in scheduler.samples:
                            scheduler.samples[key] = Sample(health=Health.HEALTHY if key[0] == 'b' else Health.FAILED_GATE, healthy_at=100, latency=20)
                        scheduler.controller.apply_policy(100)
                    select.assert_not_called()
            def checked_tick():
                try:
                    tick()
                except AssertionError as exc:
                    failures.append(exc)
            prepared = [old, new] if case in ('commit', 'stage') else [old, ValueError('invalid render')]
            atomic_write = service.atomic_write
            def staged_write(*args):
                if case == 'stage':
                    raise OSError('backup write failed')
                return atomic_write(*args)
            with patch.object(service.signal, 'signal'), \
                 patch.object(service, 'Providers', return_value=providers), \
                 patch.object(service, 'load_settings', return_value=Settings.from_mapping(settings)), \
                 patch.object(manager, 'start'), patch.object(manager, 'stop_child'), \
                 patch.object(manager, 'alive', return_value=True), patch.object(manager, 'verify', return_value=True), \
                 patch.object(manager, 'prepare', side_effect=prepared), patch.object(compiler, 'check'), \
                 patch.object(service, 'atomic_write', side_effect=staged_write), \
                 patch.object(manager, 'configure_probes', side_effect=configured), \
                 patch.object(manager.scheduler, 'tick', side_effect=checked_tick), \
                 patch.object(manager.scheduler.pool, 'submit', side_effect=lambda *args: Future()) as submit, \
                 patch.object(manager, 'wait', side_effect=service.Stopping()), \
                 patch.object(clash_api, 'proxies', return_value={'proxy_main': {'now': 'a'}}), \
                 patch.object(clash_api, 'select') as select:
                manager.child = Mock()
                self.assertEqual(manager.run(), 0)
            if failures:
                raise failures[0]

    def test_ownership_revoked_even_if_render_fails(self):
        self.exercise('revoke')

    def test_probes_cancelled_even_if_disable_render_fails(self):
        self.exercise('disable')

    def test_scheduler_uses_activated_core_when_snapshot_commit_fails(self):
        self.exercise('commit')

    def test_failed_staging_write_keeps_probes_on_running_core(self):
        self.exercise('stage')


