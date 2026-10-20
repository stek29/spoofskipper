"""Failure-path regressions from the pre-publication review."""
import copy
from concurrent.futures import Future
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import clash_api, compiler, service
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
                 patch.object(service, 'load_settings', return_value=settings), \
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


class EvidenceTests(unittest.TestCase):
    def test_tiny_success_cannot_rehabilitate_confirmed_body_failure(self):
        scheduler = Scheduler(lambda *args, **kw: None)
        key = ('candidate', 'hash')
        scheduler.samples[key] = sample = Sample()
        try:
            scheduler.accept(key, 'throttle', {'ok': False, 'bytes': 0}, 100)
            scheduler.accept(key, 'corroborate_body', {'ok': False}, 101)
            for at in (102, 103, 104):
                scheduler.accept(key, 'gate', {'ok': False, 'bytes': 0}, at)
            for kind in ('corroborate_gate', 'gate', 'throughput'):
                scheduler.accept(key, kind, {'ok': True}, 105)
                self.assertFalse(sample.healthy, kind)
                self.assertTrue(sample.body_failed)
            scheduler.accept(key, 'corroborate_body', {'ok': True}, 106)
            self.assertTrue(sample.healthy)
            self.assertTrue(sample.body_failed)  # No invented Cloudflare score.
            scheduler.accept(key, 'corroborate_gate', {'ok': True}, 107)
            self.assertEqual(sample.healthy_at, 106)  # HEAD cannot renew body evidence.
            scheduler.accept(key, 'throttle', {'ok': True}, 108)
            self.assertTrue(sample.healthy)
            self.assertFalse(sample.body_failed)
        finally:
            scheduler.close()

    def test_sufficient_body_prefix_restores_health_without_inventing_rate(self):
        scheduler = Scheduler(lambda *args, **kw: None)
        key = ('candidate', 'hash')
        scheduler.samples[key] = sample = Sample(health=Health.FAILED_BODY)
        try:
            scheduler.accept(key, 'throughput', {'ok': True, 'bytes': THROTTLE}, 100)
            self.assertTrue(sample.healthy)
            self.assertTrue(sample.body_failed)  # Cloudflare performance still unknown.
            self.assertEqual(sample.successes, [])
        finally:
            scheduler.close()

    def test_revocation_does_not_grant_new_ownership_or_reuse_old_hold(self):
        scheduler = Scheduler(lambda *args, **kw: None)
        try:
            scheduler.settings = scheduler.settings.with_changes(managed_selectors=['proxy_main'])
            scheduler.controller.policy.observe('proxy_main', 'a', 100)
            scheduler.controller.policy.pending['proxy_main'] = (('b', 'hash'), 400)
            scheduler.restrict({'probes_enabled': True, 'managed_selectors': ['proxy_deepmind']})
            self.assertEqual(scheduler.settings['managed_selectors'], ())
            self.assertNotIn('proxy_main', scheduler.controller.policy.choices)
            self.assertNotIn('proxy_main', scheduler.controller.policy.pending)
        finally:
            scheduler.close()


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
        client.run.return_value = {'ok': True}
        with patch.object(clash_api, 'proxies', side_effect=[self.api, after]):
            _, valid = self.scheduler.perform(client, self.config,
                self.scheduler.candidates[self.key], 'gate')
        self.assertFalse(valid)
