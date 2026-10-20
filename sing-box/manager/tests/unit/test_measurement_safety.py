"""Measurement faults must preserve routing and bound traffic."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import compiler, service
from spoofskipper_manager.probes import THROTTLE, Probe, ProbeResult
from spoofskipper_manager.scheduler import Health, Scheduler
from spoofskipper_manager.state import write_json


class MeasurementSafetyTests(unittest.TestCase):
    def setUp(self):
        self.scheduler = Scheduler(lambda *args, **kw: None, clock=lambda: 1000.)
        outbounds = [{'type': 'socks', 'tag': f'p{i}', 'server': 'x', 'server_port': 1}
                     for i in range(5)]
        self.config = {'outbounds': outbounds + [
            {'type': 'selector', 'tag': 'sel', 'outbounds': ['p0']}],
            'experimental': {'clash_api': {'external_controller': '127.0.0.1:9'}}}
        self.scheduler.configure(self.config, [
            {'provider': 'prov', 'weight': 1., 'outbound': outbound} for outbound in outbounds],
            {'probes_enabled': True})
        self.keys = list(self.scheduler.candidates)

    def tearDown(self):
        self.scheduler.close()

    def test_path_without_latency_can_be_ranked_and_scheduled(self):
        scheduler = self.scheduler
        for key in self.keys[:3]:
            scheduler.accept(key, ProbeResult(Probe.GATE, ok=True, latency_ms=50, bytes=1), 1000)
            scheduler.accept(key, ProbeResult(Probe.THROUGHPUT, ok=True, latency_ms=50,
                             mbps=20, bytes=5000000), 1000)
        key = self.keys[3]
        scheduler.accept(key, ProbeResult(Probe.THROTTLE, ok=True, bytes=THROTTLE), 1000)
        scheduler.samples[key].last['gate'] = 1000
        self.assertTrue(scheduler.samples[key].healthy)
        self.assertIsNone(scheduler.samples[key].latency)
        peers = scheduler.shortlist(1001)['prov']
        self.assertEqual(len(peers), 3)
        scheduler.next_test(key, peers, 1001)
        scheduler.last_inspect = 1000
        from concurrent.futures import Future
        with patch.object(scheduler.pool, 'submit', side_effect=lambda *args: Future()):
            scheduler.tick()

    def test_two_unknown_throughput_results_use_sweep_cadence(self):
        scheduler, key = self.scheduler, self.keys[0]
        sample = scheduler.samples[key]
        sample.health, sample.healthy_at = Health.HEALTHY, 1000
        for at in (1000, 2800):
            scheduler.accept(key, ProbeResult(Probe.THROUGHPUT, ok=True, bytes=1, latency_ms=10), at)
        sample.last.update(gate=4600, throughput=2800)
        self.assertIsNone(scheduler.next_test(key, [], 4600))
        sample.last['gate'] = 2800 + scheduler.settings['throughput_sweep_seconds']
        self.assertEqual(scheduler.next_test(key, [], sample.last['gate']), 'throughput')

    def test_tick_exception_is_logged_and_manager_keeps_running(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager = service.Manager(root, root / 'state')
            config = self.config.copy()
            config['outbounds'] = self.config['outbounds'] + [
                {'type': 'direct', 'tag': compiler.REVISION_PREFIX + 'test'}]
            write_json(manager.live, config)
            manager.child = Mock()
            with patch.object(service.signal, 'signal'), patch.object(manager, 'start'), \
                 patch.object(manager, 'alive', return_value=True), \
                 patch.object(manager, 'verify', return_value=True), \
                 patch.object(service, 'Providers', side_effect=ValueError()), \
                 patch.object(manager.scheduler, 'tick', side_effect=[TypeError('measurement'), None]) as tick, \
                 patch.object(manager, 'wait', side_effect=[None, service.Stopping()]), \
                 patch.object(manager, 'stop_child'), patch.object(service, 'log') as log:
                self.assertEqual(manager.run(), 0)
                self.assertEqual(tick.call_count, 2)
                log.assert_any_call('scheduler_tick_failed', error='TypeError', count=1)

    def test_repeated_tick_errors_are_rate_limited_by_type_and_counted(self):
        with tempfile.TemporaryDirectory() as temp:
            manager = service.Manager(temp, Path(temp) / 'state')
            manager.child = Mock()
            now = [1000.]
            try:
                with patch.object(service.time, 'monotonic', side_effect=lambda: now[0]), \
                     patch.object(manager.scheduler, 'tick') as tick, patch.object(service, 'log') as log:
                    tick.side_effect = TypeError('measurement')
                    for _ in range(100):
                        manager.tick_scheduler()
                    self.assertEqual(log.call_count, 1)
                    log.assert_called_once_with('scheduler_tick_failed', error='TypeError', count=1)
                    self.assertEqual(manager.scheduler_errors['TypeError'][0], 100)
                    now[0] += 60
                    manager.tick_scheduler()
                    log.assert_called_with('scheduler_tick_failed', error='TypeError', count=101)
                    tick.side_effect = ValueError('another measurement')
                    manager.tick_scheduler()
                    log.assert_called_with('scheduler_tick_failed', error='ValueError', count=1)
                    tick.side_effect = None
                    manager.tick_scheduler()
                    self.assertEqual(tick.call_count, 103)
                    self.assertEqual(log.call_count, 3)
                    manager.child.send_signal.assert_not_called()
            finally:
                manager.scheduler.close()

    def test_stop_during_first_verification_removes_unverified_config(self):
        with tempfile.TemporaryDirectory() as temp:
            manager = service.Manager(temp, Path(temp) / 'state')
            try:
                with patch.object(compiler, 'check'), patch.object(manager, 'alive', return_value=False), \
                     patch.object(manager, 'start'), patch.object(manager, 'verify', side_effect=service.Stopping()):
                    with self.assertRaises(service.Stopping):
                        manager.activate(self.config)
                self.assertFalse(manager.live.exists())
                self.assertIsNone(manager.current)
                self.assertFalse(manager.marker.exists())
            finally:
                manager.scheduler.close()

    def test_invalid_settings_explicitly_disable_probes_and_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_json(root / 'sing.json', self.config)
            (root / 'local-manager.json').write_text('{')
            (root / 'providers').mkdir()
            (root / 'providers' / '.manager-abandoned').write_text('secret')
            with patch.object(service, 'log') as log:
                manager = service.Manager(root, root)
            try:
                self.assertFalse(manager.settings['probes_enabled'])
                self.assertEqual(manager.settings['managed_selectors'], ())
                self.assertIn('probe_timeout', manager.settings)
                self.assertFalse((root / 'providers' / '.manager-abandoned').exists())
                log.assert_called_once_with('settings_invalid_using_saved_config',
                    probes_enabled=False, managed_selectors=[], fallback='native_selectors')
            finally:
                manager.scheduler.close()
