"""Ordinary discards retain cadence; cancellation alone releases retry timers."""
from concurrent.futures import Future
import itertools
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import scheduler as scheduling
from spoofskipper_manager.scheduler import Health, Sample, Scheduler


class DiscardCadenceTests(unittest.TestCase):
    def exercise(self, api_down, throughput=False):
        now = [1000.]
        logs, runs = [], []
        scheduler = Scheduler(lambda event, **fields: logs.append((event, fields)), clock=lambda: now[0])
        outbounds = [
            {'type': 'socks', 'tag': 'up', 'server': 'x', 'server_port': 1},
            {'type': 'socks', 'tag': 'up2', 'server': 'z', 'server_port': 1},
            {'type': 'socks', 'tag': 'dep', 'server': 'y', 'server_port': 2, 'detour': 'upsel'},
            {'type': 'urltest', 'tag': 'upsel', 'outbounds': ['up', 'up2']}]
        scheduler.configure({'outbounds': outbounds, 'experimental': {
            'clash_api': {'external_controller': '127.0.0.1:9'}}}, [], {'probes_enabled': True})
        if throughput:
            with patch.object(scheduling.clash_api, 'proxies', return_value={'upsel': {'now': 'up'}}):
                scheduler.controller.inspect()
            for sample in scheduler.samples.values():
                sample.health, sample.healthy_at, sample.latency = Health.HEALTHY, now[0], 10
                sample.last.update(gate=now[0], throttle=now[0], throughput=now[0]-1800)
        choices = itertools.cycle(('up', 'up2'))
        def proxies(*args, **kwargs):
            if api_down:
                raise OSError('API unavailable')
            return {'upsel': {'now': next(choices)}}
        def run(client, outbound, kind):
            runs.append((outbound['tag'], kind))
            return {'ok': True, 'bytes': 1, 'latency_ms': 10}
        def submit(function, *args):
            # Complete real perform() synchronously: deterministic ticks, no sleeps
            # or network, while retaining dependency checks before/after the probe.
            future = Future()
            try:
                future.set_result(function(*args))
            except Exception as exc:
                future.set_exception(exc)
            return future
        try:
            with patch.object(scheduling.clash_api, 'proxies', side_effect=proxies), \
                 patch.object(scheduling.ProbeClient, 'run', run), \
                 patch.object(scheduler.pool, 'submit', side_effect=submit):
                for tick in range(100):
                    now[0] = 1000. + tick / 10
                    scheduler.tick()
            discarded = [fields for event, fields in logs
                         if event == 'probe_discarded' and fields['candidate'] == 'dep']
            self.assertTrue(discarded)
            if api_down:
                self.assertEqual(len(discarded), 1)
                self.assertFalse(any(tag == 'dep' for tag, _ in runs))
            else:
                dependent = [kind for tag, kind in runs if tag == 'dep']
                self.assertGreater(len(dependent), 0)
                self.assertLessEqual(len(dependent), 2)
                self.assertLessEqual(len(discarded), 2)
                if throughput:
                    self.assertEqual(dependent.count('throughput'), 1)
        finally:
            scheduler.close()

    def test_unreachable_api_does_not_retry_on_each_tick(self):
        self.exercise(api_down=True)

    def test_flapping_upstream_does_not_send_a_gate_on_each_tick(self):
        self.exercise(api_down=False)

    def test_flapping_upstream_does_not_repeat_throughput_downloads(self):
        self.exercise(api_down=False, throughput=True)

    def test_ordinary_discard_does_not_rearm_corroboration(self):
        scheduler = Scheduler(lambda *args, **kwargs: None)
        try:
            key = ('candidate', 'hash')
            scheduler.samples[key] = sample = Sample()
            sample.last['corroborate_body'] = 1000
            future = Future()
            future.set_result(({'ok': True}, False))
            scheduler.jobs[future] = key, 'corroborate_body', scheduler.epoch
            scheduler.collect(1001)
            self.assertEqual(sample.last['corroborate_body'], 1000)
            self.assertIsNone(sample.corroborate)
        finally:
            scheduler.close()
