"""Ordinary discards retain cadence; cancellation alone releases retry timers."""
from concurrent.futures import Future
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import clash_api
from spoofskipper_manager.identity import SampleKey
from spoofskipper_manager.probes import Probe, ProbeResult
from spoofskipper_manager.scheduler import Health, Sample, Scheduler


class DiscardCadenceTests(unittest.TestCase):
    def test_unreachable_api_does_not_stop_or_flood_probing(self):
        now = [1000.]
        scheduler = Scheduler(lambda *args, **kw: None, clock=lambda: now[0])
        outbounds = [{'type': 'socks', 'tag': 'up', 'server': 'x', 'server_port': 1},
                     {'type': 'socks', 'tag': 'dep', 'server': 'y', 'server_port': 2, 'detour': 'up'}]
        scheduler.configure({'outbounds': outbounds, 'experimental': {
            'clash_api': {'external_controller': '127.0.0.1:9'}}}, [], {'probes_enabled': True})
        try:
            with patch.object(clash_api, "proxies", side_effect=OSError('API unavailable')) as api, \
                 patch.object(scheduler.pool, 'submit', side_effect=lambda *args: Future()):
                for tick in range(100):  # Ten seconds of ticks.
                    now[0] = 1000. + tick / 10
                    scheduler.tick()
            self.assertLessEqual(api.call_count, 2)  # Only the 5-second inspection uses the API.
            self.assertEqual(len(scheduler.jobs), 2)  # Gates still run.
        finally:
            scheduler.close()

    def test_ordinary_discard_does_not_rearm_confirmation(self):
        scheduler = Scheduler(lambda *args, **kwargs: None)
        try:
            key = SampleKey('candidate', 'hash')
            scheduler.samples[key] = sample = Sample(failures=1, failed_probe=Probe.THROTTLE)
            sample.last[Probe.THROTTLE] = 1000
            future = Future()
            future.set_result((ProbeResult(Probe.THROTTLE, ok=True), False))
            scheduler.jobs[future] = key, Probe.THROTTLE, scheduler.epoch
            scheduler.collect(1001)
            self.assertEqual(sample.last[Probe.THROTTLE], 1000)
            self.assertIsNone(sample.confirm)
        finally:
            scheduler.close()
