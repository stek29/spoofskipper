"""Health evidence transitions are independent of scheduling and API I/O."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager.scheduler import Health, Sample
from spoofskipper_manager.probes import THROTTLE


class SampleHealthTests(unittest.TestCase):
    def test_head_success_preserves_every_body_failure_state_and_age(self):
        for state in (Health.SUSPECT_BODY, Health.FAILED_BODY, Health.BODY_ONLY_BACKUP):
            for kind in ('gate', 'corroborate_gate', 'throughput'):
                with self.subTest(state=state, kind=kind):
                    sample = Sample(health=state, healthy_at=1)
                    sample.record(kind, {'ok': True, 'bytes': 1}, 100)
                    self.assertEqual(sample.health, state)
                    self.assertEqual(sample.healthy_at, 1)
                    self.assertEqual(sample.successes, [])

    def test_body_backup_restores_health_but_only_scored_or_throttle_clears_body_failure(self):
        for state in Health:
            with self.subTest(state=state):
                sample = Sample(health=state)
                sample.record('throttle', {'ok': False}, 100)
                self.assertEqual(sample.health, Health.SUSPECT_BODY)
                self.assertEqual(sample.corroborate, 'corroborate_body')
                sample.record('corroborate_body', {'ok': False}, 101)
                self.assertEqual(sample.health, Health.FAILED_BODY)
                sample.record('corroborate_body', {'ok': True}, 102)
                self.assertEqual(sample.health, Health.BODY_ONLY_BACKUP)
                self.assertTrue(sample.is_healthy(103, 10))
                self.assertFalse(sample.is_healthy(113, 10))
                self.assertEqual(sample.scored(103, 10), [])
                sample.record('throttle', {'ok': True}, 104)
                self.assertEqual(sample.health, Health.HEALTHY)
                self.assertEqual(sample.throttle_at, 104)

    def test_body_prefix_proves_health_and_scored_body_proves_performance(self):
        sample = Sample(health=Health.FAILED_BODY)
        sample.record('throughput', {'ok': True, 'bytes': THROTTLE}, 100)
        self.assertEqual(sample.health, Health.BODY_ONLY_BACKUP)
        self.assertEqual(sample.scored(100, 10), [])
        sample.record('throughput', {'ok': True, 'mbps': 20, 'latency_ms': 40}, 101)
        self.assertEqual(sample.health, Health.HEALTHY)
        self.assertEqual(sample.scored(102, 10), [(20, 40)])
        self.assertEqual(sample.scored(112, 10), [])

    def test_three_connection_failures_then_head_are_healthy_without_latency(self):
        sample = Sample()
        for at in (100, 101, 102):
            sample.record('gate', {'ok': False, 'latency_ms': None}, at)
        self.assertEqual(sample.corroborate, 'corroborate_gate')
        sample.record('corroborate_gate', {'ok': True}, 103)
        self.assertTrue(sample.is_healthy(104, 10))
        self.assertIsNone(sample.latency)
        self.assertEqual(sample.latency_or_inf, float('inf'))
        self.assertEqual(sample.scored(104, 10), [])
