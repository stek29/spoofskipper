"""Health evidence transitions are independent of scheduling and API I/O."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager.probes import THROTTLE, SKIP, Probe, ProbeResult
from spoofskipper_manager.samples import Health, Sample


def ok(probe, **kw):
    size = {Probe.GATE: 1, Probe.THROTTLE: THROTTLE, Probe.THROUGHPUT: SKIP + THROTTLE}[probe]
    return ProbeResult(probe, ok=True, **{'bytes': size, 'latency_ms': 40, **kw})


def failed(probe, **kw):
    return ProbeResult(probe, ok=False, error='TimeoutError', **kw)


class SampleHealthTests(unittest.TestCase):
    def test_gate_success_cannot_prove_health_past_the_threshold(self):
        for state in (Health.UNKNOWN, Health.FAILED):
            with self.subTest(state=state):
                sample = Sample(health=state, healthy_at=1)
                sample.record(ok(Probe.GATE), 100)
                self.assertEqual(sample.health, state)
                self.assertEqual(sample.healthy_at, 1)
                self.assertEqual(sample.reachable_at, 100)
                self.assertEqual(sample.latency, 40)

    def test_threshold_success_proves_health_and_gate_keeps_it_fresh(self):
        sample = Sample()
        sample.record(ok(Probe.THROTTLE), 100)
        self.assertEqual(sample.health, Health.HEALTHY)
        self.assertTrue(sample.is_healthy(105, 10))
        sample.record(ok(Probe.GATE), 110)
        self.assertTrue(sample.is_healthy(115, 10))
        self.assertFalse(sample.is_healthy(121, 10))
        self.assertEqual(sample.scored(110, 10), [])  # No invented rate.

    def test_throughput_must_pass_the_threshold_to_count(self):
        sample = Sample()
        sample.record(ProbeResult(Probe.THROUGHPUT, ok=True, bytes=THROTTLE - 1, early_stop=True), 100)
        self.assertEqual(sample.health, Health.UNKNOWN)  # Slow but alive: no evidence either way.
        self.assertEqual(sample.failures, 0)
        sample.record(ok(Probe.THROUGHPUT, bytes=THROTTLE), 101)
        self.assertEqual(sample.health, Health.HEALTHY)
        self.assertEqual(sample.successes, [])
        sample.record(ok(Probe.THROUGHPUT, mbps=20), 102)
        self.assertEqual(sample.scored(103, 10), [(20, 40)])
        self.assertEqual(sample.scored(113, 10), [])

    def test_failure_is_confirmed_by_repeating_the_same_probe(self):
        for probe in Probe:
            with self.subTest(probe=probe):
                sample = Sample(health=Health.HEALTHY, healthy_at=99)
                sample.record(failed(probe), 100)
                self.assertEqual(sample.health, Health.HEALTHY)
                self.assertEqual(sample.confirm, probe)
                sample.record(failed(probe), 101)
                self.assertEqual(sample.health, Health.FAILED)
                self.assertEqual(sample.failed_at, 101)
                sample.record(failed(probe), 102)
                self.assertEqual(sample.failed_at, 101)
        sample = Sample(health=Health.HEALTHY)
        for now in (100, 101):  # One attempt per endpoint, with three endpoints.
            sample.record(failed(Probe.GATE), now, failures_to_fail=3)
            self.assertEqual((sample.health, sample.confirm), (Health.HEALTHY, Probe.GATE))
        sample.record(failed(Probe.GATE), 102, failures_to_fail=3)
        self.assertEqual(sample.health, Health.FAILED)

    def test_gate_success_clears_only_gate_failures(self):
        sample = Sample(health=Health.HEALTHY)
        sample.record(failed(Probe.GATE), 100)
        sample.record(ok(Probe.GATE), 101)
        self.assertEqual(sample.failures, 0)
        sample.record(failed(Probe.THROTTLE), 102)
        sample.record(ok(Probe.GATE), 103)
        self.assertEqual(sample.failures, 1)  # A tiny response does not disprove throttling.
        self.assertEqual(sample.confirm, Probe.THROTTLE)
        sample.record(failed(Probe.THROTTLE), 104)
        self.assertEqual(sample.health, Health.FAILED)

    def test_failed_path_recovers_only_past_the_threshold(self):
        sample = Sample(health=Health.FAILED, failures=5)
        sample.record(ok(Probe.GATE), 100)
        self.assertEqual(sample.health, Health.FAILED)
        sample.record(ok(Probe.THROTTLE), 101)
        self.assertEqual(sample.health, Health.HEALTHY)
        self.assertEqual(sample.failures, 0)

    def test_fallback_endpoint_proves_health_but_is_not_scored(self):
        sample = Sample(latency=30)
        sample.record(failed(Probe.THROUGHPUT), 100)
        self.assertEqual(sample.confirm, Probe.THROUGHPUT)
        sample.record(ok(Probe.THROUGHPUT, mbps=90, endpoint=1, latency_ms=200), 101)
        self.assertEqual((sample.health, sample.failures, sample.threshold_at), (Health.HEALTHY, 0, 101))
        self.assertEqual((sample.latency, sample.successes), (30, []))

    def test_connection_failure_without_latency_keeps_last_latency(self):
        sample = Sample(latency=30)
        sample.record(failed(Probe.GATE), 100)
        self.assertEqual(sample.latency, 30)
        self.assertEqual(Sample().latency_or_inf, float('inf'))


if __name__ == '__main__':
    unittest.main()
