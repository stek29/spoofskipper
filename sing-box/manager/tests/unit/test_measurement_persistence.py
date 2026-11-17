import copy
import json
import sys
import tempfile
import unittest
from concurrent.futures import Future
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager.identity import sample_key
from spoofskipper_manager.probes import Probe
from spoofskipper_manager.samples import Health, Sample
from spoofskipper_manager.scheduler import Scheduler


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'measurements.json'
        self.now, self.wall = 1000., 20000.
        self.events = []
        self.config = {'outbounds': [
            {'type': 'trojan', 'tag': 'a', 'server': 'secret.example', 'password': 'secret-password'},
            {'type': 'trojan', 'tag': 'b', 'server': 'other.example', 'password': 'other-password'},
            {'type': 'selector', 'tag': 'upstream', 'outbounds': ['a', 'b']}],
            'endpoints': [{'type': 'wireguard', 'tag': 'warp', 'detour': 'upstream'}]}
        self.api = {'upstream': {'now': 'a'}}

    def scheduler(self, config=None):
        scheduler = Scheduler(lambda event, **kw: self.events.append((event, kw)),
                              clock=lambda: self.now, wall=lambda: self.wall, state_path=self.path)
        self.addCleanup(scheduler.close)
        scheduler.configure(config or self.config, [], {'probes_enabled': True})
        scheduler.update_paths(self.api)
        return scheduler

    def seed(self, scheduler, tag='a'):
        key = next(k for k in scheduler.samples if k.tag == tag)
        scheduler.samples[key] = Sample(latency=25, health=Health.HEALTHY, healthy_at=995,
            threshold_at=990, reachable_at=995, failed_at=800, failures=1,
            failed_probe=Probe.THROTTLE, confirm=Probe.THROTTLE,
            successes=[(980, 42, 25), (990, 60, 20)],
            last={Probe.GATE: 995, Probe.THROUGHPUT: 990},
            outcomes={Probe.GATE: 'ok', Probe.THROUGHPUT: '60.0 Mbps'})
        return key

    def test_restart_retains_evidence_outcomes_and_cadence_across_reboot(self):
        old = self.scheduler();key = self.seed(old)
        old.rotated_at['a'] = 990
        old.checkpoint(force=True)
        # New boot: monotonic time resets, wall time includes 20 seconds down.
        self.now, self.wall = 10, 20020
        new = self.scheduler();sample = new.samples[key]
        self.assertEqual(sample.health, Health.HEALTHY)
        self.assertEqual(sample.successes, [(-30, 42, 25), (-20, 60, 20)])
        self.assertEqual(sample.last[Probe.GATE], -15)
        self.assertEqual(sample.confirm, Probe.THROTTLE)
        self.assertEqual(sample.failures, 1)
        self.assertEqual(sample.outcomes[Probe.THROUGHPUT], '60.0 Mbps')
        self.assertEqual(new.rotated_at['a'], -20)
        text = self.path.read_text()
        self.assertNotIn('secret-password', text)
        self.assertNotIn('secret.example', text)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_downtime_does_not_refresh_health_or_scores(self):
        old = self.scheduler();key = self.seed(old);old.checkpoint(force=True)
        self.now, self.wall = 5, 20000 + 86400
        new = self.scheduler();sample = new.samples[key]
        self.assertFalse(sample.is_healthy(self.now, 960))
        self.assertEqual(sample.scored(self.now, 21600), [])
        self.assertEqual(len(sample.successes), 2)  # History remains visible.

    def test_changed_credentials_and_selected_upstream_reject_evidence(self):
        old = self.scheduler();self.seed(old);warp_key = self.seed(old, 'warp');old.checkpoint(force=True)
        changed = copy.deepcopy(self.config);changed['outbounds'][0]['password'] = 'new-password'
        new = self.scheduler(changed)
        self.assertEqual(new.samples[sample_key(changed['outbounds'][0])].successes, [])
        self.assertEqual(new.samples[warp_key].successes, [])
        self.api['upstream']['now'] = 'b'
        other = self.scheduler()
        self.assertEqual(other.samples[warp_key].successes, [])

    def test_detoured_evidence_waits_for_actual_selector_choice(self):
        old = self.scheduler();key = self.seed(old, 'warp');old.checkpoint(force=True)
        new = Scheduler(lambda *a, **k: None, clock=lambda: self.now,
                        wall=lambda: self.wall, state_path=self.path)
        self.addCleanup(new.close)
        new.configure(self.config, [], {'probes_enabled': True})
        self.assertEqual(new.samples[key].successes, [])
        new.update_paths(self.api)
        self.assertEqual(len(new.samples[key].successes), 2)

    def test_interrupted_probes_and_rotation_are_rearmed_without_losing_evidence(self):
        old = self.scheduler();key = self.seed(old)
        old.samples[key].last[Probe.THROUGHPUT] = self.now
        old.rotated_at['a'] = self.now
        old.jobs[Future()] = (key, Probe.THROUGHPUT, old.epoch)
        old.checkpoint(force=True)
        new = self.scheduler()
        self.assertNotIn(Probe.THROUGHPUT, new.samples[key].last)
        self.assertNotIn('a', new.rotated_at)
        self.assertEqual(len(new.samples[key].successes), 2)
        old.jobs.clear()  # Synthetic future has no worker to finish/cancel.

    def test_corrupt_state_and_backwards_wall_clock_do_not_block_startup(self):
        for content in ('{', json.dumps({'version': 999, 'saved_at': 20000}),
                        json.dumps({'version': 1, 'saved_at': 30000, 'samples': [], 'rotation': {}})):
            self.path.write_text(content)
            scheduler = self.scheduler()
            self.assertTrue(all(s.health is Health.UNKNOWN for s in scheduler.samples.values()))
        self.assertEqual(sum(event == 'measurement_state_invalid' for event, _ in self.events), 3)

    def test_shutdown_forces_checkpoint_before_periodic_deadline(self):
        scheduler = self.scheduler();key = self.seed(scheduler)
        scheduler.checkpoint()
        self.assertFalse(self.path.exists())
        scheduler.close()
        self.assertTrue(self.path.exists())
        self.assertEqual(len(self.scheduler().samples[key].successes), 2)
