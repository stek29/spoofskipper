"""Health evidence."""
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
