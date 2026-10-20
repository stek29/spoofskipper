"""Ownership revocation clears policy state."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager.identity import SampleKey
from spoofskipper_manager.scheduler import Scheduler


class EvidenceTests(unittest.TestCase):
    def test_revocation_does_not_grant_new_ownership_or_reuse_old_hold(self):
        scheduler = Scheduler(lambda *args, **kw: None)
        try:
            scheduler.settings = scheduler.settings.with_changes(managed_selectors=['proxy_main'])
            scheduler.controller.policy.observe('proxy_main', 'a', 100)
            scheduler.controller.policy.pending['proxy_main'] = (SampleKey('b', 'hash'), 400)
            scheduler.restrict({'probes_enabled': True, 'managed_selectors': ['proxy_deepmind']})
            self.assertEqual(scheduler.settings.managed_selectors, ())
            self.assertNotIn('proxy_main', scheduler.controller.policy.choices)
            self.assertNotIn('proxy_main', scheduler.controller.policy.pending)
        finally:
            scheduler.close()


if __name__ == '__main__':
    unittest.main()
