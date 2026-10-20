"""Snapshot/render of the read-only status page: policy order, escaping, no secrets."""
import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import clash_api
from spoofskipper_manager.dashboard import render, snapshot
from spoofskipper_manager.policy import score
from spoofskipper_manager.samples import Health
from spoofskipper_manager.scheduler import Scheduler
from spoofskipper_manager.settings import ACTIVE_SCORE_MAX_AGE

EVIL = '<script>x</script>'


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.
        self.scheduler = Scheduler(lambda *args, **kw: None, clock=lambda: self.now)
        outbounds = [{'type': 'vless', 'tag': tag, 'server': 'secret.example', 'uuid': 'uuid-secret',
                      'password': 'pass-secret'} for tag in ('a', 'b', EVIL)]
        self.config = {'outbounds': outbounds + [
            {'type': 'selector', 'tag': 'deep', 'outbounds': ['a', 'b', EVIL]},
            {'type': 'selector', 'tag': 'native', 'outbounds': ['a', 'b']},
            {'type': 'direct', 'tag': '__spoofskipper_revision_r1'}],
            'experimental': {'clash_api': {'external_controller': '127.0.0.1:1', 'secret': 'api-secret'}}}
        providers = {'a': 'blanc', 'b': 'warp', EVIL: EVIL}
        self.scheduler.configure(self.config, [{'provider': providers[o['tag']], 'weight': 1.0, 'outbound': o}
                                               for o in outbounds],
                                 {'probes_enabled': True, 'managed_selectors': ['deep'], 'uplink_urls': [],
                                  'probe_urls': ['https://user:pw@probe.test/x?bytes={bytes}'],
                                  'selector_priorities': {'deep': [['blanc'], ['warp']]}})
        for key, sample in self.scheduler.samples.items():
            sample.health, sample.healthy_at, sample.latency = Health.HEALTHY, self.now, 50
            sample.successes = [(self.now-10, {'a': 10, 'b': 80}.get(key.tag, 5), 50)]
            sample.last = {'gate': self.now, 'throttle': self.now, 'throughput': self.now}
        self.api = {'deep': {'now': 'b'}, 'native': {'now': 'a'}}
        with patch.object(clash_api, 'proxies', side_effect=lambda *a, **kw: copy.deepcopy(self.api)), \
                patch.object(self.scheduler.pool, 'submit'), patch.object(clash_api, 'select'):
            self.scheduler.tick()

    def tearDown(self):
        self.scheduler.close()

    def test_rows_follow_tiers_and_explain_scores(self):
        page = snapshot(self.scheduler, self.config, self.now, wall=0)
        self.assertEqual(page['revision'], '__spoofskipper_revision_r1')
        deep = next(s for s in page['selectors'] if s['tag'] == 'deep')
        native = next(s for s in page['selectors'] if s['tag'] == 'native')
        self.assertNotIn('rows', native)
        self.assertEqual(native['now'], 'a')
        # A higher tier wins regardless of score; the evil provider is outside the tiers.
        self.assertEqual([r['tag'] for r in deep['rows']], ['a', 'b', EVIL])
        a, b, evil = deep['rows']
        self.assertEqual((a['margin']['kind'], b['margin']['kind'], evil['margin']), ('priority_return', 'current', None))
        self.assertEqual(deep['decision']['reason'], 'hold')
        sample = next(s for k, s in self.scheduler.samples.items() if k.tag == 'b')
        self.assertAlmostEqual(b['score'], score(sample, 1.0, self.now, ACTIVE_SCORE_MAX_AGE))
        self.assertEqual((a['eligibility'], b['eligibility']), ('eligible', 'healthy, higher tier preferred'))
        self.assertTrue(evil['eligibility'].startswith('excluded'))
        # Roles are relative to this selector; another selector's choice is only noted.
        self.assertEqual((a['role'], a['flags'], b['role']), (None, ['active in native'], 'current'))

    def test_render_escapes_and_omits_secrets(self):
        body = render(snapshot(self.scheduler, self.config, self.now, wall=0), self.now + 2, 0)
        self.assertIn('&lt;script&gt;', body)
        self.assertNotIn(EVIL, body)
        for secret in ('secret.example', 'uuid-secret', 'pass-secret', 'api-secret', 'user:pw', *(
                k.digest for k in self.scheduler.candidates)):
            self.assertNotIn(secret, body)
        self.assertIn('https://probe.test/x?bytes={bytes}', body)
        self.assertIn('No snapshot yet', render(None, 0, 0))


if __name__ == '__main__':
    unittest.main()
