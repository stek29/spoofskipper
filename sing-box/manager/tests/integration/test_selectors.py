"""Pinned-core ownership transitions and real Clash PUT/verification."""
import copy
import json
import shutil
import signal
import time
import unittest
from unittest.mock import patch

from test_lifecycle import free_port, wait_for
import test_lifecycle
from spoofskipper_manager import clash_api, compiler
SELECTORS = ('traffic', 'restricted', 'transport')
from spoofskipper_manager.scheduler import Health, Sample
from spoofskipper_manager.service import Manager
from spoofskipper_manager.state import write_json


class OwnershipReload:
    """Lifecycle scenario reused below without inheriting the lifecycle suite."""

    def ownership_reload(self):
        self.settings.update(refresh_seconds=3600, probe_timeout=.2, probe_port=free_port())
        write_json(self.config/'local-manager.json', self.settings)
        self.specs['subscriptions'].append({**self.specs['subscriptions'][0], 'prefix': 'extra'})
        write_json(self.config/'local-subs-config.json', self.specs)
        suffix = ''' + {outbounds: [o for o in super.outbounds if o.tag != 'traffic'] +
            [{type: 'selector', tag: tag, outbounds: ['example', 'extra', 'example_one', 'extra_one'],
              default: 'example'} for tag in ['traffic', 'restricted', 'transport']]}'''
        (self.config/'config.jsonnet').write_text(self.source.replace('proxy_main', 'traffic').rstrip()+suffix)
        self.start()
        self.ready()
        native = self.live()
        clash_api.select(native, 'traffic', 'extra', ['traffic'])
        self.settings.update(probes_enabled=True, managed_selectors=['traffic'])
        write_json(self.config/'local-manager.json', self.settings)
        self.proc.send_signal(signal.SIGHUP)
        wait_for(lambda: 'selector_handoff' in self.logs())
        c = self.live()
        p = clash_api.proxies(c)
        self.assertEqual(p['traffic']['now'], 'extra_one')
        self.assertEqual(set(p['traffic']['all']), {'example_one', 'extra_one'})
        self.assertEqual(p['restricted']['now'], 'example')
        self.assertIn('example', p)
        self.assertIn('extra', p['restricted']['all'])
        # Last native reference disappears only when every selector is handed off.
        self.settings['managed_selectors'] = list(SELECTORS)
        write_json(self.config/'local-manager.json', self.settings)
        self.proc.send_signal(signal.SIGHUP)
        wait_for(lambda: 'example' not in {o['tag'] for o in self.live()['outbounds']})
        wait_for(lambda: clash_api.proxies(self.live())['traffic']['now'] == 'extra_one')
        # Removal restores native references/groups; dashboard control is writable.
        self.settings['managed_selectors'] = ['traffic', 'transport']
        write_json(self.config/'local-manager.json', self.settings)
        self.proc.send_signal(signal.SIGHUP)
        wait_for(lambda: 'example' in {o['tag'] for o in self.live()['outbounds']})
        c = self.live()
        clash_api.select(c, 'restricted', 'extra', ['restricted'])
        time.sleep(.3)
        self.assertEqual(clash_api.proxies(c)['restricted']['now'], 'extra')
        self.assertEqual(clash_api.proxies(c)['traffic']['now'], 'extra_one')
        self.assertEqual(self.requests, 2)  # reload did not introduce a fetch owner


# Reuse setup helpers without registering a second inherited lifecycle suite.
class SelectorIntegrationTests(unittest.TestCase):
    setUp = test_lifecycle.LifecycleTests.setUp
    tearDown = test_lifecycle.LifecycleTests.tearDown
    start = test_lifecycle.LifecycleTests.start
    logs = test_lifecycle.LifecycleTests.logs
    live = test_lifecycle.LifecycleTests.live
    ready = test_lifecycle.LifecycleTests.ready
    core = 'sing-box'
    test_partial_handoff_last_reference_and_ownership_removal_reload = unittest.skipUnless(
        shutil.which('sing-box'), 'requires offline Compose pinned core')(OwnershipReload.ownership_reload)

    @unittest.skipUnless(shutil.which('sing-box'), 'requires offline Compose pinned core')
    def test_failed_later_handoff_restores_original_group_and_other_selector(self):
        manager = Manager(self.config, self.root/'rollback')
        leaves = [{'type': 'trojan', 'tag': t, 'server': '127.0.0.1', 'server_port': 1,
                   'password': 'fixture'} for t in ('a', 'b')]
        old = {'log': {'disabled': True}, 'outbounds': copy.deepcopy(leaves)+[
            {'type': 'urltest', 'tag': 'p_best', 'outbounds': ['a', 'b'], 'url': 'http://127.0.0.1:1/'},
            *[{'type': 'selector', 'tag': tag, 'outbounds': ['p_best', 'a', 'b']} for tag in SELECTORS],
            {'type': 'direct', 'tag': compiler.REVISION_PREFIX+'old'}],
            'experimental': {'clash_api': {'external_controller': '127.0.0.1:'+str(free_port())}}}
        try:
            manager.activate(old)
            before = clash_api.proxies(old)
            new = copy.deepcopy(old)
            new['outbounds'][-1]['tag'] = compiler.REVISION_PREFIX+'new'
            manager.settings = manager.settings.with_changes(managed_selectors=['traffic', 'restricted'], probes_enabled=True)
            compiler.handoff_selectors(new, manager.settings['managed_selectors'], [{'outbound': o} for o in leaves])
            real = clash_api.select
            failed = False
            def write(config, selector, target, managed, **kw):
                nonlocal failed
                if selector == 'restricted' and not failed:
                    failed = True
                    raise ValueError('injected later handoff failure')
                return real(config, selector, target, managed, **kw)
            with patch.object(clash_api, 'select', side_effect=write):
                with self.assertRaises(ValueError):
                    manager.activate(new)
            self.assertEqual(manager.current, old)
            self.assertEqual(json.loads(manager.live.read_text()), old)
            self.assertFalse(manager.marker.exists())
            after = clash_api.proxies(old)
            for selector in SELECTORS:
                self.assertEqual(after[selector]['now'], before[selector]['now'])
                self.assertEqual(after[selector]['all'], before[selector]['all'])
        finally:
            manager.scheduler.close()
            manager.stop_child()

    @unittest.skipUnless(shutil.which('sing-box'), 'requires offline Compose pinned core')
    def test_verified_writes_optional_auth_escaping_and_per_selector_rollback(self):
        # Same manager activation path as production, using only local dead-end
        # Trojan definitions; measurements are injected so no internet is needed.
        for secret in ('', 'fixture-secret'):
            with self.subTest(secret=bool(secret)):
                manager = Manager(self.config, self.root/('auth' if secret else 'open'))
                manager.settings = manager.settings.with_changes(managed_selectors=['traffic'], probes_enabled=True)
                leaves = [{'type': 'trojan', 'tag': t, 'server': '127.0.0.1', 'server_port': 1,
                           'password': 'synthetic'} for t in ('a/🇩🇪', 'b')]
                candidates = [{'outbound': o, 'provider': 'p', 'weight': 1} for o in leaves]
                def config():
                    c = {'log': {'disabled': True}, 'outbounds': copy.deepcopy(leaves)+[
                        {'type': 'selector', 'tag': tag, 'outbounds': [o['tag'] for o in leaves]} for tag in SELECTORS],
                        'experimental': {'clash_api': {'external_controller': '127.0.0.1:'+str(free_port()), 'secret': secret}}}
                    c['outbounds'].append({'type': 'direct', 'tag': compiler.REVISION_PREFIX+'test'})
                    return c
                c = config()
                try:
                    manager.activate(c)
                    before = clash_api.proxies(c)
                    clash_api.select(c, 'traffic', 'b', ['traffic'])
                    self.assertEqual(clash_api.proxies(c)['restricted'], before['restricted'])
                    # Force a failed post-write verification after the real PUT.
                    real = clash_api.proxies
                    calls = 0
                    def inspect(*args, **kw):
                        nonlocal calls
                        calls += 1
                        result = real(*args, **kw)
                        if calls == 2:
                            result['traffic']['now'] = 'mismatch'
                        return result
                    with patch.object(clash_api, 'proxies', side_effect=inspect):
                        with self.assertRaises(ValueError):
                            clash_api.select(c, 'traffic', leaves[0]['tag'], ['traffic'])
                    self.assertEqual(real(c)['traffic']['now'], 'b')
                    self.assertEqual(real(c)['restricted'], before['restricted'])
                    # Confirmed health failure bypasses the hold and performs a
                    # real selection without ever submitting a download.
                    scheduler = manager.scheduler
                    scheduler.configure(c, candidates, {'probes_enabled': True, 'managed_selectors': ['traffic']})
                    scheduler.controller.inspect()
                    now = scheduler.clock()
                    for key in scheduler.samples:
                        scheduler.samples[key] = Sample(health=Health.HEALTHY if key[0] != 'b' else Health.FAILED_GATE, healthy_at=now,
                            latency=20, successes=[(now, 20, 20)])
                    with patch.object(scheduler.pool, 'submit') as submit:
                        scheduler.controller.apply_policy(now)
                        submit.assert_not_called()
                    self.assertEqual(real(c)['traffic']['now'], leaves[0]['tag'])
                    self.assertEqual(real(c)['transport'], before['transport'])
                finally:
                    manager.scheduler.close()
                    manager.stop_child()

