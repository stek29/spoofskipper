import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import compiler, clash_api
from spoofskipper_manager.service import Manager
from spoofskipper_manager.state import write_json


def config():
    return {'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'experimental': {
        'clash_api': {'external_controller': '[::]:9090', 'secret': 'private'}}}


class CompilerTests(unittest.TestCase):
    def test_api_validation(self):
        self.assertEqual(clash_api.credentials(config()), ('http://[::1]:9090', 'private'))
        for address in (':9090', 'localhost:9090', '[::]:9090', '192.0.2.1:9090'):
            c = config()
            c['experimental']['clash_api']['external_controller'] = address
            compiler.validate(c)
        self.assertEqual(clash_api.credentials(c | {'experimental': {'clash_api': {
            'external_controller': ':9090'}}}), ('http://127.0.0.1:9090', ''))
        for address in ('router.lan:9090', 'localhost:no', '127.0.0.1:0'):
            c = config()
            c['experimental']['clash_api']['external_controller'] = address
            with self.assertRaises(ValueError):
                compiler.validate(c)
        c = config()
        for secret in ('', None):
            if secret is None:
                c['experimental']['clash_api'].pop('secret', None)
            else:
                c['experimental']['clash_api']['secret'] = secret
            compiler.validate(c)
            self.assertEqual(clash_api.credentials(c)[1], '')
        c['experimental']['clash_api']['secret'] = 123
        with self.assertRaises(ValueError):
            compiler.validate(c)

    def test_missing_api_gets_loopback_controller(self):
        for api in (None, {}, {'external_controller': ''}):
            c = {'outbounds': [{'type': 'direct', 'tag': 'direct'}]}
            if api is not None:
                c['experimental'] = {'clash_api': api}
            compiler.ensure_clash_api(c, 19089, 'generated')
            compiler.validate(c)
            self.assertEqual(clash_api.credentials(c), ('http://127.0.0.1:19089', 'generated'))
        c = config()
        compiler.ensure_clash_api(c, 19089, 'generated')
        self.assertEqual(clash_api.credentials(c), ('http://[::1]:9090', 'private'))

    def test_graph_validation(self):
        for outbounds in ([{'tag': 'x', 'type': 'selector', 'outbounds': ['x']}],
                          [{'tag': 'x', 'type': 'selector', 'outbounds': ['missing']}],
                          [{'tag': 'x', 'type': 'selector', 'outbounds': []}],
                          [{'tag': 'x', 'type': 'direct', 'detour': 'y'}, {'tag': 'y', 'type': 'direct', 'detour': 'x'}]):
            c = config()
            c['outbounds'] = outbounds
            with self.assertRaises(ValueError):
                compiler.validate(c)

    def test_render_uses_a_scratch_copy_with_current_subscriptions(self):
        with tempfile.TemporaryDirectory() as temp:
            source, scratch = Path(temp) / 'config', Path(temp) / 'scratch'
            source.mkdir()
            (source / 'config.jsonnet').write_text("local sub_data = std.parseJson(importstr 'local-subs.json');")
            (source / 'local-subs.json').write_text('{"outbounds": [], "groups": {"static": []}}')
            seen = []
            def run(args, **kw):
                rendered = Path(args[-1])
                seen.append(json.loads((rendered.parent / 'local-subs.json').read_text()))
                return type('Result', (), {'returncode': 0, 'stdout': json.dumps(config())})()
            with patch.object(compiler.subprocess, 'run', side_effect=run):
                compiler.render(source / 'sing.jsonnet', {'outbounds': [], 'groups': {'fresh': []}}, scratch)
                compiler.render(source / 'sing.jsonnet', None, scratch)  # No providers configured.
            self.assertEqual([s['groups'] for s in seen], [{'fresh': []}, {'static': []}])
            self.assertEqual(json.loads((source / 'local-subs.json').read_text())['groups'], {'static': []})
            self.assertEqual(list(scratch.iterdir()), [])

    def test_revision_changes_with_same_tag_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            c = config()
            source, scratch = Path(temp) / 'config', Path(temp) / 'scratch'
            source.mkdir()
            def render(c):
                with patch.object(compiler.subprocess, 'run', return_value=type('Result', (), {
                        'returncode': 0, 'stdout': json.dumps(c)})()):
                    return compiler.render(source / 'sing.jsonnet', {}, scratch)
            first = render(c)
            self.assertEqual(first, render(c))
            c['experimental']['clash_api']['secret'] = 'rotated'
            self.assertNotEqual(compiler.revision(first), compiler.revision(render(c)))
            self.assertEqual(list(scratch.iterdir()), [])

    def test_activation_rollback_once_and_noop_skips_check(self):
        with tempfile.TemporaryDirectory() as temp:
            m = Manager(temp, Path(temp) / 'state')
            old = config()
            old['outbounds'].append({'type': 'direct', 'tag': compiler.REVISION_PREFIX + 'old'})
            new = copy.deepcopy(old)
            new['outbounds'][-1]['tag'] = compiler.REVISION_PREFIX + 'new'
            m.current = old
            write_json(m.live, old)
            child = type('Child', (), {'send_signal': lambda *args: None})()
            m.child = child
            with patch.object(compiler, 'check') as check, patch.object(m, 'alive', return_value=True), \
                 patch.object(m, 'verify', side_effect=[False, True]), patch.object(m, 'start') as start, \
                 patch.object(m, 'stop_child') as stop:
                with self.assertRaises(ValueError):
                    m.activate(new)
                self.assertEqual(json.loads(m.live.read_text()), old)
                self.assertFalse(m.marker.exists())
                self.assertEqual((start.call_count, stop.call_count), (1, 1))
                m.activate(old)
                self.assertEqual(check.call_count, 1)  # Unchanged config is not re-checked.

    def test_interrupted_marker_and_abandoned_temp(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'state'
            root.mkdir()
            (root / '.manager-abandoned').write_text('secret')
            m = Manager(temp, root)
            self.assertFalse((root / '.manager-abandoned').exists())
            write_json(m.previous, config())
            m.marker.write_text('activating')
            m.live.write_text('broken')
            m.recover_interrupted()
            self.assertEqual(json.loads(m.live.read_text()), config())
            self.assertTrue(m.marker.exists())

    def test_failed_recovery_keeps_marker(self):
        from spoofskipper_manager.service import RecoveryFailed
        with tempfile.TemporaryDirectory() as temp:
            m = Manager(temp, Path(temp) / 'state')
            old = config()
            old['outbounds'].append({'type': 'direct', 'tag': compiler.REVISION_PREFIX + 'old'})
            new = copy.deepcopy(old)
            new['outbounds'][-1]['tag'] = compiler.REVISION_PREFIX + 'new'
            m.current = old
            write_json(m.live, old)
            m.child = type('Child', (), {'send_signal': lambda *args: None})()
            with patch.object(compiler, 'check'), patch.object(m, 'alive', return_value=True), \
                 patch.object(m, 'verify', return_value=False), patch.object(m, 'start'), patch.object(m, 'stop_child'):
                with self.assertRaises(RecoveryFailed):
                    m.activate(new)
            self.assertTrue(m.marker.exists())
            self.assertEqual(json.loads(m.live.read_text()), old)

    def test_failed_saved_config_falls_through_to_fresh_render(self):
        with tempfile.TemporaryDirectory() as temp:
            m = Manager(temp, Path(temp) / 'state')
            saved = config()
            saved['outbounds'].append({'type': 'direct', 'tag': compiler.REVISION_PREFIX + 'saved'})
            write_json(m.live, saved)
            with patch.object(m, 'start'), patch.object(m, 'verify', return_value=False), \
                 patch.object(m, 'stop_child') as stop:
                m.start_saved()
            stop.assert_called_once()
            self.assertIsNone(m.current)

    def test_unexpected_handoff_error_rolls_back(self):
        import http.client
        from spoofskipper_manager.service import ActivationRolledBack
        with tempfile.TemporaryDirectory() as temp:
            m = Manager(temp, Path(temp) / 'state')
            old = config()
            old['outbounds'].append({'type': 'direct', 'tag': compiler.REVISION_PREFIX + 'old'})
            new = copy.deepcopy(old)
            new['outbounds'][-1]['tag'] = compiler.REVISION_PREFIX + 'new'
            m.current = old
            write_json(m.live, old)
            m.child = type('Child', (), {'send_signal': lambda *args: None})()
            with patch.object(compiler, 'check'), patch.object(m, 'alive', return_value=True), \
                 patch.object(m, 'verify', return_value=True), patch.object(m, 'start'), \
                 patch.object(m, 'stop_child'), patch.object(m, 'restore_choices'), \
                 patch.object(m, 'hand_off', side_effect=http.client.BadStatusLine('x')):
                with self.assertRaises(ActivationRolledBack):
                    m.activate(new)
            self.assertEqual(m.current, old)
            self.assertFalse(m.marker.exists())
            self.assertEqual(json.loads(m.live.read_text()), old)

    def test_rollback_with_unchanged_settings_gets_a_live_probe_client(self):
        from unittest.mock import Mock
        from spoofskipper_manager.service import ActivationRolledBack
        with tempfile.TemporaryDirectory() as temp:
            m = Manager(temp, Path(temp) / 'state')
            old = config()
            old['outbounds'] = [{'type': 'trojan', 'tag': 'a'}, {'type': 'selector', 'tag': 'sel', 'outbounds': ['a']},
                                {'type': 'direct', 'tag': compiler.REVISION_PREFIX + 'old'}]
            new = copy.deepcopy(old)
            new['outbounds'][-1]['tag'] = compiler.REVISION_PREFIX + 'new'
            m.current, m.child = old, Mock()
            write_json(m.live, old)
            m.settings = m.settings.with_changes(probes_enabled=True, managed_selectors=('sel',))
            m.scheduler.configure(old, [{'provider': 'p', 'weight': 1, 'outbound': old['outbounds'][0]}], m.settings)
            try:
                with patch.object(compiler, 'check'), patch.object(m, 'alive', return_value=True), \
                     patch.object(m, 'verify', side_effect=[False, True]), patch.object(m, 'start'), \
                     patch.object(m, 'stop_child'), patch.object(clash_api, 'select'), \
                     patch.object(clash_api, 'proxies', return_value={'sel': {'now': 'a'}}):
                    with self.assertRaises(ActivationRolledBack):
                        m.activate_and_configure(new, Mock(), {})
                self.assertFalse(m.scheduler.client.cancelled.is_set())
            finally:
                m.scheduler.close()

    def test_shutdown_kills_unresponsive_child_with_deadline(self):
        import subprocess
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as temp:
            m = Manager(temp, Path(temp) / 'state')
            child = Mock()
            child.poll.return_value = None
            child.wait.side_effect = [subprocess.TimeoutExpired('core', 1), 0]
            m.child = child
            m.stop_child()
            child.kill.assert_called_once()
            self.assertEqual(child.wait.call_count, 2)
            self.assertIsNone(m.child)


class OwnershipTests(unittest.TestCase):
    def config(self):
        leaves = [{'type': 'trojan', 'tag': tag, 'server': '127.0.0.1', 'server_port': 1, 'password': 'fixture'} for tag in ('a', 'b')]
        c = {'outbounds': leaves + [{'type': 'urltest', 'tag': 'p_best', 'outbounds': ['a', 'b']}] +
            [{'type': 'selector', 'tag': tag, 'outbounds': ['p_best', 'a', 'b']} for tag in
             ('proxy_main', 'proxy_deepmind', 'chained_upstream')],
             'experimental': {'clash_api': {'external_controller': '127.0.0.1:9090'}}}
        return c, [{'outbound': o} for o in leaves]

    def test_handoff_flattens_only_owned_selectors(self):
        native, candidates = self.config()
        c = copy.deepcopy(native)
        compiler.handoff_selectors(c, ['proxy_main'], candidates)
        entries = {o['tag']: o for o in c['outbounds']}
        self.assertEqual(entries['proxy_main']['outbounds'], ['a', 'b'])
        self.assertEqual(entries['proxy_deepmind']['outbounds'], ['p_best', 'a', 'b'])
        c = copy.deepcopy(native)
        compiler.handoff_selectors(c, [], candidates)
        self.assertEqual(c, native)

    def test_handoff_rejects_incompatible_members_and_cycles(self):
        c, candidates = self.config()
        c['outbounds'].append({'type': 'direct', 'tag': 'bypass'})
        c['outbounds'][2]['outbounds'].append('bypass')
        with self.assertRaises(ValueError):
            compiler.handoff_selectors(c, ['proxy_main'], [])
        c['outbounds'][-1]['outbounds'] = ['chained_upstream']
        with self.assertRaises(ValueError):
            compiler.handoff_selectors(c, ['proxy_main'], candidates)

    def test_write_verification_rolls_back_only_failed_selector(self):
        c, _ = self.config()
        with patch.object(clash_api, 'proxies', side_effect=[{'proxy_main': {'now': 'a'}},
                {'proxy_main': {'now': 'a'}}, {'proxy_main': {'now': 'a'}}]), \
                patch.object(clash_api.urllib.request, 'build_opener') as opener:
            with self.assertRaises(ValueError):
                clash_api.select(c, 'proxy_main', 'b', ['proxy_main'])
            calls = opener.return_value.open.call_args_list
            self.assertEqual(len(calls), 2)
            self.assertTrue(all(call.args[0].full_url.endswith('/proxies/proxy_main') for call in calls))
            self.assertIn(b'"name": "b"', calls[0].args[0].data)
            self.assertIn(b'"name": "a"', calls[1].args[0].data)
            self.assertIsNone(calls[0].args[0].get_header('Authorization'))
        with patch.object(clash_api, 'proxies') as inspect:
            with self.assertRaises(ValueError):
                clash_api.select(c, 'proxy_main', 'b', [])
            inspect.assert_not_called()
