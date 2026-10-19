import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager import compiler, clash_api
from spoofskipper_manager.service import Manager, load_settings
from spoofskipper_manager.state import write_json


def config():
    return {'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'experimental': {
        'clash_api': {'external_controller': '[::]:9090', 'secret': 'private'}}}


class CompilerTests(unittest.TestCase):
    def test_api_validation(self):
        self.assertEqual(clash_api.credentials(config()), ('http://[::1]:9090', 'private'))
        for address in ('192.0.2.1:9090', ':9090', 'localhost:no', '127.0.0.1:0'):
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

    def test_graph_validation(self):
        for outbounds in ([{'tag': 'x', 'type': 'selector', 'outbounds': ['x']}],
                          [{'tag': 'x', 'type': 'selector', 'outbounds': ['missing']}],
                          [{'tag': 'x', 'type': 'selector', 'outbounds': []}],
                          [{'tag': 'x', 'type': 'direct', 'detour': 'y'}, {'tag': 'y', 'type': 'direct', 'detour': 'x'}]):
            c = config()
            c['outbounds'] = outbounds
            with self.assertRaises(ValueError):
                compiler.validate(c)

    def test_edit_is_exact(self):
        self.assertEqual(compiler.edited_source(compiler.IMPORT_LINE), compiler.EXTVAR_LINE)
        for source in ('local x = 1;', compiler.IMPORT_LINE + '\n' + compiler.IMPORT_LINE):
            with self.assertRaises(ValueError):
                compiler.edited_source(source)

    def test_revision_changes_with_same_tag_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            c = config()
            (Path(temp) / 'config.jsonnet').write_text(compiler.EXTVAR_LINE)
            def render(c):
                with patch.object(compiler.subprocess, 'run', return_value=type('Result', (), {
                        'returncode': 0, 'stdout': json.dumps(c)})()):
                    return compiler.render(Path(temp) / 'sing.jsonnet', {}, temp)
            first = render(c)
            self.assertEqual(first, render(c))
            c['experimental']['clash_api']['secret'] = 'rotated'
            self.assertNotEqual(compiler.revision(first), compiler.revision(render(c)))
            self.assertEqual([p.name for p in Path(temp).iterdir()], ['config.jsonnet'])

    def test_settings_stage1_guards(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertFalse(load_settings(temp).get('probes_enabled', False))
            for data in ({'probes_enabled': True}, {'managed_selectors': ['proxy_main']},
                         {'provider_weights': {'a': -1}}, {'revision_timeout': 0}):
                write_json(Path(temp) / 'local-manager.json', data)
                with self.assertRaises(ValueError):
                    load_settings(temp)

    def test_activation_rollback_once_and_noop_checked(self):
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
                self.assertEqual(check.call_count, 2)

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

    def test_term_interrupts_pending_fetch(self):
        import signal
        from spoofskipper_manager.service import Stopping
        with tempfile.TemporaryDirectory() as temp:
            m = Manager(temp, Path(temp) / 'state')
            with self.assertRaises(Stopping):
                m.signal(signal.SIGTERM, None)
            self.assertEqual(m.stopping, signal.SIGTERM)

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

    def test_optional_api_authorization_header(self):
        from unittest.mock import MagicMock
        for secret in ('', 'private'):
            c = config()
            c['experimental']['clash_api']['secret'] = secret
            response = MagicMock()
            response.__enter__.return_value.read.return_value = '{"proxies":{"revision":{}}}'
            opener = MagicMock()
            opener.open.return_value = response
            with patch.object(clash_api.urllib.request, 'build_opener', return_value=opener):
                self.assertTrue(clash_api.revision_present(c, 'revision'))
            request = opener.open.call_args.args[0]
            self.assertEqual(request.get_header('Authorization'), 'Bearer private' if secret else None)
