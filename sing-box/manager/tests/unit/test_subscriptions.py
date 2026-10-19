import base64
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'manager'))
from spoofskipper_manager import subscriptions as subs


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / 'config'
        self.config.mkdir()
        self.state = self.root / 'state'
        self.specs = {'subscriptions': [{'prefix': p, 'url': 'https://invalid.test/' + p,
                      'tag_template': '{prefix}_{name}', 'group_template': '{prefix}'} for p in ('a', 'b')]}
        (self.config / 'local-subs-config.json').write_text(json.dumps(self.specs))
        self.events = []

    def tearDown(self):
        self.temp.cleanup()

    def providers(self):
        return subs.Providers(self.config, self.state, {'provider_weights': {'a': 1.25}},
                              lambda event, **fields: self.events.append((event, fields)))

    def test_partial_cached_merge_addition_removal_noop_ages(self):
        def fetch(url):
            if url.endswith('b'):
                raise ValueError('private-url-do-not-log')
            return 'trojan://secret@localhost:443#one'
        first = self.providers()
        with patch.object(subs, 'fetch_url', fetch):
            pending = first.refresh()
        self.assertEqual(list(pending), ['a'])
        self.assertFalse(first.path('a').exists())
        first.commit(pending)
        old_age = pending['a']['fetched_at']
        second = self.providers()
        self.assertEqual(first.merged(pending), second.merged(second.snapshots))
        with patch.object(subs, 'fetch_url', return_value='trojan://secret@localhost:443#one'):
            updated = second.refresh()
        self.assertEqual(set(updated), {'a', 'b'})
        self.assertGreater(updated['a']['fetched_at'], old_age)
        self.assertEqual(second.candidates(updated)[0]['weight'], 1.25)
        self.assertNotIn('private-url', json.dumps(self.events))
        second.commit(updated)
        self.specs['subscriptions'].pop()
        (self.config / 'local-subs-config.json').write_text(json.dumps(self.specs))
        self.assertEqual(set(self.providers().snapshots), {'a'})

    def test_empty_and_malformed_keep_last_good(self):
        p = self.providers()
        with patch.object(subs, 'fetch_url', return_value='trojan://secret@localhost:443#one'):
            p.commit(p.refresh())
        for body in ('', 'garbage', 'vless://bad@:nonnumeric'):
            with patch.object(subs, 'fetch_url', return_value=body):
                self.assertEqual(p.refresh(), p.snapshots)

    def test_parser_byte_parity_all_protocols(self):
        legacy_root = ROOT.parent / 'sing-subs'
        parser = load('sub2outbounds', legacy_root / 'sub2outbounds.py')
        sys.modules['sub2outbounds'] = parser
        merge = load('legacy_merge', legacy_root / 'merge-subs.py')
        vmess = base64.b64encode(json.dumps({'add': 'localhost', 'port': '443', 'id': 'uuid', 'ps': 'vm'}).encode()).decode()
        body = '\n'.join(['vless://uuid@localhost:443?security=reality&pbk=public&sid=01#vl',
                         'trojan://secret@localhost:443?security=tls&type=ws&path=%2F#tr',
                         'ss://YWVzLTEyOC1nY206cGFzcw==@localhost:443#ss', 'vmess://' + vmess,
                         'hy2://pass@localhost:443?sni=example.test#hy',
                         'hysteria2://pass@localhost:443?obfs=salamander&obfs-password=x#hyb'])
        for encoded in (body, base64.b64encode(body.encode()).decode()):
            with patch.object(parser, 'fetch_url', return_value=encoded), patch.object(subs, 'fetch_url', return_value=encoded):
                spec = self.specs['subscriptions'][0]
                expected = merge.apply_outbound_settings(merge.render_subscription(spec), {'connect_timeout': '5s'}, {})
                actual = subs.apply_outbound_settings(subs.render_subscription(spec), {'connect_timeout': '5s'}, {})
                self.assertEqual(json.dumps(expected, ensure_ascii=False, indent=2), json.dumps(actual, ensure_ascii=False, indent=2))

    def test_conflict_and_unique_prefix(self):
        with self.assertRaises(SystemExit):
            subs.merge_outputs([{'outbounds': [{'tag': 'a', 'type': 'direct'}]},
                                {'outbounds': [{'tag': 'a', 'type': 'block'}]}])
        self.specs['subscriptions'][1]['prefix'] = 'a'
        (self.config / 'local-subs-config.json').write_text(json.dumps(self.specs))
        with self.assertRaises(ValueError):
            self.providers()
