import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'manager'))
from spoofskipper_manager import parser, subscriptions as subs


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
        ticks = []
        with patch.object(parser, 'fetch_url', fetch):
            pending = first.refresh(lambda: ticks.append(1))
        self.assertEqual(list(pending), ['a'])
        self.assertEqual(len(ticks), 2)  # Probing continues after each provider.
        self.assertFalse(first.path('a').exists())
        first.commit(pending)
        old_age = pending['a']['fetched_at']
        second = self.providers()
        self.assertEqual(first.merged(pending), second.merged(second.snapshots))
        with patch.object(parser, 'fetch_url', return_value='trojan://secret@localhost:443#one'):
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
        with patch.object(parser, 'fetch_url', return_value='trojan://secret@localhost:443#one'):
            p.commit(p.refresh())
        for body in ('', 'garbage', 'vless://bad@:nonnumeric'):
            with patch.object(parser, 'fetch_url', return_value=body):
                self.assertEqual(p.refresh(), p.snapshots)

    def test_parser_output_matches_golden_all_protocols(self):
        golden = json.loads((ROOT / 'manager/tests/fixtures/parser-golden.json').read_text())
        body = golden['body']
        for encoded in (body, base64.b64encode(body.encode()).decode()):
            with patch.object(parser, 'fetch_url', return_value=encoded):
                actual = parser.apply_outbound_settings(parser.render_subscription(golden['spec']),
                                                        {'connect_timeout': '5s'}, {})
            self.assertEqual(actual, golden['output'])

    def test_sing_subs_cli_uses_shared_parser(self):
        import subprocess
        golden = json.loads((ROOT / 'manager/tests/fixtures/parser-golden.json').read_text())
        specs = self.root / 'specs.json'
        # Serve the body from a file URL so the CLI runs without network access.
        source = self.root / 'body.txt'
        source.write_text(golden['body'])
        golden['spec']['url'] = source.as_uri()
        specs.write_text(json.dumps({'subscriptions': [golden['spec']],
                                     'outbound_settings': {'global': {'connect_timeout': '5s'}}}))
        result = subprocess.run([sys.executable, str(ROOT.parent / 'sing-subs/merge-subs.py'), str(specs)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), golden['output'])

    def test_fetch_is_bounded(self):
        class Response:
            def __init__(self, chunks):
                self.chunks = iter(chunks)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read1(self, size):
                return next(self.chunks, b'')
        big = [b'x' * 65536] * (parser.MAX_BODY_BYTES // 65536 + 1)
        with patch.object(parser.urllib.request, 'urlopen', return_value=Response(big)):
            with self.assertRaises(ValueError):
                parser.fetch_url('https://invalid.test/')
        clock = iter([0, parser.FETCH_DEADLINE_SECONDS + 1])
        with patch.object(parser.urllib.request, 'urlopen', return_value=Response([b'a', b'b'])), \
             patch.object(parser.time, 'monotonic', lambda: next(clock)):
            with self.assertRaises(TimeoutError):
                parser.fetch_url('https://invalid.test/')
        with patch.object(parser.urllib.request, 'urlopen', return_value=Response([b' ok\n'])):
            self.assertEqual(parser.fetch_url('https://invalid.test/'), 'ok')

    def test_conflict_and_unique_prefix(self):
        with self.assertRaises(ValueError):
            parser.merge_outputs([{'outbounds': [{'tag': 'a', 'type': 'direct'}]},
                                {'outbounds': [{'tag': 'a', 'type': 'block'}]}])
        self.specs['subscriptions'][1]['prefix'] = 'a'
        (self.config / 'local-subs-config.json').write_text(json.dumps(self.specs))
        with self.assertRaises(ValueError):
            self.providers()

    def test_bootstrap_seeds_all_providers_or_nothing(self):
        log = lambda event, **fields: self.events.append((event, fields))
        with patch.object(parser, 'fetch_url', lambda url: 1/0 if url.endswith('b') else 'trojan://s@localhost:443#one'):
            self.assertEqual(subs.bootstrap(self.config, self.state, log), 1)
        self.assertFalse((self.state / 'providers').exists())  # A partial seed would drop provider b.
        self.assertEqual(self.events[-1], ('bootstrap_failed', {'missing': ['b']}))
        with patch.object(parser, 'fetch_url', return_value='trojan://s@localhost:443#one'):
            self.assertEqual(subs.bootstrap(self.config, self.state, log), 0)
        self.assertEqual(set(self.providers().snapshots), {'a', 'b'})

    def test_default_interface_from_main_route_table(self):
        table = self.root / 'route'
        table.write_text('Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n'
                         'eth0\t0037A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n'
                         'eth0\t00000000\t0237A8C0\t0003\t0\t0\t0\t00000000\n')
        self.assertEqual(subs.default_interface(table), 'eth0')
        table.write_text('Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n')
        self.assertIsNone(subs.default_interface(table))  # Internal network: no binding.
        self.assertIsNone(subs.default_interface(self.root / 'missing'))

    def test_bound_fetch_binds_every_socket(self):
        import http.server, threading
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'trojan://s@localhost:443#one')
            def log_message(self, *_):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        bound = []
        with patch.object(parser, 'BIND_INTERFACE', 'lo'), \
                patch.object(parser, '_bind', bound.append), \
                patch.object(parser.urllib.request, 'urlopen', side_effect=AssertionError('unbound')):
            body = parser.fetch_url(f'http://127.0.0.1:{server.server_port}/')
        self.assertEqual(body, 'trojan://s@localhost:443#one')
        self.assertEqual(bound, [])  # Loopback stays unbound; it is not behind eth0.
        sockets = []
        class Socket:
            def __init__(self, *args):
                sockets.append(self)
            settimeout = connect = lambda self, *args: None
        remote = [(2, 1, 6, '', ('192.0.2.1', 443))]
        with patch.object(parser, 'BIND_INTERFACE', 'eth0'), patch.object(parser, '_bind', bound.append), \
                patch.object(parser.socket, 'getaddrinfo', return_value=remote), \
                patch.object(parser.socket, 'socket', Socket):
            self.assertIs(parser._create_connection(('example.test', 443), 5), sockets[0])
        self.assertEqual(bound, sockets)
