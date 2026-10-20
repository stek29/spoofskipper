"""Offline test-CA HTTPS faults through the pinned core and real protocol servers."""
import base64
import http.server
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from test_lifecycle import free_port, wait_for, FIXTURES
from spoofskipper_manager import compiler, clash_api
from spoofskipper_manager.probes import ProbeClient, THROTTLE, SKIP, TOTAL


@unittest.skipUnless(shutil.which('sing-box'), 'requires offline Compose pinned core')
class ProbeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.mode, self.served = 'ok', 0
        owner = self
        class Endpoint(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_):
                pass
            def do_GET(self):
                if owner.mode == 'slow_headers':
                    try:
                        self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Test: ')
                        for _ in range(20):
                            time.sleep(.05)
                            self.wfile.write(b'x')
                    except OSError:
                        pass
                    return
                size = int(parse_qs(urlsplit(self.path).query)['bytes'][0])
                chunked = owner.mode.startswith('chunked') or owner.mode == 'ambiguous_framing'
                if owner.mode == 'chunked_oversize':
                    size += 1
                self.send_response(200)
                if chunked:
                    self.send_header('Transfer-Encoding', 'chunked')
                if not chunked or owner.mode == 'ambiguous_framing':
                    self.send_header('Content-Length', str(size))
                if owner.mode == 'keepalive':
                    self.send_header('Connection', 'keep-alive')
                    self.close_connection = False
                self.send_header('Server-Timing', 'first;dur=1')
                self.send_header('Server-Timing', 'second;dur=2')
                if owner.mode == 'duplicate_length':
                    self.send_header('Content-Length', str(size))
                if owner.mode == 'encoded':
                    self.send_header('Content-Encoding', 'gzip')
                self.end_headers()
                try:
                    for offset in range(0, size, 16384):
                        if owner.mode == 'stall' or (owner.mode == 'freeze' and offset >= 16384):
                            time.sleep(.6)
                            return
                        if owner.mode == 'truncate' and offset >= 16384:
                            return
                        if owner.mode == 'slow':
                            time.sleep(.005)
                        data = b'x' * min(16384, size-offset)
                        self.wfile.write(f'{len(data):x}\r\n'.encode()+data+b'\r\n' if chunked else data)
                        self.wfile.flush()
                        owner.served += len(data)
                    if chunked and owner.mode != 'chunked_truncate':
                        self.wfile.write(b'0\r\n\r\n')
                except (OSError, ssl.SSLError):
                    pass
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Endpoint)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(FIXTURES/'probe-ca.pem', FIXTURES/'probe-key.pem')
        context.set_ecdh_curve('X25519')
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.processes, self.streams = [], []
        self.port = free_port()
        self.settings = {'probe_port': self.port, 'probe_timeout': .45, 'probe_stall_timeout': .15,
                         'throughput_seconds': 2, 'probe_ca_bundle': str(FIXTURES/'probe-ca.pem'),
                         'probe_url': f'https://localhost:{self.server.server_port}/__down?bytes={{bytes}}'}
        relay_port = free_port()
        self.core({'log': {'disabled': True}, 'inbounds': [{'type': 'socks',
            'listen': '127.0.0.1', 'listen_port': relay_port}],
            'outbounds': [{'type': 'direct', 'tag': 'egress'}]})
        def relay_ready():
            try:
                socket.create_connection(('127.0.0.1', relay_port), timeout=.1).close()
                return True
            except OSError:
                return False
        wait_for(relay_ready)
        self.outbound = {'type': 'socks', 'tag': 'candidate', 'server': '127.0.0.1',
                         'server_port': relay_port}
        self.config = {'log': {'disabled': True}, 'outbounds': [self.outbound],
            'experimental': {'clash_api': {'external_controller': '127.0.0.1:'+str(free_port())}}}
        self.start_client([self.outbound])

    def tearDown(self):
        for proc in reversed(self.processes):
            proc.terminate()
            proc.wait(timeout=3)
        for stream in self.streams:
            stream.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def core(self, config):
        path = self.root / ('core'+str(len(self.processes))+'.json')
        path.write_text(json.dumps(config))
        check = subprocess.run(['sing-box', 'check', '-c', str(path)], capture_output=True)
        self.assertEqual(check.returncode, 0, check.stderr.decode())
        stream = (self.root/(path.stem+'.log')).open('w')
        self.streams.append(stream)
        proc = subprocess.Popen(['sing-box', 'run', '-c', str(path)], stdout=stream, stderr=stream)
        self.processes.append(proc)
        return proc

    def start_client(self, outbounds):
        self.config['outbounds'] = outbounds
        compiler.add_probe_routes(self.config, {'probes_enabled': True, 'probe_port': self.port},
                                  [{'outbound': o} for o in outbounds])
        self.core(self.config)
        def ready():
            try:
                clash_api.proxies(self.config)
                return True
            except OSError:
                return False
        wait_for(ready)
        self.client = ProbeClient(self.settings)

    def test_exact_gate_and_throttle_bodies(self):
        self.assertTrue(self.client.run(self.outbound, 'gate').ok)
        result = self.client.run(self.outbound, 'throttle')
        self.assertTrue(result.ok, result)
        self.assertEqual(result.bytes, THROTTLE)
        self.assertIsNotNone(result.burst_seconds)
        self.assertEqual(self.served, 1+THROTTLE)

    def test_generic_static_socks_chain_tracks_arbitrary_selector(self):
        from spoofskipper_manager.scheduler import Scheduler
        from spoofskipper_manager.identity import sample_key
        chained = {**self.outbound, 'tag': 'double-hop', 'detour': 'hop'}
        blocked = {**self.outbound, 'tag': 'offline', 'server_port': free_port()}
        config = {'log': {'disabled': True}, 'outbounds': [self.outbound, blocked,
            {'type': 'selector', 'tag': 'hop', 'outbounds': ['candidate', 'offline']}, chained],
            'experimental': {'clash_api': {'external_controller': '127.0.0.1:'+str(free_port())}}}
        settings = {**self.settings, 'probe_port': free_port(), 'probes_enabled': True}
        compiler.add_probe_routes(config, settings, [])
        self.core(config)
        def ready():
            try:
                return bool(clash_api.proxies(config))
            except OSError:
                return False
        wait_for(ready)
        scheduler = Scheduler(lambda *args, **kw: None)
        scheduler.configure(config, [], settings)
        key = sample_key(chained)
        try:
            scheduler.controller.inspect()
            result = scheduler.perform(scheduler.client, scheduler.candidates[key], 'throttle')
            self.assertTrue(result.ok, result)
            scheduler.accept(key, result, time.monotonic())
            self.assertTrue(scheduler.samples[key].healthy)
            clash_api.select(config, 'hop', 'offline', ['hop'])
            scheduler.controller.inspect()
            self.assertIsNone(scheduler.samples[key].healthy)
            result = scheduler.perform(scheduler.client, scheduler.candidates[key], 'gate')
            self.assertFalse(result.ok)
            clash_api.select(config, 'hop', 'candidate', ['hop'])
            scheduler.controller.inspect()
            self.assertTrue(scheduler.client.run(chained, 'gate').ok)
        finally:
            scheduler.close()

    def test_throttled_path_fails_and_only_a_threshold_probe_restores_it(self):
        from spoofskipper_manager.scheduler import Scheduler
        from spoofskipper_manager.identity import sample_key
        scheduler = Scheduler(lambda *args, **kw: None)
        scheduler.configure(self.config, [{'provider': 'p', 'weight': 1, 'outbound': self.outbound}],
                            {**self.settings, 'probes_enabled': True})
        key = sample_key(self.outbound)
        sample = scheduler.samples[key]
        try:
            self.mode = 'ok'
            scheduler.accept(key, self.client.run(self.outbound, 'throttle'), time.monotonic())
            self.assertTrue(sample.healthy)
            self.mode = 'freeze'  # Small responses pass; the body stalls after 16 KiB.
            scheduler.accept(key, self.client.run(self.outbound, 'throttle'), time.monotonic())
            self.assertEqual(sample.confirm, 'throttle')
            scheduler.accept(key, self.client.run(self.outbound, 'throttle'), time.monotonic())
            self.assertFalse(sample.healthy)
            result = self.client.run(self.outbound, 'gate')
            self.assertTrue(result.ok)
            scheduler.accept(key, result, time.monotonic())
            self.assertFalse(sample.healthy)
            self.mode = 'ok'
            scheduler.accept(key, self.client.run(self.outbound, 'throttle'), time.monotonic())
            self.assertTrue(sample.healthy)
        finally:
            scheduler.close()

    def test_freeze_truncation_slow_completion_and_throughput_early_stop(self):
        for mode in ('freeze', 'truncate'):
            self.mode = mode
            result = self.client.run(self.outbound, 'throttle')
            self.assertFalse(result.ok, result)
            self.assertEqual(result.bytes, 16384)
            self.assertIsNotNone(result.burst_seconds)
        self.mode = 'slow'
        result = self.client.run(self.outbound, 'throttle')
        self.assertTrue(result.ok, result)
        self.mode = 'ok'
        before = self.served
        result = self.client.run(self.outbound, 'throughput')
        self.assertTrue(result.ok, result)
        self.assertTrue(result.early_stop)
        self.assertEqual(result.skipped, SKIP)
        self.assertGreater(result.mbps, 0)
        self.assertLessEqual(result.bytes, SKIP+4*1024*1024)
        # Served bytes can include kernel/TLS buffers after the intentional close.
        time.sleep(.05)
        self.assertLessEqual(self.served-before, TOTAL)
        self.assertGreaterEqual(self.served-before, result.bytes)

    def test_unknown_user_rejected_and_no_selector_writes(self):
        with socket.create_connection(('127.0.0.1', self.port)) as sock:
            sock.sendall(b'CONNECT localhost:443 HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Basic '+base64.b64encode(b'unknown:unknown')+b'\r\n\r\n')
            self.assertIn(b'407', sock.recv(100))
        self.assertEqual(self.served, 0)
        self.assertTrue(self.client.run(self.outbound, 'gate').ok)
        self.assertNotIn('selector', json.dumps(self.config))

    def test_protocol_attribution_and_stopped_candidate(self):
        # Each protocol has unique credentials and a separate inbound on the
        # same local provider core. Reality handshake stays in the isolated network.
        ports = {p: free_port() for p in ('trojan', 'shadowsocks', 'hysteria2', 'vless')}
        tls = {'enabled': True, 'certificate_path': str(FIXTURES/'probe-ca.pem'), 'key_path': str(FIXTURES/'probe-key.pem')}
        uuid = 'f65c7ac1-3439-4a68-91f7-6cfbe37cf2cf'
        inbounds = [
            {'type': 'trojan', 'tag': 'trojan', 'listen': '127.0.0.1', 'listen_port': ports['trojan'], 'users': [{'password': 'fixture'}], 'tls': tls},
            {'type': 'shadowsocks', 'tag': 'shadowsocks', 'listen': '127.0.0.1', 'listen_port': ports['shadowsocks'], 'method': 'aes-128-gcm', 'password': 'fixture'},
            {'type': 'hysteria2', 'tag': 'hysteria2', 'listen': '127.0.0.1', 'listen_port': ports['hysteria2'], 'users': [{'password': 'fixture'}], 'tls': tls},
            {'type': 'vless', 'tag': 'vless', 'listen': '127.0.0.1', 'listen_port': ports['vless'], 'users': [{'uuid': uuid}],
             'tls': {'enabled': True, 'server_name': 'localhost', 'reality': {'enabled': True, 'handshake': {'server': '127.0.0.1', 'server_port': self.server.server_port},
                     'private_key': 'QGOkYe6ebZA51XDunRZfl8bGmoVBfZLxvOAUBGrmHEs', 'short_id': ['0123456789abcdef']}}}]
        provider = self.core({'log': {'level': 'debug'}, 'inbounds': inbounds, 'outbounds': [{'type': 'direct', 'tag': 'direct'}]})
        time.sleep(.2)
        self.assertIsNone(provider.poll())
        outbounds = []
        for protocol, port in ports.items():
            outbound = {'type': protocol, 'tag': protocol, 'server': '127.0.0.1', 'server_port': port}
            if protocol == 'shadowsocks':
                outbound.update(method='aes-128-gcm', password='fixture')
            elif protocol == 'vless':
                outbound.update(uuid=uuid, tls={'enabled': True, 'server_name': 'localhost', 'utls': {'enabled': True, 'fingerprint': 'chrome'},
                    'reality': {'enabled': True, 'public_key': 'taJXoFcFk_sXboeBvo9T7QyCn0kBmbg09MnmzIs2LQQ', 'short_id': '0123456789abcdef'}})
            else:
                outbound.update(password='fixture', tls={'enabled': True, 'server_name': 'localhost', 'certificate_path': str(FIXTURES/'probe-ca.pem')})
            outbounds.append(outbound)
        self.port = free_port()
        self.settings.update(probe_port=self.port, probe_timeout=5)
        self.config.pop('inbounds')
        self.config['route'] = {}
        self.config['experimental']['clash_api']['external_controller'] = '127.0.0.1:'+str(free_port())
        self.start_client(outbounds)
        for outbound in outbounds:
            with self.subTest(protocol=outbound['type']):
                result = self.client.run(outbound, 'gate')
                self.assertTrue(result.ok, (result, [p.read_text() for p in self.root.glob('*.log')]))
        provider.terminate()
        provider.wait(timeout=3)
        self.assertFalse(self.client.run(outbounds[0], 'gate').ok)

    def test_scheduler_reload_retention_observation_and_cancellation(self):
        from spoofskipper_manager.scheduler import Scheduler
        from spoofskipper_manager.identity import sample_key
        # A scratch selector makes the absence of writes observable in the API.
        self.port = free_port()
        self.settings.update(probe_port=self.port, probes_enabled=True,
            gate_active_seconds=.1, gate_standby_seconds=.1, throttle_seconds=.15,
            throughput_active_seconds=.2, throughput_shortlist_seconds=.2)
        self.config.pop('inbounds')
        self.config['route'] = {}
        self.config['experimental']['clash_api']['external_controller'] = '127.0.0.1:'+str(free_port())
        self.start_client([self.outbound, {'type': 'selector', 'tag': 'proxy_main', 'outbounds': ['candidate']}])
        events = []
        scheduler = Scheduler(lambda event, **kw: events.append((event, kw)))
        candidate = {'provider': 'p', 'weight': 1, 'outbound': self.outbound}
        scheduler.configure(self.config, [candidate], self.settings)
        before = clash_api.proxies(self.config)['proxy_main']['now']
        try:
            until = time.monotonic()+4
            key = sample_key(self.outbound)
            while not scheduler.samples[key].successes and time.monotonic() < until:
                scheduler.tick()
                time.sleep(.02)
            self.assertTrue(scheduler.samples[key].successes, events)
            retained = scheduler.samples[key]
            scheduler.configure(self.config, [candidate], self.settings)
            self.assertIs(scheduler.samples[key], retained)
            self.assertEqual(clash_api.proxies(self.config)['proxy_main']['now'], before)
            self.mode = 'freeze'
            future = scheduler.pool.submit(scheduler.client.run, self.outbound, 'throttle')
            time.sleep(.05)
            start = time.monotonic()
            scheduler.close()
            self.assertLess(time.monotonic()-start, .5)
            self.assertFalse(future.result().ok)
        finally:
            scheduler.close()


    def test_framing_stall_and_ca_validation(self):
        for mode in ('encoded', 'stall', 'slow_headers'):
            self.mode = mode
            result = self.client.run(self.outbound, 'gate')
            self.assertFalse(result.ok, (mode, result))
            self.assertEqual(result.bytes, 0)
        # Redundant framing headers do not distort the body; http.client resolves them.
        for mode in ('duplicate_length', 'ambiguous_framing'):
            self.mode = mode
            result = self.client.run(self.outbound, 'gate')
            self.assertTrue(result.ok, (mode, result))
            self.assertEqual(result.bytes, 1)
        self.mode = 'ok'
        settings = dict(self.settings)
        del settings['probe_ca_bundle']
        result = ProbeClient(settings).run(self.outbound, 'gate')
        self.assertFalse(result.ok)
        self.assertEqual(result.error, 'SSLCertVerificationError')


    def test_slow_throughput_with_insufficient_prefix_is_unknown(self):
        self.mode = 'slow'
        self.client.settings = self.client.settings.with_changes(throughput_seconds=.08)
        result = self.client.run(self.outbound, 'throughput')
        self.assertTrue(result.ok, result)
        self.assertTrue(result.early_stop)
        self.assertLess(result.bytes, SKIP)
        self.assertIsNone(result.mbps)


    def test_stdlib_chunked_framing_and_keepalive(self):
        for mode in ('chunked', 'keepalive'):
            self.mode = mode
            for kind, size in (('gate', 1), ('throttle', THROTTLE)):
                result = self.client.run(self.outbound, kind)
                self.assertTrue(result.ok, (mode, result))
                self.assertEqual(result.bytes, size)
        for mode in ('chunked_truncate', 'chunked_oversize'):
            self.mode = mode
            result = self.client.run(self.outbound, 'gate')
            self.assertFalse(result.ok, (mode, result))

    def test_cancel_during_tls_handshake(self):
        from concurrent.futures import ThreadPoolExecutor
        release, accepted = threading.Event(), threading.Event()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            def stalled_tls():
                with listener.accept()[0]:
                    accepted.set()
                    release.wait(3)
            thread = threading.Thread(target=stalled_tls, daemon=True)
            thread.start()
            client = ProbeClient({**self.settings, 'probe_timeout': 15,
                'probe_url': f'https://localhost:{listener.getsockname()[1]}/?bytes={{bytes}}'})
            try:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(client.run, self.outbound, 'gate')
                    self.assertTrue(accepted.wait(2))
                    started = time.monotonic()
                    client.cancel()
                    self.assertFalse(future.result(timeout=1).ok)
                    self.assertLess(time.monotonic()-started, .5)
            finally:
                release.set()
                thread.join(2)
