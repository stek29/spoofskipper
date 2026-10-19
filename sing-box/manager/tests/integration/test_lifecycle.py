"""Real manager subprocesses against local subscription/API fault fixtures."""
import http.server
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

MANAGER = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(MANAGER))
from spoofskipper_manager import compiler
from spoofskipper_manager.state import write_json

FIXTURES = MANAGER / 'tests/fixtures'


def wait_for(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError('condition timed out')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@unittest.skipUnless(shutil.which('jsonnet'), 'requires jsonnet (or run Compose harness)')
class LifecycleTests(unittest.TestCase):
    core = str(FIXTURES / 'fake-core.py')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config, self.state = self.root / 'config', self.root / 'data'
        shutil.copytree(FIXTURES, self.config)
        self.requests = 0
        self.mode = 'ok'
        owner = self
        class Subscription(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests += 1
                if owner.mode == 'stall':
                    time.sleep(20)
                    return
                code = 500 if owner.mode == 'outage' or (self.path == '/missing' and owner.mode != 'added') else 200
                self.send_response(code)
                self.end_headers()
                self.wfile.write(b'trojan://secret@127.0.0.1:1#one' if owner.mode != 'empty' else b'')
            def log_message(self, *_):
                pass
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Subscription)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)
        self.specs = {'subscriptions': [{'prefix': 'example', 'url': self.url + '/ok',
                      'tag_template': '{prefix}_{name}', 'group_template': '{prefix}'}]}
        write_json(self.config / 'local-subs-config.json', self.specs)
        self.settings = {'refresh_seconds': .5, 'revision_timeout': .6, 'shutdown_timeout': 1,
                         'bootstrap_backoff_seconds': .1, 'bootstrap_backoff_max_seconds': .2}
        write_json(self.config / 'local-manager.json', self.settings)
        source = (self.config / 'config.jsonnet').read_text()
        self.source = compiler.edited_source(source).replace('19090', str(free_port()))
        (self.config / 'config.jsonnet').write_text(self.source)
        # Deliberately stale: no outbound with this tag may appear in a render.
        write_json(self.config / 'local-subs.json', {'outbounds': [{'type': 'direct', 'tag': 'stale'}], 'groups': {}})
        self.output = self.root / 'manager.log'
        self.proc = None

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        if hasattr(self, 'stream'):
            self.stream.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def start(self):
        self.stream = self.output.open('a')
        self.proc = subprocess.Popen([sys.executable, '-m', 'spoofskipper_manager', 'serve',
            '--config-dir', str(self.config), '--state-dir', str(self.state), '--core', self.core],
            env={**os.environ, 'PYTHONPATH': str(MANAGER)}, stdout=self.stream, stderr=self.stream)

    def logs(self):
        return self.output.read_text() if self.output.exists() else ''

    def live(self):
        return json.loads((self.state / 'sing.json').read_text())

    def ready(self):
        wait_for(lambda: 'activation_succeeded' in self.logs())

    def test_partial_first_start_guarded_addition_outage_and_noop_age(self):
        self.specs['subscriptions'].append({**self.specs['subscriptions'][0], 'prefix': 'later', 'url': self.url + '/missing'})
        write_json(self.config / 'local-subs-config.json', self.specs)
        self.start()
        self.ready()
        self.assertNotIn('stale', json.dumps(self.live()))
        self.assertNotIn('later_one', json.dumps(self.live()))
        wait_for(lambda: 'activation_unchanged' in self.logs())
        snapshots = list((self.state / 'providers').glob('*.json'))
        before = json.loads(snapshots[0].read_text())['fetched_at']
        wait_for(lambda: json.loads(snapshots[0].read_text())['fetched_at'] > before)
        self.mode = 'added'
        wait_for(lambda: 'later_one' in (self.state / 'sing.json').read_text())
        self.mode = 'outage'
        wait_for(lambda: 'provider_refresh_failed' in self.logs())
        self.assertIsNone(self.proc.poll())
        self.assertNotIn('secret@', self.logs())

    def test_zero_bootstrap_then_runtime_failure_retries_without_fetch(self):
        self.mode = 'empty'
        (self.config / 'config.jsonnet').write_text(self.source.rstrip() + ' + {runtime_fail: true}\n')
        self.start()
        wait_for(lambda: 'bootstrap_waiting_for_providers' in self.logs())
        self.assertFalse((self.state / 'sing.json').exists())
        self.mode = 'ok'
        wait_for(lambda: self.logs().count('activation_failed') >= 2)
        count = self.requests
        time.sleep(.5)
        self.assertEqual(self.requests, count)
        (self.config / 'config.jsonnet').write_text(self.source)
        self.ready()
        self.assertIsNone(self.proc.poll())

    def test_runtime_failure_and_hup_validation_rejection_rollback(self):
        self.start()
        self.ready()
        old = self.live()
        for fault in ('runtime_fail', 'hup_reject'):
            before = self.logs().count('rollback_succeeded')
            (self.config / 'config.jsonnet').write_text(self.source.rstrip() + ' + {' + fault + ': true}\n')
            self.proc.send_signal(signal.SIGHUP)
            wait_for(lambda: self.logs().count('rollback_succeeded') > before)
            self.assertEqual(self.live(), old)
            self.assertFalse((self.state / 'activating').exists())
        self.assertIsNone(self.proc.poll())

    def test_saved_first_marker_restore_secret_rotation_and_signals(self):
        self.start()
        self.ready()
        before = self.live()
        self.proc.send_signal(signal.SIGINT)
        self.assertEqual(self.proc.wait(timeout=4), 0)
        self.stream.close()
        write_json(self.state / 'sing.prev.json', before)
        write_json(self.state / 'sing.json', {'bad': 'interrupted'})
        (self.state / 'activating').write_text('activating')
        (self.config / 'config.jsonnet').write_text(self.source.replace('synthetic-test-secret', 'rotated-test-secret'))
        self.start()
        wait_for(lambda: 'saved_config_started' in self.logs())
        wait_for(lambda: self.live()['experimental']['clash_api']['secret'] == 'rotated-test-secret')
        self.assertNotEqual(compiler.revision(self.live()), compiler.revision(before))
        wait_for(lambda: self.logs().count('provider_refreshed') >= 2)
        self.assertLess(self.logs().index('saved_config_started'), self.logs().rindex('provider_refreshed'))
        self.proc.terminate()
        self.assertEqual(self.proc.wait(timeout=4), 0)

    def test_unexpected_child_death_exits_nonzero(self):
        self.start()
        self.ready()
        starts = [json.loads(line) for line in self.logs().splitlines() if '"event": "core_started"' in line]
        os.kill(starts[-1]['pid'], signal.SIGKILL)
        self.assertEqual(self.proc.wait(timeout=4), 1)
        self.assertIn('unexpected_core_exit', self.logs())

    def test_bad_api_refused_without_starting(self):
        (self.config / 'config.jsonnet').write_text(self.source.replace("external_controller: '127.0.0.1:", "external_controller: '192.0.2.1:"))
        self.start()
        wait_for(lambda: 'refresh_failed' in self.logs())
        self.assertNotIn('core_started', self.logs())

    def test_term_interrupts_stalled_subscription_read(self):
        self.start()
        self.ready()
        count = self.requests
        self.mode = 'stall'
        wait_for(lambda: self.requests > count)
        started = time.monotonic()
        self.proc.terminate()
        self.assertEqual(self.proc.wait(timeout=3), 0)
        self.assertLess(time.monotonic() - started, 2)

    def test_saved_first_survives_invalid_private_inputs(self):
        self.start()
        self.ready()
        saved = self.live()
        self.proc.terminate()
        self.assertEqual(self.proc.wait(timeout=4), 0)
        self.stream.close()
        write_json(self.config / 'local-manager.json', {'revision_timeout': -1})
        (self.config / 'local-subs-config.json').write_text('broken')
        self.start()
        wait_for(lambda: 'saved_config_started' in self.logs())
        wait_for(lambda: 'refresh_failed' in self.logs())
        self.assertIsNone(self.proc.poll())
        self.assertEqual(self.live(), saved)

    def test_unprotected_api_with_empty_or_missing_secret(self):
        (self.config / 'config.jsonnet').write_text(self.source.replace('synthetic-test-secret', ''))
        self.start()
        self.ready()
        before = self.logs().count('activation_succeeded')
        (self.config / 'config.jsonnet').write_text(self.source.replace(
            ", secret: 'synthetic-test-secret'", ''))
        self.proc.send_signal(signal.SIGHUP)
        wait_for(lambda: self.logs().count('activation_succeeded') > before)
        self.assertNotIn('secret', self.live()['experimental']['clash_api'])
        self.assertIsNone(self.proc.poll())
