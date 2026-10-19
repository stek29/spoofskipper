"""Pinned-core verification; exercised by the offline Compose harness."""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import test_lifecycle
from test_lifecycle import wait_for
from spoofskipper_manager import compiler
from spoofskipper_manager.state import write_json


@unittest.skipUnless(shutil.which('sing-box'), 'requires pinned sing-box (run Compose harness)')
class RealCoreTests(test_lifecycle.LifecycleTests):
    core = 'sing-box'

    # Fault-only fields are deliberately rejected by the real config decoder.
    def test_runtime_failure_and_hup_validation_rejection_rollback(self):
        self.start()
        self.ready()
        before = self.live()
        # A second inbound binding the API's occupied socket passes check but
        # fails at runtime, exercising real v1.14.3 HUP behavior.
        address = before['experimental']['clash_api']['external_controller']
        port = int(address.rsplit(':', 1)[1])
        fault = ' + {inbounds: [{type: "mixed", tag: "occupied", listen: "127.0.0.1", listen_port: %d}]}' % port
        (self.config / 'config.jsonnet').write_text(self.source.rstrip() + fault + '\n')
        self.proc.send_signal(signal.SIGHUP)
        wait_for(lambda: 'rollback_succeeded' in self.logs())
        self.assertEqual(self.live(), before)
        self.assertFalse((self.state / 'activating').exists())

    def test_zero_bootstrap_then_runtime_failure_retries_without_fetch(self):
        # Runtime failure retry is covered using the fault fixture; this uses an
        # occupied port to prove the real initial-start path as well.
        import socket
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            port = occupied.getsockname()[1]
            fault = ' + {inbounds: [{type: "mixed", tag: "occupied", listen: "127.0.0.1", listen_port: %d}]}' % port
            (self.config / 'config.jsonnet').write_text(self.source.rstrip() + fault + '\n')
            self.start()
            wait_for(lambda: self.logs().count('activation_failed') >= 2)
            count = self.requests
            import time
            time.sleep(.4)
            self.assertEqual(self.requests, count)
            (self.config / 'config.jsonnet').write_text(self.source)
            self.ready()

    def test_diagnostics_are_scratch_only_and_diff_is_revision_only(self):
        # Legacy baseline uses identical fixture data; dry-run owns scratch only.
        private = self.config / 'config.jsonnet'
        private.write_text(self.source.replace(compiler.EXTVAR_LINE, compiler.IMPORT_LINE))
        snapshot = {'outbounds': [{'type': 'trojan', 'tag': 'example_one', 'server': '127.0.0.1',
                                  'server_port': 1, 'password': 'secret'}], 'groups': {'example': ['example_one']}}
        write_json(self.config / 'local-subs.json', snapshot)
        cache = self.state / 'cache.db'
        self.state.mkdir()
        cache.write_bytes(b'live-cache-sentinel')
        before = {p.name: p.read_bytes() for p in self.config.iterdir() if p.is_file()}
        def run(command, state, extra=()):
            return subprocess.run([sys.executable, '-m', 'spoofskipper_manager', command,
                '--config-dir', str(self.config), '--state-dir', str(state), '--core', self.core, *extra],
                env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[2])}, capture_output=True)
        scratch = self.root / 'dry-run'
        result = run('refresh-dry-run', scratch)
        self.assertEqual(result.returncode, 0, result.stdout)
        compare = self.root / 'compare'
        result = run('render-check', compare, ['--snapshots', str(scratch)])
        self.assertEqual(result.returncode, 0, result.stdout)
        diff = (compare / 'render.diff').read_text()
        self.assertIn(compiler.REVISION_PREFIX, diff)
        self.assertNotIn('example_one', '\n'.join(line for line in diff.splitlines() if line.startswith(('+', '-'))))
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.config.iterdir() if p.is_file()})
        self.assertEqual(cache.read_bytes(), b'live-cache-sentinel')
        self.assertFalse((self.state / 'sing.json').exists())
        private.write_text('local changed = true;\n' + private.read_text().replace(compiler.IMPORT_LINE, 'local sub_data = {};'))
        result = run('render-check', self.root / 'bad-compare', ['--snapshots', str(scratch)])
        self.assertNotEqual(result.returncode, 0)
