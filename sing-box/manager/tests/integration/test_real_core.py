"""Pinned-core verification of what the fake core cannot show; run by the offline Compose harness."""
import shutil
import signal
import unittest

import test_lifecycle
from test_lifecycle import wait_for
from spoofskipper_manager import compiler
from spoofskipper_manager.state import write_json


@unittest.skipUnless(shutil.which('sing-box'), 'requires pinned sing-box (run Compose harness)')
class RealCoreTests(test_lifecycle.LifecycleHarness):
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

    def test_disable_probes_reload_preserves_refresh_owner_and_selectors(self):
        from test_lifecycle import free_port
        self.settings.update(probes_enabled=True, probe_port=free_port(), probe_timeout=.3,
                             gate_active_seconds=.2, gate_standby_seconds=.2)
        write_json(self.config / 'local-manager.json', self.settings)
        self.start()
        self.ready()
        # The harness has no egress: probes fail, then so does the direct uplink check.
        wait_for(lambda: 'uplink_down' in self.logs())
        pid = self.proc.pid
        first = self.live()
        selectors = [o for o in first['outbounds'] if o['type'] in ('selector', 'urltest')]
        self.assertTrue(any(i['tag'] == compiler.PROBE_TAG for i in first['inbounds']))
        before = self.requests
        self.settings['probes_enabled'] = False
        write_json(self.config / 'local-manager.json', self.settings)
        self.proc.send_signal(signal.SIGHUP)
        wait_for(lambda: not any(i.get('tag') == compiler.PROBE_TAG for i in self.live().get('inbounds', [])))
        self.assertEqual(pid, self.proc.pid)
        self.assertEqual(selectors, [o for o in self.live()['outbounds'] if o['type'] in ('selector', 'urltest')])
        wait_for(lambda: self.requests > before)
        self.assertIsNone(self.proc.poll())
