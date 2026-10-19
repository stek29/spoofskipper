#!/usr/bin/env python3
"""Local lifecycle fault fixture. No external connections."""
import http.server
import json
import signal
import sys
from pathlib import Path

path = Path(sys.argv[sys.argv.index('-c') + 1])
config = json.loads(path.read_text())
if sys.argv[1] == 'check':
    raise SystemExit(1 if config.get('check_fail') else 0)
if config.get('runtime_fail'):
    raise SystemExit(2)


def reload(*_):
    global config
    new = json.loads(path.read_text())
    if new.get('hup_reject'):
        return
    if new.get('runtime_fail'):
        raise SystemExit(2)
    config = new


signal.signal(signal.SIGHUP, reload)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        secret = config['experimental']['clash_api'].get('secret', '')
        if secret and self.headers.get('Authorization') != 'Bearer ' + secret:
            self.send_response(401)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({'proxies': {o['tag']: {} for o in config['outbounds']}}).encode())

    def log_message(self, *_):
        pass


http.server.HTTPServer.allow_reuse_address = True
address = config['experimental']['clash_api']['external_controller'].rsplit(':', 1)
http.server.HTTPServer((address[0], int(address[1])), Handler).serve_forever()
