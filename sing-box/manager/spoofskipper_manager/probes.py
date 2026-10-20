"""Bounded HTTPS measurements using the standard-library CONNECT/HTTP client."""
import base64
from collections import Counter
import http.client
import io
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

GATE, THROTTLE, SKIP, TOTAL = 1, 256 * 1024, 512 * 1024, 8 * 1024 * 1024
from .identity import identity, sample_key
from .settings import Settings, NUMERIC_DEFAULTS

# Kept as a numeric defaults mapping for public measurement/test helpers.
DEFAULTS = NUMERIC_DEFAULTS


class Accounting:
    """Plaintext HTTP bytes, including partial I/O and response read-ahead."""
    def __init__(self, clock=time.time):
        self.clock, self.lock = clock, threading.Lock()
        self.period, self.today = Counter(), Counter()
        self.day = int(clock() // 86400)

    def roll_day(self):
        day = int(self.clock() // 86400)
        if day != self.day:
            self.day = day
            self.today.clear()

    def add(self, **counts):
        with self.lock:
            self.roll_day()
            self.period.update(counts)
            self.today.update(counts)

    def summary(self, reset=False):
        with self.lock:
            self.roll_day()
            totals = {'hour': dict(self.period), 'today': dict(self.today)}
            if reset:
                self.period.clear()
            return totals


class _ResponseSocket:
    """Supply HTTPResponse with a metered, buffered stream; no HTTP parsing here."""
    def __init__(self, sock, connection):
        self.sock, self.connection = sock, connection

    def makefile(self, mode):
        return io.BufferedReader(_Reader(self.sock, self.connection))


class _Reader(io.RawIOBase):
    def __init__(self, sock, connection):
        self.sock, self.connection = sock, connection
        self.raw = sock.makefile('rb', buffering=0)
        connection.io_socket = sock

    def close(self):
        self.raw.close()
        super().close()

    def readable(self):
        return True

    def readinto(self, buffer):
        connection = self.connection
        connection.arm(self.sock)
        count = self.raw.readinto(buffer)
        if count and connection.first_byte is None:
            connection.first_byte = connection.client.clock()
        connection.client.accounting.add(received=count)
        return count


class _Connection(http.client.HTTPSConnection):
    """Only instrument I/O, deadlines and cancellation; http.client owns HTTP."""
    def __init__(self, client, deadline):
        super().__init__('127.0.0.1', client.settings['probe_port'], timeout=1, context=client.context)
        self.client, self.deadline = client, deadline
        self.first_byte, self.stall, self.io_socket = None, None, None
        self.response_class = lambda sock, **kw: http.client.HTTPResponse(_ResponseSocket(sock, self), **kw)

    def arm(self, sock):
        remaining = self.deadline - self.client.clock()
        if self.client.cancelled.is_set():
            raise OSError('probe cancelled')
        if remaining <= 0:
            raise TimeoutError('probe deadline')
        sock.settimeout(min(remaining, self.stall) if self.stall else remaining)

    def connect(self):
        http.client.HTTPConnection.connect(self)  # Includes stdlib CONNECT handling.
        self.first_byte = None  # Start target latency after the CONNECT exchange.
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self._tunnel_host,
                                              do_handshake_on_connect=False)
        self.io_socket = self.sock
        self.arm(self.sock)
        self.sock.do_handshake()

    def send(self, data):
        if self.sock is None:
            self.connect()
        view = memoryview(data)
        while view:
            self.arm(self.sock)
            sent = self.sock.send(view)
            if not sent:
                raise OSError('closed while sending')
            self.client.accounting.add(sent=sent)
            view = view[sent:]


def validate_response(response, expected, ranged, head):
    headers = response.headers
    for name in ('Content-Length', 'Content-Encoding', 'Transfer-Encoding', 'Content-Range'):
        if len(headers.get_all(name, [])) > 1:
            raise ValueError('duplicate framing header')
    if headers.get('Content-Encoding', 'identity').lower() != 'identity':
        raise ValueError('encoded body')
    transfer = headers.get('Transfer-Encoding', '').lower()
    length = headers.get('Content-Length')
    if transfer not in ('', 'chunked') or (transfer and length is not None):
        raise ValueError('invalid response framing')
    length = int(length) if length is not None else None
    if not head and length is None and not response.chunked:
        raise ValueError('body has no explicit framing')
    if ranged and response.status == 206:
        match = re.fullmatch(r'bytes 0-262143/(\d+)', headers.get('Content-Range', ''))
        if not match or int(match[1]) < THROTTLE or (length is not None and length != THROTTLE):
            raise ValueError('invalid backup range')
    elif response.status != 200:
        raise ValueError('unexpected status')
    elif not head and length is not None and (length < expected if ranged else length != expected):
        raise ValueError('unexpected body length')


class ProbeClient:
    def __init__(self, settings, accounting=None, clock=time.monotonic):
        self.settings, self.clock = Settings.from_mapping(settings), clock
        self.accounting = accounting or Accounting()
        self.context = ssl.create_default_context(cafile=settings.get('probe_ca_bundle'))
        self.cancelled = threading.Event()
        self.lock, self.connections = threading.Lock(), set()

    def cancel(self):
        self.cancelled.set()
        with self.lock:
            for connection in self.connections:
                if connection.io_socket:
                    try:
                        connection.io_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

    def request(self, outbound, url, kind, backup=False, head=False):
        started = self.clock()
        duration = self.settings['throughput_seconds'] if kind == 'throughput' else self.settings['probe_timeout']
        connection = response = None
        body = skipped = 0
        burst = post_started = None
        result = {'kind': kind, 'ok': False, 'backup': backup}
        try:
            target = urlsplit(url)
            if target.scheme != 'https' or not target.hostname or target.username or target.fragment:
                raise ValueError('HTTPS endpoint required')
            connection = _Connection(self, started + duration)
            user, password = identity(outbound)
            connection.set_tunnel(target.hostname, target.port or 443, headers={
                'Proxy-Authorization': 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()})
            with self.lock:
                self.connections.add(connection)
            path = target.path or '/'
            if target.query:
                path += '?' + target.query
            ranged = backup and not head
            headers = {'Accept-Encoding': 'identity', 'Connection': 'close'}
            if ranged:
                headers['Range'] = 'bytes=0-262143'
            connection.request('HEAD' if head else 'GET', path, headers=headers)
            response = connection.getresponse()
            result.update(status=response.status, content_length=response.getheader('Content-Length'),
                          framing=response.getheader('Transfer-Encoding'))
            expected = {'gate': GATE, 'throttle': THROTTLE, 'throughput': TOTAL}[kind]
            validate_response(response, expected, ranged, head)
            connection.stall = self.settings['probe_stall_timeout']
            early = False
            while not head and body < expected:
                try:
                    data = response.read1(min(16384, expected-body))
                except TimeoutError:
                    if kind == 'throughput' and body and self.clock() >= connection.deadline:
                        early = True
                        break
                    raise
                if not data:
                    raise ValueError('truncated body')
                before, body = body, body + len(data)
                if burst is None and body >= 16384:
                    burst = self.clock() - connection.first_byte
                if kind == 'throughput':
                    skipped += min(body, SKIP) - min(before, SKIP)
                    if body >= SKIP and post_started is None:
                        post_started = self.clock()
                    scored = body - SKIP
                    elapsed = self.clock() - post_started if post_started is not None else 0
                    if scored >= 4*1024*1024 or (scored >= THROTTLE and elapsed > 0 and scored*8/elapsed/1e6 > 50):
                        early = True
                        break
            if not head and not ranged and not early and response.read1(1):
                body += 1
                raise ValueError('oversized body')
            result.update(ok=True, early_stop=early)
            if kind == 'throughput' and body-SKIP >= THROTTLE:
                result['mbps'] = (body-SKIP)*8/max(self.clock()-post_started, .000001)/1e6
        except (OSError, ValueError, http.client.HTTPException) as exc:
            result['error'] = type(exc).__name__
        finally:
            if response:
                response.close()
            if connection:
                connection.close()
                with self.lock:
                    self.connections.discard(connection)
            first = connection.first_byte if connection else None
            result.update(bytes=body, skipped=skipped, seconds=self.clock()-started,
                          latency_ms=(first-started)*1000 if first is not None else None, burst_seconds=burst)
            # Socket-level sent/received bytes are counted as they happen; the rest once here.
            self.accounting.add(probes=1, partial=int(not result['ok']), corroboration=int(backup),
                                early_stops=int(result.get('early_stop', False)),
                                body_received=body, skipped=skipped)
        return result

    def run(self, outbound, kind):
        size = {'gate': GATE, 'throttle': THROTTLE, 'throughput': TOTAL}[kind]
        url = self.settings.probe_url.replace('{bytes}', str(size))
        return self.request(outbound, url, kind)

    def corroborate(self, outbound, body=False):
        url = self.settings.probe_backup_url
        result = self.request(outbound, url, 'gate', backup=True, head=True)
        return self.request(outbound, url, 'throttle', backup=True) if body and result['ok'] else result
