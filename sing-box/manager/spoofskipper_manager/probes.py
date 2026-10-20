"""Bounded HTTPS measurements using the standard-library CONNECT/HTTP client."""
import base64
from dataclasses import asdict, dataclass
from enum import Enum
import http.client
import io
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from .identity import identity
from .settings import Settings

# Throttling middleboxes let small responses through and stall the connection
# after a few dozen KiB, so health is proven only past THROTTLE bytes.
THROTTLE, SKIP, TOTAL = 256 * 1024, 512 * 1024, 8 * 1024 * 1024


class Probe(str, Enum):
    """One request per probe; the kinds differ only in their byte budget."""
    GATE = 'gate'              # 1 byte: reachability and latency
    THROTTLE = 'throttle'      # 256 KiB: the connection survives the threshold
    THROUGHPUT = 'throughput'  # up to 8 MiB: rate after the first 512 KiB

    @property
    def budget(self):
        return {Probe.GATE: 1, Probe.THROTTLE: THROTTLE, Probe.THROUGHPUT: TOTAL}[self]


@dataclass
class ProbeResult:
    probe: Probe
    ok: bool = False
    bytes: int = 0
    skipped: int = 0
    seconds: float = 0
    latency_ms: float | None = None
    burst_seconds: float | None = None
    mbps: float | None = None
    early_stop: bool = False
    status: int | None = None
    error: str | None = None
    completed_at: float | None = None

    @property
    def passed_threshold(self):
        """A completed body probe that read past the throttling threshold."""
        return self.ok and self.probe is not Probe.GATE and self.bytes >= THROTTLE

    def fields(self):
        return {k: v for k, v in asdict(self).items() if v is not None and k != 'completed_at'}


class _ResponseSocket:
    """Supply HTTPResponse with a deadline-checked, buffered stream; no HTTP parsing here."""
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
        return count


class _Connection(http.client.HTTPSConnection):
    """Only instrument I/O, deadlines and cancellation; http.client owns HTTP."""
    def __init__(self, client, deadline):
        super().__init__('127.0.0.1', client.settings.probe_port, timeout=1, context=client.context)
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
        self.arm(self.sock)
        self.sock.sendall(data)


def validate_response(response, expected):
    # http.client handles framing; only reject what would distort the measurement.
    if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
        raise ValueError('encoded body')
    if response.status != 200:
        raise ValueError('unexpected status')
    length = response.length  # Parsed by http.client before any body is read; None if chunked.
    if length is not None and length != expected:
        raise ValueError('unexpected body length')


class ProbeClient:
    def __init__(self, settings, clock=time.monotonic):
        self.settings, self.clock = Settings.from_mapping(settings), clock
        self.context = ssl.create_default_context(cafile=self.settings.probe_ca_bundle)
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

    def run(self, outbound, probe):
        probe = Probe(probe)
        started = self.clock()
        expected = probe.budget
        connection = response = None
        body = 0
        post_started = burst = None
        result = ProbeResult(probe)
        try:
            target = urlsplit(self.settings.probe_url.replace('{bytes}', str(expected)))  # Validated on load.
            connection = _Connection(self, started + self.settings.probe_timeout)
            user, password = identity(outbound)
            connection.set_tunnel(target.hostname, target.port or 443, headers={
                'Proxy-Authorization': 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()})
            with self.lock:
                self.connections.add(connection)
            path = (target.path or '/') + ('?' + target.query if target.query else '')
            connection.request('GET', path, headers={'Accept-Encoding': 'identity', 'Connection': 'close'})
            response = connection.getresponse()
            result.status = response.status
            validate_response(response, expected)
            if probe is Probe.THROUGHPUT:
                # Time-box only the body: slow setup must not cost the measurement.
                connection.deadline = self.clock() + self.settings.throughput_seconds
            connection.stall = self.settings.probe_stall_timeout
            while body < expected:
                try:
                    data = response.read1(min(16384, expected-body))
                except TimeoutError:
                    # Throughput is time-boxed: reaching the deadline mid-body ends the sample.
                    if probe is Probe.THROUGHPUT and body and self.clock() >= connection.deadline:
                        result.early_stop = True
                        break
                    raise
                if not data:
                    raise ValueError('truncated body')
                body += len(data)
                if burst is None and body >= 16384:
                    burst = self.clock() - connection.first_byte
                if probe is Probe.THROUGHPUT:
                    if body >= SKIP and post_started is None:
                        post_started = self.clock()
                    scored = body - SKIP
                    elapsed = self.clock() - post_started if post_started is not None else 0
                    if scored >= 4*1024*1024 or (scored >= THROTTLE and elapsed > 0 and scored*8/elapsed/1e6 > 50):
                        result.early_stop = True
                        break
            if not result.early_stop and response.read1(1):
                body += 1
                raise ValueError('oversized body')
            result.ok = True
            if probe is Probe.THROUGHPUT and body-SKIP >= THROTTLE:
                result.mbps = (body-SKIP)*8/max(self.clock()-post_started, .000001)/1e6
        except (OSError, ValueError, http.client.HTTPException) as exc:
            result.error = type(exc).__name__
        finally:
            if response:
                response.close()
            if connection:
                connection.close()
                with self.lock:
                    self.connections.discard(connection)
            first = connection.first_byte if connection else None
            result.bytes, result.skipped = body, min(body, SKIP) if probe is Probe.THROUGHPUT else 0
            result.seconds = self.clock() - started
            result.latency_ms = (first-started)*1000 if first is not None else None
            result.burst_seconds = burst
        return result
