"""Immutable runtime settings and fixed policy/supervision bounds."""
from collections.abc import Mapping
import ipaddress
from dataclasses import dataclass, fields, field, replace
import json
import math
from pathlib import Path
import ssl
from types import MappingProxyType
from urllib.parse import urlsplit

ACTIVE_SCORE_MAX_AGE = 7200
SCORE_MAX_AGE = 172800  # standby scores used for ranking
CHALLENGE_RETRY_SECONDS = 1800  # retry of a failed or stale challenger test
FRESH_SAMPLE_SECONDS = 30
INSPECT_SECONDS = 5
UPLINK_FRESH_SECONDS = 30  # a working uplink check covers failures for this long
UPLINK_RETRY_SECONDS = 10  # recheck interval while the uplink is down
SCHEDULER_ERROR_LOG_SECONDS = 60
# Policy invariants, deliberately fixed rather than operator-tunable cadences.
HOLD = 300
MARGIN = 1.15
# Probes use the first endpoint; a failure is confirmed against each next one.
# URLs without {bytes} serve a large static file read with a Range request.
DEFAULT_PROBE_URLS = ('https://speed.cloudflare.com/__down?bytes={bytes}',
                      'https://proof.ovh.net/files/100Mb.dat')
# Reached directly, never through a proxy: any HTTP response means the uplink works.
DEFAULT_UPLINK_URLS = ('https://ya.ru/', 'https://yastatic.net/')


@dataclass(frozen=True)
class Settings:
    refresh_seconds: float = 7200
    revision_timeout: float = 30
    shutdown_timeout: float = 10
    bootstrap_backoff_seconds: float = 5
    bootstrap_backoff_max_seconds: float = 300
    gate_active_seconds: float = 60
    gate_standby_seconds: float = 480
    throttle_seconds: float = 300
    throughput_active_seconds: float = 3600
    throughput_shortlist_seconds: float = 21600
    throughput_rotation_seconds: float = 14400
    probe_timeout: float = 15
    probe_stall_timeout: float = 2
    throughput_seconds: float = 4
    # Throughput skips slow start, then stops at the max or once evidence bytes beat the scored cap.
    rate_cap_mbps: float = 150
    throughput_skip_mib: float = 4
    throughput_evidence_mib: float = 16
    throughput_max_mib: float = 32
    shortlist_size: int = 3  # best-scored standbys per provider that get throughput tests
    provider_shortlist_sizes: Mapping[str, int] = field(default_factory=dict)
    provider_rotation_seconds: Mapping[str, float] = field(default_factory=dict)
    probe_workers: int = 4
    probe_port: int = 19090
    clash_api_port: int = 19089
    probes_enabled: bool = False
    managed_selectors: tuple[str, ...] = ()
    provider_weights: Mapping[str, float] = field(default_factory=dict)
    selector_priorities: Mapping[str, tuple[tuple[str, ...], ...]] = field(default_factory=dict)
    probe_urls: tuple[str, ...] = DEFAULT_PROBE_URLS
    uplink_urls: tuple[str, ...] = DEFAULT_UPLINK_URLS
    probe_ca_bundle: str | None = None
    dashboard_listen: str | None = None  # 'host:port' of the read-only status page

    def __post_init__(self):
        object.__setattr__(self, 'managed_selectors', tuple(self.managed_selectors))
        object.__setattr__(self, 'probe_urls', tuple(self.probe_urls))
        object.__setattr__(self, 'uplink_urls', tuple(self.uplink_urls))
        for name in ('provider_weights', 'provider_shortlist_sizes', 'provider_rotation_seconds'):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))
        object.__setattr__(self, 'selector_priorities', MappingProxyType({
            tag: tuple(tuple(tier) for tier in tiers)
            for tag, tiers in self.selector_priorities.items()}))

    @classmethod
    def from_mapping(cls, values):
        if isinstance(values, cls):
            return values
        return cls(**{field.name: values[field.name] for field in fields(cls) if field.name in values})

    def with_changes(self, **changes):
        return replace(self, **changes)

    def shortlist_for(self, provider):
        return self.provider_shortlist_sizes.get(provider, self.shortlist_size)

    def rotation_for(self, provider):
        return self.provider_rotation_seconds.get(provider, self.throughput_rotation_seconds)

    def throughput_bytes(self):
        """Skipped, early-stop evidence and scored maximum byte counts."""
        return tuple(int(mib * 1024 * 1024) for mib in (
            self.throughput_skip_mib, self.throughput_evidence_mib, self.throughput_max_mib))

    def as_dict(self):
        return {field.name: getattr(self, field.name) for field in fields(self)}


_NUMERIC_DEFAULTS = {field.name: field.default for field in fields(Settings)
                    if isinstance(field.default, (int, float)) and not isinstance(field.default, bool)}


def load_settings(config_dir):
    path = Path(config_dir) / 'local-manager.json'
    settings = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(settings, dict):
        raise ValueError('manager settings must be an object')
    managed = settings.setdefault('managed_selectors', [])
    if (not isinstance(settings.get('probes_enabled', False), bool) or not isinstance(managed, list)
            or any(not isinstance(s, str) or not s for s in managed)
            or len(set(managed)) != len(managed)):
        raise ValueError('invalid probes_enabled or managed_selectors')
    if managed and not settings.get('probes_enabled', False):
        raise ValueError('managed selectors require probes_enabled')
    priorities = settings.get('selector_priorities', {})
    if not isinstance(priorities, dict):
        raise ValueError('selector_priorities must be an object')
    for selector, tiers in priorities.items():
        if (not isinstance(selector, str) or not selector or not isinstance(tiers, list) or not tiers
                or any(not isinstance(tier, list) or not tier or
                       any(not isinstance(p, str) or not p for p in tier) for tier in tiers)):
            raise ValueError('invalid selector priority tiers')
        providers = [p for tier in tiers for p in tier]
        if len(set(providers)) != len(providers):
            raise ValueError('duplicate provider in selector priorities')
    weights = settings.get('provider_weights', {})
    if not isinstance(weights, dict) or any(not isinstance(w, (int, float)) or isinstance(w, bool)
            or not math.isfinite(w) or w <= 0 for w in weights.values()):
        raise ValueError('provider weights must be positive finite numbers')
    sizes, rotations = settings.get('provider_shortlist_sizes', {}), settings.get('provider_rotation_seconds', {})
    if not isinstance(sizes, dict) or any(not isinstance(n, int) or isinstance(n, bool) or n < 0 for n in sizes.values()):
        raise ValueError('provider shortlist sizes must be non-negative integers')
    if not isinstance(rotations, dict) or any(not isinstance(v, (int, float)) or isinstance(v, bool)
            or not math.isfinite(v) or v <= 0 for v in rotations.values()):
        raise ValueError('provider rotation intervals must be positive finite numbers')
    for key, default in _NUMERIC_DEFAULTS.items():
        value = settings.setdefault(key, default)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise ValueError('invalid manager deadline/cadence')
    for key, maximum in (('probe_workers', 4), ('probe_port', 65535), ('clash_api_port', 65535), ('shortlist_size', 1000)):
        if not isinstance(settings[key], int) or settings[key] > maximum:
            raise ValueError('invalid probe worker count/port')
    if settings['probe_port'] == settings['clash_api_port']:
        raise ValueError('probe_port and clash_api_port must differ')
    if settings['probe_timeout'] > 15 or settings['throughput_seconds'] > 4:
        raise ValueError('probe deadlines exceed bounded maximum')
    # Cloudflare refuses requests of 100 MiB; the fallback file is exactly 100 MiB.
    if (settings['throughput_evidence_mib'] > settings['throughput_max_mib'] or settings['throughput_max_mib'] < 1
            or settings['throughput_skip_mib'] + settings['throughput_max_mib'] > 96):
        raise ValueError('throughput byte budget must satisfy evidence <= max, max >= 1 and skip + max <= 96 MiB')
    urls = settings.get('probe_urls', list(DEFAULT_PROBE_URLS))
    uplinks = settings.get('uplink_urls', list(DEFAULT_UPLINK_URLS))
    for name, value, minimum in (('probe_urls', urls, 1), ('uplink_urls', uplinks, 0)):
        if (not isinstance(value, list) or any(not isinstance(url, str) for url in value)
                or len(value) < minimum or len(set(value)) != len(value)):
            raise ValueError(f'{name} must be a list of distinct URLs')
    if 'probe_ca_bundle' in settings and not isinstance(settings['probe_ca_bundle'], str):
        raise ValueError('probe_ca_bundle must be a file path')
    if 'dashboard_listen' in settings:
        if dashboard_address(settings['dashboard_listen'])[1] in (settings['probe_port'], settings['clash_api_port']):
            raise ValueError('dashboard port must differ from probe_port and clash_api_port')
    if settings.get('probes_enabled', False):
        ssl.create_default_context(cafile=settings.get('probe_ca_bundle'))
        for url in map(urlsplit, urls + uplinks):
            if url.scheme != 'https' or not url.hostname or url.username or url.fragment:
                raise ValueError('probe endpoint must be HTTPS')
    return Settings.from_mapping(settings)


def dashboard_address(value):
    """An IP literal (IPv6 in brackets) and a port; hostnames are not resolved."""
    try:
        host, port = value.rsplit(':', 1)
        if host.startswith('['):
            if not host.endswith(']'):
                raise ValueError()
            address = ipaddress.IPv6Address(host[1:-1])
        else:
            address = ipaddress.IPv4Address(host)
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError()
    except (ValueError, AttributeError):
        raise ValueError('dashboard_listen must be "ip:port"') from None
    return str(address), int(port)
