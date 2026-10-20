"""Immutable runtime settings and fixed policy/supervision bounds."""
from collections.abc import Mapping
from dataclasses import dataclass, fields, field, replace
import json
import math
from pathlib import Path
import ssl
from types import MappingProxyType
from urllib.parse import urlsplit

ACTIVE_SCORE_MAX_AGE = 7200
FRESH_SAMPLE_SECONDS = 30
INSPECT_SECONDS = 5
SCHEDULER_ERROR_LOG_SECONDS = 60
# Policy invariants, deliberately fixed rather than operator-tunable cadences.
HOLD = 300
MARGIN = 1.15
DEFAULT_PROBE_URL = 'https://speed.cloudflare.com/__down?bytes={bytes}'


@dataclass(frozen=True)
class Settings(Mapping):
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
    throughput_sweep_seconds: float = 172800
    probe_timeout: float = 15
    probe_stall_timeout: float = 2
    throughput_seconds: float = 4
    probe_workers: int = 4
    probe_port: int = 19090
    clash_api_port: int = 19089
    early_test_seconds: float = 1800
    probes_enabled: bool = False
    managed_selectors: tuple[str, ...] = ()
    provider_weights: Mapping[str, float] = field(default_factory=dict)
    selector_priorities: Mapping[str, tuple[tuple[str, ...], ...]] = field(default_factory=dict)
    probe_url: str = DEFAULT_PROBE_URL
    probe_ca_bundle: str | None = None

    def __post_init__(self):
        object.__setattr__(self, 'managed_selectors', tuple(self.managed_selectors))
        object.__setattr__(self, 'provider_weights', MappingProxyType(dict(self.provider_weights)))
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

    # Dynamic cadence lookup and existing public helper inputs use Mapping.
    # The stored values and all nested collections remain immutable.
    def __getitem__(self, key):
        if key not in self.__dataclass_fields__:
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self):
        return iter(self.__dataclass_fields__)

    def __len__(self):
        return len(self.__dataclass_fields__)


NUMERIC_DEFAULTS = {field.name: field.default for field in fields(Settings)
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
    for key, default in NUMERIC_DEFAULTS.items():
        value = settings.setdefault(key, default)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise ValueError('invalid manager deadline/cadence')
    for key, maximum in (('probe_workers', 4), ('probe_port', 65535), ('clash_api_port', 65535)):
        if not isinstance(settings[key], int) or settings[key] > maximum:
            raise ValueError('invalid probe worker count/port')
    if settings['probe_port'] == settings['clash_api_port']:
        raise ValueError('probe_port and clash_api_port must differ')
    if settings['probe_timeout'] > 15 or settings['throughput_seconds'] > 4:
        raise ValueError('probe deadlines exceed bounded maximum')
    if 'probe_url' in settings and not isinstance(settings['probe_url'], str):
        raise ValueError('invalid probe URL')
    if 'probe_ca_bundle' in settings and not isinstance(settings['probe_ca_bundle'], str):
        raise ValueError('probe_ca_bundle must be a file path')
    if settings.get('probes_enabled', False):
        ssl.create_default_context(cafile=settings.get('probe_ca_bundle'))
        url = urlsplit(settings.get('probe_url', DEFAULT_PROBE_URL))
        if url.scheme != 'https' or not url.hostname or url.username or url.fragment:
            raise ValueError('probe endpoint must be HTTPS')
        if '{bytes}' not in settings.get('probe_url', '{bytes}'):
            raise ValueError('probe_url requires {bytes}')
    return Settings.from_mapping(settings)
