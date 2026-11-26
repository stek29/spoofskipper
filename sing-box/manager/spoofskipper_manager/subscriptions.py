"""Provider snapshots: last-good subscription outputs kept under /data."""
import hashlib
import json
import sys
import time
from pathlib import Path
from .parser import (apply_outbound_settings, assign_fingerprints, merge_outputs, read_fingerprints, read_headers,
                     read_outbound_settings, render_subscription)
from .settings import Settings
from .state import write_json


def read_specs(config_dir):
    path = Path(config_dir) / 'local-subs-config.json'
    if not path.exists():
        return {'subscriptions': []}  # No providers: render the config directory as is.
    config = json.loads(path.read_text())
    specs = config.get('subscriptions')
    if not isinstance(specs, list) or any(not isinstance(spec, dict) for spec in specs):
        raise ValueError('subscriptions must be a list of objects')
    for spec in specs:
        spec.setdefault('prefix', '')  # The sing-subs default.
        read_headers(spec.get('headers'))
        if 'refresh_seconds' in spec:
            interval = spec['refresh_seconds']
            if type(interval) not in (int, float) or not 0 < interval <= sys.float_info.max:
                raise ValueError('subscription refresh_seconds must be a positive finite number')
    read_fingerprints(config)
    prefixes = [spec['prefix'] for spec in specs]
    if any(not isinstance(p, str) for p in prefixes) or len(set(prefixes)) != len(prefixes):
        raise ValueError('provider prefixes must be unique')
    return config


class Providers:
    def __init__(self, config_dir, state_dir, settings, log):
        self.config = read_specs(config_dir)
        self.root = Path(state_dir) / 'providers'
        self.settings = Settings.from_mapping(settings)
        self.log = log
        self.snapshots = {}
        self.configured = bool(self.config['subscriptions'])
        for spec in self.config['subscriptions']:
            prefix = spec['prefix']
            path = self.path(prefix)
            if path.exists():
                snapshot = json.loads(path.read_text())
                if snapshot['provider'] != prefix or not snapshot['output']['outbounds']:
                    raise ValueError('invalid provider snapshot')
                self.snapshots[prefix] = snapshot

    def path(self, prefix):
        return self.root / (hashlib.sha256(prefix.encode()).hexdigest() + '.json')

    def refresh_at(self, spec, attempts):
        prefix = spec['prefix']
        fallback = self.settings.refresh_seconds
        advertised = self.snapshots.get(prefix, {}).get('profile_refresh_seconds', fallback)
        interval = spec.get('refresh_seconds', min(advertised, fallback))
        return attempts.get(prefix, float('-inf')) + interval

    def next_refresh(self, attempts):
        specs = self.config['subscriptions']
        # Forget removed providers so a later re-add is due immediately.
        for prefix in attempts.keys() - {spec['prefix'] for spec in specs}:
            del attempts[prefix]
        return min((self.refresh_at(spec, attempts) for spec in specs),
                   default=time.monotonic() + self.settings.refresh_seconds)

    def refresh(self, between=lambda: None, *, attempts=None, force=False):
        """Fetch due providers; between() runs after each attempt so probes can continue."""
        pending = dict(self.snapshots)
        global_settings, type_settings = read_outbound_settings(self.config)
        fingerprints = read_fingerprints(self.config)
        for spec in self.config['subscriptions']:
            prefix = spec['prefix']
            if attempts is not None and not force and time.monotonic() < self.refresh_at(spec, attempts):
                continue
            try:
                metadata = {}
                output = render_subscription(spec, self.log, metadata=metadata)
                output = assign_fingerprints(apply_outbound_settings(output, global_settings, type_settings), fingerprints)
                if not output['outbounds']:
                    raise ValueError('empty provider')
                pending[prefix] = {'provider': prefix, 'fetched_at': time.time(), 'output': output, **metadata}
                self.log('provider_refreshed', provider=prefix, candidates=len(output['outbounds']))
            except Exception as exc:
                old = pending.get(prefix)
                # Never emit exceptions: upstream errors can contain credentials/URLs.
                self.log('provider_refresh_failed', provider=prefix, error=type(exc).__name__,
                         snapshot_age_seconds=time.time() - old['fetched_at'] if old else None,
                         missing=old is None)
            if attempts is not None:
                attempts[prefix] = time.monotonic()
            between()
        return pending

    def merged(self, snapshots):
        if not self.configured:
            return None
        return merge_outputs([snapshots[s['prefix']]['output'] for s in self.config['subscriptions']
                              if s['prefix'] in snapshots])

    def candidates(self, snapshots):
        weights = self.settings.provider_weights
        return [{'provider': prefix, 'weight': weights.get(prefix, 1.0), 'outbound': outbound}
                for prefix, snapshot in snapshots.items() for outbound in snapshot['output']['outbounds']]

    def commit(self, snapshots):
        for prefix, snapshot in snapshots.items():
            if snapshot is not self.snapshots.get(prefix):
                write_json(self.path(prefix), snapshot)
        self.snapshots = dict(snapshots)


def default_interface(route_table='/proc/net/route'):
    """Interface of the main table's IPv4 default route; the tun routes from its own table."""
    try:
        for line in Path(route_table).read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) > 7 and fields[1] == '00000000' and fields[7] == '00000000':
                return fields[0]
    except OSError:
        pass
    return None


def bootstrap(config_dir, state_dir, log):
    """Seed snapshots for every provider, so the first serve starts the core before fetching.

    Run once before cutover while the old core still provides egress. Nothing is
    written unless every configured provider has a snapshot: a partial seed would
    start the core without that provider's outbounds.
    """
    providers = Providers(config_dir, state_dir, Settings(), log)
    pending = providers.refresh()
    missing = [s['prefix'] for s in providers.config['subscriptions'] if s['prefix'] not in pending]
    if missing:
        log('bootstrap_failed', missing=missing)
        return 1
    providers.commit(pending)
    log('bootstrap_completed', providers=sorted(pending))
    return 0
