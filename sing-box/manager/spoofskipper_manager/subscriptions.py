"""Provider snapshots: last-good subscription outputs kept under /data."""
import hashlib
import json
import time
from pathlib import Path
from .parser import apply_outbound_settings, merge_outputs, read_outbound_settings, render_subscription
from .state import write_json


def read_specs(config_dir):
    config = json.loads((Path(config_dir) / 'local-subs-config.json').read_text())
    specs = config.get('subscriptions')
    if not isinstance(specs, list) or not specs:
        raise ValueError('subscriptions must be a nonempty list')
    prefixes = [spec.get('prefix') for spec in specs]
    if any(not isinstance(p, str) or not p for p in prefixes) or len(set(prefixes)) != len(prefixes):
        raise ValueError('provider prefixes must be nonempty and unique')
    return config


class Providers:
    def __init__(self, config_dir, state_dir, settings, log):
        self.config = read_specs(config_dir)
        self.root = Path(state_dir) / 'providers'
        self.settings = settings
        self.log = log
        self.snapshots = {}
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

    def refresh(self):
        pending = dict(self.snapshots)
        global_settings, type_settings = read_outbound_settings(self.config)
        for spec in self.config['subscriptions']:
            prefix = spec['prefix']
            try:
                output = apply_outbound_settings(render_subscription(spec, self.log), global_settings, type_settings)
                if not output['outbounds']:
                    raise ValueError('empty provider')
                pending[prefix] = {'provider': prefix, 'fetched_at': time.time(), 'output': output}
                self.log('provider_refreshed', provider=prefix, candidates=len(output['outbounds']))
            except Exception as exc:
                old = pending.get(prefix)
                # Never emit exceptions: upstream errors can contain credentials/URLs.
                self.log('provider_refresh_failed', provider=prefix, error=type(exc).__name__,
                         snapshot_age_seconds=time.time() - old['fetched_at'] if old else None,
                         missing=old is None)
        return pending

    def merged(self, snapshots):
        return merge_outputs([snapshots[s['prefix']]['output'] for s in self.config['subscriptions']
                              if s['prefix'] in snapshots])

    def candidates(self, snapshots):
        weights = self.settings.get('provider_weights', {})
        return [{'provider': prefix, 'weight': weights.get(prefix, 1.0), 'outbound': outbound}
                for prefix, snapshot in snapshots.items() for outbound in snapshot['output']['outbounds']]

    def commit(self, snapshots):
        for prefix, snapshot in snapshots.items():
            write_json(self.path(prefix), snapshot)
        self.snapshots = dict(snapshots)
