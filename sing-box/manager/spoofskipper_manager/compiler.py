"""Jsonnet rendering, structural validation, and content-derived revisions."""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from .clash_api import credentials
from .state import atomic_write
from .graph import OutboundGraph
from .identity import identity
from .settings import Settings

REVISION_PREFIX = '__spoofskipper_revision_'
def validate(config):
    credentials(config)
    OutboundGraph(config).validate()


def revision(config):
    tags = [o['tag'] for o in config.get('outbounds', []) if o['tag'].startswith(REVISION_PREFIX)]
    if len(tags) != 1:
        raise ValueError('expected one manager revision')
    return tags[0]


def ensure_clash_api(config, port, secret):
    """Verification needs the Clash API; supply a loopback one if none is configured."""
    experimental = config.setdefault('experimental', {})
    api = experimental.get('clash_api') or {}
    if not api.get('external_controller'):
        experimental['clash_api'] = {**api, 'external_controller': f'127.0.0.1:{port}', 'secret': secret}


def render(template, subscriptions, scratch, settings=None, candidates=(), api_secret=''):
    """Render a scratch copy of the config directory.

    Merged subscriptions replace local-subs.json, which config.jsonnet already
    imports, and are also offered as the subscription_outbounds extVar. With
    subscriptions=None (no providers configured) the directory renders as is.
    """
    template, scratch = Path(template), Path(scratch)
    root = scratch / 'config'
    shutil.copytree(template.parent, root)
    if subscriptions is not None:
        atomic_write(root / 'local-subs.json', json.dumps(subscriptions))
    ext = scratch / 'subscriptions.json'
    atomic_write(ext, json.dumps(subscriptions or {'outbounds': [], 'groups': {}}))
    try:
        result = subprocess.run(['jsonnet', '--ext-code-file', 'subscription_outbounds=' + str(ext),
                                 str(root / template.name)], capture_output=True, timeout=60)
        if result.returncode:
            raise ValueError('Jsonnet render failed (diagnostics suppressed to protect secrets)')
        config = json.loads(result.stdout)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        ext.unlink(missing_ok=True)
    settings = Settings.from_mapping(settings or {})
    ensure_clash_api(config, settings.clash_api_port, api_secret)
    add_probe_routes(config, settings, candidates)
    handoff_selectors(config, settings.managed_selectors, candidates)
    validate(config)
    if any(o['tag'].startswith(REVISION_PREFIX) for o in config.get('outbounds', [])):
        raise ValueError('reserved revision tag prefix')
    digest = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    config.setdefault('outbounds', []).append({'type': 'direct', 'tag': REVISION_PREFIX + digest})
    return config


def check(config, scratch, core='sing-box'):
    path = Path(scratch) / 'checked.json'
    atomic_write(path, json.dumps(config))
    try:
        result = subprocess.run([core, 'check', '-c', str(path)], capture_output=True, timeout=60)
        if result.returncode:
            raise ValueError('sing-box check failed (diagnostics suppressed to protect secrets)')
    finally:
        path.unlink(missing_ok=True)


PROBE_TAG = '__spoofskipper_probe'


def selectors(config):
    return [o['tag'] for o in config.get('outbounds', []) if o.get('type') == 'selector']


def probe_outbounds(config, candidates=()):
    # Every rendered proxy leaf is eligible, whether subscribed or local.
    return [o for o in config.get('outbounds', []) + config.get('endpoints', [])
            if o.get('type') not in ('selector', 'urltest', 'direct', 'block', 'dns')]


def add_probe_routes(config, settings, candidates):
    settings = Settings.from_mapping(settings)
    if not settings.probes_enabled:
        return
    if any(i.get('tag') == PROBE_TAG for i in config.get('inbounds', [])):
        raise ValueError('reserved probe inbound tag')
    outbounds = probe_outbounds(config, candidates)
    config.setdefault('inbounds', []).append({
        'type': 'mixed', 'tag': PROBE_TAG, 'listen': '127.0.0.1',
        'listen_port': settings.probe_port,
        'users': [{'username': identity(o)[0], 'password': identity(o)[1]} for o in outbounds]})
    # First rules prevent production routing from shadowing authenticated probes.
    rules = [{'inbound': [PROBE_TAG], 'auth_user': [identity(o)[0]],
              'action': 'route', 'outbound': o['tag']} for o in outbounds]
    rules.append({'inbound': [PROBE_TAG], 'action': 'reject'})
    route = config.setdefault('route', {})
    route['rules'] = rules + route.get('rules', [])


def handoff_selectors(config, managed, candidates):
    """Flatten owned selectors to their proxy leaves; native groups stay as they are."""
    if not managed:
        return
    graph = OutboundGraph(config)
    tags = graph.entries
    selectable = {outbound['tag'] for outbound in probe_outbounds(config, candidates)}
    validate(config)  # Reject cycles before recursively expanding members.
    for selector in managed:
        if tags.get(selector, {}).get('type') != 'selector':
            raise ValueError('managed selector missing or incompatible')
        members = list(dict.fromkeys(graph.leaves(selector)))
        if not members or any(tag not in selectable for tag in members):
            raise ValueError('managed selector has incompatible candidate members')
        tags[selector]['outbounds'] = members
        tags[selector].pop('default', None)
