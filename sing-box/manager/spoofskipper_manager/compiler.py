"""Jsonnet rendering, structural validation, and content-derived revisions."""
import hashlib
import json
import subprocess
from pathlib import Path
from .clash_api import credentials
from .state import atomic_write

REVISION_PREFIX = '__spoofskipper_revision_'
IMPORT_LINE = "local sub_data = std.parseJson(importstr 'local-subs.json');"
EXTVAR_LINE = "local sub_data = std.extVar('subscription_outbounds');"


def edited_source(source):
    if source.splitlines().count(IMPORT_LINE) != 1:
        raise ValueError('expected subscription import line exactly once')
    return source.replace(IMPORT_LINE, EXTVAR_LINE, 1)


def validate(config):
    credentials(config)
    entries = config.get('outbounds', []) + config.get('endpoints', [])
    tags = {entry['tag']: entry for entry in entries}
    if len(tags) != len(entries):
        raise ValueError('duplicate outbound/endpoint tags')
    edges = {}
    for tag, entry in tags.items():
        dependencies = list(entry.get('outbounds', []))
        if entry.get('detour'):
            dependencies.append(entry['detour'])
        if entry.get('type') in ('selector', 'urltest') and not dependencies:
            raise ValueError('empty selector group')
        if entry.get('default') and entry['default'] not in dependencies:
            raise ValueError('selector default is not a member')
        if any(member not in tags for member in dependencies):
            raise ValueError('unknown outbound dependency')
        edges[tag] = dependencies
    active, done = set(), set()
    def visit(tag):
        if tag in active:
            raise ValueError('outbound dependency cycle')
        if tag in done:
            return
        active.add(tag)
        for member in edges[tag]:
            visit(member)
        active.remove(tag)
        done.add(tag)
    for tag in tags:
        visit(tag)


def revision(config):
    tags = [o['tag'] for o in config.get('outbounds', []) if o['tag'].startswith(REVISION_PREFIX)]
    if len(tags) != 1:
        raise ValueError('expected one manager revision')
    return tags[0]


def render(template, subscriptions, scratch, settings=None, candidates=()):
    private = Path(template).parent / 'config.jsonnet'
    if private.read_text().splitlines().count(EXTVAR_LINE) != 1 or IMPORT_LINE in private.read_text():
        raise ValueError('private config requires documented subscription extVar edit')
    scratch = Path(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    ext = scratch / 'subscriptions.json'
    atomic_write(ext, json.dumps(subscriptions))
    try:
        result = subprocess.run(['jsonnet', '--ext-code-file', 'subscription_outbounds=' + str(ext),
                                 str(template)], capture_output=True, timeout=60)
        if result.returncode:
            raise ValueError('Jsonnet render failed (diagnostics suppressed to protect secrets)')
        config = json.loads(result.stdout)
    finally:
        ext.unlink(missing_ok=True)
    add_probe_routes(config, settings or {}, candidates)
    handoff_selectors(config, (settings or {}).get('managed_selectors', []), candidates)
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


def selector_members(config, selector):
    entries = {o['tag']: o for o in config.get('outbounds', []) + config.get('endpoints', [])}
    def leaves(tag, seen):
        if tag in seen:
            raise ValueError('selector dependency cycle')
        entry = entries[tag]
        if entry.get('type') in ('selector', 'urltest'):
            return [leaf for member in entry['outbounds'] for leaf in leaves(member, seen | {tag})]
        return [tag]
    return leaves(selector, set())


def probe_outbounds(config, candidates=()):
    # Every rendered proxy leaf is eligible, whether subscribed or local.
    return [o for o in config.get('outbounds', []) + config.get('endpoints', [])
            if o.get('type') not in ('selector', 'urltest', 'direct', 'block', 'dns')]


def add_probe_routes(config, settings, candidates):
    if not settings.get('probes_enabled', False):
        return
    from .probes import identity
    if any(i.get('tag') == PROBE_TAG for i in config.get('inbounds', [])):
        raise ValueError('reserved probe inbound tag')
    outbounds = probe_outbounds(config, candidates)
    config.setdefault('inbounds', []).append({
        'type': 'mixed', 'tag': PROBE_TAG, 'listen': '127.0.0.1',
        'listen_port': settings.get('probe_port', 19090),
        'users': [{'username': identity(o)[0], 'password': identity(o)[1]} for o in outbounds]})
    # First rules prevent production routing from shadowing authenticated probes.
    rules = [{'inbound': [PROBE_TAG], 'auth_user': [identity(o)[0]],
              'action': 'route', 'outbound': o['tag']} for o in outbounds]
    rules.append({'inbound': [PROBE_TAG], 'action': 'reject'})
    route = config.setdefault('route', {})
    route['rules'] = rules + route.get('rules', [])


def handoff_selectors(config, managed, candidates):
    """Flatten owned selectors; retain native groups with any other reference."""
    if not managed:
        return
    tags = {o['tag']: o for o in config.get('outbounds', []) + config.get('endpoints', [])}
    selectable = {o['tag'] for o in probe_outbounds(config, candidates)}
    removed = set()
    def leaves(tag):
        entry = tags[tag]
        if entry.get('type') in ('selector', 'urltest'):
            if entry['type'] == 'urltest':
                removed.add(tag)
            return [leaf for member in entry['outbounds'] for leaf in leaves(member)]
        return [tag]
    validate(config)  # Reject cycles before recursively expanding members.
    for selector in managed:
        if tags.get(selector, {}).get('type') != 'selector':
            raise ValueError('managed selector missing or incompatible')
        entry = tags[selector]
        members = list(dict.fromkeys(leaf for member in entry['outbounds'] for leaf in leaves(member)))
        if not members or any(tag not in selectable for tag in members):
            raise ValueError('managed selector has incompatible candidate members')
        entry['outbounds'] = members
        entry.pop('default', None)
    # Scan all references, including routing/DNS/detours. Never remove a group
    # still used by an unmanaged selector or another part of the native config.
    def references(obj):
        if isinstance(obj, dict):
            return set().union(*(references(v) for k, v in obj.items() if k != 'tag')) if obj else set()
        if isinstance(obj, list):
            return set().union(*(references(v) for v in obj)) if obj else set()
        return {obj} if isinstance(obj, str) else set()
    while removed:
        unused = removed - references(config)
        if not unused:
            break
        config['outbounds'] = [o for o in config['outbounds'] if o['tag'] not in unused]
        removed -= unused
