"""Loopback Clash inspection and verified, explicitly owned selector writes."""
import ipaddress
import json
import urllib.request
from urllib.parse import quote


def credentials(config):
    api = config.get('experimental', {}).get('clash_api', {})
    address, secret = api.get('external_controller', ''), api.get('secret', '')
    try:
        host, port = address.rsplit(':', 1)
        host = host.strip('[]')
        port = int(port)
        if not 0 < port < 65536 or not isinstance(secret, str):
            raise ValueError()
        if host == 'localhost':
            host = '127.0.0.1'
        ip = ipaddress.ip_address(host)
        if ip.is_unspecified:
            host = '::1' if ip.version == 6 else '127.0.0.1'
        elif not ip.is_loopback:
            raise ValueError()
    except (ValueError, AttributeError):
        raise ValueError('render requires a loopback-reachable Clash API with an optional string secret') from None
    return f'http://[{host}]:{port}' if ':' in host else f'http://{host}:{port}', secret


def proxies(config, timeout=1):
    base, secret = credentials(config)
    headers = {'Authorization': 'Bearer ' + secret} if secret else {}
    request = urllib.request.Request(base + '/proxies', headers=headers)
    # Local verification must never go through environment HTTP proxies.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout) as response:
        return json.load(response).get('proxies', {})


def revision_present(config, tag, timeout=1):
    return tag in proxies(config, timeout)


def select(config, selector, target, managed, timeout=1):
    if selector not in managed:
        raise ValueError('selector is not managed')
    entries = {o['tag']: o for o in config.get('outbounds', [])}
    entry = entries.get(selector, {})
    if entry.get('type') != 'selector' or target not in entry.get('outbounds', []):
        raise ValueError('selection is not a selector member')
    before = proxies(config, timeout).get(selector, {}).get('now')
    if before not in entry['outbounds']:
        raise ValueError('API selector choice unavailable')
    base, secret = credentials(config)
    headers = {'Content-Type': 'application/json'}
    if secret:
        headers['Authorization'] = 'Bearer ' + secret
    def put(name):
        request = urllib.request.Request(base + '/proxies/' + quote(selector, safe=''),
            data=json.dumps({'name': name}).encode(), headers=headers, method='PUT')
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout):
            pass
    try:
        put(target)
        if proxies(config, timeout).get(selector, {}).get('now') != target:
            raise ValueError('selector verification failed')
    except Exception:
        # A failed/ambiguous write rolls back only this selector, never its peers.
        if before in entry['outbounds']:
            put(before)
            if proxies(config, timeout).get(selector, {}).get('now') != before:
                raise ValueError('selector rollback verification failed') from None
        raise
