"""Loopback-only revision inspection with optional authentication. Stage 1 has no writes."""
import ipaddress
import json
import urllib.request


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
