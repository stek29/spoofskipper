"""Read-only status page: the main loop copies plain values, a daemon thread renders them."""
import base64
from datetime import datetime, timezone
import hashlib
import html
import http.server
import math
import socket
import socketserver
import threading
import time
from urllib.parse import urlsplit

from . import compiler
from .controller import retry_in
from .policy import eligible_pool, score_terms
from .probes import Probe
from .samples import Health
from .settings import ACTIVE_SCORE_MAX_AGE, HOLD, MARGIN, SCORE_MAX_AGE, dashboard_address

SNAPSHOT_SECONDS = 1
INF = float('inf')
STYLE = ('body{margin:16px;font:14px/1.45 system-ui,sans-serif;color-scheme:light dark}'
         'table{border-collapse:collapse;margin:4px 0 16px;font-variant-numeric:tabular-nums}'
         'td,th{border:1px solid #8884;padding:3px 8px;text-align:left;vertical-align:top;white-space:nowrap}'
         '.wrap{overflow-x:auto}.kv th{font-weight:normal;opacity:.7}tr.cur td{background:#58f2}'
         '.sub,.x{opacity:.65;font-size:12.5px}.x{text-decoration:line-through}'
         '.ok{color:#1a8f3c}.bad{color:#d0362c;font-weight:600}.rules{max-width:72ch}')
# Defense in depth behind escaping: nothing loads except the page's own style, and the
# sandbox gives it an opaque origin with no scripts, forms, popups or navigation.
CSP = ("default-src 'none'; style-src 'sha256-" + base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
       + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox")
HEADERS = {'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
           'Referrer-Policy': 'no-referrer', 'Cross-Origin-Opener-Policy': 'same-origin',
           'Cross-Origin-Resource-Policy': 'same-origin', 'Cache-Control': 'no-store'}


def _age(now, at):
    return now-at if math.isfinite(at) else None


def _public(url):
    parts = urlsplit(url)
    return parts._replace(netloc=parts.netloc.rpartition('@')[2], fragment='').geturl()


def snapshot(scheduler, config, now, wall=None):
    """Copy what the page shows into fresh plain values; called on the main loop only.

    Only tags, provider names, reasons and numbers are copied: never outbound
    definitions, sample digests, subscription URLs or the Clash API secret.
    """
    settings = scheduler.settings
    try:
        revision = compiler.revision(config) if config else None
    except ValueError:
        revision = None
    shortlisted = scheduler.shortlist(now) if scheduler.candidates else set()
    providers = sorted({c.provider for c in scheduler.candidates.values()} | set(settings.provider_shortlist_sizes)
                       | set(settings.provider_rotation_seconds))
    page = {'wall': time.time() if wall is None else wall, 'taken': now, 'revision': revision,
            'settings': {'probes_enabled': settings.probes_enabled,
                         'managed_selectors': list(settings.managed_selectors),
                         'selector_priorities': {t: [list(x) for x in tiers] for t, tiers in settings.selector_priorities.items()},
                         'provider_weights': dict(settings.provider_weights),
                         'rate_cap_mbps': settings.rate_cap_mbps,
                         'throughput_mib': (settings.throughput_skip_mib, settings.throughput_evidence_mib,
                                            settings.throughput_max_mib),
                         'shortlist': {p: settings.shortlist_for(p) for p in providers},
                         'rotation': {p: settings.rotation_for(p) for p in providers},
                         'probe_urls': [_public(url) for url in settings.probe_urls]},
            'probing': scheduler.client is not None, 'candidates': len(scheduler.candidates),
            'uplink': {'enabled': bool(settings.uplink_urls), 'down': scheduler.uplink_down,
                       'checking': scheduler.uplink is not None, 'held': len(scheduler.held),
                       'checked_age': _age(now, scheduler.uplink_checked_at)},
            'inspected_age': _age(now, scheduler.last_inspect), 'selectors': []}
    for tag in compiler.selectors(scheduler.config or {}):
        choice = scheduler.proxy_choices.get(tag, {}).get('now')
        entry = {'tag': tag, 'managed': tag in settings.managed_selectors,
                 'now': None if choice is None else str(choice), 'leaf': scheduler.active.get(tag)}
        if entry['managed'] and tag in scheduler.active and scheduler.graph is not None:
            entry.update(_managed(scheduler, tag, now, shortlisted))
        page['selectors'].append(entry)
    return page


def _managed(scheduler, selector, now, shortlisted):
    settings, controller = scheduler.settings, scheduler.controller
    policy, decision = controller.policy, controller.decisions.get(selector)
    members = set(scheduler.selector_members(selector))
    pool = eligible_pool(selector, scheduler.active[selector], scheduler.candidates, scheduler.samples,
                         now, settings, members)
    tiers = settings.selector_priorities.get(selector)
    switched, pending = policy.switched_at.get(selector, -INF), policy.pending.get(selector)
    tests = []
    for key, probe in decision.tests if decision else ():
        last = scheduler.samples[key].last.get(probe, -INF) if key in scheduler.samples else -INF
        tests.append({'candidate': key.tag, 'probe': probe.value, 'last_age': _age(now, last),
                      'retry_in': max(0, retry_in(last, probe, decision.since, now, settings))})
    incumbent = None
    if pool.active is not None:
        terms = score_terms(scheduler.samples[pool.active], now, ACTIVE_SCORE_MAX_AGE, settings.rate_cap_mbps)
        incumbent = None if terms is None else scheduler.candidates[pool.active].weight * terms[2] * terms[3]
    keys = [key for key in scheduler.candidates if key.tag in members]
    rows = [_row(scheduler, selector, pool, key, tiers, now, shortlisted, incumbent) for key in keys]
    # Policy order: tier first (excluded last), then score, then latency.
    rows.sort(key=lambda r: (INF if r['tier'] == 'excluded' else r['tier'] or 0,
                             r['score'] is None, -(r['score'] or 0), r['latency'] if r['latency'] is not None else INF, r['tag']))
    measured = {key.tag for key in keys}
    return {'decision': None if decision is None else {
                'reason': decision.reason, 'target': decision.target.tag if decision.target else None,
                'age': _age(now, controller.decided_at.get(selector, -INF))},
            'switched_age': _age(now, switched),
            'hold_left': max(0, HOLD-(now-switched)) if math.isfinite(switched) else None,
            'pending': None if pending is None else {'candidate': pending[0].tag, 'age': now-pending[1]},
            'tests': tests, 'tiers': None if tiers is None else [list(t) for t in tiers],
            'incumbent': incumbent, 'rows': rows,
            'unmeasured': sorted(members - measured)}


def _row(scheduler, selector, pool, key, tiers, now, shortlisted, incumbent):
    sample, candidate, settings = scheduler.samples[key], scheduler.candidates[key], scheduler.settings
    current = key == pool.active
    active = key.tag in scheduler.active.values()  # current somewhere: active probe cadence
    elsewhere = sorted(tag for tag, leaf in scheduler.active.items() if leaf == key.tag and tag != selector)
    max_age = ACTIVE_SCORE_MAX_AGE if current else SCORE_MAX_AGE
    terms = score_terms(sample, now, max_age, settings.rate_cap_mbps)
    value = None if terms is None else candidate.weight * terms[2] * terms[3]
    tier = None if tiers is None else pool.priorities.get(key, 'excluded')
    last = lambda probe: sample.last.get(probe, -INF)
    healthy = sample.health is Health.HEALTHY
    role = 'current' if current else 'shortlist' if key in shortlisted else 'rotation' if healthy and not active else None
    # Next due times follow Scheduler.next_test; requests and confirmations come first.
    gate = last(Probe.GATE) + (settings.gate_active_seconds if active else settings.gate_standby_seconds)
    if healthy:
        throttle = last(Probe.THROTTLE) + settings.throttle_seconds if active else None
    else:
        throttle = now if sample.reachable_at > last(Probe.THROTTLE) else None
    throughput = (None if not healthy else last(Probe.THROUGHPUT) + settings.throughput_active_seconds if active
                  else last(Probe.THROUGHPUT) + settings.throughput_shortlist_seconds if role == 'shortlist'
                  else scheduler.rotated_at.get(candidate.provider, -INF) + settings.rotation_for(candidate.provider))
    probes = {probe.value: {'last_age': _age(now, last(probe)), 'outcome': sample.outcomes.get(probe),
                            'due_in': None if due is None else max(0, due-now)}
              for probe, due in ((Probe.GATE, gate), (Probe.THROTTLE, throttle), (Probe.THROUGHPUT, throughput))}
    if tier == 'excluded':
        eligibility = 'excluded: provider not in tiers'
    elif sample.health is Health.FAILED:
        eligibility = 'failed'
    elif key in pool.unresolved:
        eligibility = 'unknown: gate pending, blocks lower tiers'
    elif not pool.healthy(key):
        eligibility = 'unknown' if not healthy else 'stale health'
    elif key in pool.members:
        eligibility = 'eligible'
    else:
        eligibility = 'healthy, higher tier preferred'
    if current:
        margin = {'kind': 'current'}
    elif pool.active is None or tier == 'excluded':
        margin = None
    elif tiers is not None and tier < pool.priorities[pool.active]:
        margin = {'kind': 'priority_return'}
    else:
        margin = {'kind': 'margin', 'challenger': value, 'incumbent': incumbent,
                  'needed': None if incumbent is None else incumbent*MARGIN,
                  'passes': value is not None and (incumbent is None or value >= incumbent*MARGIN)}
    running = [probe.value for k, probe, _ in scheduler.jobs.values() if k == key]
    requested = scheduler.requested.get(key)
    return {'tag': key.tag, 'provider': candidate.provider, 'tier': tier, 'weight': candidate.weight,
            'current': current, 'health': sample.health.value, 'failures': sample.failures,
            'failed_probe': sample.failed_probe.value if sample.failed_probe else None,
            'healthy_age': _age(now, sample.healthy_at), 'latency': sample.latency, 'eligibility': eligibility,
            'samples': [{'age': now-at, 'mbps': rate, 'latency': latency, 'counted': 0 <= now-at <= max_age}
                        for at, rate, latency in sample.successes],
            'window': max_age, 'score': value,
            'terms': None if terms is None else dict(zip(('mbps', 'latency', 'rate_factor', 'latency_factor'), terms), cap=settings.rate_cap_mbps),
            'margin': margin, 'probes': probes, 'role': role,
            'flags': [f'active in {tag}' for tag in elsewhere] + [f'running {p}' for p in running] + ([f'requested {requested.value}'] if requested else [])
                     + ([f'confirm {sample.confirm.value}'] if sample.confirm else [])}


def _dur(seconds):
    if seconds is None:
        return '—'
    for unit, size, limit in (('s', 1, 90), ('m', 60, 5400), ('h', 3600, 172800)):
        if seconds < limit:
            return f'{seconds/size:.0f}{unit}' if unit != 'h' else f'{seconds/size:.1f}h'
    return f'{seconds/86400:.1f}d'


def _ago(seconds):
    return 'never' if seconds is None else _dur(seconds) + ' ago'


def _due(seconds):
    return '—' if seconds is None else 'now' if seconds <= 0 else 'in ' + _dur(seconds)


def _num(value, digits=2):
    return '—' if value is None else f'{value:.{digits}f}'


def _table(header, rows, classes=()):
    e = lambda v: html.escape(str(v))
    head = ''.join(f'<th>{e(h)}</th>' for h in header)
    classes = list(classes) + [None] * (len(rows) - len(classes))
    body = ''.join((f'<tr class={c}>' if c else '<tr>') + ''.join(f'<td>{cell}</td>' for cell in row) + '</tr>'
                   for row, c in zip(rows, classes))
    return f'<div class=wrap><table><tr>{head}</tr>{body}</table></div>'


def _tone(text, tone=None):
    """Escaped text; only good ('ok') and failed ('bad') states are colored."""
    return f'<span class={tone}>{html.escape(str(text))}</span>' if tone in ('ok', 'bad') else html.escape(str(text))


def _cell(main, *subs):
    """Pre-escaped main markup above muted, escaped detail lines."""
    return main + ''.join(f'<div class=sub>{html.escape(str(s))}</div>' for s in subs)


def _kv(pairs):
    """Label/value rows; values are pre-escaped markup."""
    return ('<div class=wrap><table class=kv>' + ''.join(f'<tr><th>{html.escape(k)}</th><td>{v}</td></tr>' for k, v in pairs)
            + '</table></div>')


REASON_TONES = {'all_paths_failed': 'bad'}


def render(page, now, wall):
    """The whole page; every value is escaped, pre-built cells contain escaped text only."""
    e = lambda v: html.escape(str(v))
    out = ['<!doctype html><html lang=en><head><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
           f'<title>Outbound manager</title><style>{STYLE}</style></head><body><h1>Outbound manager</h1>']
    generated = datetime.fromtimestamp(wall, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    if page is None:
        out.append(f'<p class=meta>No snapshot yet. Generated {e(generated)}.</p></body></html>')
        return ''.join(out)
    s, uplink = page['settings'], page['uplink']
    out.append(f'<p class=meta>Generated {e(generated)} · snapshot taken {e(_ago(now-page["taken"]))}; '
               'ages below are relative to the snapshot.</p>')
    uplink_state = (_tone('down: probing paused', 'bad') if uplink['down'] else _tone('up') if uplink['enabled']
                    else _tone('check disabled'))
    uplink_detail = f'; checked {_ago(uplink["checked_age"])}' + ('; checking now' if uplink['checking'] else '') \
                    + (f'; {uplink["held"]} failures held' if uplink['held'] else '')
    tiers = lambda tiers: ' › '.join('[' + ', '.join(t) + ']' for t in tiers)
    out.append(_kv([
        ('Config revision', e(page['revision'] or 'none')),
        ('Probes', (_tone('enabled') if s['probes_enabled'] else _tone('disabled'))
                   + ('' if page['probing'] == s['probes_enabled'] else ', not running')
                   + e(f'; {page["candidates"]} candidates; selectors read {_ago(page["inspected_age"])}')),
        ('Uplink', uplink_state + e(uplink_detail)),
        ('Managed selectors', e(', '.join(s['managed_selectors']) or '—')),
        ('Priorities', '<br>'.join(e(f'{t}: {tiers(x)}') for t, x in s['selector_priorities'].items()) or '—'),
        ('Provider weights', e(', '.join(f'{p} {w:g}' for p, w in s['provider_weights'].items()) or 'all 1')),
        ('Throughput', e('skip {:g} MiB, stop at {:g} MiB scored or once {:g} MiB beat the cap; cap '.format(
            *(s['throughput_mib'][i] for i in (0, 2, 1))) + f'{s["rate_cap_mbps"]:g} Mbps')),
        ('Shortlist · rotation', e(', '.join(f'{p} {s["shortlist"][p]} · every {_dur(s["rotation"][p])}'
                                             for p in s['shortlist']) or '—')),
        ('Probe URLs', '<br>'.join(e(u) for u in s['probe_urls']))]))
    out.append('<h2>Selectors</h2>')
    out.append(_table(['selector', 'owner', 'choice', 'resolved leaf', 'last decision'], [
        [e(x['tag']), _tone('manager') if x['managed'] else _tone('native'),
         e(x['now'] or 'unknown'), e(x['leaf'] or 'unknown'),
         _cell(_tone(x['decision']['reason'], REASON_TONES.get(x['decision']['reason'])),
               _ago(x['decision']['age'])) if x.get('decision') else '—']
        for x in page['selectors']]))
    for x in page['selectors']:
        if 'rows' in x:
            out.append(_selector(x))
    out.append('<h2>How decisions are made</h2><ul class=rules>'
               f'<li>Score = weight × (min(median Mbps, {s["rate_cap_mbps"]:g}) / 10)<sup>0.6</sup> × '
               '(200 / max(median latency ms, 20))<sup>0.4</sup>, over the last three throughput samples.</li>'
               f'<li>Samples count for {_dur(ACTIVE_SCORE_MAX_AGE)} on the current choice and {_dur(SCORE_MAX_AGE)} '
               'on standbys. Struck-through samples have aged out.</li>'
               '<li>Only a healthy path is scored, and a lower tier is eligible only once every path above it has failed.</li>'
               f'<li>An elective switch needs a challenger at least {MARGIN:g}× the current score, the {_dur(HOLD)} '
               'hold to be over, and a fresh throughput test taken after the challenge began.</li>'
               '<li>A return to a higher tier skips the margin. If the current choice fails, the hold and margin are '
               'bypassed once a replacement passes a throttle check.</li></ul></body></html>')
    return ''.join(out)


def _selector(x):
    e = lambda v: html.escape(str(v))
    d, incumbent = x['decision'], x['incumbent']
    pairs = [('Decision', _cell(_tone(d['reason'], REASON_TONES.get(d['reason']))
                                + e(f' → {d["target"] or "keep current"}, since {_ago(d["age"])}')) if d else 'none yet'),
             ('Hold', (_tone('over') if not x['hold_left'] else _tone(f'{_dur(x["hold_left"])} left'))
                      + e(f'; last change {_ago(x["switched_age"])}')),
             ('Tiers', e(' › '.join('[' + ', '.join(t) + ']' for t in x['tiers']) if x['tiers'] else 'none, score only')),
             ('Current score', e(f'{_num(incumbent)} ({_dur(ACTIVE_SCORE_MAX_AGE)} window); a challenger needs '
                                 f'≥ {_num(incumbent and incumbent*MARGIN)}' if incumbent is not None else
                                 'unscored; any scored challenger qualifies'))]
    if x['pending']:
        pairs.append(('Challenge', e(f'{x["pending"]["candidate"]}, started {_ago(x["pending"]["age"])}')))
    for t in x['tests']:
        pairs.append(('Requested', e(f'{t["probe"]} on {t["candidate"]}: last {_ago(t["last_age"])}, '
                                     f'next {_due(t["retry_in"])}')))
    if x['unmeasured']:
        pairs.append(('Unmeasured', e(', '.join(x['unmeasured']))))
    rows, classes = [], []
    eligibility_tones = {'eligible': 'ok', 'failed': 'bad'}
    for i, r in enumerate(x['rows'], 1):
        samples = ''.join(f'<div{"" if s["counted"] else " class=x"}>{e(_num(s["mbps"], 1))} Mbps · '
                          f'{e(_num(s["latency"], 0))} ms · {e(_ago(s["age"]))}</div>' for s in r['samples']) or '—'
        t = r['terms']
        if t is None:
            score = _cell(_tone('unscored'), r['health'] if r['health'] != 'healthy'
                          else 'no sample in ' + _dur(r['window']))
        else:
            score = _cell(f'<b>{e(_num(r["score"]))}</b>',
                          f'{_num(t["mbps"], 1)} Mbps → cap {_num(min(t["mbps"], t["cap"]), 1)} → ^0.6 = {_num(t["rate_factor"])}',
                          f'{_num(t["latency"], 0)} ms → ^0.4 = {_num(t["latency_factor"])}',
                          f'× weight {r["weight"]:g}, {_dur(r["window"])} window')
        m = r['margin']
        if m is None:
            margin = '—'
        elif m['kind'] == 'current':
            margin = _tone('current')
        elif m['kind'] == 'priority_return':
            margin = _cell(_tone('higher tier', 'ok'), 'no margin needed')
        elif m['challenger'] is None:
            margin = _tone('unscored')
        elif m['incumbent'] is None:
            margin = _cell(_tone('passes', 'ok'), 'current unscored')
        else:
            margin = _cell(_tone('passes', 'ok') if m['passes'] else _tone('fails', 'bad'),
                           f'{m["challenger"]/m["incumbent"]:.2f}× of current, needs {MARGIN:g}×')
        health = _cell(_tone(r['health'], 'bad' if r['health'] == 'failed' else None),
                       f'{r["failures"]} failures' + (f' ({r["failed_probe"]})' if r['failed_probe'] else ''),
                       f'healthy {_ago(r["healthy_age"])}', f'latency {_num(r["latency"], 0)} ms')
        eligibility = _tone(r['eligibility'], eligibility_tones.get(r['eligibility']))
        probes = ''.join(f'<div>{e(name)} <span class=sub>{e(_ago(p["last_age"]))}'
                         + (f', {e(p["outcome"])}' if p['outcome'] and p['last_age'] is not None else '')
                         + f' · next {e(_due(p["due_in"]))}</span></div>'
                         for name, p in r['probes'].items())
        classes.append('cur' if r['current'] else 'off' if r['tier'] == 'excluded' or r['health'] == 'failed' else None)
        rows.append([e(i), _cell(e(r['tag']), r['provider']),
                     e('—' if r['tier'] is None else r['tier']), e(f'{r["weight"]:g}'), health, eligibility,
                     samples, score, margin, probes, _cell(e(r['role'] or ('' if r['flags'] else '—')), *r['flags'])])
    return (f'<h2>{e(x["tag"])}</h2>' + _kv(pairs)
            + _table(['#', 'candidate', 'tier', 'weight', 'health', 'eligibility', 'samples',
                      'score', 'vs current', 'probes', 'role'], rows, classes))


class _Server(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind does a reverse DNS lookup; never block the main loop on it.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Dashboard:
    def __init__(self, log):
        self.log, self.server, self.address = log, None, None
        self.page, self.built, self.failing = None, -INF, False

    def listen(self, address):
        """Bind the configured address; a bind failure is logged and retried on the next settings load."""
        if address == self.address:
            return
        self.close()
        if address is None:
            return
        host, port = dashboard_address(address)
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            timeout = 10
            server_version, sys_version = 'spoofskipper', ''
            def reply(self, code, body, head=False):
                self.send_response(code)
                for name, value in {**HEADERS, 'Content-Type': 'text/html; charset=utf-8',
                                    'Content-Length': str(len(body))}.items():
                    self.send_header(name, value)
                self.end_headers()
                if not head:
                    self.wfile.write(body)
            def send_error(self, code, message=None, explain=None):
                # Errors (including unsupported methods) get the same headers and a bare body.
                self.close_connection = True
                self.reply(code, html.escape(f'{code} {message or self.responses.get(code, ("",))[0]}').encode())
            def do_GET(self, head=False):
                if urlsplit(self.path).path != '/':
                    self.reply(404, b'not found', head)
                    return
                try:
                    body, code = render(owner.page, time.monotonic(), time.time()).encode(), 200
                except Exception as exc:
                    body, code = html.escape(f'render failed: {type(exc).__name__}').encode(), 500
                self.reply(code, body, head)
            def do_HEAD(self):
                self.do_GET(head=True)
            def log_message(self, *_):
                pass
        server_class = type('Server', (_Server,), {'address_family': socket.AF_INET6 if ':' in host else socket.AF_INET})
        try:
            self.server = server_class((host, port), Handler)
        except OSError as exc:
            self.log('dashboard_failed', address=address, error=type(exc).__name__)
            return
        self.address = address
        threading.Thread(target=self.server.serve_forever, name='dashboard', daemon=True).start()
        self.log('dashboard_listening', address=address)

    def refresh(self, scheduler, config):
        """Replace the snapshot at most once a second; the server thread only reads the reference."""
        now = scheduler.clock()
        if self.server is None or now-self.built < SNAPSHOT_SECONDS:
            return
        self.built = now
        try:
            self.page, self.failing = snapshot(scheduler, config, now), False
        except Exception as exc:
            if not self.failing:
                self.log('dashboard_snapshot_failed', error=type(exc).__name__)
            self.failing = True

    def close(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        self.server, self.address = None, None
