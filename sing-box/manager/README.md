# Outbound manager

The manager supervises sing-box, refreshes subscriptions at startup and every two
hours, and optionally measures and selects proxy paths. It starts the saved
`/data/sing.json` before refreshing. `/reload` sends SIGHUP: reloads use cached
subscriptions and current settings without fetching providers.

Private inputs are read-only under `/config`: `sing.jsonnet`, `config.jsonnet`,
and optional `local-subs-config.json` and `local-manager.json`. The manager renders
a scratch copy of `/config` in which the merged subscriptions replace
`local-subs.json`, so `config.jsonnet` keeps importing it unchanged. Without
`local-subs-config.json` there are no providers and `/config` renders as is.
State under `/data` contains live/previous JSON, an activation marker, and
provider snapshots. Keep private inputs out of version control.

`ZAPRET_PRERUN` is an optional shell hook before manager startup. `CONFIG_TMPL`
is no longer supported; use `/config/sing.jsonnet` or the CLI `--config-dir`.
Keep Compose's stop grace period greater than `shutdown_timeout`.

The manager verifies activations through the Clash API. It connects to the
configured `external_controller` (loopback for an empty or unspecified host such
as `:9090`). Without one, the manager adds `127.0.0.1:<clash_api_port>` with a
secret generated once and kept in `/data/clash-api-secret`.

## Settings

Missing `local-manager.json` means probes disabled and no selector ownership.
Invalid settings disable probes and ownership until fixed, while rendering and
subscription refresh continue; `settings_invalid` records that fallback.
Settings are validated on load. Cadences/deadlines below are positive seconds.

| Setting | Default | Meaning |
|---|---|---|
| `probes_enabled` | `false` | Add loopback probe routes and run measurements |
| `managed_selectors` | `[]` | Selector tags the manager may write; requires probes |
| `provider_weights` | `{}` | Positive finite weight by subscription prefix or local proxy/endpoint tag; omitted weights are 1 |
| `selector_priorities` | `{}` | Ordered provider tiers per selector; omitted selectors use score alone |
| `refresh_seconds` | 7200 | Subscription refresh interval |
| `revision_timeout` | 30 | Core revision verification deadline |
| `shutdown_timeout` | 10 | Graceful child stop before forced termination |
| `bootstrap_backoff_seconds` | 5 | Initial retry delay |
| `bootstrap_backoff_max_seconds` | 300 | Maximum bootstrap retry delay |
| `gate_active_seconds` | 60 | Active-path gate interval |
| `gate_standby_seconds` | 480 | Standby-path gate interval |
| `throttle_seconds` | 300 | Active-path threshold check interval |
| `throughput_active_seconds` | 3600 | Active throughput interval |
| `throughput_shortlist_seconds` | 21600 | Throughput interval for the 3 best-scored healthy standbys per provider |
| `throughput_rotation_seconds` | 14400 | Interval of one extra throughput test per provider on its least recently tested other standby |
| `probe_workers` | 4 | Concurrent gates, integer 1–4; body checks/downloads are serial |
| `probe_port` | 19090 | Loopback mixed inbound port, integer 1–65535 |
| `clash_api_port` | 19089 | Loopback Clash API port added when the config has no `external_controller` |
| `probe_timeout` | 15 | Overall probe deadline, maximum 15 |
| `probe_stall_timeout` | 2 | Body stall deadline |
| `throughput_seconds` | 4 | Throughput body time box after headers, maximum 4 |
| `probe_urls` | Cloudflare `__down`, then the OVH 100 MiB file | Verified HTTPS endpoints: the first is measured, later ones confirm failures |
| `uplink_urls` | `https://ya.ru/`, `https://yastatic.net/` | HTTPS URLs reached directly, never through a proxy; empty disables the uplink check |
| `probe_ca_bundle` | System trust | Optional trusted CA file |
| `dashboard_listen` | absent (disabled) | `ip:port` (IPv6 as `[addr]:port`) of the read-only status page |

Subscription bodies are limited to 16 MiB and 60 seconds per fetch. Fetches bind to
the interface of the main table's default route, so they leave directly (as a host
cron did) instead of being captured by the supervised core's tun, where they would
arrive without a domain and follow the final rule. Loopback destinations, hosts
without a default route, or a process
without the privilege to bind use normal routing.
Subscription specs retain the existing format; provider prefixes must be unique
(a missing prefix is `''`, as in `sing-subs`). Local proxy leaves are discovered from the rendered graph;
direct/block/DNS entries are excluded. Protocols have no special preference.

For example, these synthetic settings prefer two subscription providers equally
before a local proxy. Providers outside an explicit tier list are excluded.

```json
{
  "probes_enabled": true,
  "managed_selectors": ["restricted"],
  "provider_weights": {"provider-a": 1.25, "provider-b": 1.0},
  "selector_priorities": {"restricted": [["provider-a", "provider-b"], ["local-proxy"]]}
}
```

Every probe is one HTTPS request through the path, differing only in size. A URL
with a `{bytes}` placeholder is asked for exactly that many bytes; a URL without
one must be a static file of at least 9 MiB, read with a `Range` request.

| Probe | Body | Proves |
|---|---|---|
| `gate` | 1 byte | Reachability and latency |
| `throttle` | 256 KiB | The connection keeps working past the throttling threshold |
| `throughput` | up to 9 MiB | Rate after the first 1 MiB; also passes the threshold |

A path is healthy only after a `throttle` or `throughput` probe reads past 256 KiB.
Gates keep proven health fresh but cannot make an unknown or failed path healthy,
because throttling middleboxes pass small responses and stall larger ones. A
failed probe is repeated immediately against each next endpoint in `probe_urls`;
the path is failed once every endpoint failed in a row (two attempts with a
single endpoint), so an outage or block of one endpoint does not fail working
paths. Only the first endpoint's latency and
throughput are scored, keeping scores comparable; while it is unreachable,
paths stay healthy through the fallback but their scores age out, so only
failover and priority returns (which accept fallback proof) still switch. A
failed path that answers a gate gets one `throttle` re-check per gate.

A probe failure counts only after a direct request to one of `uplink_urls`
succeeds (any HTTP response; a success within the last 30 seconds is reused).
If none answers, the uplink is down: failures are dropped, probing and policy
pause, and the uplink is rechecked every 10 seconds until it returns. This keeps
a local outage from failing every path and reshuffling selectors afterwards.

A higher tier must be failed before a lower tier is eligible. Unknown health
requests gates first. Failure of the active path bypasses the hold and score
margin, but the best-ranked replacement must first pass a `throttle` check taken
after the failure; if it fails too, the next one is checked. If the probe
endpoint itself is down, no path qualifies and the current route is kept.
All-path failure keeps the current route and never adds direct routing.

The five-minute elective hold and 15% improvement margin are fixed policy rules,
not configurable cadences. Scores use the last three successful throughput/latency
samples, capped at 100 Mbps and weighted by provider. Active scores expire after
two hours, standby scores after two days. Every elective switch, including a
switch requires a `throughput` result taken after the hold and no older than 30
seconds. A return to a higher tier skips the margin and accepts any fresh proof
past the threshold from that request, including a fallback endpoint's. A failed or stale challenge is
retried after 30 minutes. Attempts cancelled by a reload or selector write can be
retried immediately; upstream-change and worker-error discards retain their
normal scheduling timestamps.

Throughput runs on active paths and on the three best-scored healthy standbys of
each provider (unscored ones by latency). Every four hours, one more standby per
provider, the least recently tested, gets a throughput test, so every healthy
path is eventually scored and can enter the shortlist. It skips 1 MiB (TCP slow start), then reads for at
most four seconds after the response headers, stopping early at 8 MiB scored or
once 4 MiB show a rate above 100 Mbps. Native URLTest checks remain independently active.

Approximate probe traffic with default cadences, for fast paths:

| Source | Volume |
|---|---|
| Each active path | up to about 290 MiB/day (throttle every 5 min, throughput hourly, at most 9 MiB each) |
| Each provider's 3 shortlisted standbys | up to about 108 MiB/day together |
| Each provider's rotation | up to about 54 MiB/day |
| Gates | a TLS handshake each: every minute (active) or 8 minutes (standby) |
| Failed paths that still answer gates | one `throttle` attempt per gate; throttled paths usually stall within tens of KiB |

Slow paths read less, because throughput is time-boxed.

## Status page

With `dashboard_listen` set, the manager serves one read-only HTML page at `/`
showing its current in-memory state: settings, uplink, every selector's choice
and, for managed selectors, the last decision, hold and pending challenge, and a
table of candidates in policy order (tier, then score) with health, samples, the
score breakdown, the 15% margin against the current choice and probe due times.
The main loop copies a plain snapshot at most once a second between scheduler
ticks; a daemon thread renders it, so a slow client never blocks supervision.
It shows tags, provider names and numbers only, never outbound definitions,
subscription URLs or the Clash API secret. Its CSP allows nothing but the page's own
stylesheet and sandboxes it (no scripts, forms or framing); errors carry the same headers.
There is no authentication: bind it to a LAN address, for example the sing-tun
container IP (`"dashboard_listen": "192.168.55.9:9091"`), then `/reload`.
Invalid settings fall back to defaults, which also disables the page.

## Enable and disable

1. Save the pre-cutover `docker-compose.yml`, `.env`, image tag and crontab.
2. While the old core still serves, seed provider snapshots with the new image:
   `docker run --rm --network host -v ./config/sing:/config:ro -v ./data:/data <image> bootstrap`.
   Without snapshots the first `serve` fetches before starting the core, which
   deadlocks when provider egress depends on that core. `bootstrap` writes
   nothing and exits nonzero unless every provider has a snapshot.
3. Disable only the subscription cron job and verify no refresh is running.
4. Keep the existing loopback-reachable Clash API controller; authentication is
   optional. Start with probes disabled and no managed selectors.
5. Verify the revision and existing routes. Enable probes and `/reload` to observe
   `probe_sample` logs. Add selectors one at a time.

A managed selector is flattened to proxy leaves while preserving its resolved
choice through a verified write. Native groups are left in place.
Dashboard changes to managed selectors may be overwritten by policy.

To return one selector to native control, remove it from `managed_selectors` and
`/reload`, then select the restored native group in the dashboard if needed.
To disable all policy and measurements, empty the list, disable probes and
`/reload`. The manager remains the sole subscription refresh owner. Revocations
apply before rendering, including when an unrelated render fails.

## Recovery and full rollback

Failed activation restores and verifies the previous core once. Interrupted
activation restores previous JSON before startup. Failed recovery leaves the
marker and exits nonzero. A saved config that fails to start is stopped and
replaced by a fresh render from `/config`. First-install failures retry in-process and discard
unverified JSON. Unexpected child exit triggers Docker restart.

For full image/cron rollback:

1. Stop the manager container.
2. Run `sing-subs/merge-subs.py` once with the private specs to update `local-subs.json`.
   It imports the shared parser from `sing-box/manager`, so run it from a full checkout.
3. Restore the pre-cutover `docker-compose.yml` and `.env`, for example from the
   saved pre-cutover commit. Verify `sing-tun.command` is
   `['run', '-c', '/tmp/sing.json']` and `.env` selects the old image tag.
4. Start that image through restored Compose on the same `/data`.
5. Restore the subscription cron job and verify exactly one refresh scheduler.

The old image ignores manager state. Reverting the image tag alone is insufficient:
the legacy entrypoint needs the restored Compose command.

## Tests

```sh
python3 -m unittest discover -s sing-box/manager/tests/unit
docker build --build-arg REVISION=v1.14.3 -t spoofskipper-manager:test sing-box
sing-box/manager/tests/run-integration
```

The integration harness uses the preloaded `spoofskipper-manager:test`, mounted
code/tests, an unprivileged user and an internal Docker network. It uses
synthetic fixtures and no real providers; fixture keys are public test credentials.
Core/Jsonnet error output is suppressed in logs to protect secrets.

## Logs

| Events | Operator meaning |
|---|---|
| `core_started`, `saved_config_started`, `revision_verified` | Core startup and verified configuration |
| `activation_succeeded`, `activation_unchanged` | Checked render activated, or identical config already running (not re-checked) |
| `activation_failed`, `revision_timeout`, `rollback_succeeded` | New config failed; inspect recovery outcome |
| `rollback_failed`, `selector_rollback_failed`, `unexpected_core_exit` | Recovery failed or core died; investigate before rollout |
| `interrupted_activation_restored` | Interrupted activation recovered from previous JSON |
| `settings_invalid`, `cached_render_failed`, `refresh_failed` | Settings/render/fetch problem; saved state may still serve traffic |
| `provider_refreshed`, `provider_refresh_failed` | Per-provider refresh result; failed providers retain last-good snapshots |
| `bootstrap_waiting_for_providers` | No usable provider snapshot yet; retrying |
| `bootstrap_completed`, `bootstrap_failed` | One-shot `bootstrap` seeded every provider, or wrote nothing (`missing` lists providers) |
| `probe_sample`, `probe_failed`, `probe_discarded` | Measurement result, failure or invalidated result |
| `uplink_down`, `uplink_restored` | Direct uplink check failed (probing paused) or recovered |
| `probe_inspection_failed`, `scheduler_tick_failed` | Measurement/control error logged while the core remains running |
| `selector_decision`, `selector_switched`, `selector_handoff`, `selector_write_failed` | Policy reason, verified write or write failure |
| `shutdown_requested`, `manager_failed` | Requested shutdown or startup failure |
| `dashboard_listening`, `dashboard_failed`, `dashboard_snapshot_failed` | Status page bound, bind failed (retried on the next settings load), or snapshot error (logged once until it recovers) |

Repeated `scheduler_tick_failed` errors are logged at most once per error type
per minute, with a cumulative `count`. The manager keeps retrying ticks and
supervising the core.
