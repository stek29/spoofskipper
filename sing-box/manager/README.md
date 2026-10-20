# Outbound manager

The manager supervises sing-box, refreshes subscriptions at startup and every two
hours, and optionally measures and selects proxy paths. It starts the saved
`/data/sing.json` before refreshing. `/reload` sends SIGHUP: reloads use cached
subscriptions and current settings without fetching providers.

Private inputs are read-only under `/config`: `sing.jsonnet`, `config.jsonnet`,
`local-subs-config.json`, and optional `local-manager.json`. State under `/data`
contains live/previous JSON, an activation marker, and provider snapshots. Keep
private inputs and diagnostic diffs out of version control.

`ZAPRET_PRERUN` is an optional shell hook before manager startup. `CONFIG_TMPL`
is no longer supported; use `/config/sing.jsonnet` or the CLI `--config-dir`.
Keep Compose's stop grace period greater than `shutdown_timeout`.

The manager verifies activations through the Clash API. A configured
`external_controller` must be loopback-reachable (an empty host such as `:9090`
counts). Without one, the manager adds `127.0.0.1:<clash_api_port>` with a
secret generated once and kept in `/data/clash-api-secret`.

## Settings

Missing `local-manager.json` means probes disabled and no selector ownership.
Invalid settings at restart use the saved config with probes and ownership
explicitly disabled; `settings_invalid_using_saved_config` records that fallback.
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
| `throttle_seconds` | 300 | Active-path body check interval |
| `throughput_active_seconds` | 3600 | Active throughput interval |
| `throughput_shortlist_seconds` | 21600 | Shortlisted standby throughput interval |
| `throughput_sweep_seconds` | 172800 | Remaining standby throughput interval and ranking age |
| `early_test_seconds` | 1800 | Early shortlist/challenge retry interval |
| `probe_workers` | 4 | Concurrent gates, integer 1–4; body checks/downloads are serial |
| `probe_port` | 19090 | Loopback mixed inbound port, integer 1–65535 |
| `clash_api_port` | 19089 | Loopback Clash API port added when the config has no `external_controller` |
| `probe_timeout` | 15 | Overall probe deadline, maximum 15 |
| `probe_stall_timeout` | 2 | Body stall deadline |
| `throughput_seconds` | 4 | Throughput duration, maximum 4 |
| `probe_url` | `https://speed.cloudflare.com/__down?bytes={bytes}` | Verified HTTPS endpoint with a `{bytes}` placeholder |
| `probe_backup_url` | `https://proof.ovh.net/files/1Mb.dat` | Verified HTTPS backup HEAD/Range endpoint |
| `probe_ca_bundle` | System trust | Optional trusted CA file |

Subscription bodies are limited to 16 MiB and 60 seconds per fetch.
Subscription specs retain the existing format and require unique, nonempty
provider prefixes. Local proxy leaves are discovered from the rendered graph;
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

A higher tier must be confirmed failed before a lower tier is eligible. Unknown
health requests gates first. Confirmed failure bypasses the hold and score margin;
all-path failure keeps the current route and never adds direct routing.

The five-minute elective hold and 15% improvement margin are fixed policy rules,
not configurable cadences. Scores use the last three successful throughput/latency
samples, capped at 50 Mbps and weighted by provider. Active scores expire after
two hours. Elective switches require a new post-hold challenger measurement.
Return from a working lower tier requires post-hold throughput and throttle
checks no more than `30 + probe_timeout` seconds apart, with the throttle
completed within 30 seconds of the decision. An expired pair starts a new
challenge immediately. Attempts cancelled by a reload or selector write can
be retried immediately; upstream-change and worker-error discards retain their
normal scheduling timestamps.

Three failed gates request backup HEAD. Body failures require body evidence;
HEAD/tiny successes cannot clear them. Throughput skips 512 KiB and stops at four
seconds, 4 MiB scored, or sufficient evidence above 50 Mbps. Insufficient evidence
means unknown performance; after two unknown results, early shortlist downloads
back off to the sweep cadence. Native URLTest checks remain independently active.

## Enable and disable

1. Save the pre-cutover `docker-compose.yml`, `.env`, image tag, crontab, and
   private `config.jsonnet` as `config.jsonnet.legacy`.
2. Disable only the subscription cron job and verify no refresh is running.
3. Replace exactly `local sub_data = std.parseJson(importstr 'local-subs.json');`
   in private `config.jsonnet` with
   `local sub_data = std.extVar('subscription_outbounds');`.
4. Keep the existing loopback-reachable Clash API controller; authentication is
   optional. Seed `/data/providers` from a checked scratch dry-run, preserving
   the running core's `cache.db`. Start with probes disabled and no managed selectors.
5. Verify the revision and existing routes. Enable probes and `/reload` to observe
   measurements. Add selectors one at a time after reviewing the summaries.

A managed selector is flattened to proxy leaves while preserving its resolved
choice through a verified write. Shared native groups remain while referenced.
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
2. Restore `config.jsonnet.legacy` to `config.jsonnet`.
3. Run `sing-subs/merge-subs.py` once with the private specs to update `local-subs.json`.
   It imports the shared parser from `sing-box/manager`, so run it from a full checkout.
4. Restore the pre-cutover `docker-compose.yml` and `.env`, for example from the
   saved pre-cutover commit. Verify `sing-tun.command` is
   `['run', '-c', '/tmp/sing.json']` and `.env` selects the old image tag.
5. Start that image through restored Compose on the same `/data`.
6. Restore the subscription cron job and verify exactly one refresh scheduler.

The old image ignores manager state. Reverting the image tag alone is insufficient:
the legacy entrypoint needs the restored Compose command.

## Diagnostics and verification

Use separate, empty scratch directories and read-only config mounts. Never use
live `/data` for diagnostics. `render-check` expects the unedited private template
and derives the extVar change in a temporary copy. Its mode-0600 `render.diff`
can contain credentials. Core/Jsonnet error output is suppressed to protect secrets.

```sh
docker build --build-arg REVISION=v1.14.3 -t spoofskipper-manager:test sing-box
docker run --rm --tmpfs /data -v "$CONFIG:/config:ro" -v "$SCRATCH:/scratch" \
  spoofskipper-manager:test refresh-dry-run --state-dir /scratch/fetched
docker run --rm --network none --tmpfs /data \
  -v "$CONFIG:/config:ro" -v "$SCRATCH:/scratch" spoofskipper-manager:test \
  render-check --state-dir /scratch/comparison --snapshots /scratch/fetched
python3 -m unittest discover -s sing-box/manager/tests/unit
sing-box/manager/tests/run-integration
sing-box/manager/tests/run-rollback
```

The integration harness uses the preloaded `spoofskipper-manager:test`, mounted
code/tests, an unprivileged user and an internal Docker network. Rollback also
requires `spoofskipper-legacy:test`, built from the pre-cutover Dockerfile,
entrypoint and reload script. It restores release inputs from `b03a046`
(overridable with `MANAGER_LEGACY_REF`) and exercises their Compose command.
Both harnesses use synthetic fixtures and no real providers. Fixture keys are
public test credentials. The historical live driver is archived with private validation notes outside
the tracked suite; it is not a supported test interface for this runtime.

## Logs

| Events | Operator meaning |
|---|---|
| `core_started`, `saved_config_started`, `revision_verified` | Core startup and verified configuration |
| `activation_succeeded`, `activation_unchanged` | Checked render activated or already running |
| `activation_failed`, `revision_timeout`, `rollback_succeeded` | New config failed; inspect recovery outcome |
| `rollback_failed`, `selector_rollback_failed`, `unexpected_core_exit` | Recovery failed or core died; investigate before rollout |
| `interrupted_activation_restored` | Interrupted activation recovered from previous JSON |
| `settings_invalid_using_saved_config`, `cached_render_failed`, `refresh_failed` | Settings/render/fetch problem; saved state may still serve traffic |
| `provider_refreshed`, `provider_refresh_failed` | Per-provider refresh result; failed providers retain last-good snapshots |
| `bootstrap_waiting_for_providers` | No usable provider snapshot yet; retrying |
| `probe_sample`, `probe_failed`, `probe_corroboration`, `probe_discarded` | Measurement result, failure, backup evidence or invalidated result |
| `probe_inspection_failed`, `scheduler_tick_failed` | Measurement/control error logged while the core remains running |
| `selector_decision`, `selector_switched`, `selector_handoff`, `selector_write_failed` | Policy reason, verified write or write failure |
| `observe_summary` | Choices, scores/ages, actual managed decisions and unmanaged eligible rankings |
| `shutdown_requested`, `manager_failed` | Requested shutdown or startup failure |

`observe_summary.application_bytes.hour` counts application traffic since the
previous summary and resets after logging; `today` counts the UTC day. Counters
include partial attempts, CONNECT/HTTP requests, headers/framing, received bodies,
skipped prefixes and backups. `body_received` counts consumed decoded body bytes;
received bytes also include buffer read-ahead. TLS/transport overhead and unread
server buffers are excluded. These are application counters, not billing totals.

Repeated `scheduler_tick_failed` errors are logged at most once per error type
per minute, with a cumulative `count`. The manager keeps retrying ticks and
supervising the core.
