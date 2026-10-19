# Outbound manager (stage 2)

The container runs the Python manager as PID 1. It starts saved `/data/sing.json`
first, applies current cached inputs, then refreshes subscriptions at startup and
every two hours. `/reload` sends SIGHUP only: it renders cached subscriptions and
current private settings without fetching. Selectors and native URLTest behavior
come from the existing Jsonnet. Set `probes_enabled: true` to enable observe-only measurements. Selector writes
remain unavailable; nonempty `managed_selectors` is rejected.

Private inputs are read-only `/config/sing.jsonnet`, `config.jsonnet`,
`local-subs-config.json` (existing format, unique nonempty provider `prefix`), and
optional `local-manager.json`. Synthetic examples live in `tests/fixtures/`.
`provider_weights` maps prefixes to positive numbers and defaults to 1.0. Manager
cadences/deadlines in seconds: `refresh_seconds` 7200, `revision_timeout` 30,
`shutdown_timeout` 10, `bootstrap_backoff_seconds` 5,
`bootstrap_backoff_max_seconds` 300. Keep the Compose stop grace period greater
than `shutdown_timeout`. Probes default to disabled; native URLTest groups continue their existing checks.

## Private cutover edits (owner applies at authorized rollout)

Save the original private file as `config.jsonnet.legacy`. Replace exactly this
line in `config.jsonnet`:

```jsonnet
local sub_data = std.parseJson(importstr 'local-subs.json');
```

with:

```jsonnet
local sub_data = std.extVar('subscription_outbounds');
```

Keep the existing Clash API configuration. A loopback-reachable
`clash_api.external_controller` is required; `clash_api.secret` is optional.
Wildcard listeners such as `[::]:9090` are inspected through loopback. The manager
only sends authentication when a secret is configured, using each rendered JSON's
settings, including the previous JSON during rollback. It refuses the
old subscription import; stale `local-subs.json` cannot shadow its external value.
Do not commit private settings or the legacy template.

Disable **only** the subscription cron job and verify no refresh is running before
starting this image. Keep the pre-cutover image tag and crontab. Seed `/data/providers`
from a checked scratch dry-run; do not replace the running core's `cache.db`.
Stage 1 settings are `probes_enabled: false`, `managed_selectors: []` (also the
missing-file defaults). No deployment or push is part of local implementation.

## Scratch diagnostics

Build with the pinned revision using the existing `./sing-box` build context.
Preload the image before running offline checks. For example, from the repository:

```sh
docker build --build-arg REVISION=v1.14.3 -t spoofskipper-manager:stage2 sing-box
# CONFIG is an absolute config directory; SCRATCH is a private, separate directory.
docker run --rm --tmpfs /data -v "$CONFIG:/config:ro" -v "$SCRATCH:/scratch" \
  spoofskipper-manager:stage2 refresh-dry-run --state-dir /scratch/fetched
docker run --rm --network none --tmpfs /data \
  -v "$CONFIG:/config:ro" -v "$SCRATCH:/scratch" spoofskipper-manager:stage2 \
  render-check --state-dir /scratch/comparison --snapshots /scratch/fetched
```

Each diagnostic requires a new empty state directory, separate from `/config` and
live `/data`. `refresh-dry-run` fetches/checks/commits scratch provider snapshots
without starting a core. `render-check` requires the **unedited** private template;
it derives the one-line edit in a temporary copy and fails if the expected import
line is absent or repeated. Both baseline and manager renders pass pinned
`sing-box check`. The private diff is written mode 0600 to
`comparison/render.diff`; it may contain credentials, so keep it private. With
identical subscription inputs the only difference is the inert revision outbound.
Fresh inputs may also show expected subscription changes. Diagnostics never write
to `/config` or the live data mount. Jsonnet/core check diagnostics are suppressed
in logs because they can quote secrets.

## Recovery and rollback

The only durable manager state is live/previous JSON, `activating`, and per-provider
snapshots. Successful checks update snapshot ages even on unchanged renders.
Changed renders commit snapshots only after API revision verification. A failed
runtime activation restores previous JSON and restarts/verifies the child once;
failed recovery leaves the marker and exits nonzero. An interrupted activation
restores previous JSON before starting the saved core. Zero-provider startup backs
off in-process; first-start check/runtime retries reuse already-fetched inputs.
An unexpected child exit causes nonzero manager exit and Docker restart.

For full rollback: stop the manager image; restore `config.jsonnet.legacy`; run
`sing-subs/merge-subs.py` once with the private specs to update `local-subs.json`;
start the pre-cutover image on the same `/data`; restore the subscription cron job
and verify exactly one scheduler. The old image ignores all manager state.

## Tests

```sh
python3 -m unittest discover -s sing-box/manager/tests/unit
python3 -m unittest discover -s sing-box/manager/tests/integration
sing-box/manager/tests/run-integration
sing-box/manager/tests/run-rollback
```

Host integration requires Jsonnet; pinned-core tests also require sing-box.
`run-integration` uses preloaded `spoofskipper-manager:stage2` on Docker Desktop,
as an unprivileged user with a read-only root filesystem, no capabilities/TUN,
and an internal Compose network without internet access. It mounts tests/code
read-only and uses local subscription/API fault fixtures plus the real pinned
core. The same harness tests real Trojan, Shadowsocks, Hysteria2 and VLESS/Reality
paths, test-CA HTTPS faults, authentication, and application-byte accounting.

`run-rollback` also needs a preloaded `spoofskipper-legacy:stage1` built from the
pre-stage Dockerfile/entrypoint/reload. It uses synthetic specs, isolated Docker
network namespaces, and the same scratch data for both images. It stops the
manager scheduler, restores the legacy template, executes the legacy refresh
once, verifies the old core's API has no revision outbound, and checks the old
image leaves manager state unchanged. Tests do not contact real providers.

## Observe-only probes

Enabling probes adds one loopback mixed inbound (default port 19090), a private
user derived from each rendered candidate, and inbound/user routes placed before
production rules. Unknown probe traffic is rejected. Subscription candidates and
the endpoint detouring through `warp_upstream` are measured without changing any
selector. Disable probes and `/reload` to remove these routes while keeping the
manager as the sole subscription refresh owner.

Settings (seconds) default to `gate_active_seconds: 60`,
`gate_standby_seconds: 480`, `throttle_seconds: 300`,
`throughput_active_seconds: 3600`, `throughput_shortlist_seconds: 21600`,
`throughput_sweep_seconds: 172800`, `early_test_seconds: 1800`.
`probe_workers` is 1–4 concurrent gates; downloads/corroboration run serially.
`probe_timeout` defaults to 15 (maximum 15), `probe_stall_timeout` to 2,
`throughput_seconds` to 4 (maximum 4). `probe_port` is configurable.
`probe_url` defaults to `https://speed.cloudflare.com/__down?bytes={bytes}`;
`probe_backup_url` defaults to `https://proof.ovh.net/files/1Mb.dat`.
`probe_ca_bundle` optionally supplies a trusted CA file for isolated fixtures.
HTTPS certificates are always verified. `http.client` handles CONNECT and HTTP
parsing, including chunked responses. Endpoints must return identity bodies with
explicit framing; gate/throttle sizes are exact. Backup Range may return a
validated 206 or a 200 bounded to 256 KiB received.

Throughput skips 512 KiB and closes early at four seconds, 4 MiB scored, or
256 KiB of post-skip evidence above 50 Mbps. Results without enough post-skip
data have unknown performance. Three gate failures trigger backup HEAD;
body failures trigger HEAD and a ranged body check. A tiny success cannot clear
a body failure. Slow, complete bodies do not imply a fixed throughput floor.

Samples remain in memory and survive reload only for unchanged rendered outbound
keys. Results crossing activation/rollback are discarded. WARP also checks the
resolved upstream before and after each measurement. Restart starts with gates,
then latency-ranked shortlist bootstrap; remaining sweeps are staggered. There
are no catch-up bursts. Hourly `observe_summary` logs contain active choices,
scores/sample ages, proposed rankings and application-byte totals for the rolling
hour (minute resolution) and UTC day. `probe_sample`, `probe_failed`,
`probe_corroboration`, and `probe_discarded` explain measurements.
Counts include plaintext CONNECT/HTTP requests, response headers and framing,
received bodies, partial attempts, skipped prefixes and backup requests. Received
bytes include HTTP buffer read-ahead; `body_received` counts decoded body bytes
consumed by the measurement. TLS, transport, and unread server-side buffers after
an early close are excluded. These
counters are not wire traffic or a billing estimate. Proposed rankings are
observe-only; stage 3 adds switching holds, fresh challenger tests and writes.

`tests/fixtures/probe-key.pem` and the Reality keys in the protocol test are
public synthetic test credentials. Never use them outside the offline harness.
