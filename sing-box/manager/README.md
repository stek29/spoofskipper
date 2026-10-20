# Outbound manager

The container runs the Python manager as PID 1. It starts saved `/data/sing.json`
first, applies current cached inputs, then refreshes subscriptions at startup and
every two hours. `/reload` sends SIGHUP only: it renders cached subscriptions and
current private settings without fetching. Selectors and native URLTest behavior
come from the existing Jsonnet. Set `probes_enabled: true` for measurements. Add
individual selectors to `managed_selectors` to enable verified policy writes.

`ZAPRET_PRERUN` remains an optional shell hook before manager startup.
`CONFIG_TMPL` is no longer supported: the manager always reads
`/config/sing.jsonnet` (or its diagnostic `--config-dir`).

Private inputs are read-only `/config/sing.jsonnet`, `config.jsonnet`,
`local-subs-config.json` (existing format, unique nonempty provider `prefix`), and
optional `local-manager.json`. Synthetic examples live in `tests/fixtures/`.
`provider_weights` maps subscription prefixes or local outbound/endpoint tags to
positive numbers and defaults to 1.0. Local proxy leaves are discovered from the
rendered configuration, regardless of protocol or tag; direct/block/DNS outbounds
are excluded from selection and probing. Manager
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
Initial settings are `probes_enabled: false`, `managed_selectors: []` (also the
missing-file defaults). No deployment or push is part of local implementation.

## Scratch diagnostics

Build with the pinned revision using the existing `./sing-box` build context.
Preload the image before running offline checks. For example, from the repository:

```sh
docker build --build-arg REVISION=v1.14.3 -t spoofskipper-manager:stage3 sing-box
# CONFIG is an absolute config directory; SCRATCH is a private, separate directory.
docker run --rm --tmpfs /data -v "$CONFIG:/config:ro" -v "$SCRATCH:/scratch" \
  spoofskipper-manager:stage3 refresh-dry-run --state-dir /scratch/fetched
docker run --rm --network none --tmpfs /data \
  -v "$CONFIG:/config:ro" -v "$SCRATCH:/scratch" spoofskipper-manager:stage3 \
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
restore the pre-cutover `docker-compose.yml` and `.env` (for example from the
pre-cutover commit). Verify `sing-tun.command` is `['run', '-c', '/tmp/sing.json']`
and `.env` selects the saved image tag, then start that image through Compose on
the same `/data`; restore the subscription cron job
and verify exactly one scheduler. The old image ignores all manager state.

## Tests

```sh
python3 -m unittest discover -s sing-box/manager/tests/unit
python3 -m unittest discover -s sing-box/manager/tests/integration
sing-box/manager/tests/run-integration
sing-box/manager/tests/run-rollback
```

Host integration requires Jsonnet; pinned-core tests also require sing-box.
`run-integration` uses preloaded `spoofskipper-manager:stage3` on Docker Desktop,
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
production rules. Unknown probe traffic is rejected. Subscribed and local proxy leaves, including their configured detours, are measured without changing any
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
keys. Results crossing activation/rollback are discarded. fallback also checks the
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
observational when `managed_selectors` is empty. Owned selectors also log their
policy reason; application counters include `policy_tests` and `challenger_tests`.

`tests/fixtures/probe-key.pem` and the Reality keys in the protocol test are
public synthetic test credentials. Never use them outside the offline harness.

## Selector ownership

`managed_selectors` is an explicit list of selector tags in the rendered config;
it defaults to empty and requires `probes_enabled: true`.
Enable one selector at a time after reviewing observe-only logs, then `/reload`.
The manager flattens that selector's native group references to subscribed leaves
and local proxy leaves, preserving its current resolved leaf through a verified API write.
Unknown/direct/incompatible members and dependency cycles reject the render.
Shared native URLTest groups remain until their last reference disappears.
Removing a selector and `/reload` restores its native references/groups and stops
all manager writes to it. The native config and core cache determine its choice;
use the dashboard to select its native `_best` group when resuming native failover.
No separate choice store or cache editing is introduced.

Dashboard changes on managed selectors are subject to policy and will be
overwritten. Remove ownership first for manual control. The five-minute hold
starts at initial ownership/current-choice observation, and after each switch.
Elective switching requires a freshly requested challenger throughput test after
the hold and at least 15% improvement. Scores use weighted, capped throughput and
latency medians (last three successes, two hours for active choices; configured
sweep age for standby ranking). Unknown performance is distinct from failure.
Confirmed failure bypasses hold/margin and chooses by last known score, then
recent gate health/latency when no healthy candidate has a score. Downloads never
block that choice. All-path failure keeps the current route and logs the failure;
the manager never adds direct routing as a fallback.

Optional `selector_priorities` defines ordered provider tiers per selector.
Providers within a tier compete by score. Higher tiers must be confirmed failed
before a lower tier is eligible; unknown health requests gates first. Providers
not listed for that selector are excluded. Without priorities, every proxy member
competes by score. For example, these entirely synthetic identifiers prefer two
subscription sources equally before a local chained proxy:

```json
{
  "provider_weights": {"provider-a": 1.25, "provider-b": 1.0, "local-proxy": 1.0},
  "selector_priorities": {"restricted": [["provider-a", "provider-b"], ["local-proxy"]]}
}
```

Returning from a working lower tier requires the five-minute hold, fresh
throughput at hold expiry, and a throttle check within 30 seconds. Confirmed
failure bypasses that wait without requesting downloads. Protocols have no
special ranking rules. Configure priorities explicitly when migrating from an
older runtime that embedded provider preferences.

Activation and API writes run on the manager thread. Core reloads and upstream
writes cancel/drain dependent probes; results cannot cross these transitions.
Only listed selectors receive API writes, using optional rendered authentication.
Each PUT is verified; an ambiguous/failed write attempts one verified rollback of
that selector alone. Failed activation/handoff restores the previous core and
original owned selector/group choices, without writing unlisted selectors.
`selector_decision` logs reasons, compared scores and ages; `selector_switched`,
`selector_write_failed` and `selector_handoff` cover writes and handoffs.

To roll back one selector, remove it from `managed_selectors` and `/reload`, then
select the restored native group in the dashboard. To roll back all policy and
probes, empty the list, disable probes and `/reload`. The manager remains the only
subscription scheduler. The full image/cron rollback runbook above is unchanged.


Validated ownership revocations and probe shutdown apply before rendering, so an
unrelated render failure cannot keep revoked writes or probes running. New grants
wait for a checked handoff. The scheduler follows verified activation before
snapshot persistence; a snapshot-write failure cannot strand it on a cancelled
client or previous API credentials. Failed staging writes leave old probes running.

HEAD/tiny successes cannot rehabilitate confirmed body failures or renew body
health evidence. A successful body check can restore health without inventing a
throughput score. Every candidate's sample retention checks its rendered definition and resolved
group/detour dependencies, including same-tag credential changes. Unchanged
effective paths retain their samples. Probes crossing dependency changes are
discarded for every protocol.

## Explicit live validation on a development machine

`tests/live.py` is an opt-in live runner; unittest discovery never invokes it.
It fetches actual private subscription URLs, gates every candidate with four
workers, measures three scored candidates per provider with bounded backfill,
and reads weights from private manager settings. It then exercises a real
five-minute elective hold, fresh challenger downloads, chained-proxy connectivity,
a preferred provider outage, the five-minute return hold with fresh measurements,
and confirmed-failure bypass. It also tests simultaneous failure of every preferred-provider
route in the full subscription graph, gate-only/unknown-throughput recovery, and
all eligible priority-selector paths failing without direct fallback. Samples, failures,
throughput and clocks are real. A scratch unreachable detour injects endpoint
failure without assumptions about its protocol.
Faults change only scratch outbound definitions. Native selection caching is
enabled in scratch state, matching the normal template, so independent fallback
upstream selection survives core reloads.

Run only on an authorized development machine with the real config mounted
read-only, no production data or published ports, and a separate writable artifact
directory. For example (CONFIG and ARTIFACTS are absolute paths):

```sh
docker run --rm --user 65534:65534 --cap-drop ALL --read-only --tmpfs /tmp \
  -e PYTHONPATH=/opt/manager -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$CONFIG:/config:ro" -v "$PWD/sing-box/manager/tests/live.py:/live.py:ro" \
  -v "$ARTIFACTS:/artifacts" --entrypoint python3 spoofskipper-manager:stage3 /live.py \
  --endpoint-file /config/local-endpoint.json --preferred-provider provider-a
```

The endpoint file can contain any supported local proxy outbound or endpoint.
The preferred provider argument is a subscription prefix from the supplied private
configuration. ARTIFACTS must be writable by uid 65534. The run takes at least ten minutes plus
subscription discovery and fault checks. Received plaintext probe bytes have a
384 MiB test-run ceiling, checked between ticks/probes; this excludes subscription
fetches, TLS/transport overhead, and unread early-close overshoot. It is not a
production budget subsystem. Reports redact candidate names to provider/protocol/
index and contain no outbound definitions or subscription credentials.

The reduced fault topology uses one real preferred-provider candidate and a local
endpoint through a separate real subscription path; it does not shut down provider servers. Additional
authenticated loopback routes send real HTTPS requests through the selected
selectors after switches. The runner distinguishes operator setup choices from
policy writes, and emits measurements, compared scores, sample ages and byte totals
in `events.json` and `summary.json`. A failed assertion is a failed/incomplete run.
`--resume-chained-report PATH` repeats the chained-proxy phase with newly fetched inputs and
new real measurements after a passed live elective checkpoint;
`--selected-traffic-report PATH` adds independent selected-route and full-provider
outage checks from a passed elective checkpoint.
Run only on an authorized development host; production testing requires separate
authorization and an agreed byte budget.
