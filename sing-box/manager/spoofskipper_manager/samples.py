"""Per-path measurement evidence and its health transitions; no I/O."""
from dataclasses import dataclass, field
from enum import Enum

from .probes import Probe

# A failure is confirmed by immediate repeats of the same probe kind against
# the next probe endpoints, so one endpoint's outage does not fail every path.
# A path fails once every endpoint failed in a row (twice with a single one).
FAILURES_TO_FAIL = 2


class Health(Enum):
    UNKNOWN = 'unknown'
    HEALTHY = 'healthy'  # passed the throttling threshold and is still reachable
    FAILED = 'failed'    # failed twice in a row


@dataclass
class Sample:
    latency: float | None = None
    health: Health = Health.UNKNOWN
    healthy_at: float = float('-inf')  # last success while healthy (gates keep it fresh)
    threshold_at: float = float('-inf')  # last read past the throttling threshold
    failed_at: float = float('-inf')   # when the path last became failed
    reachable_at: float = float('-inf')  # last gate success, healthy or not
    failures: int = 0
    failed_probe: Probe | None = None  # kind of the latest failure
    confirm: Probe | None = None  # repeat this probe now to confirm a failure
    successes: list[tuple[float, float, float]] = field(default_factory=list)  # (at, mbps, latency)
    last: dict[Probe, float] = field(default_factory=dict)  # submission times

    @property
    def healthy(self):
        return {Health.HEALTHY: True, Health.FAILED: False}.get(self.health)

    @property
    def latency_or_inf(self):
        return self.latency if self.latency is not None else float('inf')

    @property
    def throughput_at(self):
        return self.successes[-1][0] if self.successes else float('-inf')

    def is_healthy(self, now, max_age):
        return self.health is Health.HEALTHY and 0 <= now-self.healthy_at <= max_age

    def scored(self, now, max_age):
        if self.health is not Health.HEALTHY:
            return []
        return [(rate, latency) for at, rate, latency in self.successes if 0 <= now-at <= max_age]

    def record(self, result, now, failures_to_fail=FAILURES_TO_FAIL):
        probe = result.probe
        # Fallback endpoints prove health only; latency and rate stay comparable.
        primary = result.endpoint == 0
        if result.latency_ms is not None and primary:
            self.latency = result.latency_ms
        if not result.ok:
            self.failures, self.failed_probe = self.failures + 1, probe
            if self.failures < failures_to_fail:
                self.confirm = probe
            elif self.health is not Health.FAILED:
                self.health, self.failed_at = Health.FAILED, now
            return
        if probe is Probe.GATE:
            self.reachable_at = now
            # A tiny response says nothing about throttling: it clears only gate
            # failures and keeps proven health fresh, but cannot make an unknown
            # or failed path healthy.
            if self.failed_probe is Probe.GATE and self.health is not Health.FAILED:
                self.failures = 0
            if self.health is Health.HEALTHY:
                self.healthy_at = now
            return
        if not result.passed_threshold:
            return  # Slow but alive within the time box: no new evidence.
        self.failures, self.health, self.healthy_at, self.threshold_at = 0, Health.HEALTHY, now, now
        if result.mbps is not None and primary:
            self.successes = (self.successes + [(now, result.mbps, self.latency)])[-3:]
