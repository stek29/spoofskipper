"""Stable, secret-safe candidate and probe-user identities."""
from dataclasses import dataclass
import hashlib
import json
from typing import NamedTuple


class SampleKey(NamedTuple):
    tag: str
    digest: str  # changes whenever the rendered outbound definition changes


@dataclass(frozen=True)
class Candidate:
    outbound: dict
    provider: str
    weight: float = 1.0


# Direct egress for uplink checks, reached through the probe inbound like a path.
UPLINK = {'type': 'direct', 'tag': '__spoofskipper_uplink'}


def sample_key(outbound):
    return SampleKey(outbound['tag'], hashlib.sha256(json.dumps(outbound, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest())


def identity(outbound):
    digest = sample_key(outbound).digest
    return 'probe_' + digest, digest
