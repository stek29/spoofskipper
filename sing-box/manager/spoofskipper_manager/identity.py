"""Stable, secret-safe candidate and probe-user identities."""
import hashlib
import json


def sample_key(outbound):
    return outbound['tag'], hashlib.sha256(json.dumps(outbound, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def identity(outbound):
    digest = sample_key(outbound)[1]
    return 'probe_' + digest, digest
