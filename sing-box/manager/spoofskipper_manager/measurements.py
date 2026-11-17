"""Durable measurement evidence, keyed by the complete rendered traffic path."""
import hashlib
import json
import math
import time
from dataclasses import asdict
from pathlib import Path

from .identity import SampleKey
from .probes import Probe
from .samples import Health, Sample
from .state import write_json

TIMES = ('healthy_at', 'threshold_at', 'failed_at', 'reachable_at')
CHECKPOINT_SECONDS = 30


def path_digest(path):
    return hashlib.sha256(json.dumps(path, sort_keys=True).encode()).hexdigest()


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError('invalid measurement number')
    return value


def encode(sample, now, wall):
    timestamp = lambda at: wall + at - now if math.isfinite(at) else None
    data = asdict(sample)
    data['health'] = sample.health.value
    for name in ('failed_probe', 'confirm'):
        data[name] = getattr(sample, name).value if getattr(sample, name) else None
    for name in TIMES:
        data[name] = timestamp(getattr(sample, name))
    data['successes'] = [[timestamp(at), rate, latency] for at, rate, latency in sample.successes]
    data['last'] = {probe.value: timestamp(at) for probe, at in sample.last.items()}
    data['outcomes'] = {probe.value: outcome for probe, outcome in sample.outcomes.items()}
    return data


def decode(data, now, wall):
    def timestamp(at):
        if at is None:
            return float('-inf')
        return now + min(0, number(at) - wall)
    sample = Sample(health=Health(data['health']))
    sample.latency = None if data['latency'] is None else number(data['latency'])
    if sample.latency is not None and sample.latency < 0:
        raise ValueError('invalid latency')
    sample.failures = data['failures']
    if type(sample.failures) is not int or sample.failures < 0:
        raise ValueError('invalid failure count')
    for name in ('failed_probe', 'confirm'):
        setattr(sample, name, Probe(data[name]) if data[name] is not None else None)
    for name in TIMES:
        setattr(sample, name, timestamp(data[name]))
    sample.successes = [(timestamp(at), number(rate), number(latency))
                        for at, rate, latency in data['successes']]
    if len(sample.successes) > 3 or any(rate < 0 or latency < 0 for _, rate, latency in sample.successes):
        raise ValueError('invalid throughput samples')
    sample.last = {Probe(probe): timestamp(at) for probe, at in data['last'].items()}
    sample.outcomes = {Probe(probe): outcome for probe, outcome in data['outcomes'].items()}
    if any(not isinstance(outcome, str) for outcome in sample.outcomes.values()):
        raise ValueError('invalid probe outcome')
    return sample


class Measurements:
    def __init__(self, path, log, clock=time.monotonic, wall=time.time):
        self.path, self.log, self.clock, self.wall = Path(path), log, clock, wall
        self.pending, self.rotation = {}, {}
        self.next_save = self.clock() + CHECKPOINT_SECONDS
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            now, wall_now = self.clock(), self.wall()
            if data['version'] != 1 or number(data['saved_at']) > wall_now:
                raise ValueError('unsupported state or wall clock moved backwards')
            pending = {}
            for entry in data['samples']:
                key = SampleKey(entry['tag'], entry['digest'])
                if (not isinstance(key.tag, str) or not isinstance(key.digest, str)
                        or not isinstance(entry['path'], str)):
                    raise ValueError('invalid path identity')
                pending[key] = (entry['path'], decode(entry['sample'], now, wall_now))
            rotation = {provider: now + min(0, number(at) - wall_now)
                        for provider, at in data['rotation'].items()}
            self.pending, self.rotation = pending, rotation
        except (OSError, ValueError, TypeError, KeyError):
            self.log('measurement_state_invalid')

    def restore(self, key, path):
        if path is None or key not in self.pending:
            return None
        digest, sample = self.pending.pop(key)
        return sample if path_digest(path) == digest else None

    def save(self, scheduler, force=False):
        now = self.clock()
        if not scheduler.settings.probes_enabled or (not force and now < self.next_save):
            return
        self.next_save = now + CHECKPOINT_SECONDS
        wall = self.wall()
        entries = []
        # In-flight/held attempts did not complete. Retry them after a restart.
        interrupted = {(key, probe) for key, probe, _ in scheduler.jobs.values()}
        interrupted.update((key, result.probe) for key, result, _ in scheduler.held)
        rotation = dict(scheduler.rotated_at)
        for key, sample in scheduler.samples.items():
            path = scheduler.paths.get(key)
            if path is None:
                saved = self.pending.get(key)
                if saved is None:
                    continue
                digest, sample = saved
            else:
                digest = path_digest(path)
            data = encode(sample, now, wall)
            for candidate, probe in interrupted:
                if candidate != key:
                    continue
                data['last'].pop(probe.value, None)
                if sample.failed_probe is probe and sample.failures and sample.health is not Health.FAILED:
                    data['confirm'] = probe.value
                if probe is Probe.THROUGHPUT:
                    rotation.pop(scheduler.candidates[key].provider, None)
            entries.append({'tag': key.tag, 'digest': key.digest, 'path': digest, 'sample': data})
        data = {'version': 1, 'saved_at': wall, 'samples': entries,
                'rotation': {provider: wall + at - now for provider, at in rotation.items() if math.isfinite(at)}}
        try:
            write_json(self.path, data)
        except OSError:
            self.log('measurement_state_write_failed')
