"""PID 1 supervision and serialized, marker-protected activation."""
import json
import os
import signal
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from . import compiler, clash_api
from .state import atomic_write, write_json, remove
from .subscriptions import Providers
from .scheduler import Scheduler
from .clash_api import resolve
from .settings import Settings, load_settings, SCHEDULER_ERROR_LOG_SECONDS


def log(event, **fields):
    print(json.dumps({'event': event, **fields}, ensure_ascii=False), flush=True)


class Stopping(BaseException):
    pass


class RecoveryFailed(Exception):
    pass


class ActivationRolledBack(ValueError):
    """The old core is verified; its measurement client must be recreated."""


class Manager:
    def __init__(self, config_dir, state_dir, core='sing-box'):
        self.config_dir, self.root, self.core = Path(config_dir), Path(state_dir), core
        self.root.mkdir(parents=True, exist_ok=True)
        self.live, self.previous, self.marker = [self.root / name for name in
                                                ('sing.json', 'sing.prev.json', 'activating')]
        # Only manager-owned abandoned temporary files are removed.
        for directory in (self.root, self.root / 'providers'):
            for path in directory.glob('.manager-*'):
                shutil.rmtree(path) if path.is_dir() else path.unlink()
        try:
            self.settings = load_settings(self.config_dir)
        except (ValueError, OSError):
            if not self.live.exists():
                raise
            self.settings = Settings()
            log('settings_invalid_using_saved_config', probes_enabled=False, managed_selectors=[],
                fallback='native_selectors')
        self.child = None
        self.stopping = None
        self.reload_requested = False
        self.current = None
        self.scheduler = Scheduler(log)
        self.scheduler_errors = {}

    def signal(self, number, _frame):
        if number == signal.SIGHUP:
            self.reload_requested = True
        elif self.stopping is None:
            self.stopping = number
            if self.child and self.child.poll() is None:
                try:
                    self.child.send_signal(number)
                except ProcessLookupError:
                    pass
            # Interrupt blocked subscription reads/checks as well as the loop.
            # BaseException deliberately bypasses provider fallback handlers.
            raise Stopping()

    def alive(self):
        return self.child is not None and self.child.poll() is None

    def wait(self, seconds):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if self.stopping:
                raise Stopping()
            time.sleep(min(0.1, max(0, until - time.monotonic())))

    def start(self):
        if self.stopping:
            raise Stopping()
        self.child = subprocess.Popen([self.core, 'run', '-c', str(self.live)])
        log('core_started', pid=self.child.pid)

    def stop_child(self):
        if self.alive():
            self.child.send_signal(self.stopping or signal.SIGTERM)
            try:
                self.child.wait(timeout=self.settings['shutdown_timeout'])
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait()
        elif self.child:
            self.child.wait()
        self.child = None

    def verify(self, config):
        deadline = time.monotonic() + self.settings['revision_timeout']
        tag = compiler.revision(config)
        while time.monotonic() < deadline:
            if self.stopping:
                raise Stopping()
            if not self.alive():
                return False
            try:
                if clash_api.revision_present(config, tag, timeout=min(1, self.settings['revision_timeout'])):
                    log('revision_verified', revision=tag)
                    return True
            except Exception:
                pass
            self.wait(0.1)
        log('revision_timeout', revision=tag)
        return False

    def recover_interrupted(self):
        if self.marker.exists():
            if not self.previous.exists():
                raise RecoveryFailed('interrupted activation has no previous config')
            atomic_write(self.live, self.previous.read_bytes())
            # Keep marker until the restored core verifies.
            log('interrupted_activation_restored')

    def activate(self, config):
        with tempfile.TemporaryDirectory(prefix='.manager-', dir=self.root) as scratch:
            compiler.check(config, scratch, self.core)
        if self.stopping:
            raise Stopping()
        if self.current is not None and not self.alive():
            log('unexpected_core_exit', returncode=self.child.returncode if self.child else None)
            raise RecoveryFailed('core died outside activation')
        if self.current == config and self.alive():
            log('activation_unchanged', revision=compiler.revision(config))
            return
        managed = self.settings.managed_selectors
        choices, selections = self.capture_choices(managed)
        old = self.current
        if old is not None:
            atomic_write(self.previous, self.live.read_bytes())
            atomic_write(self.marker, 'activating\n')
        verified = False
        try:
            verified = self.write_and_reload(config)
            if verified:
                self.hand_off(config, choices, managed)
        except (OSError, ValueError):
            verified = False
        finally:
            if old is None and not verified:
                remove(self.live)
        if verified:
            self.current = config
            remove(self.marker)
            log('activation_succeeded', revision=compiler.revision(config))
            return
        log('activation_failed')
        if old is None:
            self.stop_child()
            # Failed first installation is not a saved, usable configuration.
            remove(self.live)
            raise ValueError('initial core startup failed')
        self.roll_back(old, selections, managed)
        raise ActivationRolledBack('new configuration rolled back')

    def capture_choices(self, managed):
        if self.current is None or not managed:
            return {}, {}
        proxies = clash_api.proxies(self.current)
        choices = {tag: resolve(proxies, tag) for tag in managed if tag in proxies}
        return choices, {tag: proxies[tag].get('now') for tag in choices}

    def write_and_reload(self, config):
        write_json(self.live, config)
        self.scheduler.invalidate()
        if self.alive():
            self.child.send_signal(signal.SIGHUP)
        else:
            self.start()
        return self.verify(config)

    def hand_off(self, config, choices, managed):
        entries = {outbound['tag']: outbound for outbound in config.get('outbounds', [])}
        for tag, leaf in choices.items():
            if leaf in entries.get(tag, {}).get('outbounds', []):
                clash_api.select(config, tag, leaf, managed)
                log('selector_handoff', selector=tag, candidate=leaf)

    def roll_back(self, old, selections, managed):
        atomic_write(self.live, self.previous.read_bytes())
        # Restart once: handles both a surviving old instance and a dead new one.
        self.stop_child()
        try:
            self.start()
            recovered = self.verify(old)
        except OSError:
            recovered = False
        if not recovered:
            log('rollback_failed')
            raise RecoveryFailed('bounded rollback failed')
        self.restore_choices(old, selections, managed)
        self.current = old
        remove(self.marker)
        log('rollback_succeeded', revision=compiler.revision(old))

    def restore_choices(self, config, selections, managed):
        # Never restore a selector whose ownership has been revoked.
        entries = {outbound['tag']: outbound for outbound in config.get('outbounds', [])}
        for tag, selection in selections.items():
            if selection in entries.get(tag, {}).get('outbounds', []):
                try:
                    clash_api.select(config, tag, selection, managed)
                except Exception:
                    log('selector_rollback_failed', selector=tag)
                    raise RecoveryFailed('selector recovery failed') from None

    def activate_and_configure(self, config, providers, snapshots):
        previous_settings = self.scheduler.settings
        previous_candidates = list(self.scheduler.candidates.values())
        try:
            self.activate(config)
        except ActivationRolledBack:
            if self.scheduler.config is not None:
                owned = tuple(tag for tag in previous_settings.managed_selectors
                              if tag in self.settings.managed_selectors)
                self.scheduler.configure(self.current, previous_candidates,
                                         previous_settings.with_changes(managed_selectors=owned))
            raise
        self.configure_probes(providers, snapshots)

    def prepare(self, snapshots, providers):
        with tempfile.TemporaryDirectory(prefix='.manager-', dir=self.root) as scratch:
            return compiler.render(self.config_dir / 'sing.jsonnet', providers.merged(snapshots), scratch,
                                   self.settings, providers.candidates(snapshots))

    def configure_probes(self, providers, snapshots):
        # Hash the actual rendered definitions, including private overrides.
        tags = {c['outbound']['tag']: c for c in providers.candidates(snapshots)}
        candidates = [{**tags[o['tag']], 'outbound': o} for o in self.current.get('outbounds', []) if o['tag'] in tags]
        self.scheduler.configure(self.current, candidates, self.settings)

    def tick_scheduler(self):
        try:
            self.scheduler.tick()
        except Exception as exc:
            error = type(exc).__name__
            now = time.monotonic()
            count, last_logged = self.scheduler_errors.get(error, (0, float('-inf')))
            count += 1
            if now-last_logged >= SCHEDULER_ERROR_LOG_SECONDS:
                log('scheduler_tick_failed', error=error, count=count)
                last_logged = now
            self.scheduler_errors[error] = count, last_logged

    def run(self):
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, self.signal)
        try:
            self.recover_interrupted()
            if self.live.exists():
                saved = json.loads(self.live.read_text())
                compiler.validate(saved)
                self.start()
                if not self.verify(saved):
                    raise RecoveryFailed('saved configuration failed startup')
                self.current = saved
                remove(self.marker)
                log('saved_config_started')
            pending = None
            try:
                providers = Providers(self.config_dir, self.root, self.settings, log)
                if providers.snapshots:
                    pending = dict(providers.snapshots)
                    self.activate_and_configure(self.prepare(pending, providers), providers, pending)
                    pending = None
            except (Stopping, RecoveryFailed):
                raise
            except (Exception, SystemExit) as exc:
                log('cached_render_failed', error=type(exc).__name__)
                if self.current is not None:
                    pending = None
            fetched = False
            next_refresh = 0
            backoff = self.settings['bootstrap_backoff_seconds']
            while True:
                if self.stopping:
                    raise Stopping()
                if self.current is not None and not self.alive():
                    log('unexpected_core_exit', returncode=self.child.returncode)
                    return 1
                now = time.monotonic()
                if pending is not None or self.reload_requested or now >= next_refresh:
                    reload_only = self.reload_requested
                    self.reload_requested = False
                    try:
                        self.settings = load_settings(self.config_dir)
                        self.scheduler.restrict(self.settings)
                        providers = Providers(self.config_dir, self.root, self.settings, log)
                        if pending is None:
                            pending = dict(providers.snapshots) if reload_only else providers.refresh()
                            fetched = not reload_only
                        if not pending:
                            log('bootstrap_waiting_for_providers')
                            pending = None
                            next_refresh = now + backoff
                            self.wait(backoff)
                            backoff = min(backoff * 2, self.settings['bootstrap_backoff_max_seconds'])
                            continue
                        self.activate_and_configure(self.prepare(pending, providers), providers, pending)
                        providers.commit(pending)
                        pending = None
                        backoff = self.settings['bootstrap_backoff_seconds']
                        if not reload_only:
                            next_refresh = time.monotonic() + (self.settings['refresh_seconds'] if fetched else 0)
                    except (Stopping, RecoveryFailed):
                        raise
                    except (Exception, SystemExit) as exc:
                        log('refresh_failed', error=type(exc).__name__)
                        if self.current is not None:
                            pending = None
                            next_refresh = time.monotonic() + self.settings['refresh_seconds']
                        else:
                            # Retain fetched snapshots in memory: runtime retries do not refetch.
                            self.wait(backoff)
                            backoff = min(backoff * 2, self.settings['bootstrap_backoff_max_seconds'])
                self.tick_scheduler()
                self.wait(0.1)
        except Stopping:
            log('shutdown_requested', signal=self.stopping)
            return 0
        except RecoveryFailed:
            return 1
        finally:
            self.scheduler.close()
            self.stop_child()
            # Reap any orphaned descendants when running as container PID 1.
            while True:
                try:
                    pid, _ = os.waitpid(-1, os.WNOHANG)
                    if not pid:
                        break
                except ChildProcessError:
                    break
