"""Operational commands always keep /config read-only."""
import argparse
import difflib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from . import compiler
from .service import Manager, load_settings, log
from .state import atomic_write
from .subscriptions import Providers


def diagnostics(args):
    source, state = Path(args.config_dir).resolve(), Path(args.state_dir).resolve()
    # The user must supply a fresh scratch location, never a live data directory.
    if state == Path('/data') or state == source or source in state.parents:
        raise ValueError('diagnostics require separate empty scratch state')
    state.mkdir(parents=True, exist_ok=True)
    if any(state.iterdir()):
        raise ValueError('diagnostics require empty scratch state')
    settings = load_settings(source)
    providers = Providers(source, state, settings, log)
    if args.command == 'refresh-dry-run':
        pending = providers.refresh()
        if not pending:
            raise ValueError('no successful providers')
        with tempfile.TemporaryDirectory(dir=state) as temp:
            root = Path(temp) / 'config'
            shutil.copytree(source, root)
            private = root / 'config.jsonnet'
            text = private.read_text()
            if compiler.IMPORT_LINE in text:
                private.write_text(compiler.edited_source(text))
            config = compiler.render(root / 'sing.jsonnet', providers.merged(pending), temp, settings, providers.candidates(pending))
            compiler.check(config, temp, args.core)
        providers.commit(pending)
        log('dry_run_checked', providers=len(pending))
        return
    if not args.snapshots:
        raise ValueError('render-check requires --snapshots from refresh-dry-run')
    providers = Providers(source, Path(args.snapshots), settings, log)
    if not providers.snapshots:
        raise ValueError('no snapshots for render-check')
    with tempfile.TemporaryDirectory(dir=state) as temp:
        root = Path(temp) / 'config'
        shutil.copytree(source, root)
        baseline = subprocess.run(['jsonnet', str(root / 'sing.jsonnet')], capture_output=True, timeout=60)
        if baseline.returncode:
            raise ValueError('baseline Jsonnet render failed')
        baseline = json.loads(baseline.stdout)
        compiler.validate(baseline)
        compiler.check(baseline, temp, args.core)
        private = root / 'config.jsonnet'
        private.write_text(compiler.edited_source(private.read_text()))
        managed = compiler.render(root / 'sing.jsonnet', providers.merged(providers.snapshots), temp, settings, providers.candidates(providers.snapshots))
        compiler.check(managed, temp, args.core)
        diff = ''.join(difflib.unified_diff(
            (json.dumps(baseline, indent=2, sort_keys=True) + '\n').splitlines(True),
            (json.dumps(managed, indent=2, sort_keys=True) + '\n').splitlines(True),
            fromfile='legacy', tofile='manager'))
        atomic_write(state / 'render.diff', diff)
        log('render_check_passed', private_diff=str(state / 'render.diff'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['serve', 'refresh-dry-run', 'render-check'], nargs='?', default='serve')
    parser.add_argument('--config-dir', default='/config')
    parser.add_argument('--state-dir', default='/data')
    parser.add_argument('--core', default='sing-box')
    parser.add_argument('--snapshots')
    args = parser.parse_args()
    try:
        if args.command == 'serve':
            return Manager(args.config_dir, args.state_dir, args.core).run()
        diagnostics(args)
        return 0
    except (Exception, SystemExit) as exc:
        log('manager_failed', error=type(exc).__name__)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
