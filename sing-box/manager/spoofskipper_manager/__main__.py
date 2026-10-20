"""Entry point: supervise sing-box with /config read-only and state under /data."""
import argparse
from .service import Manager, log


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['serve'], nargs='?', default='serve')
    parser.add_argument('--config-dir', default='/config')
    parser.add_argument('--state-dir', default='/data')
    parser.add_argument('--core', default='sing-box')
    args = parser.parse_args()
    try:
        return Manager(args.config_dir, args.state_dir, args.core).run()
    except Exception as exc:
        log('manager_failed', error=type(exc).__name__)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
