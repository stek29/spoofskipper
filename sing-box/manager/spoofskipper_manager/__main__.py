"""Entry point: supervise sing-box with /config read-only and state under /data."""
import argparse
from .service import Manager, log
from . import parser as subscription_parser
from .subscriptions import bootstrap, default_interface


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['serve', 'bootstrap'], nargs='?', default='serve')
    parser.add_argument('--config-dir', default='/config')
    parser.add_argument('--state-dir', default='/data')
    parser.add_argument('--core', default='sing-box')
    args = parser.parse_args()
    # Subscription fetches go out directly, never through the supervised core's tun.
    subscription_parser.BIND_INTERFACE = default_interface()
    try:
        if args.command == 'bootstrap':
            return bootstrap(args.config_dir, args.state_dir, log)
        return Manager(args.config_dir, args.state_dir, args.core).run()
    except Exception as exc:
        log('manager_failed', error=type(exc).__name__)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
