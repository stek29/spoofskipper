#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# The parser lives in the manager package so both share a single copy.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sing-box" / "manager"))
from spoofskipper_manager.parser import (  # noqa: E402
    apply_outbound_settings,
    merge_outputs,
    read_outbound_settings,
    render_subscription,
)


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config")
    args = parser.parse_args()

    try:
        config = load_config(Path(args.config))
        global_outbound_settings, type_outbound_settings = read_outbound_settings(config)
        subscriptions = config.get("subscriptions")
        if not isinstance(subscriptions, list) or not subscriptions:
            raise ValueError("config must include a non-empty subscriptions array")

        outputs = [
            apply_outbound_settings(
                render_subscription(spec),
                global_outbound_settings,
                type_outbound_settings,
            )
            for spec in subscriptions
        ]
        merged = merge_outputs(outputs)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    json.dump(merged, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
