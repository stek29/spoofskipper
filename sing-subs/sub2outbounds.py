#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The parser lives in the manager package so both share a single copy.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sing-box" / "manager"))
from spoofskipper_manager.parser import generate_output  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--prefix", default="")
    parser.add_argument("--name-regex")
    parser.add_argument("--tag-template")
    parser.add_argument("--group-template")
    parser.add_argument("--group-fallback", default="other")
    parser.add_argument("--ignore-regex")
    parser.add_argument("--group-exclude-regex")
    parser.add_argument("--exclude-transport-type", action="append")
    args = parser.parse_args()

    try:
        output = generate_output(
            args.url,
            prefix=args.prefix,
            name_regex=args.name_regex,
            tag_template=args.tag_template,
            group_template=args.group_template,
            group_fallback=args.group_fallback,
            ignore_regex=args.ignore_regex,
            group_exclude_regex=args.group_exclude_regex,
            exclude_transport_types=args.exclude_transport_type,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    json.dump(output, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
