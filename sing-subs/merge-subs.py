#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import sub2outbounds


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise SystemExit("config must be a JSON object")
    return data


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def merge_outputs(outputs: list[dict[str, Any]]) -> dict[str, Any]:
    merged_outbounds: list[dict[str, Any]] = []
    seen_outbounds: dict[str, str] = {}
    merged_groups: dict[str, list[str]] = {}
    seen_group_tags: dict[str, set[str]] = {}

    for output in outputs:
        for outbound in output.get("outbounds", []):
            tag = outbound["tag"]
            serialized = stable_json(outbound)
            previous = seen_outbounds.get(tag)
            if previous is None:
                seen_outbounds[tag] = serialized
                merged_outbounds.append(outbound)
            elif previous != serialized:
                raise SystemExit(f"conflicting outbound definitions for tag: {tag}")

        for group_name, tags in output.get("groups", {}).items():
            if group_name not in merged_groups:
                merged_groups[group_name] = []
                seen_group_tags[group_name] = set()
            for tag in tags:
                if tag not in seen_group_tags[group_name]:
                    seen_group_tags[group_name].add(tag)
                    merged_groups[group_name].append(tag)

    return {"outbounds": merged_outbounds, "groups": merged_groups}


def render_subscription(spec: dict[str, Any]) -> dict[str, Any]:
    url = spec.get("url")
    if not isinstance(url, str) or not url:
        raise SystemExit("each subscription must include a non-empty string url")

    return sub2outbounds.generate_output(
        url,
        prefix=str(spec.get("prefix", "")),
        name_regex=spec.get("name_regex"),
        tag_template=spec.get("tag_template"),
        group_template=spec.get("group_template"),
        group_fallback=str(spec.get("group_fallback", "other")),
        ignore_regex=spec.get("ignore_regex"),
        group_exclude_regex=spec.get("group_exclude_regex"),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config")
    args = parser.parse_args()

    config = load_config(Path(args.config))
    subscriptions = config.get("subscriptions")
    if not isinstance(subscriptions, list) or not subscriptions:
        raise SystemExit("config must include a non-empty subscriptions array")

    outputs = [render_subscription(spec) for spec in subscriptions]
    json.dump(merge_outputs(outputs), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
