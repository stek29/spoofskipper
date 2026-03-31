#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import urllib.parse
import urllib.request
from typing import Any
from collections import ChainMap


SUPPORTED_SCHEMES = ("vless://", "trojan://", "ss://", "vmess://", "hy2://", "hysteria2://")


def fetch_url(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "spoofskipper/sing-box",
            "Accept": "*/*",
        },
    )
    with urllib.request.urlopen(request) as response:
        return response.read().decode("utf-8", errors="replace").strip()


def pad_base64(value: str) -> str:
    return value + "=" * ((4 - len(value) % 4) % 4)


def try_decode_base64(value: str) -> str | None:
    compact = "".join(value.split())
    if not compact:
        return None

    candidates = [compact]
    if "-" in compact or "_" in compact:
        candidates.append(compact.replace("-", "+").replace("_", "/"))

    for candidate in candidates:
        try:
            decoded = base64.b64decode(pad_base64(candidate), validate=True)
        except Exception:
            continue
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return decoded.decode("utf-8", errors="replace")
    return None


def decode_subscription_body(body: str) -> str:
    decoded = try_decode_base64(body)
    if decoded and any(scheme in decoded for scheme in SUPPORTED_SCHEMES):
        return decoded.strip()
    return body.strip()


def extract_links(text: str) -> list[str]:
    links: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(SUPPORTED_SCHEMES):
            links.append(line)
    return links


def decode_tag(value: str) -> str:
    return urllib.parse.unquote(value) if value else ""


def clean_query_value(parsed: urllib.parse.ParseResult, key: str) -> str | None:
    values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True).get(key)
    if not values:
        return None
    value = values[0]
    return value if value != "" else None


def apply_tls_fields(outbound: dict[str, Any], parsed: urllib.parse.ParseResult, security: str | None) -> None:
    if security not in {"tls", "reality"}:
        return

    tls: dict[str, Any] = {"enabled": True}
    server_name = clean_query_value(parsed, "sni")
    if server_name:
        tls["server_name"] = server_name

    fingerprint = clean_query_value(parsed, "fp")
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

    if security == "reality":
        reality: dict[str, Any] = {"enabled": True}
        public_key = clean_query_value(parsed, "pbk")
        if public_key:
            reality["public_key"] = public_key
        short_id = clean_query_value(parsed, "sid")
        if short_id:
            reality["short_id"] = short_id
        tls["reality"] = reality

    outbound["tls"] = tls


def build_transport(parsed: urllib.parse.ParseResult) -> dict[str, Any] | None:
    network_type = clean_query_value(parsed, "type")
    if not network_type or network_type == "tcp":
        return None

    transport: dict[str, Any] = {"type": network_type}

    path = clean_query_value(parsed, "path")
    if path:
        transport["path"] = path

    host = clean_query_value(parsed, "host")
    headers: dict[str, Any] = {}
    if network_type == "ws":
        if host:
            headers["Host"] = host
        transport["headers"] = headers
    elif network_type == "http":
        if host:
            transport["host"] = [item.strip() for item in host.split(",") if item.strip()]
    elif network_type == "httpupgrade":
        if host:
            transport["host"] = host
    elif host:
        transport["headers"] = {"Host": host}

    service_name = clean_query_value(parsed, "serviceName")
    if service_name:
        transport["service_name"] = service_name

    return transport


def parse_vless(link: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(link)
    outbound: dict[str, Any] = {
        "type": "vless",
        "tag": decode_tag(parsed.fragment),
        "server": parsed.hostname or "",
        "server_port": parsed.port or 443,
        "uuid": urllib.parse.unquote(parsed.username or ""),
    }

    flow = clean_query_value(parsed, "flow")
    if flow:
        outbound["flow"] = flow

    apply_tls_fields(outbound, parsed, clean_query_value(parsed, "security"))

    transport = build_transport(parsed)
    if transport:
        outbound["transport"] = transport

    return outbound


def parse_trojan(link: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(link)
    outbound: dict[str, Any] = {
        "type": "trojan",
        "tag": decode_tag(parsed.fragment),
        "server": parsed.hostname or "",
        "server_port": parsed.port or 443,
        "password": urllib.parse.unquote(parsed.username or ""),
    }

    apply_tls_fields(outbound, parsed, clean_query_value(parsed, "security"))

    transport = build_transport(parsed)
    if transport:
        outbound["transport"] = transport

    return outbound


def decode_ss_userinfo(value: str) -> tuple[str, str]:
    decoded = try_decode_base64(value)
    if decoded and ":" in decoded:
        method, password = decoded.split(":", 1)
        return method, password
    if ":" in value:
        method, password = value.split(":", 1)
        return method, password
    raise ValueError(f"invalid shadowsocks credentials: {value!r}")


def parse_ss(link: str) -> dict[str, Any]:
    rest = link[len("ss://") :]
    tag = ""
    if "#" in rest:
        rest, raw_tag = rest.split("#", 1)
        tag = decode_tag(raw_tag)

    if "?" in rest:
        rest, _query = rest.split("?", 1)

    if "@" in rest:
        raw_userinfo, raw_hostport = rest.rsplit("@", 1)
        method, password = decode_ss_userinfo(raw_userinfo)
    else:
        decoded = try_decode_base64(rest)
        if not decoded or "@" not in decoded:
            raise ValueError("invalid shadowsocks URI")
        decoded_userinfo, raw_hostport = decoded.rsplit("@", 1)
        method, password = decode_ss_userinfo(decoded_userinfo)

    parsed_host = urllib.parse.urlparse(f"//{raw_hostport}")
    return {
        "type": "shadowsocks",
        "tag": tag,
        "server": parsed_host.hostname or "",
        "server_port": parsed_host.port or 443,
        "method": method,
        "password": password,
        "network": "tcp",
    }


def parse_vmess(link: str) -> dict[str, Any]:
    payload = link[len("vmess://") :]
    decoded = try_decode_base64(payload)
    if not decoded:
        raise ValueError("invalid vmess payload")
    data = json.loads(decoded)

    outbound: dict[str, Any] = {
        "type": "vmess",
        "tag": data.get("ps", ""),
        "server": data["add"],
        "server_port": int(data["port"]),
        "uuid": data["id"],
        "security": data.get("scy", "auto"),
    }

    if aid := data.get("aid"):
        outbound["alter_id"] = int(aid)

    parsed_transport = urllib.parse.urlparse(
        "vmess://unused"
        + "?"
        + urllib.parse.urlencode(
            {
                "type": data.get("net", ""),
                "path": data.get("path", ""),
                "host": data.get("host", ""),
                "serviceName": data.get("serviceName", ""),
            },
            doseq=True,
        )
    )
    transport = build_transport(parsed_transport)
    if transport:
        outbound["transport"] = transport

    if tls_mode := data.get("tls"):
        security = "tls" if tls_mode == "tls" else None
        apply_tls_fields(
            outbound,
            urllib.parse.urlparse(
                "vmess://unused"
                + "?"
                + urllib.parse.urlencode(
                    {"sni": data.get("sni", ""), "fp": data.get("fp", "")},
                    doseq=True,
                )
            ),
            security,
        )

    return outbound


def parse_hysteria2(link: str) -> dict[str, Any]:
    normalized = "hysteria2://" + link.split("://", 1)[1]
    parsed = urllib.parse.urlparse(normalized)
    outbound: dict[str, Any] = {
        "type": "hysteria2",
        "tag": decode_tag(parsed.fragment),
        "server": parsed.hostname or "",
        "server_port": parsed.port or 443,
        "password": urllib.parse.unquote(parsed.username or ""),
        "tls": {"enabled": True},
    }

    if server_name := clean_query_value(parsed, "sni"):
        outbound["tls"]["server_name"] = server_name
    elif clean_query_value(parsed, "insecure") == "1":
        outbound["tls"]["insecure"] = True

    if obfs := clean_query_value(parsed, "obfs"):
        outbound["obfs"] = {"type": obfs}
        if obfs_password := clean_query_value(parsed, "obfs-password"):
            outbound["obfs"]["password"] = obfs_password

    return outbound


def parse_link(link: str) -> dict[str, Any]:
    if link.startswith("vless://"):
        return parse_vless(link)
    if link.startswith("trojan://"):
        return parse_trojan(link)
    if link.startswith("ss://"):
        return parse_ss(link)
    if link.startswith("vmess://"):
        return parse_vmess(link)
    if link.startswith(("hy2://", "hysteria2://")):
        return parse_hysteria2(link)
    raise ValueError(f"unsupported link: {link}")


def match_name_parts(tag: str, pattern: re.Pattern[str] | None) -> dict[str, str]:
    if pattern is None:
        return {}

    match = pattern.search(tag)
    if not match:
        return {}

    captures: dict[str, str] = {}
    captures.update({key: value if value is not None else "" for key, value in match.groupdict().items()})

    groups = match.groups()
    for index, value in enumerate(groups, start=1):
        captures[str(index)] = value if value is not None else ""

    captures["0"] = match.group(0)
    return captures


def render_template(template: str, context: dict[str, str], fallback: str) -> str:
    try:
        value = template.format_map(ChainMap(context, {"fallback": fallback}))
    except KeyError as exc:
        raise SystemExit(f"missing template field: {exc.args[0]}")
    value = value.strip()
    return value if value else fallback


def transform_outbounds(
    outbounds: list[dict[str, Any]],
    prefix: str,
    name_pattern: re.Pattern[str] | None,
    tag_template: str | None,
    group_template: str | None,
    group_fallback: str,
    ignore_pattern: re.Pattern[str] | None,
    group_exclude_pattern: re.Pattern[str] | None,
) -> dict[str, Any]:
    transformed: list[dict[str, Any]] = []
    grouped: dict[str, list[str]] = {}

    for outbound in outbounds:
        original_tag = outbound["tag"]
        captures = match_name_parts(original_tag, name_pattern)
        outbound = dict(outbound)
        template_context = {
            "prefix": prefix,
            "type": outbound["type"],
            "name": original_tag,
            **captures,
        }
        if tag_template:
            outbound["tag"] = render_template(tag_template, template_context, original_tag)

        if ignore_pattern and ignore_pattern.search(outbound["tag"]):
            continue

        transformed.append(outbound)

        if group_template and (not group_exclude_pattern or not group_exclude_pattern.search(outbound["tag"])):
            group_key = render_template(group_template, template_context, group_fallback)
            grouped.setdefault(group_key, []).append(outbound["tag"])

    return {"outbounds": transformed, "groups": grouped}


def generate_output(
    url: str,
    prefix: str = "",
    name_regex: str | None = None,
    tag_template: str | None = None,
    group_template: str | None = None,
    group_fallback: str = "other",
    ignore_regex: str | None = None,
    group_exclude_regex: str | None = None,
) -> dict[str, Any]:
    name_pattern = re.compile(name_regex) if name_regex else None
    ignore_pattern = re.compile(ignore_regex) if ignore_regex else None
    group_exclude_pattern = re.compile(group_exclude_regex) if group_exclude_regex else None

    body = fetch_url(url)
    decoded = decode_subscription_body(body)
    links = extract_links(decoded)
    if not links:
        raise SystemExit("no supported proxy links found in subscription")

    outbounds = [parse_link(link) for link in links]
    return transform_outbounds(
        outbounds,
        prefix,
        name_pattern,
        tag_template,
        group_template,
        group_fallback,
        ignore_pattern,
        group_exclude_pattern,
    )


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
    args = parser.parse_args()

    json.dump(
        generate_output(
            args.url,
            prefix=args.prefix,
            name_regex=args.name_regex,
            tag_template=args.tag_template,
            group_template=args.group_template,
            group_fallback=args.group_fallback,
            ignore_regex=args.ignore_regex,
            group_exclude_regex=args.group_exclude_regex,
        ),
        sys.stdout,
        ensure_ascii=False,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
