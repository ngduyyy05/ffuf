"""Strict JSON authentication profiles and explicit route access expectations."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .utils import build_url, parse_header_values


def load_profiles(path: str) -> list[dict]:
    source = Path(path)
    if source.stat().st_size > 1024 * 1024:
        raise ValueError("profile file exceeds 1 MiB")
    profiles = json.loads(source.read_text(encoding="utf-8-sig"))
    if not isinstance(profiles, list) or not 1 <= len(profiles) <= 10:
        raise ValueError("profile file must be an array of 1 to 10 profiles")
    names = set()
    for profile in profiles:
        if not isinstance(profile, dict) or set(profile) - {"name", "headers", "cookie", "access"}:
            raise ValueError("unknown or invalid profile fields")
        name = profile.get("name", "")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name)
            or name in names
        ):
            raise ValueError("profile names must be unique safe identifiers")
        names.add(name)
        headers = profile.get("headers", {})
        if not isinstance(headers, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in headers.items()
        ):
            raise ValueError("profile headers must map strings to strings")
        parse_header_values([f"{k}: {v}" for k, v in headers.items()])
        if "cookie" in profile:
            if not isinstance(profile["cookie"], str):
                raise ValueError("profile cookie must be a string")
            parse_header_values(["Cookie: " + profile["cookie"]])
        access = profile.get("access", {})
        if not isinstance(access, dict):
            raise ValueError("access must map route templates to rules")
        for route, rule in access.items():
            build_url("http://localhost/", route)
            if not isinstance(rule, dict) or set(rule) - {"allow", "deny", "public"}:
                raise ValueError("access rules support allow, deny, public only")
            if not isinstance(rule.get("public", False), bool):
                raise ValueError("public must be boolean")
            for key in ("allow", "deny"):
                if not isinstance(rule.get(key, []), list) or not all(
                    isinstance(i, str) for i in rule.get(key, [])
                ):
                    raise ValueError("allow/deny must be arrays of string IDs")
            if set(rule.get("allow", [])) & set(rule.get("deny", [])):
                raise ValueError("allow and deny IDs overlap")
            if rule.get("public") and rule.get("deny"):
                raise ValueError("public route cannot have denied IDs")
    return profiles
