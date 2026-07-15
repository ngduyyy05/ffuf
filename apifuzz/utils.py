from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

LOGGER_NAME = "apifuzz"


@dataclass(slots=True)
class RequestResult:
    method: str
    url: str
    path_template: str
    expanded_path: str
    placeholder_values: dict[str, str]
    status_code: int | None
    response_length: int
    content_type: str
    redirect_location: str
    response_time_ms: float
    preview: str
    error: str = ""
    json_body: Any | None = None
    interesting: bool = False
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class IdorFinding:
    method: str
    path_template: str
    tested_ids: list[str]
    evidence: str
    urls: list[str]
    differing_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
    )


def normalize_base_url(base_url: str) -> str:
    if not base_url.startswith(("http://", "https://")):
        raise ValueError("base URL must start with http:// or https://")
    return base_url.rstrip("/") + "/"


def build_url(base_url: str, path: str) -> str:
    return urljoin(normalize_base_url(base_url), path.lstrip("/"))


def load_wordlist(path: str | Path) -> list[str]:
    wordlist_path = Path(path)
    if not wordlist_path.exists():
        raise FileNotFoundError(f"wordlist not found: {wordlist_path}")

    entries: list[str] = []
    for line in wordlist_path.read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        if not item.startswith("/"):
            item = "/" + item
        entries.append(item)
    return entries


def parse_methods(value: str) -> list[str]:
    allowed = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
    methods = [method.strip().upper() for method in value.split(",") if method.strip()]
    invalid = sorted(set(methods) - allowed)
    if invalid:
        raise ValueError(f"unsupported methods: {', '.join(invalid)}")
    return methods or ["GET"]


def parse_header_values(values: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if not values:
        return headers

    for raw in values:
        if ":" not in raw:
            raise ValueError(f"invalid header format: {raw!r}. Expected 'Name: value'.")
        name, value = raw.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            raise ValueError("header name cannot be empty")
        headers[name] = value
    return headers


def parse_ids(value: str | None = None, file_path: str | None = None) -> list[str]:
    ids: list[str] = []

    if value:
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            match = re.fullmatch(r"(-?\d+)-(-?\d+)", part)
            if match:
                start = int(match.group(1))
                end = int(match.group(2))
                step = 1 if end >= start else -1
                ids.extend(str(num) for num in range(start, end + step, step))
            else:
                ids.append(part)

    if file_path:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"ID file not found: {path}")
        for line in path.read_text(encoding="utf-8").splitlines():
            item = line.strip()
            if item and not item.startswith("#"):
                ids.append(item)

    seen: set[str] = set()
    unique_ids: list[str] = []
    for item in ids:
        if item not in seen:
            seen.add(item)
            unique_ids.append(item)
    return unique_ids


def expand_path(path_template: str, ids: list[str]) -> list[tuple[str, dict[str, str]]]:
    if "{id}" not in path_template:
        return [(path_template, {})]

    if not ids:
        return []

    expanded: list[tuple[str, dict[str, str]]] = []
    for item in ids:
        expanded.append((path_template.replace("{id}", item), {"id": item}))
    return expanded


def make_preview(body: str, limit: int = 160) -> str:
    body = body.replace("\r", " ").replace("\n", " ").strip()
    return body[:limit]


def safe_lower(value: str | None) -> str:
    return (value or "").lower()
