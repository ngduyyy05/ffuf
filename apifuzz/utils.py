from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

LOGGER_NAME = "apifuzz"
MAX_IDS = 10000
MAX_PATHS = 10000


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
    body_sha256: str = ""
    matches_baseline: bool = False
    truncated: bool = False
    attempts: int = 1
    profile: str = "default"
    filtered: bool = False

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
    classification: str = "Potential IDOR"
    confidence: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger(LOGGER_NAME).setLevel(level)


def normalize_base_url(base_url: str) -> str:
    if re.search(r"[\x00-\x20\x7f\\]", base_url):
        raise ValueError("base URL contains whitespace, controls, or backslashes")
    parts = urlsplit(base_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("base URL must be an absolute http:// or https:// URL")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise ValueError("base URL cannot contain credentials, query, or fragment")
    try:
        _ = parts.port  # Access validates malformed and out-of-range ports.
    except ValueError as exc:
        raise ValueError("invalid base URL port") from exc
    _validate_path(parts.path)
    return base_url.rstrip("/") + "/"


def _validate_path(path: str) -> None:
    decoded = path
    for _ in range(4):
        if re.search(r"[\x00-\x1f\x7f\\]", decoded):
            raise ValueError("path contains controls or backslashes")
        if any(segment in {".", ".."} for segment in decoded.split("/")):
            raise ValueError("path traversal is outside the allowed base prefix")
        new = unquote(decoded)
        if new == decoded:
            break
        decoded = new


def build_url(base_url: str, path: str) -> str:
    base = normalize_base_url(base_url)
    parts = urlsplit(path)
    if parts.scheme or parts.netloc or path.startswith("//") or "\\" in path or parts.fragment:
        raise ValueError(f"wordlist entry must be a relative path: {path!r}")
    _validate_path(parts.path)
    if re.search(r"[{}]", path.replace("{id}", "")):
        raise ValueError("only {id} path placeholders are supported")
    url = urljoin(base, path.lstrip("/"))
    if urlsplit(url).netloc != urlsplit(base).netloc:
        raise ValueError("path escapes target origin")
    return url


def load_wordlist(path: str | Path) -> list[str]:
    wordlist_path = Path(path)
    if not wordlist_path.exists():
        raise FileNotFoundError(f"wordlist not found: {wordlist_path}")

    entries: list[str] = []
    seen: set[str] = set()
    if wordlist_path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("wordlist exceeds 4 MiB")
    for line in wordlist_path.read_text(encoding="utf-8-sig").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        build_url("http://validation.local/", item)
        if not item.startswith("/"):
            item = "/" + item
        if item not in seen:
            seen.add(item)
            entries.append(item)
            if len(entries) > MAX_PATHS:
                raise ValueError(f"wordlist exceeds {MAX_PATHS} paths")
    if not entries:
        raise ValueError("wordlist contains no paths")
    return entries


def parse_methods(value: str) -> list[str]:
    allowed = {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
    methods = [method.strip().upper() for method in value.split(",") if method.strip()]
    invalid = sorted(set(methods) - allowed)
    if invalid:
        raise ValueError(f"unsupported methods: {', '.join(invalid)}")
    if not methods:
        raise ValueError("provide at least one HTTP method")
    return list(dict.fromkeys(methods))


def parse_header_values(values: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if not values:
        return headers

    for raw in values:
        if "\r" in raw or "\n" in raw:
            raise ValueError("header contains a line break")
        if ":" not in raw:
            raise ValueError("invalid header format; expected 'Name: value'")
        name, value = raw.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or re.search(
            r"[\x00-\x1f\x7f]", value
        ):
            raise ValueError("invalid header name or value")
        if name.lower() in {
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "proxy-authorization",
        }:
            raise ValueError(f"header {name} is managed by the HTTP engine")
        try:
            value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ValueError("header values must be Latin-1 encodable") from exc
        for old in list(headers):
            if old.lower() == name.lower():
                del headers[old]
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
                if abs(end - start) + 1 + len(ids) > MAX_IDS:
                    raise ValueError(f"ID expansion exceeds {MAX_IDS}")
                step = 1 if end >= start else -1
                ids.extend(str(num) for num in range(start, end + step, step))
            else:
                if re.fullmatch(r"\d+-.*", part):
                    raise ValueError(f"invalid ID range: {part}")
                ids.append(part)
            if len(ids) > MAX_IDS:
                raise ValueError(f"ID expansion exceeds {MAX_IDS}")

    if file_path:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"ID file not found: {path}")
        if path.stat().st_size > 1024 * 1024:
            raise ValueError("ID file exceeds 1 MiB")
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            item = line.strip()
            if item and not item.startswith("#"):
                ids.append(item)
                if len(ids) > MAX_IDS:
                    raise ValueError(f"ID expansion exceeds {MAX_IDS}")

    seen: set[str] = set()
    unique_ids: list[str] = []
    for item in ids:
        if item in {".", ".."} or len(item) > 1024 or re.search(r"[\x00-\x1f\x7f]", item):
            raise ValueError("invalid ID: dot segments, controls, or length above 1024")
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
        if item in {".", ".."}:
            raise ValueError("ID cannot be a dot segment")
        expanded.append((path_template.replace("{id}", quote(item, safe="")), {"id": item}))
    return expanded


def make_preview(body: str, limit: int = 160) -> str:
    body = body.replace("\r", " ").replace("\n", " ").strip()
    return body[:limit]


def safe_lower(value: str | None) -> str:
    return (value or "").lower()


def redact_url(value: str) -> str:
    """Omit all query values, including unknown application credential names."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return "[invalid URL omitted]"
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc.rsplit("@", 1)[-1],
            parts.path,
            urlencode(
                [(key, "REDACTED") for key, _ in parse_qsl(parts.query, keep_blank_values=True)]
            ),
            "",
        )
    )
