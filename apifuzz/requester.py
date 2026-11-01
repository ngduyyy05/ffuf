from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.exceptions import RequestException

from .analyzer import ResponseAnalyzer
from .utils import RequestResult, make_preview, normalize_base_url, parse_header_values


class ApiRequester:
    """Isolated principal, bounded streaming, TLS verification, no redirects.

    Retries apply only to GET/HEAD/OPTIONS. Fuzzer pacing covers every attempt.
    Environment proxies/netrc and server-set cookie persistence are disabled.
    """

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        cookie: str | None = None,
        timeout: float = 8.0,
        user_agent: str = "APIEndpointFuzzer/0.2 (authorized-security-lab)",
        body: str | None = None,
        retries: int = 1,
        max_response_bytes: int = 1048576,
        body_template: bool = False,
        profile: str = "default",
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a positive finite number")
        if not 0 <= retries <= 5:
            raise ValueError("retries must be between 0 and 5")
        if not 1 <= max_response_bytes <= 16 * 1024 * 1024:
            raise ValueError("max response bytes must be between 1 and 16777216")
        self.timeout = timeout
        self.body = body
        self.retries = retries
        self.max_response_bytes = max_response_bytes
        self.body_template = body_template
        self.profile = profile
        self.before_request: Callable[[], None] | None = None
        validated = parse_header_values([f"{k}: {v}" for k, v in (headers or {}).items()])
        if cookie:
            validated.update(parse_header_values([f"Cookie: {cookie}"]))
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": user_agent, **validated})

    def request(
        self,
        method: str,
        url: str,
        path_template: str,
        expanded_path: str,
        placeholder_values: dict[str, str],
    ) -> RequestResult:
        parts = urlsplit(url)
        normalize_base_url(urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")))
        method = method.upper()
        started = time.perf_counter()
        result = RequestResult(
            method,
            url,
            path_template,
            expanded_path,
            placeholder_values,
            None,
            0,
            "",
            "",
            0,
            "",
            profile=self.profile,
        )
        safe_retry = method in {"GET", "HEAD", "OPTIONS"}
        for attempt in range(1 + (self.retries if safe_retry else 0)):
            if self.before_request:
                self.before_request()
            result.attempts = attempt + 1
            try:
                body = self.body
                if body is not None and self.body_template:
                    # Use {id} inside JSON quotes; replacement escapes string contents.
                    body = body.replace("{id}", json.dumps(placeholder_values.get("id", ""))[1:-1])
                self.session.cookies.clear()
                with self.session.request(
                    method=method,
                    url=url,
                    timeout=(self.timeout, self.timeout),
                    allow_redirects=False,
                    stream=True,
                    data=body.encode("utf-8")
                    if body is not None and method in {"POST", "PUT", "PATCH", "DELETE"}
                    else None,
                ) as response:
                    content = bytearray()
                    deadline = time.monotonic() + self.timeout
                    for chunk in response.iter_content(
                        chunk_size=min(65536, self.max_response_bytes + 1)
                    ):
                        remaining = self.max_response_bytes + 1 - len(content)
                        content.extend(chunk[:remaining])
                        if len(content) > self.max_response_bytes:
                            break
                        if time.monotonic() > deadline:
                            raise requests.exceptions.Timeout("response deadline exceeded")
                    result.truncated = len(content) > self.max_response_bytes
                    raw = bytes(content[: self.max_response_bytes])
                    result.status_code = response.status_code
                    result.response_length = len(raw)
                    result.content_type = response.headers.get("Content-Type", "")
                    result.redirect_location = response.headers.get("Location", "")
                    text = raw.decode(response.encoding or "utf-8", errors="replace")
                    result.preview = make_preview(text)
                    result.body_sha256 = "" if result.truncated else hashlib.sha256(raw).hexdigest()
                    result.json_body = None
                    if not result.truncated and ResponseAnalyzer.is_json(result.content_type):
                        try:
                            result.json_body = json.loads(text)
                        except (ValueError, RecursionError):
                            pass
                    result.error = ""
                    retry_after = response.headers.get("Retry-After", "")
                if (
                    result.status_code not in {429, 502, 503, 504}
                    or attempt >= self.retries
                    or not safe_retry
                ):
                    break
                delay = (
                    min(float(retry_after), 30.0)
                    if retry_after.isdigit()
                    else min(0.5 * 2**attempt, 8)
                )
                time.sleep(delay)
            except (RequestException, LookupError) as exc:
                # Exception text can contain credentials; preserve the failure class only.
                result.error = type(exc).__name__
                result.status_code = None
                result.response_length = 0
                result.preview = ""
                result.json_body = None
                result.body_sha256 = ""
                result.content_type = ""
                result.redirect_location = ""
                result.truncated = False
                if attempt >= self.retries or not safe_retry:
                    break
                time.sleep(min(0.5 * 2**attempt, 8))
            finally:
                self.session.cookies.clear()
        result.response_time_ms = round((time.perf_counter() - started) * 1000, 2)
        return result

    def close(self) -> None:
        self.session.close()
