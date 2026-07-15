from __future__ import annotations

import logging
import time
from typing import Any

import requests
from requests import Response
from requests.exceptions import ConnectionError, InvalidURL, RequestException, Timeout

from .utils import LOGGER_NAME, RequestResult, make_preview

logger = logging.getLogger(LOGGER_NAME)


class ApiRequester:
    def __init__(
        self,
        headers: dict[str, str] | None = None,
        cookie: str | None = None,
        timeout: float = 8.0,
        user_agent: str = "APIEndpointFuzzer/0.1 (authorized-security-lab)",
    ) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        if headers:
            self.session.headers.update(headers)
        if cookie:
            self.session.headers.update({"Cookie": cookie})

    def request(
        self,
        method: str,
        url: str,
        path_template: str,
        expanded_path: str,
        placeholder_values: dict[str, str],
    ) -> RequestResult:
        started = time.perf_counter()
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                allow_redirects=False,
            )
            elapsed_ms = (time.perf_counter() - started) * 1000
            return self._to_result(
                response=response,
                method=method,
                url=url,
                path_template=path_template,
                expanded_path=expanded_path,
                placeholder_values=placeholder_values,
                elapsed_ms=elapsed_ms,
            )
        except (Timeout, ConnectionError, InvalidURL, RequestException) as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000
            logger.debug("request failed for %s %s: %s", method, url, exc)
            return RequestResult(
                method=method,
                url=url,
                path_template=path_template,
                expanded_path=expanded_path,
                placeholder_values=placeholder_values,
                status_code=None,
                response_length=0,
                content_type="",
                redirect_location="",
                response_time_ms=round(elapsed_ms, 2),
                preview="",
                error=f"{type(exc).__name__}: {exc}",
            )

    @staticmethod
    def _to_result(
        response: Response,
        method: str,
        url: str,
        path_template: str,
        expanded_path: str,
        placeholder_values: dict[str, str],
        elapsed_ms: float,
    ) -> RequestResult:
        text = response.text or ""
        json_body: Any | None = None
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type.lower():
            try:
                json_body = response.json()
            except ValueError:
                json_body = None

        return RequestResult(
            method=method,
            url=url,
            path_template=path_template,
            expanded_path=expanded_path,
            placeholder_values=placeholder_values,
            status_code=response.status_code,
            response_length=len(response.content or b""),
            content_type=content_type,
            redirect_location=response.headers.get("Location", ""),
            response_time_ms=round(elapsed_ms, 2),
            preview=make_preview(text),
            json_body=json_body,
        )
