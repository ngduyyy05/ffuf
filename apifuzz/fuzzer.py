from __future__ import annotations

import logging
import math
import time
import uuid
from dataclasses import dataclass, field

from .analyzer import ResponseAnalyzer, build_baseline_from_result
from .idor import detect_idor_findings, is_error_envelope
from .requester import ApiRequester
from .utils import (
    LOGGER_NAME,
    IdorFinding,
    RequestResult,
    build_url,
    expand_path,
    normalize_base_url,
    parse_methods,
)

logger = logging.getLogger(LOGGER_NAME)


@dataclass(slots=True)
class FuzzRunResult:
    results: list[RequestResult]
    idor_findings: list[IdorFinding]
    baseline: RequestResult | None
    baselines: list[RequestResult] = field(default_factory=list)
    cancelled: bool = False
    assessments: list[dict] = field(default_factory=list)
    stop_reason: str = ""
    attempts_started: int = 0


class ScanLimitReached(Exception):
    pass


class ApiFuzzer:
    def __init__(
        self,
        base_url: str,
        paths: list[str],
        methods: list[str],
        requester: ApiRequester,
        ids: list[str] | None = None,
        rate_limit: float = 5.0,
        max_requests: int = 10000,
        profiles: list[ApiRequester] | None = None,
        policies: dict | None = None,
        exclude_status: set[int] | None = None,
        min_size: int = 0,
        content_type: str | None = None,
    ) -> None:
        self.base_url = normalize_base_url(base_url)
        self.paths = list(dict.fromkeys(paths))
        self.methods = parse_methods(",".join(methods))
        self.requester = requester
        self.profiles = profiles or [requester]
        self.policies = policies or {}
        self.ids = list(dict.fromkeys(ids or []))
        if not math.isfinite(rate_limit) or rate_limit <= 0:
            raise ValueError("rate limit must be a positive finite number")
        if not 1 <= max_requests <= 100000:
            raise ValueError("max requests must be between 1 and 100000")
        self.rate_limit = rate_limit
        self.max_requests = max_requests
        self.exclude_status = exclude_status or set()
        self.min_size = min_size
        self.content_type = content_type
        self._last_request: float | None = None
        self._attempts = 0
        self._received_bytes = 0
        self._plan = []
        planned = sum((len(self.ids) if "{id}" in path else 1) + 1 for path in self.paths) * len(
            self.methods
        )
        worst_case = sum(planned * (1 + p.retries) for p in self.profiles)
        if worst_case > max_requests:
            raise ValueError(
                f"scan may require {worst_case} attempts; exceeds --max-requests {max_requests}"
            )
        for path in self.paths:
            build_url(self.base_url, path)
            if "{id}" in path and not self.ids:
                raise ValueError("templates containing {id} require IDs")
            expanded = expand_path(path, self.ids)
            for expanded_path, _ in expanded:
                build_url(self.base_url, expanded_path)
            self._plan.append((path, expanded))
        # One random sibling per route and method/profile. Budget includes retries.

    def _pace(self) -> None:
        if self._attempts >= self.max_requests:
            raise ScanLimitReached("request budget exhausted")
        if self._received_bytes >= 8 * 1024 * 1024:
            raise ScanLimitReached("aggregate response budget of 8 MiB reached")
        if self._last_request is not None:
            time.sleep(max(0, 1 / self.rate_limit - (time.monotonic() - self._last_request)))
        self._last_request = time.monotonic()
        self._attempts += 1

    def run(self) -> FuzzRunResult:
        self._last_request = None
        self._attempts = 0
        self._received_bytes = 0
        run = FuzzRunResult([], [], None)
        try:
            for requester in self.profiles:
                requester.before_request = self._pace
                for method in self.methods:
                    for template, items in self._plan:
                        baseline = self._get_baseline(method, template, requester)
                        if baseline is not None:
                            run.baselines.append(baseline)
                            if (
                                run.baseline is None
                                and not baseline.error
                                and not baseline.truncated
                            ):
                                run.baseline = baseline
                        analyzer = ResponseAnalyzer(
                            build_baseline_from_result(baseline)
                            if baseline and not baseline.error and not baseline.truncated
                            else None
                        )
                        for path, values in items:
                            result = requester.request(
                                method, build_url(self.base_url, path), template, path, values
                            )
                            self._received_bytes += result.response_length
                            analyzer.analyze(result)
                            result.filtered = (
                                result.status_code in self.exclude_status
                                or result.response_length < self.min_size
                                or bool(
                                    self.content_type
                                    and self.content_type.lower() not in result.content_type.lower()
                                )
                            )
                            if result.filtered:
                                result.interesting = False
                            run.results.append(result)
        except KeyboardInterrupt:
            run.cancelled = True
            run.stop_reason = "interrupted by user"
            logger.warning("scan interrupted; exporting completed requests")
        except ScanLimitReached as exc:
            run.cancelled = True
            run.stop_reason = str(exc)
        finally:
            for requester in self.profiles:
                requester.before_request = None
        run.idor_findings = detect_idor_findings(run.results, self.policies)
        run.attempts_started = self._attempts
        for template in self.paths:
            if "{id}" not in template or "GET" not in self.methods:
                continue
            findings = [f for f in run.idor_findings if f.path_template == template]
            samples = [r for r in run.results if r.path_template == template and r.method == "GET"]
            rules = [self.policies.get(p.profile, {}).get(template, {}) for p in self.profiles]
            tested_denials = [
                (r, rule)
                for r in samples
                for rule in [self.policies.get(r.profile, {}).get(template, {})]
                if r.placeholder_values.get("id") in rule.get("deny", [])
            ]
            allowed = [
                r
                for r in samples
                if r.placeholder_values.get("id")
                in self.policies.get(r.profile, {}).get(template, {}).get("allow", [])
            ]
            valid_allowed = bool(allowed) and all(
                r.status_code == 200
                and not r.error
                and not r.truncated
                and not is_error_envelope(r.json_body)
                for r in allowed
            )
            if findings:
                category = findings[0].classification
            elif (
                samples
                and not run.cancelled
                and all(rule.get("public") for rule in rules)
                and all(
                    r.status_code == 200
                    and not r.error
                    and not r.truncated
                    and not is_error_envelope(r.json_body)
                    for r in samples
                )
            ):
                category = "No Issue Observed"
            elif (
                not run.cancelled
                and valid_allowed
                and tested_denials
                and all(r.status_code in {403, 404} and not r.error for r, _ in tested_denials)
            ):
                category = "No Issue Observed"
            else:
                category = "Inconclusive"
            run.assessments.append(
                {
                    "path_template": template,
                    "classification": category,
                    "scope": "completed GET samples and supplied policy only",
                    "authentication_failures": sum(r.status_code == 401 for r in samples),
                    "authorization_denials": sum(r.status_code == 403 for r in samples),
                }
            )
        return run

    def _get_baseline(
        self, method: str = "GET", template: str = "/", requester: ApiRequester | None = None
    ) -> RequestResult | None:
        marker = "__apifuzz_not_found_" + uuid.uuid4().hex
        if "{id}" in template:
            path = template.replace("{id}", marker)
        else:
            path = template.split("?", 1)[0].rsplit("/", 1)[0] + "/" + marker
        result = (requester or self.requester).request(
            method, build_url(self.base_url, path), path, path, {}
        )
        self._received_bytes += result.response_length
        return result
