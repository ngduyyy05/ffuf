from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass

from .analyzer import ResponseAnalyzer, build_baseline_from_result
from .idor import detect_idor_findings
from .requester import ApiRequester
from .utils import LOGGER_NAME, IdorFinding, RequestResult, build_url, expand_path

logger = logging.getLogger(LOGGER_NAME)


@dataclass(slots=True)
class FuzzRunResult:
    results: list[RequestResult]
    idor_findings: list[IdorFinding]
    baseline: RequestResult | None


class ApiFuzzer:
    def __init__(
        self,
        base_url: str,
        paths: list[str],
        methods: list[str],
        requester: ApiRequester,
        ids: list[str] | None = None,
        rate_limit: float = 5.0,
    ) -> None:
        self.base_url = base_url
        self.paths = paths
        self.methods = methods
        self.requester = requester
        self.ids = ids or []
        self.rate_limit = max(rate_limit, 0.1)

    def run(self) -> FuzzRunResult:
        baseline = self._get_baseline()
        analyzer = ResponseAnalyzer(build_baseline_from_result(baseline) if baseline else None)

        results: list[RequestResult] = []
        delay = 1.0 / self.rate_limit

        for method in self.methods:
            for path_template in self.paths:
                expanded_items = expand_path(path_template, self.ids)
                if not expanded_items:
                    logger.warning("skipping %s because it contains {id} but no IDs were provided", path_template)
                    continue

                for expanded_path, placeholder_values in expanded_items:
                    url = build_url(self.base_url, expanded_path)
                    result = self.requester.request(
                        method=method,
                        url=url,
                        path_template=path_template,
                        expanded_path=expanded_path,
                        placeholder_values=placeholder_values,
                    )
                    analyzer.analyze(result)
                    results.append(result)
                    time.sleep(delay)

        idor_findings = detect_idor_findings(results)
        return FuzzRunResult(results=results, idor_findings=idor_findings, baseline=baseline)

    def _get_baseline(self) -> RequestResult | None:
        path = f"/__apifuzz_not_found_{uuid.uuid4().hex}"
        url = build_url(self.base_url, path)
        result = self.requester.request(
            method="GET",
            url=url,
            path_template=path,
            expanded_path=path,
            placeholder_values={},
        )
        if result.error:
            logger.warning("could not establish 404 baseline: %s", result.error)
            return None
        return result
