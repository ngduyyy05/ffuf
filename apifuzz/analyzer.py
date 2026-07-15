from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .utils import RequestResult, safe_lower

SUCCESS_CODES = {200, 201, 202, 204}
BLOCKED_CODES = {401, 403}
SERVER_ERROR_CODES = {500}
SENSITIVE_KEYWORDS = {
    "id",
    "user",
    "email",
    "role",
    "admin",
    "token",
    "secret",
    "order",
    "invoice",
}


@dataclass(slots=True)
class Baseline:
    status_code: int | None = None
    response_length: int = 0
    content_type: str = ""


class ResponseAnalyzer:
    def __init__(self, baseline: Baseline | None = None, length_delta_ratio: float = 0.35) -> None:
        self.baseline = baseline or Baseline()
        self.length_delta_ratio = length_delta_ratio

    def analyze(self, result: RequestResult) -> RequestResult:
        reasons = self.get_reasons(result)
        result.reasons = reasons
        result.interesting = bool(reasons)
        return result

    def get_reasons(self, result: RequestResult) -> list[str]:
        reasons: list[str] = []
        status = result.status_code

        if status in SUCCESS_CODES:
            reasons.append(f"success status {status}")
        if status in BLOCKED_CODES:
            reasons.append(f"protected endpoint status {status}")
        if status in SERVER_ERROR_CODES:
            reasons.append("server error status 500")
        if self.is_json(result.content_type):
            reasons.append("JSON response")
        if self.length_differs_from_baseline(result.response_length):
            reasons.append("response length differs from 404 baseline")

        matched_keywords = self.find_sensitive_keywords(result)
        if matched_keywords:
            reasons.append("sensitive keywords: " + ", ".join(matched_keywords))

        return reasons

    @staticmethod
    def is_json(content_type: str) -> bool:
        return "application/json" in safe_lower(content_type)

    def length_differs_from_baseline(self, response_length: int) -> bool:
        baseline_length = self.baseline.response_length
        if baseline_length <= 0 or response_length <= 0:
            return False
        delta = abs(response_length - baseline_length)
        return delta / max(baseline_length, 1) >= self.length_delta_ratio

    @staticmethod
    def find_sensitive_keywords(result: RequestResult) -> list[str]:
        text = result.preview
        if result.json_body is not None:
            try:
                text += " " + json.dumps(result.json_body, sort_keys=True)
            except (TypeError, ValueError):
                pass

        lowered = safe_lower(text)
        found = sorted(keyword for keyword in SENSITIVE_KEYWORDS if keyword in lowered)
        return found


def build_baseline_from_result(result: RequestResult) -> Baseline:
    return Baseline(
        status_code=result.status_code,
        response_length=result.response_length,
        content_type=result.content_type,
    )


def extract_json_field(json_body: Any, field_name: str) -> Any | None:
    if isinstance(json_body, dict):
        if field_name in json_body:
            return json_body[field_name]
        for value in json_body.values():
            nested = extract_json_field(value, field_name)
            if nested is not None:
                return nested
    if isinstance(json_body, list):
        for item in json_body:
            nested = extract_json_field(item, field_name)
            if nested is not None:
                return nested
    return None
