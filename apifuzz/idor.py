from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

from .analyzer import extract_json_field
from .utils import IdorFinding, RequestResult

OWNER_FIELDS = ("id", "user_id", "owner_id")


def _body_fingerprint(result: RequestResult) -> str:
    if result.json_body is not None:
        try:
            raw = json.dumps(result.json_body, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            raw = result.preview
    else:
        raw = result.preview
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def _field_values(result: RequestResult) -> dict[str, Any]:
    values: dict[str, Any] = {}
    if result.json_body is None:
        return values
    for field in OWNER_FIELDS:
        value = extract_json_field(result.json_body, field)
        if value is not None:
            values[field] = value
    return values


def detect_idor_findings(results: list[RequestResult]) -> list[IdorFinding]:
    groups: dict[tuple[str, str], list[RequestResult]] = defaultdict(list)
    for result in results:
        if "{id}" not in result.path_template:
            continue
        if not result.placeholder_values.get("id"):
            continue
        if result.status_code == 200 and not result.error:
            groups[(result.method, result.path_template)].append(result)

    findings: list[IdorFinding] = []
    for (method, template), group in groups.items():
        unique_ids = sorted({item.placeholder_values["id"] for item in group})
        if len(unique_ids) < 2:
            continue

        fingerprints = {_body_fingerprint(item) for item in group}
        lengths = {item.response_length for item in group}
        field_snapshots = [_field_values(item) for item in group]
        differing_fields = _differing_fields(field_snapshots)

        if len(fingerprints) < 2 and len(lengths) < 2 and not differing_fields:
            continue

        evidence_parts = [
            f"{len(unique_ids)} different IDs returned HTTP 200",
        ]
        if len(fingerprints) >= 2:
            evidence_parts.append("response bodies differ")
        if len(lengths) >= 2:
            evidence_parts.append("response lengths differ")
        if differing_fields:
            evidence_parts.append("owner-like JSON fields differ: " + ", ".join(differing_fields))

        findings.append(
            IdorFinding(
                method=method,
                path_template=template,
                tested_ids=unique_ids,
                evidence="; ".join(evidence_parts),
                urls=[item.url for item in group],
                differing_fields=differing_fields,
            )
        )

    return findings


def _differing_fields(snapshots: list[dict[str, Any]]) -> list[str]:
    fields: list[str] = []
    for field in OWNER_FIELDS:
        values = {str(snapshot[field]) for snapshot in snapshots if field in snapshot}
        if len(values) >= 2:
            fields.append(field)
    return fields
