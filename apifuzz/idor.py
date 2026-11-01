from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

from .analyzer import extract_json_field
from .utils import IdorFinding, RequestResult

OWNER_FIELDS = ("user_id", "owner_id")


def is_error_envelope(body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    raw_message = body.get("message", "")
    message = raw_message.lower().strip() if isinstance(raw_message, str) else ""
    status = body.get("status", "")
    message_error = not any(
        k in body for k in ("id", "owner_id", "user_id", "data")
    ) and message in {
        "unauthorized",
        "forbidden",
        "access denied",
        "not found",
        "authentication required",
        "permission denied",
    }
    return bool(
        message_error
        or body.get("error")
        or body.get("errors")
        or body.get("success") is False
        or (
            isinstance(status, str)
            and status.lower() in {"error", "failed", "unauthorized", "forbidden"}
        )
        or (
            body.get("type")
            and body.get("title")
            and isinstance(body.get("status"), int)
            and body["status"] >= 400
        )
    )


def _body_fingerprint(result: RequestResult) -> str:
    if result.body_sha256:
        return result.body_sha256
    if result.json_body is not None:
        try:
            raw = json.dumps(result.json_body, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError):
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
        if isinstance(value, (str, int, float, bool)):
            values[field] = value
    return values


def detect_idor_findings(
    results: list[RequestResult],
    policies: dict | None = None,
) -> list[IdorFinding]:
    groups: dict[tuple[str, str], list[RequestResult]] = defaultdict(list)
    for result in results:
        if "{id}" not in result.path_template:
            continue
        if not result.placeholder_values.get("id"):
            continue
        if (
            result.method == "GET"
            and result.status_code == 200
            and not result.error
            and not result.matches_baseline
            and not result.truncated
            and not is_error_envelope(result.json_body)
            and result.response_length > 0
        ):
            groups[(result.method, result.path_template)].append(result)

    findings: list[IdorFinding] = []
    for (method, template), group in groups.items():
        unique_ids = sorted({item.placeholder_values["id"] for item in group})
        confirmed = []
        allowed_responses: dict[tuple[str, str], set[str]] = defaultdict(set)
        for owner in group:
            item_id = owner.placeholder_values["id"]
            rule = (policies or {}).get(owner.profile, {}).get(template, {})
            if item_id in rule.get("allow", []) and owner.body_sha256:
                allowed_responses[(item_id, owner.body_sha256)].add(owner.profile)
        for item in group:
            item_id = item.placeholder_values["id"]
            rule = (policies or {}).get(item.profile, {}).get(template, {})
            if item_id not in rule.get("deny", []):
                continue
            owners = allowed_responses.get((item_id, item.body_sha256), set()) - {item.profile}
            if owners:
                confirmed.append(
                    f"profile {item.profile} retrieved denied ID {item_id}; full response matches allowed profile {sorted(owners)[0]}"
                )
        if confirmed:
            findings.append(
                IdorFinding(
                    method,
                    template,
                    unique_ids,
                    "; ".join(confirmed) + "; evaluated against user-supplied access policy",
                    [item.url for item in group],
                    classification="Confirmed Authorization Issue",
                    confidence="high",
                )
            )
            continue
        # Compare IDs within a principal, never confuse principal-specific responses
        # for differences between resources. Explicit public rules suppress heuristics.
        by_profile: dict[str, list[RequestResult]] = defaultdict(list)
        for item in group:
            rule = (policies or {}).get(item.profile, {}).get(template, {})
            if not rule.get("public", False):
                by_profile[item.profile].append(item)
        candidates = [
            items
            for items in by_profile.values()
            if len({i.placeholder_values["id"] for i in items}) >= 2
        ]
        if not candidates:
            continue
        candidates = [
            items
            for items in candidates
            if len({_body_fingerprint(i) for i in items}) > 1
            or len({i.response_length for i in items}) > 1
            or _differing_fields([_field_values(i) for i in items])
        ]
        if not candidates:
            continue
        group = max(candidates, key=len)
        unique_ids = sorted({item.placeholder_values["id"] for item in group})

        fingerprints = {_body_fingerprint(item) for item in group}
        lengths = {item.response_length for item in group}
        field_snapshots = [_field_values(item) for item in group]
        differing_fields = _differing_fields(field_snapshots)

        if len(fingerprints) < 2 and len(lengths) < 2 and not differing_fields:
            continue

        evidence_parts = [
            f"profile {group[0].profile}",
            f"{len(unique_ids)} different IDs returned HTTP 200",
            "authorization not verified; manual access-policy validation required",
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
