from __future__ import annotations

import csv
import html
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from .fuzzer import FuzzRunResult
from .utils import IdorFinding, RequestResult, redact_url


def _safe_run(run: FuzzRunResult) -> FuzzRunResult:
    def clean(item: RequestResult) -> RequestResult:
        return replace(
            item,
            url=redact_url(item.url),
            path_template=redact_url(item.path_template),
            expanded_path=redact_url(item.expanded_path),
            redirect_location=redact_url(item.redirect_location),
            preview="",
            json_body=None,
        )

    return replace(
        run,
        results=[clean(r) for r in run.results],
        baseline=clean(run.baseline) if run.baseline else None,
        baselines=[clean(r) for r in run.baselines],
        assessments=[
            {**a, "path_template": redact_url(a["path_template"])} for a in run.assessments
        ],
        idor_findings=[
            replace(
                f, urls=[redact_url(u) for u in f.urls], path_template=redact_url(f.path_template)
            )
            for f in run.idor_findings
        ],
    )


try:
    from rich.console import Console
    from rich.table import Table
except ImportError:  # pragma: no cover - fallback for minimal installs
    Console = None
    Table = None


def print_terminal_report(run: FuzzRunResult) -> None:
    run = _safe_run(run)
    interesting = [result for result in run.results if result.interesting]
    errors = [result for result in run.results if result.error or (result.status_code or 0) >= 500]

    if Console and Table:
        console = Console(markup=False, highlight=False)
        console.print(
            f"Scan {'incomplete' if run.cancelled else 'complete'} "
            f"requests={len(run.results)} interesting={len(interesting)} "
            f"authorization_findings={len(run.idor_findings)} errors={len(errors)}"
        )

        table = Table(title="Interesting Endpoints")
        table.add_column("Method")
        table.add_column("Status")
        table.add_column("Length", justify="right")
        table.add_column("Time ms", justify="right")
        table.add_column("Content-Type")
        table.add_column("URL")
        table.add_column("Reasons")
        for item in interesting:
            table.add_row(
                item.method,
                str(item.status_code),
                str(item.response_length),
                f"{item.response_time_ms:.2f}",
                item.content_type[:40],
                item.url,
                "; ".join(item.reasons),
            )
        console.print(table)

        if run.idor_findings:
            idor_table = Table(title="Authorization Findings")
            idor_table.add_column("Method")
            idor_table.add_column("Template")
            idor_table.add_column("IDs")
            idor_table.add_column("Evidence")
            idor_table.add_column("Classification / confidence")
            for finding in run.idor_findings:
                idor_table.add_row(
                    finding.method,
                    finding.path_template,
                    ", ".join(finding.tested_ids[:12]),
                    finding.evidence,
                    finding.classification + " / " + finding.confidence,
                )
            console.print(idor_table)
        return

    print(
        f"Scan complete requests={len(run.results)} interesting={len(interesting)} "
        f"authorization_findings={len(run.idor_findings)} errors={len(errors)}"
    )
    for item in interesting:
        print(
            f"{item.method} {item.status_code} {item.response_length} {item.url} :: {'; '.join(item.reasons)}"
        )


def write_json(run: FuzzRunResult, output_path: str | Path) -> None:
    run = _safe_run(run)
    payload: dict[str, Any] = {
        "summary": _summary(run),
        "baseline": run.baseline.to_dict() if run.baseline else None,
        "results": [result.to_dict() for result in run.results],
        "idor_findings": [finding.to_dict() for finding in run.idor_findings],
        "baselines": [result.to_dict() for result in run.baselines],
        "assessments": run.assessments,
        "cancelled": run.cancelled,
        "stop_reason": run.stop_reason,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def write_csv(run: FuzzRunResult, output_path: str | Path) -> None:
    run = _safe_run(run)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "method",
                "url",
                "path_template",
                "status_code",
                "response_length",
                "content_type",
                "redirect_location",
                "response_time_ms",
                "interesting",
                "reasons",
                "error",
                "preview",
                "profile",
                "truncated",
                "attempts",
                "filtered",
            ],
        )
        writer.writeheader()
        for item in run.results:
            row = {
                "method": item.method,
                "url": item.url,
                "path_template": item.path_template,
                "status_code": item.status_code,
                "response_length": item.response_length,
                "content_type": item.content_type,
                "redirect_location": item.redirect_location,
                "response_time_ms": item.response_time_ms,
                "interesting": item.interesting,
                "reasons": "; ".join(item.reasons),
                "error": item.error,
                "preview": item.preview,
                "profile": item.profile,
                "truncated": item.truncated,
                "attempts": item.attempts,
                "filtered": item.filtered,
            }
            writer.writerow(
                {
                    k: (
                        "'" + v
                        if isinstance(v, str) and v.lstrip().startswith(("=", "+", "-", "@"))
                        else v
                    )
                    for k, v in row.items()
                }
            )


def write_markdown(run: FuzzRunResult, output_path: str | Path) -> None:
    run = _safe_run(run)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    summary = _summary(run)

    lines.append("# API Fuzz Report")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- cancelled: {run.cancelled}")
    if run.stop_reason:
        lines.append(f"- stop_reason: {_escape(run.stop_reason)}")
    for key, value in summary.items():
        lines.append(f"- {key}: {value}")
    lines.append("")

    lines.extend(
        _markdown_results(
            "Interesting Endpoints", [item for item in run.results if item.interesting]
        )
    )
    lines.extend(_markdown_idor(run.idor_findings))
    lines.extend(
        _markdown_results(
            "Error Endpoints",
            [item for item in run.results if item.error or (item.status_code or 0) >= 500],
        )
    )
    lines.append("## Route Assessments\n")
    for assessment in run.assessments:
        lines.append(f"- {_escape(assessment['path_template'])}: {assessment['classification']}")
    lines.extend(_markdown_results("Full Request Table", run.results))

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _summary(run: FuzzRunResult) -> dict[str, int]:
    return {
        "total_requests": len(run.results),
        "interesting_endpoints": len([item for item in run.results if item.interesting]),
        "potential_idor_findings": sum(
            f.classification == "Potential IDOR" for f in run.idor_findings
        ),
        "confirmed_authorization_issues": sum(
            f.classification == "Confirmed Authorization Issue" for f in run.idor_findings
        ),
        "error_endpoints": len(
            [item for item in run.results if item.error or (item.status_code or 0) >= 500]
        ),
        "network_errors": sum(bool(item.error) for item in run.results),
        "truncated_responses": sum(item.truncated for item in run.results),
        "filtered_responses": sum(item.filtered for item in run.results),
        "baseline_requests": len(run.baselines),
        "completed_attempts": sum(item.attempts for item in run.results + run.baselines),
        "attempts_started": run.attempts_started,
    }


def _markdown_results(title: str, results: list[RequestResult]) -> list[str]:
    lines = [f"## {title}", ""]
    if not results:
        lines.extend(["None.", ""])
        return lines

    lines.append("| Method | Status | Length | Time ms | URL | Reasons |")
    lines.append("| --- | ---: | ---: | ---: | --- | --- |")
    for item in results:
        reasons = "; ".join(item.reasons) or item.error
        lines.append(
            f"| {item.method} | {item.status_code} | {item.response_length} | "
            f"{item.response_time_ms:.2f} | {_escape(item.url)} | {_escape(reasons)} |"
        )
    lines.append("")
    return lines


def _markdown_idor(findings: list[IdorFinding]) -> list[str]:
    lines = ["## Authorization Findings", ""]
    if not findings:
        lines.extend(["None.", ""])
        return lines

    lines.append("| Method | Template | IDs | Classification | Confidence | Evidence |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for finding in findings:
        ids = ", ".join(finding.tested_ids)
        lines.append(
            f"| {finding.method} | {_escape(finding.path_template)} | {_escape(ids)} | {finding.classification} | {finding.confidence} | {_escape(finding.evidence)} |"
        )
    lines.append("")
    return lines


def _escape(value: str) -> str:
    return (
        html.escape(value)
        .replace("|", "&#124;")
        .replace("`", "&#96;")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def write_html(run: FuzzRunResult, output_path: str | Path) -> None:
    """Self-contained escaped report, no remote scripts or raw response bodies."""
    run = _safe_run(run)
    payload = {
        "summary": _summary(run),
        "cancelled": run.cancelled,
        "stop_reason": run.stop_reason,
        "results": [r.to_dict() for r in run.results],
        "idor_findings": [f.to_dict() for f in run.idor_findings],
        "assessments": run.assessments,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        "<title>API Fuzz Report</title><h1>API Fuzz Report</h1><pre>"
        + html.escape(json.dumps(payload, indent=2))
        + "</pre></html>",
        encoding="utf-8",
    )
