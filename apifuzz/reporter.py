from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .fuzzer import FuzzRunResult
from .utils import IdorFinding, RequestResult

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:  # pragma: no cover - fallback for minimal installs
    Console = None
    Table = None


def print_terminal_report(run: FuzzRunResult) -> None:
    interesting = [result for result in run.results if result.interesting]
    errors = [result for result in run.results if result.error or result.status_code == 500]

    if Console and Table:
        console = Console()
        console.print(
            f"[bold]Scan complete[/bold] "
            f"requests={len(run.results)} interesting={len(interesting)} "
            f"potential_idor={len(run.idor_findings)} errors={len(errors)}"
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
            idor_table = Table(title="Potential IDOR Findings")
            idor_table.add_column("Method")
            idor_table.add_column("Template")
            idor_table.add_column("IDs")
            idor_table.add_column("Evidence")
            for finding in run.idor_findings:
                idor_table.add_row(
                    finding.method,
                    finding.path_template,
                    ", ".join(finding.tested_ids[:12]),
                    finding.evidence,
                )
            console.print(idor_table)
        return

    print(
        f"Scan complete requests={len(run.results)} interesting={len(interesting)} "
        f"potential_idor={len(run.idor_findings)} errors={len(errors)}"
    )
    for item in interesting:
        print(f"{item.method} {item.status_code} {item.response_length} {item.url} :: {'; '.join(item.reasons)}")


def write_json(run: FuzzRunResult, output_path: str | Path) -> None:
    payload: dict[str, Any] = {
        "summary": _summary(run),
        "baseline": run.baseline.to_dict() if run.baseline else None,
        "results": [result.to_dict() for result in run.results],
        "idor_findings": [finding.to_dict() for finding in run.idor_findings],
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def write_csv(run: FuzzRunResult, output_path: str | Path) -> None:
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
            ],
        )
        writer.writeheader()
        for item in run.results:
            writer.writerow(
                {
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
                }
            )


def write_markdown(run: FuzzRunResult, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    summary = _summary(run)

    lines.append("# API Fuzz Report")
    lines.append("")
    lines.append("## Summary")
    for key, value in summary.items():
        lines.append(f"- {key}: {value}")
    lines.append("")

    lines.extend(_markdown_results("Interesting Endpoints", [item for item in run.results if item.interesting]))
    lines.extend(_markdown_idor(run.idor_findings))
    lines.extend(_markdown_results("Error Endpoints", [item for item in run.results if item.error or item.status_code == 500]))
    lines.extend(_markdown_results("Full Request Table", run.results))

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _summary(run: FuzzRunResult) -> dict[str, int]:
    return {
        "total_requests": len(run.results),
        "interesting_endpoints": len([item for item in run.results if item.interesting]),
        "potential_idor_findings": len(run.idor_findings),
        "error_endpoints": len([item for item in run.results if item.error or item.status_code == 500]),
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
            f"{item.response_time_ms:.2f} | `{item.url}` | {reasons} |"
        )
    lines.append("")
    return lines


def _markdown_idor(findings: list[IdorFinding]) -> list[str]:
    lines = ["## Potential IDOR Findings", ""]
    if not findings:
        lines.extend(["None.", ""])
        return lines

    lines.append("| Method | Template | IDs | Evidence |")
    lines.append("| --- | --- | --- | --- |")
    for finding in findings:
        ids = ", ".join(finding.tested_ids)
        lines.append(f"| {finding.method} | `{finding.path_template}` | {ids} | {finding.evidence} |")
    lines.append("")
    return lines
