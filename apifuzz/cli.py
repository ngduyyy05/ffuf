from __future__ import annotations

import argparse
import logging
import math
from pathlib import Path

from .fuzzer import ApiFuzzer
from .profiles import load_profiles
from .reporter import print_terminal_report, write_csv, write_html, write_json, write_markdown
from .requester import ApiRequester
from .utils import (
    configure_logging,
    load_wordlist,
    normalize_base_url,
    parse_header_values,
    parse_ids,
    parse_methods,
)

logger = logging.getLogger("apifuzz")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apifuzz",
        description="API Endpoint Fuzzer & IDOR Finder for authorized labs and CTFs.",
    )
    parser.add_argument(
        "--base-url", required=True, help="Target base URL, for example http://localhost:5000"
    )
    parser.add_argument("--wordlist", required=True, help="Path to API path wordlist")
    parser.add_argument(
        "--methods",
        default="GET",
        help="Comma-separated HTTP methods: GET,POST,PUT,DELETE,PATCH,OPTIONS",
    )
    parser.add_argument("--ids", help="ID list or ranges, for example 1-50,100,alice")
    parser.add_argument("--ids-file", help="File containing one ID per line")
    parser.add_argument(
        "--header", action="append", help="Extra header, repeatable. Format: 'Name: value'"
    )
    parser.add_argument("--cookie", help="Cookie header value, for example 'session=abc'")
    parser.add_argument(
        "--rate-limit", type=float, default=5.0, help="Requests per second. Default: 5"
    )
    parser.add_argument(
        "--timeout", type=float, default=8.0, help="Request timeout in seconds. Default: 8"
    )
    parser.add_argument("--output", help="JSON report path")
    parser.add_argument("--csv-output", help="CSV report path")
    parser.add_argument("--md-output", help="Markdown report path")
    parser.add_argument("--html-output", help="Escaped standalone HTML report path")
    parser.add_argument(
        "--profiles-file", help="JSON authentication profiles and explicit access rules"
    )
    parser.add_argument(
        "--retries", type=int, default=1, help="GET/HEAD/OPTIONS retries, 0-5 (default 1)"
    )
    parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=1048576,
        help="Decompressed body limit (default 1 MiB)",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        default=10000,
        help="Attempt budget including probes/retries (max 100000)",
    )
    parser.add_argument(
        "--exclude-status",
        default="",
        help="Comma-separated statuses to hide from interesting results",
    )
    parser.add_argument("--min-size", type=int, default=0, help="Minimum interesting response size")
    parser.add_argument(
        "--content-type", help="Required content type substring for interesting results"
    )
    parser.add_argument(
        "--body-template",
        action="store_true",
        help="Replace {id} in body using JSON string escaping",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    body = parser.add_mutually_exclusive_group()
    body.add_argument("--data", help="Raw request body for POST/PUT/PATCH/DELETE")
    body.add_argument("--data-file", help="UTF-8 file containing a raw request body")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    requesters = []
    try:
        base_url = normalize_base_url(args.base_url)
        paths = load_wordlist(args.wordlist)
        methods = parse_methods(args.methods)
        ids = parse_ids(args.ids, args.ids_file)
        headers = parse_header_values(args.header)
        for name, value in (("timeout", args.timeout), ("rate limit", args.rate_limit)):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a positive finite number")
        if args.data_file and Path(args.data_file).stat().st_size > 1048576:
            raise ValueError("request body file exceeds 1 MiB")
        body = Path(args.data_file).read_text(encoding="utf-8") if args.data_file else args.data
        if body is not None and len(body.encode("utf-8")) > 1048576:
            raise ValueError("request body exceeds 1 MiB")
        if args.body_template and body is None:
            raise ValueError("--body-template requires --data or --data-file")
        statuses = {int(s.strip()) for s in args.exclude_status.split(",") if s.strip()}
        if any(not 100 <= s <= 599 for s in statuses) or args.min_size < 0:
            raise ValueError("invalid status filter or negative minimum size")
        if any("{id}" in path for path in paths) and not ids:
            raise ValueError("wordlist contains {id}; provide --ids or --ids-file")
        if args.profiles_file and (headers or args.cookie):
            raise ValueError("--profiles-file cannot be combined with --header/--cookie")
        configs = (
            load_profiles(args.profiles_file)
            if args.profiles_file
            else [{"name": "default", "headers": headers, "cookie": args.cookie}]
        )
        for config in configs:
            requesters.append(
                ApiRequester(
                    headers=config.get("headers"),
                    cookie=config.get("cookie"),
                    timeout=args.timeout,
                    body=body,
                    retries=args.retries,
                    max_response_bytes=args.max_response_bytes,
                    body_template=args.body_template,
                    profile=config["name"],
                )
            )
        fuzzer = ApiFuzzer(
            base_url,
            paths,
            methods,
            requesters[0],
            ids,
            args.rate_limit,
            max_requests=args.max_requests,
            profiles=requesters,
            policies={c["name"]: c.get("access", {}) for c in configs},
            exclude_status=statuses,
            min_size=args.min_size,
            content_type=args.content_type,
        )
    except (ValueError, OSError, UnicodeError) as exc:
        for requester in requesters:
            requester.close()
        parser.error(str(exc))
        return 2
    logger.info(
        "starting scan: paths=%d methods=%s ids=%d profiles=%d",
        len(paths),
        ",".join(methods),
        len(ids),
        len(requesters),
    )
    try:
        run = fuzzer.run()
    except KeyboardInterrupt:
        logger.warning("scan interrupted")
        return 130
    finally:
        for requester in requesters:
            requester.close()
    print_terminal_report(run)
    outputs = [
        (write_json, args.output),
        (write_csv, args.csv_output),
        (write_markdown, args.md_output),
        (write_html, args.html_output),
    ]
    if not any(path for _, path in outputs):
        outputs = [(write_json, Path("reports") / "report.json")]
    try:
        for writer, path in outputs:
            if path:
                writer(run, path)
    except OSError as exc:
        logger.error("cannot write report (%s); choose a writable output path", type(exc).__name__)
        return 1
    return 130 if run.cancelled else 0
