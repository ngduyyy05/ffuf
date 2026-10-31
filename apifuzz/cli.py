from __future__ import annotations

import argparse
import logging
import math
from pathlib import Path

from .fuzzer import ApiFuzzer
from .reporter import print_terminal_report, write_csv, write_json, write_markdown
from .requester import ApiRequester
from .utils import configure_logging, load_wordlist, normalize_base_url, parse_header_values, parse_ids, parse_methods

logger = logging.getLogger("apifuzz")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apifuzz",
        description="API Endpoint Fuzzer & IDOR Finder for authorized labs and CTFs.",
    )
    parser.add_argument("--base-url", required=True, help="Target base URL, for example http://localhost:5000")
    parser.add_argument("--wordlist", required=True, help="Path to API path wordlist")
    parser.add_argument("--methods", default="GET", help="Comma-separated HTTP methods: GET,POST,PUT,DELETE,PATCH,OPTIONS")
    parser.add_argument("--ids", help="ID list or ranges, for example 1-50,100,alice")
    parser.add_argument("--ids-file", help="File containing one ID per line")
    parser.add_argument("--header", action="append", help="Extra header, repeatable. Format: 'Name: value'")
    parser.add_argument("--cookie", help="Cookie header value, for example 'session=abc'")
    parser.add_argument("--rate-limit", type=float, default=5.0, help="Requests per second. Default: 5")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds. Default: 8")
    parser.add_argument("--output", help="JSON report path")
    parser.add_argument("--csv-output", help="CSV report path")
    parser.add_argument("--md-output", help="Markdown report path")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    body = parser.add_mutually_exclusive_group()
    body.add_argument("--data", help="Raw request body for POST/PUT/PATCH/DELETE")
    body.add_argument("--data-file", help="UTF-8 file containing a raw request body")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    try:
        base_url = normalize_base_url(args.base_url)
        paths = load_wordlist(args.wordlist)
        methods = parse_methods(args.methods)
        ids = parse_ids(args.ids, args.ids_file)
        headers = parse_header_values(args.header)
        for name, value in (("timeout", args.timeout), ("rate limit", args.rate_limit)):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a positive finite number")
        body = Path(args.data_file).read_text(encoding="utf-8") if args.data_file else args.data
        if any("{id}" in path for path in paths) and not ids:
            raise ValueError("wordlist contains {id}; provide --ids or --ids-file")
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
        return 2

    requester = ApiRequester(headers=headers, cookie=args.cookie, timeout=args.timeout, body=body)
    fuzzer = ApiFuzzer(
        base_url=base_url,
        paths=paths,
        methods=methods,
        requester=requester,
        ids=ids,
        rate_limit=args.rate_limit,
    )

    logger.info("starting scan: base_url=%s paths=%d methods=%s ids=%d", base_url, len(paths), ",".join(methods), len(ids))
    try:
        run = fuzzer.run()
    except KeyboardInterrupt:
        logger.warning("scan interrupted")
        return 130
    finally:
        requester.close()
    print_terminal_report(run)

    if args.output:
        write_json(run, args.output)
        logger.info("wrote JSON report to %s", args.output)
    if args.csv_output:
        write_csv(run, args.csv_output)
        logger.info("wrote CSV report to %s", args.csv_output)
    if args.md_output:
        write_markdown(run, args.md_output)
        logger.info("wrote Markdown report to %s", args.md_output)

    if not any([args.output, args.csv_output, args.md_output]):
        default_output = Path("reports") / "report.json"
        write_json(run, default_output)
        logger.info("wrote default JSON report to %s", default_output)

    return 0
