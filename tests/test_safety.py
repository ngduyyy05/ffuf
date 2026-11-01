import json

import pytest
from test_analyzer import make_result

from apifuzz.idor import detect_idor_findings
from apifuzz.utils import build_url, normalize_base_url, parse_header_values, parse_ids


@pytest.mark.parametrize(
    "url", ["http://local host", "http://localhost/\napi", "http://localhost/../admin"]
)
def test_invalid_base_structure(url):
    with pytest.raises(ValueError):
        normalize_base_url(url)


@pytest.mark.parametrize("path", ["../admin", "/%2e%2e/admin", "/users/{unknown}", "/api\x00"])
def test_scope_and_template_validation(path):
    with pytest.raises(ValueError):
        build_url("http://localhost/api/", path)


def test_id_expansion_is_bounded():
    with pytest.raises(ValueError):
        parse_ids("1-1000000000")


@pytest.mark.parametrize(
    "header", ["X-Name: snowman \u2603", "Host: external.test", "Content-Length: 10"]
)
def test_unsafe_headers_rejected(header):
    with pytest.raises(ValueError):
        parse_header_values([header])


def test_200_error_envelopes_do_not_produce_idor():
    results = [make_result(item_id=str(i), json_body={"error": f"no user {i}"}) for i in (1, 2)]
    assert detect_idor_findings(results) == []


def test_report_does_not_export_raw_bodies_or_query_secrets(tmp_path):
    from apifuzz.fuzzer import FuzzRunResult
    from apifuzz.reporter import write_csv, write_json, write_markdown

    result = make_result(json_body={"token": "SENSITIVE"}, preview="SENSITIVE")
    result.url = "http://localhost/user?token=SENSITIVE"
    result.expanded_path = "/user?token=SENSITIVE"
    result.path_template = result.expanded_path
    run = FuzzRunResult([result], [], None)
    for writer in (write_json, write_csv, write_markdown):
        target = tmp_path / writer.__name__
        writer(run, target)
        assert "SENSITIVE" not in target.read_text(encoding="utf-8")
    assert json.loads((tmp_path / "write_json").read_text())["results"][0]["json_body"] is None


@pytest.mark.parametrize(
    "body",
    [
        {"success": False},
        {"status": "forbidden"},
        {"message": "Access denied"},
        {"type": "problem", "title": "Forbidden", "status": 403},
        {"errors": ["no access"]},
    ],
)
def test_more_error_envelopes(body):
    results = [make_result(item_id=str(i), json_body={**body, "trace": i}) for i in (1, 2)]
    assert detect_idor_findings(results) == []


def test_profiles_with_identical_responses_do_not_mask_other_profile():
    results = []
    for name in ("same", "different"):
        for item in ("1", "2"):
            result = make_result(
                item_id=item,
                json_body={"owner_id": item} if name == "different" else {"message": "constant"},
            )
            result.profile = name
            results.append(result)
    findings = detect_idor_findings(results)
    assert len(findings) == 1 and "different" in findings[0].evidence


def test_truncated_and_baseline_results_cannot_confirm():
    results = [make_result(item_id=str(i), json_body={"owner_id": i}) for i in (1, 2)]
    results[0].truncated = True
    results[1].matches_baseline = True
    assert not detect_idor_findings(results)


def test_nested_json_does_not_crash_field_extraction():
    from apifuzz.analyzer import extract_json_field

    body = {"owner_id": 2}
    for _ in range(2000):
        body = {"nested": body}
    assert extract_json_field(body, "owner_id") == 2


def test_report_escaping_and_no_mutation(tmp_path):
    import csv

    from apifuzz.fuzzer import FuzzRunResult
    from apifuzz.reporter import write_csv, write_html, write_markdown

    result = make_result(preview="SECRET")
    result.url = "http://localhost/<script>alert(1)</script>?secret=SECRET"
    result.path_template = "/pipe|path"
    result.content_type = "=1+2"
    run = FuzzRunResult([result], [], None)
    write_html(run, tmp_path / "r.html")
    write_csv(run, tmp_path / "r.csv")
    write_markdown(run, tmp_path / "r.md")
    assert "<script>" not in (tmp_path / "r.html").read_text()
    assert "&lt;script&gt;" in (tmp_path / "r.md").read_text()
    with (tmp_path / "r.csv").open(newline="") as handle:
        assert next(csv.DictReader(handle))["content_type"] == "'=1+2"
    assert result.preview == "SECRET" and "SECRET" in result.url


@pytest.mark.parametrize("header", ["X-Test:\nvalue", "X-Test: value\r", "Cookie: a=1\x00"])
def test_header_controls_rejected_before_stripping(header):
    with pytest.raises(ValueError):
        parse_header_values([header])


@pytest.mark.parametrize(
    "location", ["http://[invalid", "http://name:SECRET@localhost/path?x=SECRET"]
)
def test_untrusted_redirect_location_sanitized(tmp_path, location):
    from apifuzz.fuzzer import FuzzRunResult
    from apifuzz.reporter import write_json

    result = make_result()
    result.redirect_location = location
    path = tmp_path / "report.json"
    write_json(FuzzRunResult([result], [], None), path)
    assert "SECRET" not in path.read_text()


def test_deep_json_analysis_handles_recursion_limits():
    from apifuzz.analyzer import ResponseAnalyzer

    body = {"status": {}, "message": {}, "owner_id": {}}
    for _ in range(2000):
        body = {"nested": body}
    result = make_result(json_body=body)
    assert ResponseAnalyzer().analyze(result).interesting
    other = make_result(item_id="2", json_body=body)
    assert detect_idor_findings([result, other]) == []


def test_encoded_id_traversal_rejected_before_network():
    from apifuzz.fuzzer import ApiFuzzer
    from apifuzz.requester import ApiRequester

    client = ApiRequester()
    try:
        with pytest.raises(ValueError):
            ApiFuzzer("http://localhost/api/", ["/users/{id}"], ["GET"], client, ["../admin"])
    finally:
        client.close()
