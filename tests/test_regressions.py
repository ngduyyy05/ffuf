import threading

import pytest
from werkzeug.serving import make_server

from apifuzz.analyzer import ResponseAnalyzer, build_baseline_from_result
from apifuzz.cli import main
from apifuzz.fuzzer import ApiFuzzer
from apifuzz.requester import ApiRequester
from apifuzz.utils import build_url, expand_path, normalize_base_url
from lab.app import app
from test_analyzer import make_result


@pytest.mark.parametrize("path", ["https://other.test/api", "//other.test/api", "\\other.test", "/api#fragment"])
def test_reject_external_paths(path):
    with pytest.raises(ValueError):
        build_url("http://localhost/api/", path)


@pytest.mark.parametrize("url", ["http://", "http://host:bad", "http://user:pass@host", "http://host?a=1"])
def test_invalid_targets(url):
    with pytest.raises(ValueError):
        normalize_base_url(url)


def test_ids_are_encoded_as_values():
    assert expand_path("/users/{id}", ["a/b?x=1"])[0][0] == "/users/a%2Fb%3Fx%3D1"


def test_json_not_found_is_not_interesting():
    result = make_result(status_code=404, json_body={"user": "not found"})
    assert not ResponseAnalyzer().analyze(result).interesting


def test_identical_soft_404_is_filtered():
    baseline = make_result()
    baseline.body_sha256 = "same"
    result = make_result()
    result.body_sha256 = "same"
    assert not ResponseAnalyzer(build_baseline_from_result(baseline)).analyze(result).interesting
    assert result.matches_baseline


def test_problem_json_and_keyword_boundaries():
    assert ResponseAnalyzer.is_json("application/problem+json; charset=utf-8")
    result = make_result(preview="video guidance")
    assert ResponseAnalyzer.find_sensitive_keywords(result) == []


@pytest.mark.parametrize("args", [["--timeout", "nan"], ["--rate-limit", "0"], []])
def test_cli_rejects_bad_input(args):
    with pytest.raises(SystemExit) as exc:
        main(["--base-url", "http://localhost", "--wordlist", "wordlists/sample_api.txt", *args])
    assert exc.value.code == 2


def test_real_http_lab_end_to_end(tmp_path):
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    requester = ApiRequester(headers={"X-Lab-User": "1"})
    try:
        run = ApiFuzzer(
            f"http://127.0.0.1:{server.server_port}",
            ["/api/orders/{id}", "/api/admin", "/api/missing"],
            ["GET"], requester, ids=["1", "2"], rate_limit=1000,
        ).run()
        assert len(run.results) == 4
        assert len(run.idor_findings) == 1
        assert "owner_id" in run.idor_findings[0].differing_fields
        assert run.results[2].status_code == 403
        assert not run.results[3].interesting
        from apifuzz.reporter import write_json, write_csv, write_markdown
        for writer, suffix in [(write_json, "json"), (write_csv, "csv"), (write_markdown, "md")]:
            target = tmp_path / f"report.{suffix}"
            writer(run, target)
            assert target.stat().st_size > 0
    finally:
        requester.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
