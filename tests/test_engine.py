import csv
import json
import threading
import time
from contextlib import contextmanager

import pytest
from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from apifuzz.cli import main
from apifuzz.fuzzer import ApiFuzzer
from apifuzz.profiles import load_profiles
from apifuzz.requester import ApiRequester
from apifuzz.utils import load_wordlist, parse_header_values, parse_ids, parse_methods


@contextmanager
def serve(app):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.fixture(scope="module")
def http_lab():
    app = Flask(__name__)
    counts = {}

    @app.route("/status/<int:status>", methods=["GET", "POST", "HEAD"])
    def status(status):
        return jsonify(error="controlled test"), status

    @app.route("/retry/<name>", methods=["GET", "POST"])
    def retry(name):
        key = (request.method, name)
        counts[key] = counts.get(key, 0) + 1
        if counts[key] == 1:
            return jsonify(error="retry"), 503, {"Retry-After": "0"}
        return jsonify(attempt=counts[key])

    @app.get("/large")
    def large():
        return "x" * 100000

    @app.get("/invalid-json")
    def invalid_json():
        return "{oops", 200, {"Content-Type": "application/json"}

    @app.get("/loop")
    def loop():
        return "", 302, {"Location": "/loop"}

    @app.get("/external")
    def external():
        return "", 302, {"Location": "http://uncontrolled.invalid/"}

    @app.get("/slow")
    def slow():
        time.sleep(0.15)
        return "late"

    @app.get("/cookie")
    def cookie():
        response = jsonify(cookie=request.headers.get("Cookie", ""))
        response.set_cookie("unexpected", "server-value")
        return response

    @app.route("/echo/<item>", methods=["POST", "PUT", "PATCH", "DELETE"])
    def echo(item):
        return jsonify(request.get_json())

    @app.get("/fallback/<path:item>")
    def fallback(item):
        return jsonify(message="same route fallback")

    @app.get("/vulnerable/<item>")
    def vulnerable(item):
        if item not in {"1", "2"}:
            return jsonify(error="missing"), 404
        return jsonify(id=item, owner_id=item, secret="lab-only")

    @app.get("/secure/<item>")
    def secure(item):
        principal = request.headers.get("X-User")
        if principal is None:
            return jsonify(error="authentication required"), 401
        if item not in {"1", "2"}:
            return jsonify(error="missing"), 404
        if item != principal:
            return jsonify(error="forbidden"), 403
        return jsonify(id=item, owner_id=item)

    with serve(app) as url:
        yield url


def send(client, base, path, method="GET", values=None):
    return client.request(method, base + path, path, path, values or {})


@pytest.mark.parametrize("status", [200, 204, 400, 401, 403, 404, 429, 500])
def test_http_status_is_not_network_error(http_lab, status):
    client = ApiRequester(retries=0)
    try:
        result = send(client, http_lab, f"/status/{status}")
        assert result.status_code == status
        assert not result.error
        if status == 204:
            assert result.response_length == 0
    finally:
        client.close()


def test_stream_limit_and_invalid_json(http_lab):
    client = ApiRequester(max_response_bytes=1024)
    try:
        large = send(client, http_lab, "/large")
        assert large.truncated and large.response_length == 1024
        assert large.json_body is None and not large.body_sha256
        invalid = send(client, http_lab, "/invalid-json")
        assert invalid.status_code == 200 and invalid.json_body is None and not invalid.error
    finally:
        client.close()


@pytest.mark.parametrize("path", ["/loop", "/external"])
def test_redirects_never_followed(http_lab, path):
    client = ApiRequester()
    try:
        result = send(client, http_lab, path)
        assert result.status_code == 302 and result.attempts == 1
    finally:
        client.close()


def test_retries_paced_and_mutations_not_repeated(http_lab, monkeypatch):
    client = ApiRequester(retries=2)
    paced = []
    client.before_request = lambda: paced.append(True)
    monkeypatch.setattr("apifuzz.requester.time.sleep", lambda _: None)
    try:
        result = send(client, http_lab, "/retry/get")
        assert result.status_code == 200 and result.attempts == 2 and len(paced) == 2
        post = send(client, http_lab, "/retry/post", "POST")
        assert post.status_code == 503 and post.attempts == 1
    finally:
        client.close()


def test_timeout_and_refused_are_network_errors(http_lab):
    client = ApiRequester(timeout=0.03, retries=0)
    try:
        slow = send(client, http_lab, "/slow")
        assert slow.status_code is None and slow.error
        # Reserve then close a local port, without using an external target.
        import socket

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        refused = send(client, f"http://127.0.0.1:{port}", "/?token=SECRET")
        assert refused.status_code is None and "SECRET" not in refused.error
    finally:
        client.close()


def test_cookie_and_environment_isolation(http_lab):
    client = ApiRequester(cookie="explicit=ok")
    try:
        assert not client.session.trust_env
        assert send(client, http_lab, "/cookie").json_body == {"cookie": "explicit=ok"}
        assert send(client, http_lab, "/cookie").json_body == {"cookie": "explicit=ok"}
        assert not client.session.cookies
    finally:
        client.close()


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_json_string_body_template(http_lab, method):
    client = ApiRequester(
        headers={"Content-Type": "application/json"}, body='{"id":"{id}"}', body_template=True
    )
    try:
        result = send(client, http_lab, "/echo/1", method, {"id": 'a"\\\n\u2603'})
        assert result.json_body == {"id": 'a"\\\n\u2603'}
    finally:
        client.close()


def test_route_baseline_and_filters(http_lab):
    client = ApiRequester(retries=0)
    try:
        run = ApiFuzzer(
            http_lab,
            ["/fallback/{id}", "/status/200"],
            ["GET"],
            client,
            ["1", "2"],
            rate_limit=10000,
            exclude_status={200},
        ).run()
        assert all(r.matches_baseline for r in run.results[:2])
        assert len(run.baselines) == 2
        assert all(not r.interesting and r.filtered for r in run.results)
        assert not run.idor_findings
    finally:
        client.close()


def test_two_principal_access_policy(http_lab):
    alice = ApiRequester(headers={"X-User": "1"}, profile="alice", retries=0)
    bob = ApiRequester(headers={"X-User": "2"}, profile="bob", retries=0)
    policies = {
        name: {
            route: {"allow": [own], "deny": [other]}
            for route in ["/vulnerable/{id}", "/secure/{id}"]
        }
        for name, own, other in [("alice", "1", "2"), ("bob", "2", "1")]
    }
    try:
        run = ApiFuzzer(
            http_lab,
            ["/vulnerable/{id}", "/secure/{id}"],
            ["GET"],
            alice,
            ["1", "2"],
            profiles=[alice, bob],
            policies=policies,
            rate_limit=10000,
        ).run()
        assert len(run.idor_findings) == 1
        finding = run.idor_findings[0]
        assert finding.classification == "Confirmed Authorization Issue"
        assert finding.confidence == "high" and "user-supplied" in finding.evidence
        assert run.assessments[1]["classification"] == "No Issue Observed"
    finally:
        alice.close()
        bob.close()


def test_no_policy_never_confirms_and_public_suppresses(http_lab):
    client = ApiRequester(retries=0)
    try:
        args = (http_lab, ["/vulnerable/{id}"], ["GET"], client, ["1", "2"])
        run = ApiFuzzer(*args, rate_limit=10000).run()
        assert run.idor_findings[0].classification == "Potential IDOR"
        public = ApiFuzzer(
            *args, policies={"default": {"/vulnerable/{id}": {"public": True}}}, rate_limit=10000
        ).run()
        assert (
            not public.idor_findings
            and public.assessments[0]["classification"] == "No Issue Observed"
        )
    finally:
        client.close()


def test_budget_rejected_before_expanding(http_lab):
    client = ApiRequester()
    try:
        with pytest.raises(ValueError, match="exceeds"):
            ApiFuzzer(http_lab, ["/a/{id}"] * 2, ["GET"], client, ["1", "2"], max_requests=2)
    finally:
        client.close()


def test_interrupt_returns_partial_results(http_lab, monkeypatch):
    client = ApiRequester(retries=0)
    original = client.request
    count = 0

    def interrupted(*args, **kwargs):
        nonlocal count
        count += 1
        if count == 3:
            raise KeyboardInterrupt
        return original(*args, **kwargs)

    monkeypatch.setattr(client, "request", interrupted)
    try:
        run = ApiFuzzer(
            http_lab, ["/vulnerable/{id}"], ["GET"], client, ["1", "2"], rate_limit=10000
        ).run()
        assert run.cancelled and len(run.results) == 1 and run.stop_reason
    finally:
        client.close()


@pytest.mark.parametrize(
    "content",
    [
        [],
        {},
        [{"name": "same"}, {"name": "same"}],
        [{"name": "x", "unknown": 1}],
        [{"name": "x", "access": {"/a": {"allow": ["1"], "deny": ["1"]}}}],
        [{"name": "x", "cookie": "a\r\nb"}],
        [{"name": "x", "headers": {"Host": "evil"}}],
    ],
)
def test_bad_profiles(tmp_path, content):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps(content))
    with pytest.raises(ValueError):
        load_profiles(str(path))


def test_input_utilities(tmp_path):
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("\ufeff# comment\n\napi/users\n/api/users\n/api/\u2603\n", encoding="utf-8")
    assert load_wordlist(wordlist) == ["/api/users", "/api/\u2603"]
    wordlist.write_text("# empty\n")
    with pytest.raises(ValueError):
        load_wordlist(wordlist)
    assert parse_methods("get, HEAD,get") == ["GET", "HEAD"]
    assert parse_ids("3-1,-2--1,alice,alice") == ["3", "2", "1", "-2", "-1", "alice"]
    assert parse_header_values(["X-Test: a", "x-test: b"]) == {"x-test": "b"}
    with pytest.raises(ValueError):
        parse_methods("TRACE")
    with pytest.raises(ValueError):
        parse_methods(" , ")


def test_cli_real_exports_and_write_errors(http_lab, tmp_path, monkeypatch):
    words = tmp_path / "words.txt"
    words.write_text("/vulnerable/{id}\n/status/500\n")
    outputs = {suffix: tmp_path / ("report." + suffix) for suffix in ["json", "csv", "md", "html"]}
    args = [
        "--base-url",
        http_lab,
        "--wordlist",
        str(words),
        "--ids",
        "1-2",
        "--rate-limit",
        "10000",
        "--retries",
        "0",
    ]
    for suffix, flag in [
        ("json", "--output"),
        ("csv", "--csv-output"),
        ("md", "--md-output"),
        ("html", "--html-output"),
    ]:
        args += [flag, str(outputs[suffix])]
    assert main(args) == 0
    payload = json.loads(outputs["json"].read_text())
    assert payload["summary"]["total_requests"] == 3
    assert payload["idor_findings"][0]["confidence"] == "low"
    assert all(r["json_body"] is None and not r["preview"] for r in payload["results"])
    with outputs["csv"].open(newline="") as handle:
        assert len(list(csv.DictReader(handle))) == 3
    assert "Potential IDOR" in outputs["md"].read_text()
    assert "<!doctype html>" in outputs["html"].read_text()

    def denied(*args, **kwargs):
        raise PermissionError("test denial")

    monkeypatch.setattr("apifuzz.cli.write_json", denied)
    assert main(args) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout": 0},
        {"timeout": float("inf")},
        {"retries": -1},
        {"retries": 6},
        {"max_response_bytes": 0},
    ],
)
def test_requester_rejects_invalid_options(kwargs):
    with pytest.raises(ValueError):
        ApiRequester(**kwargs)


def test_aggregate_response_budget_stops_and_exports_partial(http_lab, monkeypatch):
    client = ApiRequester(retries=0)
    real = client.request

    def large_metadata(*args, **kwargs):
        result = real(*args, **kwargs)
        result.response_length = 8 * 1024 * 1024
        return result

    monkeypatch.setattr(client, "request", large_metadata)
    try:
        run = ApiFuzzer(
            http_lab, ["/vulnerable/{id}"], ["GET"], client, ["1", "2"], rate_limit=10000
        ).run()
        assert run.cancelled and "budget" in run.stop_reason and not run.results
        assert run.attempts_started == 1
    finally:
        client.close()


def test_stream_interruption_closes_response(http_lab, monkeypatch):
    import requests

    client = ApiRequester(retries=0)
    response = requests.Response()
    response.status_code = 200
    closed = []

    def broken(*args, **kwargs):
        yield b"first"
        raise requests.exceptions.ChunkedEncodingError("SECRET")

    monkeypatch.setattr(response, "iter_content", broken)
    monkeypatch.setattr(response, "close", lambda: closed.append(True))
    monkeypatch.setattr(client.session, "request", lambda **kwargs: response)
    try:
        result = send(client, http_lab, "/interrupted")
        assert result.status_code is None and result.error == "ChunkedEncodingError"
        assert not result.preview and closed
    finally:
        client.close()


def test_id_file_and_invalid_ranges(tmp_path):
    file = tmp_path / "ids"
    file.write_text("\ufeff# IDs\n1\n2\n1\n", encoding="utf-8")
    assert parse_ids("3", str(file)) == ["3", "1", "2"]
    with pytest.raises(ValueError):
        parse_ids("1-")
    with pytest.raises(ValueError):
        parse_ids("..")


def test_profiles_example_and_cli_validation(tmp_path):
    assert len(load_profiles("examples/profiles.json")) == 2
    words = tmp_path / "words"
    words.write_text("/api/health")
    for extra in [
        ["--retries", "-1"],
        ["--body-template"],
        ["--exclude-status", "999"],
        ["--min-size", "-1"],
        ["--profiles-file", "examples/profiles.json", "--cookie", "x=1"],
    ]:
        with pytest.raises(SystemExit) as exc:
            main(["--base-url", "http://127.0.0.1", "--wordlist", str(words), *extra])
        assert exc.value.code == 2


def test_pacing_with_monotonic_clock(monkeypatch):
    client = ApiRequester(retries=0)
    scan = ApiFuzzer("http://localhost", ["/a"], ["GET"], client, rate_limit=4)
    values = iter([0, 0.05, 0.25])
    sleeps = []
    monkeypatch.setattr("apifuzz.fuzzer.time.monotonic", lambda: next(values))
    monkeypatch.setattr("apifuzz.fuzzer.time.sleep", sleeps.append)
    try:
        scan._pace()
        scan._pace()
        assert sleeps == pytest.approx([0.2]) and scan._attempts == 2
    finally:
        client.close()


@pytest.mark.parametrize(
    "principal,order,status",
    [
        (None, "1", 401),
        ("bad", "1", 401),
        ("1", "1", 200),
        ("1", "2", 403),
        ("2", "2", 200),
        ("1", "999", 404),
    ],
)
def test_bundled_lab_authorization_control(principal, order, status):
    from lab.app import app

    headers = {"X-Lab-User": principal} if principal else {}
    with app.test_client() as client:
        response = client.get("/api/private-orders/" + order, headers=headers)
        assert response.status_code == status


def test_cli_cancellation_exports_completed_samples(http_lab, tmp_path, monkeypatch):
    from apifuzz.fuzzer import FuzzRunResult

    words = tmp_path / "words"
    words.write_text("/api/health")
    output = tmp_path / "partial.json"
    monkeypatch.setattr(
        ApiFuzzer,
        "run",
        lambda self: FuzzRunResult([], [], None, cancelled=True, stop_reason="interrupted by user"),
    )
    assert main(["--base-url", http_lab, "--wordlist", str(words), "--output", str(output)]) == 130
    assert json.loads(output.read_text())["cancelled"]


def test_terminal_fallback_and_default_report(http_lab, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("apifuzz.reporter.Console", None)
    words = tmp_path / "words"
    words.write_text("/vulnerable/1?secret=SENSITIVE")
    assert (
        main(
            [
                "--base-url",
                http_lab,
                "--wordlist",
                str(words),
                "--retries",
                "0",
                "--rate-limit",
                "10000",
            ]
        )
        == 0
    )
    assert "SENSITIVE" not in capsys.readouterr().out
    assert (tmp_path / "reports" / "report.json").exists()
