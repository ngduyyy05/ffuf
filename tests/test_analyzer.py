from apifuzz.analyzer import Baseline, ResponseAnalyzer
from apifuzz.idor import detect_idor_findings
from apifuzz.utils import RequestResult


def make_result(
    path_template: str = "/api/users/{id}",
    item_id: str = "1",
    status_code: int = 200,
    length: int = 120,
    json_body=None,
    preview: str = "",
) -> RequestResult:
    expanded_path = path_template.replace("{id}", item_id)
    return RequestResult(
        method="GET",
        url=f"http://lab.local{expanded_path}",
        path_template=path_template,
        expanded_path=expanded_path,
        placeholder_values={"id": item_id} if "{id}" in path_template else {},
        status_code=status_code,
        response_length=length,
        content_type="application/json",
        redirect_location="",
        response_time_ms=10.0,
        preview=preview,
        json_body=json_body,
    )


def test_analyzer_marks_success_json_and_keywords():
    analyzer = ResponseAnalyzer(Baseline(status_code=404, response_length=20))
    result = make_result(json_body={"id": 1, "email": "user@example.test", "role": "user"})

    analyzed = analyzer.analyze(result)

    assert analyzed.interesting is True
    assert "success status 200" in analyzed.reasons
    assert "JSON response" in analyzed.reasons
    assert any(reason.startswith("sensitive keywords") for reason in analyzed.reasons)


def test_analyzer_marks_blocked_endpoint():
    analyzer = ResponseAnalyzer(Baseline(status_code=404, response_length=100))
    result = make_result(path_template="/api/admin", status_code=403, length=100, json_body={"error": "forbidden"})

    analyzed = analyzer.analyze(result)

    assert analyzed.interesting is True
    assert "protected endpoint status 403" in analyzed.reasons


def test_idor_detection_flags_multiple_200_different_owners():
    results = [
        make_result(item_id="1", json_body={"id": 1, "user_id": 1, "total": 10}),
        make_result(item_id="2", json_body={"id": 2, "user_id": 2, "total": 20}),
    ]

    findings = detect_idor_findings(results)

    assert len(findings) == 1
    assert findings[0].path_template == "/api/users/{id}"
    assert "user_id" in findings[0].differing_fields


def test_idor_detection_ignores_single_id():
    results = [make_result(item_id="1", json_body={"id": 1, "user_id": 1})]

    findings = detect_idor_findings(results)

    assert findings == []
