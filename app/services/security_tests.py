from uuid import uuid4

from werkzeug.security import check_password_hash, generate_password_hash

from ..extensions import limiter
from ..security.controls import owns_resource, parameterized_lookup, validate_resume_upload

REQUIRED_TESTS = [
    "sql_injection", "password_hashing", "authorization",
    "file_validation", "rate_limiting", "session_handling",
]


def execute_security_checks(app):
    outcomes = []
    checks = [
        ("sql_injection", True, _check_parameterized_lookup),
        ("password_hashing", True, _check_password_hashing),
        ("authorization", True, _check_authorization),
        ("file_validation", True, _check_file_validation),
        ("rate_limiting", False, lambda: _check_rate_limiting(app)),
        ("session_handling", False, lambda: _check_session_handling(app)),
    ]
    for name, critical, check in checks:
        try:
            detail = check()
            outcomes.append({"test_name": name, "status": "PASS", "critical": critical, "details": detail})
        except Exception as exc:
            outcomes.append({
                "test_name": name, "status": "FAIL", "critical": critical,
                "details": f"Check failed: {type(exc).__name__}.",
            })
    return outcomes


def _check_parameterized_lookup():
    rows = parameterized_lookup("' OR '1'='1")
    assert rows == [], "Injected input must not return all applicant rows."
    return "A quote-based input was treated as a literal parameter and returned no rows."


def _check_password_hashing():
    password = "CareerConnect-demo-Password-42!"
    hashed = generate_password_hash(password)
    assert hashed != password
    assert check_password_hash(hashed, password)
    assert not check_password_hash(hashed, password + "x")
    return "Werkzeug password hashing stored a non-plaintext value and verified the correct secret."


def _check_authorization():
    assert owns_resource(7, 7)
    assert not owns_resource(7, 8)
    assert not owns_resource(None, 7)
    return "The owner check allows the matching user and rejects another or missing owner."


def _check_file_validation():
    assert validate_resume_upload("resume.pdf", 1024)[0]
    assert not validate_resume_upload("resume.html", 1024)[0]
    assert not validate_resume_upload("..\\private\\resume.pdf", 1024 * 1024 * 6)[0]
    valid, filename, _ = validate_resume_upload("..\\private\\resume.pdf", 1024)
    assert valid and filename == "resume.pdf"
    return "Extension, size, and client-path handling passed allow-list checks."


def _check_rate_limiting(app):
    if not limiter.enabled:
        raise AssertionError("Flask-Limiter is disabled.")
    client = app.test_client()
    address = f"198.51.100.{(uuid4().int % 200) + 1}"
    statuses = [
        client.get("/api/rate-limit-probe", environ_overrides={"REMOTE_ADDR": address}).status_code
        for _ in range(3)
    ]
    assert statuses == [200, 200, 429], f"Unexpected rate-limit response sequence: {statuses}"
    return "The live Flask-Limiter probe allowed two requests and throttled the third."


def _check_session_handling(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"]
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    with app.test_client() as client:
        with client.session_transaction() as browser_session:
            browser_session["training_check"] = "signed-session-value"
        with client.session_transaction() as browser_session:
            assert browser_session.get("training_check") == "signed-session-value"
    return "Signed session data round-tripped and HttpOnly/SameSite cookie settings are enabled."
