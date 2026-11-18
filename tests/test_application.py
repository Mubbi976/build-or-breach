import re

from app.extensions import db
from app.models import AIAnalysis, Challenge, ChallengeAttempt, ReviewItem, TestResult as SecurityTestResult, User


def test_health_landing_and_module_access(client, logged_in):
    assert client.get("/").status_code == 302
    assert client.get("/health").json == {"status": "ok"}
    assert client.get("/mission").status_code == 200
    for slug in (
        "threat-model", "code-studio", "ai-engineer", "arena",
        "testing-lab", "deployment-gate", "profile",
    ):
        response = client.get(f"/modules/{slug}")
        assert response.status_code == 200, slug
    assert b"CareerConnect 2026" in client.get("/mission").data


def test_registration_hashes_password_and_login(client, app):
    response = client.post("/auth/register", data={
        "username": "new-learner",
        "email": "learner@example.edu",
        "password": "a-valid-password-with-12",
    })
    assert response.status_code == 302
    with app.app_context():
        account = db.session.scalar(db.select(User).filter_by(email="learner@example.edu"))
        assert account is not None
        assert account.password_hash != "a-valid-password-with-12"
        assert account.check_password("a-valid-password-with-12")
    response = client.post("/auth/login", data={
        "email": "learner@example.edu",
        "password": "a-valid-password-with-12",
    })
    assert response.status_code == 302
    assert client.get("/mission").status_code == 200


def test_sqlite_foreign_keys_are_enforced(app):
    import pytest
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy import text

    with app.app_context():
        assert db.session.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
        db.session.add(ReviewItem(user_id=99999, title="Invalid owner", severity="low"))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_login_is_required_and_logout_is_post(client):
    assert client.get("/api/threat-model/data").status_code == 401
    assert client.post("/auth/logout").status_code == 302
    assert client.get("/modules/profile").status_code == 302


def test_authenticated_logout_ends_session(client, logged_in):
    assert client.post("/auth/logout").status_code == 302
    assert client.get("/mission").status_code == 302


def test_threat_model_evaluates_control_and_tracks_progress(client, logged_in, app, user):
    catalog = client.get("/api/threat-model/data")
    assert catalog.status_code == 200
    assert {item["id"] for item in catalog.json["components"]} == {"browser", "api", "database"}
    response = client.post("/api/threat-model/evaluate", json={
        "component": "database", "threat": "tampering", "control": "parameterized-query",
    })
    assert response.status_code == 200
    assert response.json["passed"] is True
    assert client.post("/api/threat-model/evaluate", json={
        "component": "database", "threat": "tampering", "control": "audit-log",
    }).json["passed"] is False
    with app.app_context():
        from app.models import UserProgress
        progress = db.session.scalar(db.select(UserProgress).filter_by(user_id=user, module="threat-model"))
        assert progress.completed is True


def test_challenge_records_only_current_user_history(client, logged_in, app, user):
    challenge = client.get("/modules/code-studio")
    assert challenge.status_code == 200 and b"Stop SQL Injection" in challenge.data
    response = client.post("/api/challenges/sql-injection/attempt", json={"answer": "secure"})
    assert response.status_code == 200 and response.json["passed"] is True
    assert client.post("/api/challenges/sql-injection/attempt", json={"answer": "unknown"}).status_code == 400
    with app.app_context():
        row = db.session.scalar(db.select(ChallengeAttempt).filter_by(user_id=user))
        assert row is not None and row.passed


def test_every_seeded_challenge_accepts_secure_and_rejects_vulnerable_answers(client, logged_in, app, user):
    with app.app_context():
        slugs = [item.slug for item in db.session.scalars(db.select(Challenge)).all()]
    for slug in slugs:
        vulnerable = client.post(f"/api/challenges/{slug}/attempt", json={"answer": "vulnerable"})
        secure = client.post(f"/api/challenges/{slug}/attempt", json={"answer": "secure"})
        assert vulnerable.status_code == secure.status_code == 200
        assert vulnerable.json["passed"] is False
        assert secure.json["passed"] is True
    with app.app_context():
        assert ChallengeAttempt.query.filter_by(user_id=user).count() == 10


def test_simulation_vulnerable_and_defended_results_are_distinct(client, logged_in, app, user):
    catalog = client.get("/api/simulations/catalog")
    assert catalog.status_code == 200
    assert len(catalog.json["scenarios"]) == 4
    for item in catalog.json["scenarios"]:
        vulnerable = client.post("/api/simulations/run", json={
            "scenario": item["id"], "defended": False,
        })
        defended = client.post("/api/simulations/run", json={
            "scenario": item["id"], "defended": True,
        })
        assert vulnerable.status_code == defended.status_code == 200
        assert vulnerable.json["blocked"] is False
        assert defended.json["blocked"] is True
        assert vulnerable.json["result"] != defended.json["result"]
    with app.app_context():
        from app.models import SimulationSession
        assert SimulationSession.query.filter_by(user_id=user).count() == 8


def test_all_arena_scenarios_compare_vulnerable_and_defended_outcomes():
    from app.services.simulations import SCENARIOS, run_simulation

    for scenario in SCENARIOS:
        vulnerable = run_simulation(scenario, False)
        defended = run_simulation(scenario, True)
        assert vulnerable["blocked"] is False
        assert defended["blocked"] is True
        assert vulnerable["result"] != defended["result"]
        assert vulnerable["evidence"] and defended["evidence"]


def test_ai_failure_preserves_client_code_and_does_not_save_history(client, logged_in, app, user):
    code = "def insecure(): return True"
    response = client.post("/api/ai/analyze", json={"code": code})
    assert response.status_code == 503
    assert "not configured" in response.json["error"]
    with app.app_context():
        assert AIAnalysis.query.filter_by(user_id=user).count() == 0


def test_ai_success_stores_validated_result_for_current_user(client, logged_in, app, user, monkeypatch):
    result = {
        "risk": "medium", "summary": "Use an owner-scoped query.",
        "findings": [], "secure_example": "", "test_recommendations": ["Try a different applicant id."],
        "disclaimer": "AI suggestions are educational guidance, not verified security testing.",
    }
    monkeypatch.setattr(
        "app.routes.modules.analyze_code",
        lambda code, api_key, model, provider="openai": result,
    )
    response = client.post("/api/ai/analyze", json={"code": "Application.query.get(record_id)"})
    assert response.status_code == 200
    assert response.json["result"]["risk"] == "medium"
    with app.app_context():
        record = db.session.scalar(db.select(AIAnalysis).filter_by(user_id=user))
        assert record is not None
        assert record.code == "Application.query.get(record_id)"
        assert record.result["summary"] == "Use an owner-scoped query."
    assert client.get("/api/ai/history").json["analyses"][0]["id"] == response.json["id"]


def test_ai_route_uses_selected_gemini_configuration(client, logged_in, app, user, monkeypatch):
    app.config.update(
        AI_PROVIDER="gemini",
        GEMINI_API_KEY="gemini-test-key",
        GEMINI_MODEL="gemini-test-model",
    )
    result = {
        "risk": "low", "summary": "No immediate issue found.",
        "findings": [], "secure_example": "", "test_recommendations": [],
        "disclaimer": "AI suggestions are educational guidance, not verified security testing.",
    }
    calls = {}

    def fake_analysis(code, api_key, model, provider):
        calls.update(code=code, api_key=api_key, model=model, provider=provider)
        return result

    monkeypatch.setattr("app.routes.modules.analyze_code", fake_analysis)
    response = client.post("/api/ai/analyze", json={"code": "print('safe demo')"})
    assert response.status_code == 200
    assert calls == {
        "code": "print('safe demo')",
        "api_key": "gemini-test-key",
        "model": "gemini-test-model",
        "provider": "gemini",
    }
    with app.app_context():
        record = db.session.scalar(db.select(AIAnalysis).filter_by(user_id=user))
        assert record.model == "gemini-test-model"


def test_ai_status_reports_loaded_configuration_without_exposing_key(client, logged_in, app):
    assert client.get("/api/ai/status").json == {
        "provider": "openai", "configured": False, "model": "gpt-4.1-mini",
    }
    app.config["OPENAI_API_KEY"] = "test-secret-do-not-return"
    response = client.get("/api/ai/status")
    assert response.json == {"provider": "openai", "configured": True, "model": "gpt-4.1-mini"}
    assert "test-secret-do-not-return" not in response.get_data(as_text=True)
    app.config.update(
        AI_PROVIDER="gemini", GEMINI_API_KEY="gemini-secret-do-not-return",
        GEMINI_MODEL="gemini-test",
    )
    response = client.get("/api/ai/status")
    assert response.json == {"provider": "gemini", "configured": True, "model": "gemini-test"}
    assert "gemini-secret-do-not-return" not in response.get_data(as_text=True)


def test_ai_result_validation_rejects_malformed_response():
    from app.services.ai_analysis import AIAnalysisError, validate_result
    import pytest

    with pytest.raises(AIAnalysisError):
        validate_result({"risk": "unknown", "summary": "x", "findings": [], "test_recommendations": []})
    result = validate_result({
        "risk": "medium", "summary": "A useful summary",
        "findings": [{
            "title": "Missing owner check", "severity": "high",
            "explanation": "The record is looked up without its owner.", "remediation": "Scope by user.",
        }],
        "secure_example": "", "test_recommendations": ["Try a different owner id."],
    })
    assert result["findings"][0]["severity"] == "high"
    assert "not verified" in result["disclaimer"]


def test_ai_service_uses_responses_api_and_validates_provider_json(monkeypatch):
    import json
    from types import SimpleNamespace
    from app.services import ai_analysis

    calls = {}

    class FakeResponses:
        def create(self, **kwargs):
            calls.update(kwargs)
            return SimpleNamespace(output_text=json.dumps({
                "risk": "low", "summary": "No immediate issue found.",
                "findings": [], "secure_example": "",
                "test_recommendations": ["Add an authorization test."],
            }))

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["api_key"] == "test-key"
            self.responses = FakeResponses()

    monkeypatch.setattr(ai_analysis, "OpenAI", FakeClient)
    result = ai_analysis.analyze_code("print('hello')", "test-key", "gpt-test")
    assert calls["model"] == "gpt-test"
    assert calls["input"][0]["role"] == "developer"
    assert calls["input"][1]["role"] == "user"
    assert "print('hello')" in calls["input"][1]["content"]
    assert calls["text"]["format"]["type"] == "json_object"
    assert result["risk"] == "low"
    assert result["test_recommendations"] == ["Add an authorization test."]


def test_ai_service_uses_gemini_openai_compatible_chat_completions(monkeypatch):
    import json
    from types import SimpleNamespace
    from app.services import ai_analysis

    calls = {}

    class FakeCompletions:
        def create(self, **kwargs):
            calls.update(kwargs)
            content = json.dumps({
                "risk": "low", "summary": "Use an owner-scoped query.",
                "findings": [], "secure_example": "",
                "test_recommendations": ["Add an authorization test."],
            })
            message = SimpleNamespace(content=content)
            choice = SimpleNamespace(message=message)
            return SimpleNamespace(choices=[choice])

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["api_key"] == "gemini-test-key"
            assert kwargs["base_url"] == ai_analysis.GEMINI_OPENAI_BASE_URL
            self.chat = SimpleNamespace(
                completions=FakeCompletions()
            )

    monkeypatch.setattr(ai_analysis, "OpenAI", FakeClient)
    result = ai_analysis.analyze_code(
        "Application.query.get(record_id)", "gemini-test-key", "gemini-test", provider="gemini"
    )
    assert calls["model"] == "gemini-test"
    assert calls["messages"][0]["role"] == "system"
    assert calls["messages"][1]["role"] == "user"
    assert "Application.query.get(record_id)" in calls["messages"][1]["content"]
    assert result["risk"] == "low"


def test_ai_service_requires_the_selected_provider_key():
    import pytest
    from app.services.ai_analysis import AIAnalysisError, analyze_code

    with pytest.raises(AIAnalysisError, match="GEMINI_API_KEY"):
        analyze_code("print('hello')", None, "gemini-test", provider="gemini")


def test_ai_service_gives_specific_key_error_without_logging_key(monkeypatch, caplog):
    import pytest
    from app.services import ai_analysis

    class FakeAuthenticationError(Exception):
        pass

    class FakeResponses:
        def create(self, **_kwargs):
            raise FakeAuthenticationError("provider rejected key")

    class FakeClient:
        def __init__(self, **_kwargs):
            self.responses = FakeResponses()

    monkeypatch.setattr(ai_analysis, "OpenAI", FakeClient)
    monkeypatch.setattr(ai_analysis, "AuthenticationError", FakeAuthenticationError)
    with pytest.raises(ai_analysis.AIAnalysisError, match="OpenAI rejected the API key"):
        ai_analysis.analyze_code("print('hello')", "test-secret-do-not-log", "gpt-test")
    assert "test-secret-do-not-log" not in caplog.text


def test_ai_service_exposes_only_safe_bad_request_diagnostic(monkeypatch):
    import pytest
    from app.services import ai_analysis

    class FakeBadRequestError(Exception):
        code = "unsupported_value"
        param = "text.format.type"
        body = {"error": {
            "message": "Invalid request containing submitted snippet print('hello') and token sk-abcdefghijk",
        }}

    class FakeResponses:
        def create(self, **_kwargs):
            raise FakeBadRequestError()

    class FakeClient:
        def __init__(self, **_kwargs):
            self.responses = FakeResponses()

    monkeypatch.setattr(ai_analysis, "OpenAI", FakeClient)
    monkeypatch.setattr(ai_analysis, "BadRequestError", FakeBadRequestError)
    with pytest.raises(ai_analysis.AIAnalysisError) as error:
        ai_analysis.analyze_code("print('hello')", "test-key", "gpt-test")
    assert "unsupported_value" in str(error.value)
    assert "text.format.type" in str(error.value)
    assert "[submitted code]" in str(error.value)
    assert "[redacted API key]" in str(error.value)
    assert "sk-abcdefghijk" not in str(error.value)


def test_security_lab_executes_all_required_checks_and_gate_uses_results(client, logged_in, app, user):
    before = client.get("/api/deployment")
    assert before.json["deployment"]["status"] == "NEEDS REVIEW"
    response = client.post("/api/tests/run", json={})
    assert response.status_code == 200
    assert len(response.json["results"]) == 6
    assert {item["status"] for item in response.json["results"]} == {"PASS"}
    assert response.json["deployment"]["status"] == "READY"
    with app.app_context():
        assert SecurityTestResult.query.filter_by(user_id=user).count() == 6
    assert client.get("/api/tests/latest").status_code == 200


def test_deployment_gate_blocks_critical_failure_and_tracks_review_ownership(client, logged_in, app, user):
    with app.app_context():
        db.session.add(SecurityTestResult(
            user_id=user, test_name="sql_injection", status="FAIL", critical=True,
            details="Controlled failure for gate test.",
        ))
        db.session.commit()
    assert client.get("/api/deployment").json["deployment"]["status"] == "BLOCKED"
    added = client.post("/api/review-items", json={"title": "Review reviewer roles", "severity": "medium"})
    assert added.status_code == 201
    item_id = added.json["id"]
    assert client.get("/api/deployment").json["deployment"]["status"] == "BLOCKED"
    assert client.post(f"/api/review-items/{item_id}/resolve", json={}).json["resolved"] is True
    assert client.post("/api/review-items/99999/resolve", json={}).status_code == 404


def test_users_cannot_resolve_another_users_review_item(client, app, logged_in):
    with app.app_context():
        owner = User(username="secondbuilder", email="second@example.edu")
        owner.set_password("another-safe-password-2026")
        db.session.add(owner)
        db.session.flush()
        item = ReviewItem(user_id=owner.id, title="Private review item", severity="low")
        db.session.add(item)
        db.session.commit()
        item_id = item.id
    response = client.post(f"/api/review-items/{item_id}/resolve", json={})
    assert response.status_code == 404


def test_unresolved_critical_finding_blocks_deployment(client, logged_in):
    added = client.post("/api/review-items", json={
        "title": "Unresolved critical applicant data exposure", "severity": "critical",
    })
    assert added.status_code == 201
    assert client.get("/api/deployment").json["deployment"]["status"] == "BLOCKED"
    assert client.post(f"/api/review-items/{added.json['id']}/resolve", json={}).status_code == 200
    assert client.get("/api/deployment").json["deployment"]["status"] == "NEEDS REVIEW"


def test_mission_restart_clears_progress_but_preserves_test_history(client, logged_in, app, user):
    client.post("/api/challenges/password-security/attempt", json={"answer": "secure"})
    client.post("/api/tests/run", json={})
    response = client.post("/mission/restart")
    assert response.status_code == 302
    with app.app_context():
        from app.models import ChallengeAttempt, UserProgress
        assert ChallengeAttempt.query.filter_by(user_id=user).count() == 0
        assert UserProgress.query.filter_by(user_id=user).count() == 0
        assert SecurityTestResult.query.filter_by(user_id=user).count() == 6


def test_csrf_rejects_state_change_without_token(tmp_path):
    from app import create_app
    app = create_app({
        "TESTING": False, "WTF_CSRF_ENABLED": True, "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "UPLOAD_FOLDER": tmp_path / "csrf-uploads", "RATELIMIT_STORAGE_URI": "memory://",
    })
    client = app.test_client()
    login_page = client.get("/auth/login")
    assert login_page.status_code == 200
    assert client.post("/auth/login", data={"email": "a@example.edu", "password": "password"}).status_code == 400
    token = re.search(rb'name="csrf_token" type="hidden" value="([^"]+)"', login_page.data)
    assert token
    response = client.post("/auth/login", data={
        "email": "a@example.edu", "password": "wrong-but-valid-length", "csrf_token": token.group(1).decode(),
    })
    assert response.status_code == 200
