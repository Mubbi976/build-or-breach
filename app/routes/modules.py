from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

from ..extensions import db, limiter
from ..models import (
    AIAnalysis, Challenge, ChallengeAttempt, ReviewItem, SimulationSession,
    TestResult, UserProgress,
)
from ..services.ai_analysis import AIAnalysisError, analyze_code
from ..services.security_tests import REQUIRED_TESTS, execute_security_checks
from ..services.simulations import SCENARIOS, run_simulation

bp = Blueprint("modules", __name__)

THREAT_COMPONENTS = {
    "browser": {
        "label": "Applicant browser",
        "description": "Untrusted applicant devices and browsers",
        "threats": {
            "spoofing": {"label": "Spoofing", "control": "session-cookie"},
            "repudiation": {"label": "Repudiation", "control": "audit-log"},
            "information-disclosure": {"label": "Information disclosure", "control": "output-encoding"},
        },
    },
    "api": {
        "label": "CareerConnect API",
        "description": "Authentication, application, and resume endpoints",
        "threats": {
            "tampering": {"label": "Tampering", "control": "input-validation"},
            "repudiation": {"label": "Repudiation", "control": "audit-log"},
            "denial-of-service": {"label": "Denial of service", "control": "rate-limit"},
            "elevation-of-privilege": {"label": "Elevation of privilege", "control": "authorization"},
        },
    },
    "database": {
        "label": "Applicant database",
        "description": "Personal information and application records",
        "threats": {
            "tampering": {"label": "Tampering", "control": "parameterized-query"},
            "information-disclosure": {"label": "Information disclosure", "control": "least-privilege"},
            "denial-of-service": {"label": "Denial of service", "control": "rate-limit"},
        },
    },
}

THREAT_CONTROLS = {
    "session-cookie": "Secure, HttpOnly, SameSite session cookies",
    "audit-log": "Append-only audit events for sensitive changes",
    "output-encoding": "Context-aware output encoding",
    "input-validation": "Validate input against a server-side allow-list",
    "rate-limit": "Rate limit sensitive API actions",
    "authorization": "Enforce owner checks on every record request",
    "parameterized-query": "Use bound parameters for database queries",
    "least-privilege": "Restrict database access to minimum required records",
}

REQUIRED_TEST_LABELS = {
    "sql_injection": "SQL injection protection",
    "password_hashing": "Password hashing",
    "authorization": "Authorization",
    "file_validation": "File validation",
    "rate_limiting": "Rate limiting",
    "session_handling": "Session handling",
}


@bp.get("/status")
def status():
    return jsonify(status="ready")


@bp.get("/rate-limit-probe")
@limiter.limit("2 per minute")
def rate_limit_probe():
    return jsonify(status="allowed")


@bp.get("/threat-model/data")
@login_required
def threat_model_data():
    components = []
    for key, component in THREAT_COMPONENTS.items():
        components.append({
            "id": key,
            "label": component["label"],
            "description": component["description"],
            "threats": [
                {"id": threat_id, "label": threat["label"],
                 "controls": [
                     {"id": control_id, "label": THREAT_CONTROLS[control_id]}
                     for control_id in THREAT_CONTROLS
                 ]}
                for threat_id, threat in component["threats"].items()
            ],
        })
    return jsonify(components=components)


@bp.post("/threat-model/evaluate")
@login_required
def threat_model_evaluate():
    data = _json_body()
    component_id = _string(data, "component", 40)
    threat_id = _string(data, "threat", 40)
    control_id = _string(data, "control", 40)
    component = THREAT_COMPONENTS.get(component_id)
    threat = component and component["threats"].get(threat_id)
    if not threat or control_id not in THREAT_CONTROLS:
        return _error("Choose a valid component, threat, and defensive control.", 400)
    passed = threat["control"] == control_id
    if passed:
        _set_progress("threat-model", 100, True)
    db.session.commit()
    return jsonify(
        passed=passed,
        expected_control=threat["control"],
        explanation=(
            f"{THREAT_CONTROLS[threat['control']]} addresses {threat['label']} for "
            f"{component['label']}."
            if passed else
            f"For {threat['label']} on {component['label']}, select a control that mitigates "
            "the identified threat."
        ),
    )


@bp.post("/challenges/<slug>/attempt")
@login_required
def challenge_attempt(slug):
    challenge = db.session.scalar(db.select(Challenge).filter_by(slug=slug))
    if not challenge:
        return _error("Challenge not found.", 404)
    data = _json_body()
    answer = _string(data, "answer", 20)
    if answer not in {"secure", "vulnerable"}:
        return _error("Choose either the secure or vulnerable implementation.", 400)
    passed = answer == "secure"
    db.session.add(ChallengeAttempt(
        user_id=current_user.id, challenge_id=challenge.id, passed=passed, answer=answer
    ))
    if passed:
        successful = db.session.scalar(
            db.select(db.func.count(db.func.distinct(ChallengeAttempt.challenge_id)))
            .filter_by(user_id=current_user.id, passed=True)
        )
        total = db.session.scalar(db.select(db.func.count()).select_from(Challenge))
        score = round(successful / max(total, 1) * 100)
        _set_progress("code-studio", score, successful >= total)
    db.session.commit()
    return jsonify(
        passed=passed,
        feedback=challenge.explanation if passed else "Not quite. Compare how the two versions handle untrusted input or identity.",
        explanation=challenge.explanation,
        secure_code=challenge.secure_code,
        vulnerable_code=challenge.vulnerable_code,
    )


@bp.post("/ai/analyze")
@login_required
@limiter.limit("5 per minute")
def ai_analyze():
    data = _json_body()
    code = data.get("code")
    if not isinstance(code, str) or not code.strip():
        return _error("Paste code to analyze.", 400)
    if len(code) > current_app.config["MAX_CODE_LENGTH"]:
        return _error(f"Code must be {current_app.config['MAX_CODE_LENGTH']} characters or fewer.", 400)
    provider, api_key, model = _ai_settings()
    try:
        result = analyze_code(code, api_key, model, provider=provider)
    except AIAnalysisError as exc:
        return jsonify(error=str(exc)), 503
    analysis = AIAnalysis(
        user_id=current_user.id, code=code, result=result,
        model=model,
    )
    db.session.add(analysis)
    _set_progress("ai-engineer", 100, True)
    db.session.commit()
    return jsonify(id=analysis.id, result=result)


@bp.get("/ai/history")
@login_required
def ai_history():
    records = AIAnalysis.query.filter_by(user_id=current_user.id).order_by(
        AIAnalysis.created_at.desc()
    ).limit(20).all()
    return jsonify(analyses=[
        {"id": item.id, "risk": item.result["risk"], "summary": item.result["summary"],
         "created_at": item.created_at.isoformat()}
        for item in records
    ])


@bp.get("/ai/status")
@login_required
def ai_status():
    provider, api_key, model = _ai_settings()
    return jsonify(
        provider=provider,
        configured=bool(api_key),
        model=model,
    )


@bp.post("/simulations/run")
@login_required
def simulation_run():
    data = _json_body()
    scenario = _string(data, "scenario", 60)
    defended = data.get("defended")
    if scenario not in SCENARIOS or not isinstance(defended, bool):
        return _error("Choose a supported scenario and defense state.", 400)
    result = run_simulation(scenario, defended)
    db.session.add(SimulationSession(
        user_id=current_user.id, scenario=scenario, defended=defended, outcome=result
    ))
    _set_progress("arena", 100 if defended else 50, defended)
    db.session.commit()
    return jsonify(result)


@bp.get("/simulations/catalog")
@login_required
def simulation_catalog():
    return jsonify(scenarios=[
        {"id": key, **value} for key, value in SCENARIOS.items()
    ])


@bp.post("/tests/run")
@login_required
@limiter.limit("10 per minute")
def run_tests():
    results = execute_security_checks(current_app._get_current_object())
    for item in results:
        db.session.add(TestResult(
            user_id=current_user.id, test_name=item["test_name"], status=item["status"],
            critical=item["critical"], details=item["details"],
        ))
    _set_progress("testing-lab", 100, all(item["status"] == "PASS" for item in results))
    db.session.commit()
    return jsonify(results=results, deployment=deployment_decision(current_user.id))


@bp.get("/tests/latest")
@login_required
def latest_tests():
    results = latest_test_results(current_user.id)
    return jsonify(results=[
        {"test_name": item.test_name, "status": item.status, "critical": item.critical,
         "details": item.details, "created_at": item.created_at.isoformat()}
        for item in results.values()
    ])


@bp.get("/deployment")
@login_required
def deployment_status():
    return jsonify(deployment=deployment_decision(current_user.id))


@bp.post("/review-items")
@login_required
def create_review_item():
    data = _json_body()
    title = _string(data, "title", 180)
    severity = _string(data, "severity", 20)
    if not title.strip() or severity not in {"critical", "high", "medium", "low"}:
        return _error("Provide a title and valid severity.", 400)
    item = ReviewItem(user_id=current_user.id, title=title.strip(), severity=severity)
    db.session.add(item)
    db.session.commit()
    return jsonify(id=item.id, title=item.title, severity=item.severity, resolved=False), 201


@bp.post("/review-items/<int:item_id>/resolve")
@login_required
def resolve_review_item(item_id):
    item = db.session.scalar(
        db.select(ReviewItem).filter_by(id=item_id, user_id=current_user.id)
    )
    if not item:
        return _error("Review item not found.", 404)
    item.resolved = True
    db.session.commit()
    return jsonify(id=item.id, resolved=True)


def latest_test_results(user_id):
    records = TestResult.query.filter_by(user_id=user_id).order_by(
        TestResult.created_at.desc(), TestResult.id.desc()
    ).all()
    latest = {}
    for record in records:
        latest.setdefault(record.test_name, record)
    return latest


def deployment_decision(user_id):
    latest = latest_test_results(user_id)
    unresolved = ReviewItem.query.filter_by(user_id=user_id, resolved=False).all()
    failed_critical = [
        item.test_name for item in latest.values()
        if item.status == "FAIL" and item.critical
    ]
    critical_review_items = [item for item in unresolved if item.severity == "critical"]
    missing = [name for name in REQUIRED_TESTS if name not in latest]
    failed = [name for name, result in latest.items() if result.status == "FAIL"]
    if failed_critical or critical_review_items:
        status_value = "BLOCKED"
        reason = "A critical security check failed or a critical finding remains unresolved."
    elif missing or failed or unresolved:
        status_value = "NEEDS REVIEW"
        reason = "Run missing checks and resolve failed tests or open review items."
    else:
        status_value = "READY"
        reason = "All required security checks passed and no review items remain open."
    return {
        "status": status_value,
        "reason": reason,
        "required_tests": [
            {"id": name, "label": REQUIRED_TEST_LABELS[name],
             "status": latest[name].status if name in latest else "NOT RUN",
             "critical": latest[name].critical if name in latest else name in {"sql_injection", "password_hashing", "authorization", "file_validation"}}
            for name in REQUIRED_TESTS
        ],
        "failed_tests": failed,
        "missing_tests": missing,
        "open_review_items": [
            {"id": item.id, "title": item.title, "severity": item.severity}
            for item in unresolved
        ],
    }


def _set_progress(module, score, completed):
    progress = db.session.scalar(
        db.select(UserProgress).filter_by(user_id=current_user.id, module=module)
    )
    if progress is None:
        progress = UserProgress(user_id=current_user.id, module=module, score=0)
        db.session.add(progress)
    progress.score = max(progress.score or 0, score)
    progress.completed = progress.completed or completed


def _ai_settings():
    provider = current_app.config.get("AI_PROVIDER", "openai").strip().lower()
    if provider == "gemini":
        return (
            provider,
            current_app.config.get("GEMINI_API_KEY"),
            current_app.config.get("GEMINI_MODEL", "gemini-4-hydrogen"),
        )
    if provider == "openai":
        return (
            provider,
            current_app.config.get("OPENAI_API_KEY"),
            current_app.config.get("OPENAI_MODEL", "gpt-4.1-mini"),
        )
    return provider, None, ""


def _json_body():
    if not request.is_json:
        return {}
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


def _string(data, key, max_length):
    value = data.get(key)
    if not isinstance(value, str) or len(value) > max_length:
        return ""
    return value


def _error(message, status):
    return jsonify(error=message), status
