from flask import Blueprint, abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from ..extensions import db
from ..models import AIAnalysis, Challenge, ChallengeAttempt, SimulationSession, TestResult, UserProgress

bp = Blueprint("main", __name__)

MODULES = [
    ("threat-model", "Threat Modeling Lab", "Map CareerConnect's trust boundaries and make STRIDE decisions.", "01"),
    ("code-studio", "Secure Code Studio", "Practice five secure coding patterns with guided feedback.", "02"),
    ("ai-engineer", "AI Security Engineer", "Request a code review from the configured OpenAI model.", "03"),
    ("arena", "Attack & Defense Arena", "Run safe, local simulations against fictional mock data.", "04"),
    ("testing-lab", "Security Testing Lab", "Execute the platform's focused security checks.", "05"),
    ("deployment-gate", "Deployment Gate", "Make a release decision from evidence, not guesswork.", "06"),
]


@bp.get("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.mission"))
    return render_template("landing.html")


@bp.get("/mission")
@login_required
def mission():
    progress = {p.module: p for p in current_user.progress}
    attempts = ChallengeAttempt.query.filter_by(user_id=current_user.id).all()
    completed_challenges = {a.challenge_id for a in attempts if a.passed}
    challenges = Challenge.query.order_by(Challenge.id).all()
    return render_template(
        "mission.html", modules=MODULES, progress=progress,
        challenges=challenges, completed_challenges=completed_challenges,
        passed_tests=TestResult.query.filter_by(user_id=current_user.id, status="PASS").count()
    )


@bp.post("/mission/restart")
@login_required
def restart_mission():
    ChallengeAttempt.query.filter_by(user_id=current_user.id).delete()
    UserProgress.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash("Mission progress restarted. Your AI, simulation, and test history is preserved.", "success")
    return redirect(url_for("main.mission"))


@bp.get("/modules/<slug>")
@login_required
def module_page(slug):
    pages = {
        "threat-model": "modules/threat_model.html",
        "code-studio": "modules/code_studio.html",
        "ai-engineer": "modules/ai_engineer.html",
        "arena": "modules/arena.html",
        "testing-lab": "modules/testing_lab.html",
        "deployment-gate": "modules/deployment_gate.html",
        "profile": "modules/profile.html",
    }
    if slug not in pages:
        abort(404)
    context = {"module_slug": slug}
    if slug == "code-studio":
        context["challenges"] = Challenge.query.order_by(Challenge.id).all()
    elif slug == "profile":
        context.update(
            challenge_history=ChallengeAttempt.query.filter_by(user_id=current_user.id).order_by(
                ChallengeAttempt.created_at.desc()
            ).limit(20).all(),
            ai_history=AIAnalysis.query.filter_by(user_id=current_user.id).order_by(
                AIAnalysis.created_at.desc()
            ).limit(10).all(),
            simulations=SimulationSession.query.filter_by(user_id=current_user.id).order_by(
                SimulationSession.created_at.desc()
            ).limit(10).all(),
        )
    return render_template(pages[slug], **context)
