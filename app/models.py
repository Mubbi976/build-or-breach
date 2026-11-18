from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    progress = db.relationship("UserProgress", back_populates="user", cascade="all, delete-orphan")
    challenge_attempts = db.relationship("ChallengeAttempt", back_populates="user", cascade="all, delete-orphan")
    ai_analyses = db.relationship("AIAnalysis", back_populates="user", cascade="all, delete-orphan")
    test_results = db.relationship("TestResult", back_populates="user", cascade="all, delete-orphan")
    simulations = db.relationship("SimulationSession", back_populates="user", cascade="all, delete-orphan")
    review_items = db.relationship("ReviewItem", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(80), unique=True, nullable=False)
    title = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(60), nullable=False)
    description = db.Column(db.Text, nullable=False)
    vulnerable_code = db.Column(db.Text, nullable=False)
    secure_code = db.Column(db.Text, nullable=False)
    explanation = db.Column(db.Text, nullable=False)
    tests = db.Column(db.JSON, nullable=False, default=list)
    attempts = db.relationship("ChallengeAttempt", back_populates="challenge", cascade="all, delete-orphan")


class ChallengeAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenge.id"), nullable=False)
    passed = db.Column(db.Boolean, nullable=False)
    answer = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    user = db.relationship("User", back_populates="challenge_attempts")
    challenge = db.relationship("Challenge", back_populates="attempts")


class AIAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    code = db.Column(db.Text, nullable=False)
    result = db.Column(db.JSON, nullable=False)
    model = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    user = db.relationship("User", back_populates="ai_analyses")


class TestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    test_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(16), nullable=False)
    critical = db.Column(db.Boolean, nullable=False, default=False)
    details = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    user = db.relationship("User", back_populates="test_results")


class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    module = db.Column(db.String(60), nullable=False)
    completed = db.Column(db.Boolean, nullable=False, default=False)
    score = db.Column(db.Integer, nullable=False, default=0)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    user = db.relationship("User", back_populates="progress")
    __table_args__ = (db.UniqueConstraint("user_id", "module", name="uq_user_module_progress"),)


class SimulationSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    scenario = db.Column(db.String(60), nullable=False)
    defended = db.Column(db.Boolean, nullable=False)
    outcome = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    user = db.relationship("User", back_populates="simulations")


class ReviewItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    resolved = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    user = db.relationship("User", back_populates="review_items")


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


CHALLENGE_SEEDS = [
    {
        "slug": "sql-injection", "title": "Stop SQL Injection", "category": "Injection",
        "description": "Choose the implementation that keeps user input separate from SQL syntax.",
        "vulnerable_code": "query = \"SELECT * FROM applicants WHERE email = '\" + email + \"'\"",
        "secure_code": "db.session.execute(text('SELECT * FROM applicants WHERE email = :email'), {'email': email})",
        "explanation": "Bound parameters ensure the database treats email as data, not executable query syntax.",
        "tests": ["A quote in input cannot change the query structure.", "Normal lookup still returns the matching applicant."]
    },
    {
        "slug": "password-security", "title": "Protect Account Passwords", "category": "Authentication",
        "description": "Select a password storage approach resistant to database disclosure.",
        "vulnerable_code": "user.password = submitted_password",
        "secure_code": "user.password_hash = generate_password_hash(submitted_password)",
        "explanation": "Use a purpose-built, salted password hash and verify with its matching checker.",
        "tests": ["Stored value differs from the submitted password.", "Password verification succeeds without storing plaintext."]
    },
    {
        "slug": "access-control", "title": "Enforce Applicant Ownership", "category": "Authorization",
        "description": "Choose the record lookup that limits applicants to their own application.",
        "vulnerable_code": "application = Application.query.get(application_id)",
        "secure_code": "application = Application.query.filter_by(id=application_id, owner_id=current_user.id).first_or_404()",
        "explanation": "Authentication alone is not authorization. Scope every object lookup to the current user's permission.",
        "tests": ["A different applicant cannot read this application.", "An owner can still read their own application."]
    },
    {
        "slug": "file-uploads", "title": "Validate Resume Uploads", "category": "File handling",
        "description": "Select a defense that validates file type and avoids trusting submitted paths.",
        "vulnerable_code": "file.save(os.path.join(upload_dir, file.filename))",
        "secure_code": "name = secure_filename(file.filename); validate_extension_and_size(file); file.save(safe_path(name))",
        "explanation": "Allow-list expected types, limit size, generate safe storage names, and never trust a client filename.",
        "tests": ["Unexpected extensions are rejected.", "Storage path does not use a raw client filename."]
    },
    {
        "slug": "cross-site-scripting", "title": "Render Applicant Content Safely", "category": "Output encoding",
        "description": "Choose the output behavior that treats applicant text as untrusted content.",
        "vulnerable_code": "element.innerHTML = applicant.bio",
        "secure_code": "element.textContent = applicant.bio",
        "explanation": "Use context-appropriate output encoding. In browser text nodes, textContent avoids interpreting markup.",
        "tests": ["Markup is shown as text rather than interpreted.", "Trusted page structure remains intact."]
    },
]


def seed_challenges():
    for seed in CHALLENGE_SEEDS:
        if not db.session.scalar(db.select(Challenge).filter_by(slug=seed["slug"])):
            db.session.add(Challenge(**seed))
    db.session.commit()
