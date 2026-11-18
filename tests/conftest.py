import pytest

from app import create_app
from app.extensions import db
from app.models import User


@pytest.fixture
def app(tmp_path):
    application = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SESSION_COOKIE_SECURE": False,
        "UPLOAD_FOLDER": tmp_path / "uploads",
        "RATELIMIT_STORAGE_URI": "memory://",
        "AI_PROVIDER": "openai",
        "OPENAI_API_KEY": None,
        "OPENAI_MODEL": "gpt-4.1-mini",
        "GEMINI_API_KEY": None,
    })
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def user(app):
    with app.app_context():
        account = User(username="securebuilder", email="builder@example.edu")
        account.set_password("a-long-secure-password-2026")
        db.session.add(account)
        db.session.commit()
        return account.id


@pytest.fixture
def logged_in(client, user):
    response = client.post("/auth/login", data={
        "email": "builder@example.edu",
        "password": "a-long-secure-password-2026",
    })
    assert response.status_code == 302
    return client
