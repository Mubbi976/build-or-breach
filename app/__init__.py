from flask import Flask, jsonify, redirect, render_template, request, url_for
from sqlalchemy import event, text

from .config import Config
from .extensions import csrf, db, limiter, login_manager


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    app.config["UPLOAD_FOLDER"].mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify(error="Authentication is required."), 401
        return redirect(url_for("auth.login", next=request.full_path))

    from . import models
    from .routes import auth, main, modules

    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp, url_prefix="/auth")
    app.register_blueprint(modules.bp, url_prefix="/api")

    @app.get("/health")
    def health():
        db.session.execute(text("SELECT 1"))
        return jsonify(status="ok")

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="Request is too large."), 413

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response

    with app.app_context():
        if db.engine.dialect.name == "sqlite":
            @event.listens_for(db.engine, "connect")
            def enable_sqlite_foreign_keys(connection, _record):
                cursor = connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        db.create_all()
        models.seed_challenges()

    return app
