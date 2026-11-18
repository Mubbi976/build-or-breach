from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user
from flask_wtf import FlaskForm
from sqlalchemy.exc import IntegrityError
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp

from ..extensions import db, limiter
from ..models import User

bp = Blueprint("auth", __name__)


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[
        DataRequired(), Length(min=3, max=40),
        Regexp(r"^[A-Za-z0-9_.-]+$", message="Use letters, numbers, dots, dashes, or underscores.")
    ])
    email = StringField("Email", validators=[
        DataRequired(), Length(max=255),
        Regexp(r"^[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+$", message="Enter a valid email address.")
    ])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=12, max=128)])
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[
        DataRequired(), Length(max=255),
        Regexp(r"^[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+$", message="Enter a valid email address.")
    ])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Sign in")


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.mission"))
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        username = form.username.data.strip()
        if db.session.scalar(db.select(User).filter_by(email=email)) or db.session.scalar(
            db.select(User).filter_by(username=username)
        ):
            flash("That email or username is already registered.", "error")
        else:
            user = User(email=email, username=username)
            user.set_password(form.password.data)
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash("That email or username is already registered.", "error")
            else:
                flash("Account created. Sign in to begin your mission.", "success")
                return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.mission"))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = db.session.scalar(db.select(User).filter_by(email=email))
        if user and user.check_password(form.password.data):
            login_user(user, remember=False, fresh=True)
            next_page = request.args.get("next", "")
            if not next_page.startswith("/") or next_page.startswith("//"):
                next_page = url_for("main.mission")
            return redirect(next_page)
        flash("Email or password was not recognized.", "error")
    return render_template("auth/login.html", form=form)


@bp.post("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
    return redirect(url_for("main.index"))
