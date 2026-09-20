"""
Password Strength Analyser & Breach Checker
==========================================

A Flask application that replaces rigid password complexity rules with

  * an evidence based strength score (entropy + attack-pattern detection)
  * a k-anonymity breach lookup against the Have I Been Pwned range API

Privacy design
--------------
The browser analyser computes the SHA-1 digest locally and sends **only the
first five characters** of that digest to `/api/range/<prefix>`. The company
integration endpoint accepts a password transiently so it can analyse and
record metadata for the organisation; the password itself is never stored.
"""

import os
import hashlib
import secrets
from datetime import datetime, timezone

from flask import (Flask, jsonify, render_template, request, redirect,
                   url_for, flash, abort)
from flask_login import login_user, logout_user, login_required, current_user

from config import Config
from extensions import db, login_manager
from models import User, Analysis, AuditLog
from services.analyzer import analyse as analyse_password
from services.breach import check_breach
from services import stats as stats_svc
from services.breach import fetch_range


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --------------------------------------------------------------------------- #
def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    os.makedirs(os.path.join(os.path.dirname(__file__), "instance"),
                exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)

    # Add integration columns when upgrading an existing SQLite installation.
    # Fresh databases receive them through db.create_all().
    with app.app_context():
        inspector = db.inspect(db.engine)
        if "users" in inspector.get_table_names():
            columns = {column["name"] for column in
                       inspector.get_columns("users")}
            for name, definition in (
                    ("integration_key_hash", "VARCHAR(64)"),
                    ("integration_key_prefix", "VARCHAR(24)"),
                    ("integration_key_created_at", "DATETIME")):
                if name not in columns:
                    db.session.execute(db.text(
                        "ALTER TABLE users ADD COLUMN %s %s" %
                        (name, definition)))
            db.session.commit()

    # ---------------------------------------------------------------- utils
    def audit(action, detail=None, user=None):
        try:
            log = AuditLog(
                user_id=(user.id if user else
                         (current_user.id if current_user.is_authenticated
                          else None)),
                action=action,
                detail=(detail or "")[:255],
                ip_address=request.headers.get("X-Forwarded-For",
                                               request.remote_addr),
            )
            db.session.add(log)
            db.session.commit()
        except Exception:                                   # never break a page
            db.session.rollback()

    def scope():
        """The user whose data the current page should show (None = global)."""
        return current_user if current_user.is_authenticated else None

    # -------------------------------------------------------- public pages
    @app.route("/")
    def landing():
        """Marketing / information page."""
        return render_template("landing.html",
                               totals=stats_svc.headline(None))

    @app.route("/app")
    def analyser():
        """The analyser itself."""
        return render_template("analyser.html",
                               stats=stats_svc.headline(scope()))

    @app.route("/dashboard")
    def dashboard():
        """Statistics dashboard.

        By default a signed-in user sees only their own numbers; an
        administrator can add ?scope=all to see the whole installation.
        """
        see_all = (request.args.get("scope") == "all"
                   and current_user.is_authenticated
                   and current_user.is_admin)
        owner = None if (see_all or not current_user.is_authenticated) \
            else current_user
        return render_template("dashboard.html",
                               data=stats_svc.build_dashboard(owner),
                               scoped=current_user.is_authenticated,
                               see_all=see_all,
                               can_see_all=bool(current_user.is_authenticated
                                                and current_user.is_admin))

    @app.route("/history")
    @login_required
    def history():
        page = request.args.get("page", 1, type=int)
        q = Analysis.query.filter_by(user_id=current_user.id)
        if request.args.get("filter") == "breached":
            q = q.filter(Analysis.breached.is_(True))
        elif request.args.get("filter") == "weak":
            q = q.filter(Analysis.score < 41)
        rows = (q.order_by(Analysis.created_at.desc())
                .paginate(page=page, per_page=Config.PAGE_SIZE,
                          error_out=False))
        return render_template("history.html", rows=rows,
                               stats=stats_svc.headline(scope()))

    # ------------------------------------------------------------------ api
    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/api/range/<prefix>")
    def api_range(prefix):
        """k-anonymity range lookup - returns only suffix:count pairs."""
        if len(prefix) != 5 or any(c not in "0123456789ABCDEFabcdef"
                                   for c in prefix):
            return jsonify({"available": False,
                            "error": "prefix must be 5 hex characters"}), 400
        suffixes, source = fetch_range(prefix.upper())
        return jsonify({
            "available": source == "hibp",
            "count": len(suffixes),
            "suffixes": suffixes,
        })

    @app.route("/api/v1/analyse", methods=["POST"])
    def integration_analyse():
        """Analyze and record a password for the key owner's organisation."""
        supplied_key = request.headers.get("X-API-Key", "")
        key_hash = hashlib.sha256(supplied_key.encode("utf-8")).hexdigest()
        owner = User.query.filter_by(integration_key_hash=key_hash,
                                     is_active=True).first()
        if not supplied_key or not owner:
            return jsonify({"error": "invalid API key"}), 401

        data = request.get_json(silent=True) or {}
        password = data.get("password")
        if not isinstance(password, str) or not password:
            return jsonify({"error": "password must be a non-empty string"}), 400
        if len(password) > 1024:
            return jsonify({"error": "password is too long"}), 400

        result = analyse_password(password)
        breach = check_breach(password)
        breach.pop("prefix", None)
        row = Analysis(
            user_id=owner.id,
            length=result["length"],
            score=result["score"],
            verdict=result["verdict"],
            entropy_bits=result["entropy_bits"],
            crack_time=result["crack_time"],
            breached=bool(breach["breached"]),
            breach_count=breach["count"],
            breach_source=breach["source"],
            pattern_count=len(result["patterns"]),
            patterns_text="||".join(p["name"] for p in result["patterns"]),
        )
        db.session.add(row)
        db.session.commit()
        audit("api-analysis", "key owner %s" % owner.username, owner)
        return jsonify({
            "analysis": result,
            "breach": breach,
            "recorded": True,
        })

    @app.route("/settings/api-key", methods=["POST"])
    @login_required
    def generate_api_key():
        """Generate a new organisation key and show it once."""
        raw_key = "psa_live_" + secrets.token_urlsafe(32)
        current_user.integration_key_hash = hashlib.sha256(
            raw_key.encode("utf-8")).hexdigest()
        current_user.integration_key_prefix = raw_key[:16]
        current_user.integration_key_created_at = _utcnow()
        db.session.commit()
        audit("generate-api-key", "integration key replaced")
        flash("Your new API key (shown once): %s" % raw_key, "success")
        return redirect(url_for("dashboard"))

    @app.route("/api/analysis", methods=["POST"])
    @login_required
    def api_save_analysis():
        """Store *metadata only* - the password is never transmitted."""
        data = request.get_json(silent=True) or {}
        try:
            score = int(data.get("score", 0))
            length = int(data.get("length", 0))
            entropy = float(data.get("entropy_bits", 0))
        except (TypeError, ValueError):
            return jsonify({"saved": False,
                            "error": "invalid payload"}), 400

        raw_patterns = data.get("patterns") or []
        if isinstance(raw_patterns, str):
            raw_patterns = [raw_patterns]
        names = [str(p)[:64] for p in raw_patterns][:12]

        row = Analysis(
            user_id=current_user.id,
            length=max(0, length),
            score=max(0, min(100, score)),
            verdict=str(data.get("verdict", ""))[:32],
            entropy_bits=entropy,
            crack_time=str(data.get("crack_time", ""))[:64],
            sha1_prefix=(str(data.get("sha1_prefix", ""))[:5] or None),
            breached=bool(data.get("breached")),
            breach_count=int(data.get("breach_count") or 0),
            breach_source=str(data.get("breach_source", "unknown"))[:32],
            pattern_count=int(data.get("pattern_count") or len(names)),
            patterns_text="||".join(names),
        )
        db.session.add(row)
        db.session.commit()
        return jsonify({"saved": True, "id": row.id})

    # ------------------------------------------------------------ auth views
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("analyser"))
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip().lower()
            pwd = request.form.get("password") or ""

            if len(username) < 3:
                flash("Username must be at least 3 characters.", "danger")
            elif len(pwd) < 8:
                flash("Password must be at least 8 characters.", "danger")
            elif User.query.filter_by(username=username).first():
                flash("That username is already taken.", "danger")
            elif User.query.filter_by(email=email).first():
                flash("That email is already registered.", "danger")
            else:
                user = User(username=username, email=email)
                user.set_password(pwd)
                db.session.add(user)
                db.session.commit()
                audit("register", "user %s" % username, user)
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("analyser"))
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            pwd = request.form.get("password") or ""
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(pwd) and user.is_active:
                login_user(user, remember=bool(request.form.get("remember")))
                audit("login", "user %s" % username)
                flash("Welcome back, %s." % user.username, "success")
                return redirect(request.args.get("next") or url_for("analyser"))
            audit("login-failed", "user %s" % username)
            flash("Invalid username or password.", "danger")
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        audit("logout", "user %s" % current_user.username)
        logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for("landing"))

    # ----------------------------------------------------------------- admin
    @app.route("/admin")
    @login_required
    def admin():
        if not current_user.is_admin:
            abort(403)
        page = request.args.get("page", 1, type=int)
        rows = (Analysis.query.order_by(Analysis.created_at.desc())
                .paginate(page=page, per_page=Config.PAGE_SIZE,
                          error_out=False))
        users = User.query.order_by(User.created_at.desc()).all()
        logs = (AuditLog.query.order_by(AuditLog.created_at.desc())
                .limit(20).all())
        return render_template("admin.html", rows=rows, users=users,
                               logs=logs,
                               overview=stats_svc.system_overview(),
                               headline=stats_svc.headline(None))

    @app.route("/admin/user/<int:user_id>/toggle", methods=["POST"])
    @login_required
    def toggle_user(user_id):
        if not current_user.is_admin:
            abort(403)
        user = db.session.get(User, user_id) or abort(404)
        if user.id == current_user.id:
            flash("You cannot disable your own account.", "warning")
        else:
            user.is_active = not user.is_active
            db.session.commit()
            audit("toggle-user", "%s -> active=%s" % (user.username,
                                                      user.is_active))
            flash("%s has been %s." % (user.username,
                                       "enabled" if user.is_active
                                       else "disabled"), "info")
        return redirect(url_for("admin"))

    @app.route("/admin/analysis/<int:analysis_id>/delete", methods=["POST"])
    @login_required
    def delete_analysis(analysis_id):
        row = db.session.get(Analysis, analysis_id) or abort(404)
        if not current_user.is_admin and row.user_id != current_user.id:
            abort(403)
        db.session.delete(row)
        db.session.commit()
        audit("delete-analysis", "id=%d" % analysis_id)
        flash("Record deleted.", "info")
        return redirect(request.referrer or url_for("history"))

    # ----------------------------------------------------------- error pages
    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("errors.html", code=403,
                               message="You do not have access to this "
                                       "page."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("errors.html", code=404,
                               message="The page you requested was not "
                                       "found."), 404

    @app.errorhandler(500)
    def server_error(_e):
        db.session.rollback()
        return render_template("errors.html", code=500,
                               message="Something went wrong on the "
                                       "server."), 500

    # ------------------------------------------------------------ cli helper
    @app.cli.command("init-db")
    def init_db_command():
        """Create the database tables."""
        db.create_all()
        print("Database initialised.")

    return app


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0",
            port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG", "1") == "1")
