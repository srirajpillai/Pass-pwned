"""Database models.

PRIVACY NOTE
------------
Neither the plain-text password, nor its complete SHA-1 digest is ever
persisted.  Only non-reversible metadata is stored: the length, the strength
score, the entropy estimate and the first five characters of the SHA-1 digest
(the k-anonymity prefix that is transmitted to the breach service).
"""

from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db, login_manager


def _utcnow():
    """Timezone naive UTC timestamp (keeps SQLite happy)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    integration_key_hash = db.Column(db.String(64), unique=True, nullable=True,
                                      index=True)
    integration_key_prefix = db.Column(db.String(24), nullable=True)
    integration_key_created_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    analyses = db.relationship(
        "Analysis", backref="author", lazy="dynamic",
        cascade="all, delete-orphan")

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

    def __repr__(self):
        return "<User %s>" % self.username


class Analysis(db.Model):
    """One password check.  The password itself is never stored."""

    __tablename__ = "analyses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True,
                        index=True)

    length = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    verdict = db.Column(db.String(32), nullable=False)
    entropy_bits = db.Column(db.Float, nullable=False)
    crack_time = db.Column(db.String(64), nullable=False)

    # k-anonymity: only the 5 character prefix is kept
    sha1_prefix = db.Column(db.String(5), nullable=True)
    breached = db.Column(db.Boolean, default=False, nullable=False)
    breach_count = db.Column(db.Integer, default=0, nullable=False)
    breach_source = db.Column(db.String(32), default="unknown", nullable=False)

    pattern_count = db.Column(db.Integer, default=0, nullable=False)
    # "||" separated list of the weakness names that were detected, so the
    # dashboard can report which problems are most common
    patterns_text = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False,
                           index=True)

    @property
    def pattern_names(self):
        return [p for p in (self.patterns_text or "").split("||") if p]

    @pattern_names.setter
    def pattern_names(self, names):
        self.patterns_text = "||".join(names or [])
        self.pattern_count = len(names or [])

    def __repr__(self):
        return "<Analysis score=%d breached=%s>" % (self.score, self.breached)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    detail = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False,
                           index=True)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
