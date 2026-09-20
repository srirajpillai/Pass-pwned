"""Test suite for the Password Strength Analyser & Breach Checker."""

import hashlib
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app                      # noqa: E402
from extensions import db                       # noqa: E402
from models import User, Analysis               # noqa: E402
from services.analyzer import analyse, crack_time   # noqa: E402
from services.breach import sha1_hex, split_digest, fetch_range  # noqa: E402


# --------------------------------------------------------------------------- #
#  fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def app():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    class TestConfig:
        TESTING = True
        WTF_CSRF_ENABLED = False
        SECRET_KEY = "test-secret"
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + path
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        HIBP_TIMEOUT = 1.0
        PAGE_SIZE = 15

    application = create_app(TestConfig)
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()
    os.unlink(path)


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, username="tester", email="t@example.com",
             password="Str0ng!Passphrase"):
    return client.post("/register", data={
        "username": username, "email": email, "password": password,
    }, follow_redirects=True)


def login(client, username="tester", password="Str0ng!Passphrase"):
    return client.post("/login", data={
        "username": username, "password": password,
    }, follow_redirects=True)


# --------------------------------------------------------------------------- #
#  analyser
# --------------------------------------------------------------------------- #
def test_empty_password_scores_zero():
    r = analyse("")
    assert r["score"] == 0
    assert r["verdict"] == "Very Weak"


def test_common_password_is_very_weak():
    r = analyse("password")
    assert r["score"] < 25
    assert any(p["name"] == "Found in common password list"
               for p in r["patterns"])
    assert r["tone"] == "danger"


def test_sequence_penalty():
    r = analyse("abcdef123456")
    names = [p["name"] for p in r["patterns"]]
    assert "Letter sequence" in names or "Number sequence" in names


def test_repeat_penalty():
    r = analyse("aaabbbcccddd")
    assert any(p["name"] == "Repeated characters" for p in r["patterns"])


def test_keyboard_walk_detected():
    r = analyse("qwerty123")
    assert any(p["name"] == "Keyboard walk" for p in r["patterns"])


def test_long_passphrase_is_excellent():
    r = analyse("correct-horse-battery-staple-47")
    assert r["score"] >= 81
    assert r["verdict"] == "Excellent"


def test_score_monotonic_on_length():
    base = "Tr0ub4dor&3"
    short = analyse(base)
    long_ = analyse(base + "Xk9!qw")
    assert long_["score"] > short["score"]


def test_entropy_and_charset():
    r = analyse("Abc123!@#")
    assert r["charset_size"] == 26 + 26 + 10 + 33
    assert r["entropy_bits"] > 0


def test_crack_time_is_readable():
    assert "instant" in crack_time(1)
    assert isinstance(crack_time(80), str)


def test_result_is_json_serialisable():
    import json
    json.dumps(analyse("password123"))


# --------------------------------------------------------------------------- #
#  breach service (k-anonymity)
# --------------------------------------------------------------------------- #
def test_sha1_and_split():
    digest = sha1_hex("password")
    assert digest == hashlib.sha1(b"password").hexdigest().upper()
    prefix, suffix = split_digest(digest)
    assert prefix == "5BAA6"
    assert len(prefix) == 5 and len(suffix) == 35


def test_fetch_range_returns_dict():
    suffixes, source = fetch_range("5BAA6")
    assert isinstance(suffixes, dict)
    assert source in ("hibp", "offline")


def test_breach_detects_known_password():
    from services.breach import check_breach
    r = check_breach("password")           # offline corpus always contains it
    if r["available"]:
        assert r["breached"] is True
        assert r["count"] > 0


# --------------------------------------------------------------------------- #
#  web layer
# --------------------------------------------------------------------------- #
def test_landing_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"Attack-pattern detection" in r.data


def test_analyser_loads(client):
    assert client.get("/app").status_code == 200


def test_dashboard_loads_empty(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert b"Statistics" in r.data


def test_dashboard_renders_charts_with_data(client):
    register(client)
    login(client)
    for i, (sc, vd) in enumerate([(12, "Very Weak"), (55, "Fair"),
                                  (91, "Excellent")]):
        client.post("/api/analysis", json={
            "score": sc, "verdict": vd, "length": 8 + i,
            "entropy_bits": 40.0, "crack_time": "centuries",
            "sha1_prefix": "ABCDE", "breached": i == 0,
            "breach_count": 3 if i == 0 else 0,
            "breach_source": "hibp",
            "patterns": ["Found in common password list"] if i == 0 else [],
        })
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert b"Checks per day" in r.data
    assert b"Most common weaknesses" in r.data
    assert b"Found in common password list" in r.data


def test_pattern_names_are_persisted(client, app):
    register(client)
    login(client)
    client.post("/api/analysis", json={
        "score": 8, "verdict": "Very Weak", "length": 8,
        "entropy_bits": 33.0, "crack_time": "instant",
        "sha1_prefix": "5BAA6", "breached": True, "breach_count": 10,
        "breach_source": "hibp",
        "patterns": ["Found in common password list", "Too short"],
    })
    with app.app_context():
        row = Analysis.query.first()
        assert row.pattern_names == ["Found in common password list",
                                     "Too short"]
        assert row.pattern_count == 2


def test_breach_card_shows_no_service_details(client):
    """The UI must not leak the API source or the transmitted prefix."""
    body = client.get("/app").data.decode()
    for leak in ("prefix sent", "source: hibp", "breachMeta"):
        assert leak not in body


def test_health_endpoint(client):
    assert client.get("/api/health").get_json()["status"] == "ok"


def test_range_endpoint_rejects_bad_prefix(client):
    assert client.get("/api/range/XYZ").status_code == 400


def test_range_endpoint_ok(client):
    r = client.get("/api/range/5BAA6")
    assert r.status_code == 200
    assert "suffixes" in r.get_json()


def test_register_login_logout(client):
    assert b"Account created" in register(client).data
    assert client.get("/logout", follow_redirects=True).status_code == 200
    assert b"Welcome back" in login(client).data


def test_duplicate_username_rejected(client):
    register(client)
    assert b"already taken" in register(client).data


def test_short_password_rejected(client):
    r = client.post("/register", data={"username": "bob",
                                       "email": "bob@example.com",
                                       "password": "123"},
                    follow_redirects=True)
    assert b"at least 8 characters" in r.data


def test_history_requires_login(client):
    r = client.get("/history", follow_redirects=True)
    assert r.status_code == 200
    # anonymous visitors land on the login page
    assert b"Welcome back" in r.data


def test_admin_requires_admin_role(client, app):
    register(client)
    login(client)
    assert client.get("/admin").status_code == 403

    # the fixture keeps an application context pushed, so the model can be
    # updated directly here
    u = User.query.filter_by(username="tester").first()
    u.is_admin = True
    db.session.commit()
    assert client.get("/admin").status_code == 200
    assert b"Administration" in client.get("/admin").data


def test_saving_analysis_stores_no_password(client, app):
    register(client)
    login(client)
    r = client.post("/api/analysis", json={
        "score": 92, "verdict": "Excellent", "length": 16,
        "entropy_bits": 88.4, "crack_time": "centuries",
        "sha1_prefix": "ABCDE", "breached": False, "breach_count": 0,
        "breach_source": "hibp", "pattern_count": 0,
    })
    assert r.get_json()["saved"] is True

    with app.app_context():
        row = Analysis.query.first()
        assert row.score == 92
        # privacy: only the 5 character prefix is kept
        assert row.sha1_prefix == "ABCDE"
        assert len(row.sha1_prefix) == 5
        record = {c.name: getattr(row, c.name)
                  for c in Analysis.__table__.columns}
        assert "password" not in record
        assert "hash" not in record


def test_history_page_lists_records(client):
    register(client)
    login(client)
    client.post("/api/analysis", json={
        "score": 12, "verdict": "Very Weak", "length": 6,
        "entropy_bits": 24.0, "crack_time": "instant",
        "sha1_prefix": "7C4A8", "breached": True, "breach_count": 1,
        "breach_source": "hibp", "pattern_count": 3,
    })
    body = client.get("/history").data
    assert b"Very Weak" in body
    assert b"breached" in body.lower()
