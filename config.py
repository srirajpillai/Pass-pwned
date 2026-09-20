"""Application configuration."""
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_URL = (os.environ.get("DATABASE_URL") or
                os.environ.get("POSTGRES_URL"))
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg2://" + DATABASE_URL[len("postgres://"):]
if not DATABASE_URL:
    database_path = ("/tmp/password_analyser.db" if os.environ.get("VERCEL")
                     else os.path.join(BASE_DIR, "instance", "app.db"))
    DATABASE_URL = "sqlite:///" + database_path


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me-in-production")

    # database
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # session
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # breach service
    HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
    HIBP_TIMEOUT = float(os.environ.get("HIBP_TIMEOUT", "4"))
    HIBP_USER_AGENT = "Password-Strength-Analyser-SEPM-Project"

    # caching of range queries (seconds)
    RANGE_CACHE_TTL = int(os.environ.get("RANGE_CACHE_TTL", "900"))

    # admin account created by `python seed.py`
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@analyser.local")

    # pagination
    PAGE_SIZE = 15
