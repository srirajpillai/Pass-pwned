"""
Aggregated statistics for the dashboard.

Everything is computed with plain SQL aggregate queries, so it stays fast even
with a large history table.
"""

from collections import Counter, OrderedDict
from datetime import timedelta

from sqlalchemy import func

from extensions import db
from models import Analysis, User

BUCKETS = [
    (0, 20, "Very weak", "danger"),
    (21, 40, "Weak", "warn"),
    (41, 60, "Fair", "info"),
    (61, 80, "Strong", "ok"),
    (81, 100, "Excellent", "ok"),
]


# --------------------------------------------------------------------------- #
def _base(user=None):
    q = db.session.query(Analysis)
    if user is not None:
        q = q.filter(Analysis.user_id == user.id)
    return q


# --------------------------------------------------------------------------- #
def headline(user=None):
    """The four numbers shown at the top of the dashboard."""
    q = _base(user)
    total = q.count()
    breached = q.filter(Analysis.breached.is_(True)).count()
    weak = q.filter(Analysis.score < 41).count()
    strong = q.filter(Analysis.score >= 81).count()
    avg = db.session.query(func.avg(Analysis.score))
    if user is not None:
        avg = avg.filter(Analysis.user_id == user.id)
    avg = avg.scalar()

    return {
        "total": total,
        "breached": breached,
        "breached_pct": round(100.0 * breached / total, 1) if total else 0.0,
        "weak": weak,
        "weak_pct": round(100.0 * weak / total, 1) if total else 0.0,
        "strong": strong,
        "strong_pct": round(100.0 * strong / total, 1) if total else 0.0,
        "avg_score": round(float(avg), 1) if avg else 0.0,
    }


def score_distribution(user=None):
    """Count of checks inside each strength band."""
    q = _base(user)
    out = []
    for lo, hi, label, tone in BUCKETS:
        n = q.filter(Analysis.score >= lo, Analysis.score <= hi).count()
        out.append({"label": label, "lo": lo, "hi": hi, "count": n,
                    "tone": tone})
    return out


def daily_counts(user=None, days=14):
    """Checks per day for the last `days` days (zero filled)."""
    from models import _utcnow

    q = _base(user)
    today = _utcnow().date()
    start = today - timedelta(days=days - 1)

    rows = (q.filter(Analysis.created_at >= start)
            .with_entities(func.date(Analysis.created_at).label("d"),
                           func.count(Analysis.id))
            .group_by(func.date(Analysis.created_at)).all())
    lookup = {str(r[0]): r[1] for r in rows}

    out = []
    for i in range(days):
        day = start + timedelta(days=i)
        out.append({"date": day.strftime("%d %b"),
                    "iso": day.isoformat(),
                    "count": lookup.get(day.isoformat(), 0)})
    return out


def top_weaknesses(user=None, limit=6):
    """Most frequently detected weakness types."""
    q = _base(user).filter(Analysis.patterns_text != "")
    counter = Counter()
    for (blob,) in q.with_entities(Analysis.patterns_text).all():
        for name in (blob or "").split("||"):
            name = name.strip()
            if name:
                counter[name] += 1
    total = sum(counter.values())
    out = []
    for name, n in counter.most_common(limit):
        out.append({"name": name, "count": n,
                    "pct": round(100.0 * n / total, 1) if total else 0.0})
    return out, total


def length_profile(user=None):
    """Average score grouped by password length."""
    q = _base(user)
    rows = (q.with_entities(Analysis.length,
                            func.count(Analysis.id),
                            func.avg(Analysis.score))
            .group_by(Analysis.length).order_by(Analysis.length).all())
    return [{"length": r[0], "count": r[1],
             "avg": round(float(r[2] or 0), 1)} for r in rows]


def verdict_breakdown(user=None):
    q = _base(user)
    rows = (q.with_entities(Analysis.verdict,
                            func.count(Analysis.id))
            .group_by(Analysis.verdict).all())
    order = {label: i for i, (_l, _h, label, _t) in
             enumerate(reversed(BUCKETS))}
    rows = sorted(rows, key=lambda r: order.get(r[0], 99))
    total = sum(r[1] for r in rows) or 1
    return [{"verdict": r[0], "count": r[1],
             "pct": round(100.0 * r[1] / total, 1)} for r in rows]


def breach_sources(user=None):
    q = _base(user)
    rows = (q.with_entities(Analysis.breach_source,
                            func.count(Analysis.id))
            .group_by(Analysis.breach_source).all())
    return [{"source": r[0], "count": r[1]} for r in rows]


def recent(user=None, limit=8):
    q = _base(user).order_by(Analysis.created_at.desc()).limit(limit)
    return q.all()


def system_overview():
    """Numbers for the admin panel."""
    return {
        "users": User.query.count(),
        "active_users": User.query.filter_by(is_active=True).count(),
        "admins": User.query.filter_by(is_admin=True).count(),
        "checks": db.session.query(func.count(Analysis.id)).scalar() or 0,
        "avg_length": round(
            float(db.session.query(func.avg(Analysis.length)).scalar() or 0), 1),
        "avg_entropy": round(
            float(db.session.query(func.avg(Analysis.entropy_bits)).scalar() or 0),
            1),
    }


def build_dashboard(user=None):
    """Everything the dashboard template needs, in one call."""
    weaknesses, weakness_total = top_weaknesses(user)
    return {
        "headline": headline(user),
        "distribution": score_distribution(user),
        "daily": daily_counts(user, 14),
        "weaknesses": weaknesses,
        "weakness_total": weakness_total,
        "lengths": length_profile(user),
        "verdicts": verdict_breakdown(user),
        "recent": recent(user),
    }
