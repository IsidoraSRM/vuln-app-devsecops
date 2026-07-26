import math
from datetime import datetime, timezone
from statistics import mean, median
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from ..db import get_db
from ..models import User, WazuhVulnerability, VulnerabilityHistory
from ..services.authService import get_current_user

# Prefijo /vulns/metrics: no puede ser /metrics porque app.mount("/metrics")
# (exposición Prometheus) captura cualquier ruta bajo /metrics/*.
router = APIRouter(prefix="/vulns/metrics", tags=["metrics"])


def _coerce_datetime(value):
    """SQLite puede devolver el timestamp del subquery como string ISO."""
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    return value


def _to_days(first_seen, resolved_at):
    first_seen = _coerce_datetime(first_seen)
    resolved_at = _coerce_datetime(resolved_at)
    # Normalizar naive vs aware (SQLite guarda naive, PostgreSQL aware)
    if first_seen.tzinfo is None and resolved_at.tzinfo is not None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    if resolved_at.tzinfo is None and first_seen.tzinfo is not None:
        resolved_at = resolved_at.replace(tzinfo=timezone.utc)
    seconds = (resolved_at - first_seen).total_seconds()
    return max(seconds, 0.0) / 86400.0


def _stats(days_values):
    if not days_values:
        return {
            "count": 0,
            "avg_days": None,
            "median_days": None,
            "p90_days": None,
            "min_days": None,
            "max_days": None,
        }
    ordered = sorted(days_values)
    p90_index = max(0, math.ceil(0.9 * len(ordered)) - 1)
    return {
        "count": len(ordered),
        "avg_days": round(mean(ordered), 2),
        "median_days": round(median(ordered), 2),
        "p90_days": round(ordered[p90_index], 2),
        "min_days": round(ordered[0], 2),
        "max_days": round(ordered[-1], 2),
    }


@router.get("/dwell-time")
def get_dwell_time(
    connection_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Dwell Time: días que una vulnerabilidad estuvo expuesta, desde first_seen
    hasta su último evento RESOLVED. Solo cuenta vulnerabilidades cuyo estado
    actual es RESOLVED (las reabiertas vuelven a ser ACTIVE y se excluyen).
    Devuelve agregados globales, por severidad y tendencia mensual para gráficos.
    """
    resolved_events = (
        db.query(
            VulnerabilityHistory.vulnerability_id.label("vuln_id"),
            func.max(VulnerabilityHistory.timestamp).label("resolved_at"),
        )
        .filter(VulnerabilityHistory.action == "RESOLVED")
        .group_by(VulnerabilityHistory.vulnerability_id)
        .subquery()
    )

    query = (
        db.query(
            WazuhVulnerability.severity,
            WazuhVulnerability.first_seen,
            resolved_events.c.resolved_at,
        )
        .join(resolved_events, resolved_events.c.vuln_id == WazuhVulnerability.id)
        .filter(WazuhVulnerability.status == "RESOLVED")
    )
    if connection_id:
        query = query.filter(WazuhVulnerability.connection_id == connection_id)

    all_days = []
    by_severity = {}
    by_month = {}
    for severity, first_seen, resolved_at in query.all():
        if first_seen is None or resolved_at is None:
            continue
        days = _to_days(first_seen, resolved_at)
        all_days.append(days)
        sev = (severity or "UNKNOWN").upper()
        by_severity.setdefault(sev, []).append(days)
        month = _coerce_datetime(resolved_at).strftime("%Y-%m")
        by_month.setdefault(month, []).append(days)

    return {
        "metric": "dwell_time",
        "unit": "days",
        "connection_id": connection_id,
        "overall": _stats(all_days),
        "by_severity": {sev: _stats(vals) for sev, vals in sorted(by_severity.items())},
        "monthly_trend": [
            {
                "month": month,
                "resolved_count": len(vals),
                "avg_days": round(mean(vals), 2),
            }
            for month, vals in sorted(by_month.items())
        ],
    }
