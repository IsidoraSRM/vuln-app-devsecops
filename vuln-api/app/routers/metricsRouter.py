import logging
import math
from datetime import datetime, timezone
from statistics import mean, median
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy.sql import func, text

from ..db import get_db
from ..models import User, WazuhVulnerability, VulnerabilityHistory
from ..services.authService import get_current_user

log = logging.getLogger(__name__)

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


# Objetivo de remediacion (dias) por severidad para el cumplimiento de SLA. Ajustable.
SLA_TARGETS_DAYS = {"CRITICAL": 15, "HIGH": 30, "MEDIUM": 60, "LOW": 90}
SLA_DEFAULT_DAYS = 90  # objetivo para severidades no listadas / UNKNOWN


def _sla_from_day_lists(by_sev_days):
    """Cumplimiento de SLA a partir de {SEV: [dias_dwell, ...]}: % remediadas dentro del objetivo."""
    by_severity = {}
    total = within = 0
    for sev, days in by_sev_days.items():
        target = SLA_TARGETS_DAYS.get(sev, SLA_DEFAULT_DAYS)
        w = sum(1 for d in days if d <= target)
        t = len(days)
        by_severity[sev] = {"within": w, "total": t, "target_days": target,
                            "pct": round(100.0 * w / t, 1) if t else None}
        total += t
        within += w
    return {
        "targets": SLA_TARGETS_DAYS,
        "overall": {"within": within, "total": total,
                    "pct": round(100.0 * within / total, 1) if total else None},
        "by_severity": dict(sorted(by_severity.items())),
    }


def _active_exposure_python(db, connection_id):
    """Exposicion EN CURSO (fallback SQLite/Python): antiguedad de las vulns ACTIVE = hoy - first_seen."""
    q = db.query(WazuhVulnerability.severity, WazuhVulnerability.first_seen).filter(
        WazuhVulnerability.status == "ACTIVE", WazuhVulnerability.first_seen.isnot(None))
    if connection_id:
        q = q.filter(WazuhVulnerability.connection_id == connection_id)
    now = datetime.now(timezone.utc)
    ages = []
    by_sev = {}
    for sev, fs in q.all():
        age = _to_days(fs, now)
        ages.append(age)
        by_sev.setdefault((sev or "UNKNOWN").upper(), []).append(age)
    s = _stats(ages)
    overall = {"count": s["count"], "avg_days": s["avg_days"], "median_days": s["median_days"],
               "p90_days": s["p90_days"], "max_days": s["max_days"],
               "over_30": sum(1 for a in ages if a > 30), "over_90": sum(1 for a in ages if a > 90)}
    by_severity = {}
    for sev, vals in sorted(by_sev.items()):
        ss = _stats(vals)
        by_severity[sev] = {"count": ss["count"], "median_days": ss["median_days"], "max_days": ss["max_days"]}
    return {"overall": overall, "by_severity": by_severity}


def _active_exposure_sql(db, connection_id):
    """Exposicion EN CURSO (Postgres nativo): antiguedad de las vulns ACTIVE, sin traer filas a Python."""
    cf = "AND connection_id = :cid" if connection_id else ""
    params = {"cid": connection_id} if connection_id else {}
    age = "GREATEST(EXTRACT(EPOCH FROM (now() - first_seen)) / 86400.0, 0)::double precision"
    sql = f"""
        WITH act AS MATERIALIZED (
            SELECT {age} AS age, COALESCE(UPPER(severity), 'UNKNOWN') AS sev
            FROM wazuh_vulnerabilities
            WHERE status = 'ACTIVE' AND first_seen IS NOT NULL {cf}
        )
        SELECT 'overall' AS kind, NULL::text AS grp, count(*), avg(age),
               percentile_cont(0.5) WITHIN GROUP (ORDER BY age),
               percentile_disc(0.9) WITHIN GROUP (ORDER BY age), max(age),
               count(*) FILTER (WHERE age > 30)::double precision,
               count(*) FILTER (WHERE age > 90)::double precision
        FROM act
        UNION ALL
        SELECT 'sev', sev, count(*), avg(age),
               percentile_cont(0.5) WITHIN GROUP (ORDER BY age),
               percentile_disc(0.9) WITHIN GROUP (ORDER BY age), max(age),
               NULL::double precision, NULL::double precision
        FROM act GROUP BY sev
    """
    rows = db.execute(text(sql), params).fetchall()
    overall = {"count": 0, "avg_days": None, "median_days": None, "p90_days": None,
               "max_days": None, "over_30": 0, "over_90": 0}
    by_sev = {}
    for r in rows:
        kind, grp, cnt = r[0], r[1], r[2]
        if kind == "overall" and cnt:
            overall = {"count": int(cnt), "avg_days": round(float(r[3]), 2), "median_days": round(float(r[4]), 2),
                       "p90_days": round(float(r[5]), 2), "max_days": round(float(r[6]), 2),
                       "over_30": int(r[7]), "over_90": int(r[8])}
        elif kind == "sev" and cnt:
            by_sev[grp] = {"count": int(cnt), "median_days": round(float(r[4]), 2), "max_days": round(float(r[6]), 2)}
    return {"overall": overall, "by_severity": dict(sorted(by_sev.items()))}


def _dwell_time_sql(db: Session, connection_id):
    """Dwell-time calculado 100% en PostgreSQL con agregados nativos (avg, mediana, p90, min, max),
    sin traer las filas a Python -> evita OOM y el sort en Python a gran escala. Da los MISMOS numeros
    que el fallback Python: mediana con percentile_cont(0.5) (== statistics.median, interpola en n par)
    y p90 con percentile_disc(0.9) (== nearest-rank del Python: ceil(0.9*n)-1). Ver get_dwell_time.

    Rendimiento: el set base (un dwell por vuln RESUELTA) se calcula UNA sola vez con un CTE
    MATERIALIZED y se agrega de 3 formas (global / por severidad / por mes) sobre ese set chico, en
    vez de re-escanear el hypertable vulnerability_history 3 veces. Medido a 100k resueltas: ~570ms
    (3 escaneos) -> ~200ms (1 escaneo)."""
    cf = "AND v.connection_id = :cid" if connection_id else ""
    params = {"cid": connection_id} if connection_id else {}
    d = "GREATEST(EXTRACT(EPOCH FROM (h.resolved_at - v.first_seen)) / 86400.0, 0)"
    # aggs opera sobre la columna `d` del CTE base (no sobre la expresion cruda)
    aggs = ("count(*), avg(d), percentile_cont(0.5) WITHIN GROUP (ORDER BY d), "
            "percentile_disc(0.9) WITHIN GROUP (ORDER BY d), min(d), max(d)")
    sla_case = ("CASE sev " + " ".join(f"WHEN '{s}' THEN {t}" for s, t in SLA_TARGETS_DAYS.items())
                + f" ELSE {SLA_DEFAULT_DAYS} END")
    sql = f"""
        WITH base AS MATERIALIZED (
            SELECT ({d})::double precision AS d,
                   COALESCE(UPPER(v.severity), 'UNKNOWN') AS sev,
                   to_char(h.resolved_at, 'YYYY-MM') AS mon
            FROM wazuh_vulnerabilities v
            JOIN (SELECT vulnerability_id, MAX(timestamp) AS resolved_at
                  FROM vulnerability_history WHERE action = 'RESOLVED'
                  GROUP BY vulnerability_id) h ON h.vulnerability_id = v.id
            WHERE v.status = 'RESOLVED' AND v.first_seen IS NOT NULL {cf}
        )
        SELECT 'overall' AS kind, NULL::text AS grp, {aggs} FROM base
        UNION ALL
        SELECT 'sev', sev, {aggs} FROM base GROUP BY sev
        UNION ALL
        SELECT 'month', mon, count(*), avg(d),
               NULL::double precision, NULL::double precision,
               NULL::double precision, NULL::double precision
        FROM base GROUP BY mon
        UNION ALL
        SELECT 'sla', sev, count(*),
               count(*) FILTER (WHERE d <= {sla_case})::double precision,
               NULL::double precision, NULL::double precision,
               NULL::double precision, NULL::double precision
        FROM base GROUP BY sev
    """
    rows = db.execute(text(sql), params).fetchall()

    def to_stats(cnt, av, med, p90, mn, mx):
        if not cnt:
            return {"count": 0, "avg_days": None, "median_days": None,
                    "p90_days": None, "min_days": None, "max_days": None}
        return {"count": int(cnt), "avg_days": round(float(av), 2),
                "median_days": round(float(med), 2), "p90_days": round(float(p90), 2),
                "min_days": round(float(mn), 2), "max_days": round(float(mx), 2)}

    overall = to_stats(0, None, None, None, None, None)
    by_severity = {}
    monthly = []
    sla_by_sev = {}
    sla_total = sla_within = 0
    for r in rows:
        kind, grp = r[0], r[1]
        if kind == "overall":
            overall = to_stats(r[2], r[3], r[4], r[5], r[6], r[7])
        elif kind == "sev":
            by_severity[grp] = to_stats(r[2], r[3], r[4], r[5], r[6], r[7])
        elif kind == "month" and r[2]:
            monthly.append({"month": grp, "resolved_count": int(r[2]), "avg_days": round(float(r[3]), 2)})
        elif kind == "sla":
            total_c, within_c = int(r[2]), int(r[3])
            sla_by_sev[grp] = {"within": within_c, "total": total_c,
                               "target_days": SLA_TARGETS_DAYS.get(grp, SLA_DEFAULT_DAYS),
                               "pct": round(100.0 * within_c / total_c, 1) if total_c else None}
            sla_total += total_c
            sla_within += within_c

    return {
        "metric": "dwell_time", "unit": "days", "connection_id": connection_id,
        "overall": overall,
        "by_severity": dict(sorted(by_severity.items())),
        "monthly_trend": sorted(monthly, key=lambda x: x["month"]),
        "sla": {
            "targets": SLA_TARGETS_DAYS,
            "overall": {"within": sla_within, "total": sla_total,
                        "pct": round(100.0 * sla_within / sla_total, 1) if sla_total else None},
            "by_severity": dict(sorted(sla_by_sev.items())),
        },
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
    # Operadores solo ven su conexion asignada (misma regla que /metrics/summary y /filters).
    if current_user.role != "superadmin":
        connection_id = current_user.assigned_connection_id or -1

    # Ruta rapida: agregados con SQL nativo (percentile_cont/percentile_disc), sin traer filas a Python.
    # El fallback de abajo (Python + statistics) queda para SQLite (tests) o si el SQL fallara.
    from ..models import IS_SQLITE
    if not IS_SQLITE:
        try:
            result = _dwell_time_sql(db, connection_id)
            result["active_exposure"] = _active_exposure_sql(db, connection_id)
            return result
        except Exception as e:
            # Si el SQL nativo falla NO debe pasar en silencio (asi no se esconde un bug como el
            # binding `::`): logueamos y recien ahi caemos al calculo en Python.
            log.warning("dwell_time_sql_failed_using_python_fallback", extra={"error": str(e)})
            db.rollback()

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
        "sla": _sla_from_day_lists(by_severity),
        "active_exposure": _active_exposure_python(db, connection_id),
    }
