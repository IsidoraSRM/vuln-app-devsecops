from datetime import datetime, timedelta

from sqlalchemy import text

from app.models import User, WazuhConnection, WazuhVulnerability, VulnerabilityHistory
from app.services.authService import hash_password
from app.crypto import encrypt

# helpers


def _create_user(db, username="admin", password="admin", is_active=True):
    user = User(username=username, password_hash=hash_password(password), is_active=is_active)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _get_headers(client, username="admin", password="admin"):
    res = client.post("/auth/login", data={"username": username, "password": password})
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _create_connection(db, name="test-conn", is_active=True):
    conn = WazuhConnection(
        name=name,
        indexer_url="https://wazuh.local:9200",
        wazuh_user="admin",
        wazuh_password=encrypt("secret"),
        is_active=is_active,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return conn


BASE = datetime(2026, 5, 1, 12, 0, 0)


def _create_vuln(db, conn_id, cve, severity="High", status="RESOLVED",
                 first_seen=BASE, resolved_at=None):
    vuln = WazuhVulnerability(
        connection_id=conn_id,
        status=status,
        agent_id="001",
        agent_name="host-1",
        package_name="curl",
        package_version="7.81",
        cve_id=cve,
        severity=severity,
        first_seen=first_seen,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    if resolved_at is not None:
        db.add(VulnerabilityHistory(
            vulnerability_id=vuln.id,
            action="RESOLVED",
            details="test",
            timestamp=resolved_at,
        ))
        db.commit()
    return vuln


# tests


def test_dwell_time_requires_auth(client):
    res = client.get("/vulns/metrics/dwell-time")
    assert res.status_code == 401


def test_dwell_time_empty(client, db_session):
    _create_user(db_session)
    headers = _get_headers(client)
    res = client.get("/vulns/metrics/dwell-time", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert body["metric"] == "dwell_time"
    assert body["unit"] == "days"
    assert body["overall"]["count"] == 0
    assert body["overall"]["avg_days"] is None
    assert body["by_severity"] == {}
    assert body["monthly_trend"] == []


def test_dwell_time_aggregates(client, db_session):
    _create_user(db_session)
    conn = _create_connection(db_session)
    # Resuelta a los 10 días y a los 20 días
    _create_vuln(db_session, conn.id, "CVE-2026-0001", severity="High",
                 resolved_at=BASE + timedelta(days=10))
    _create_vuln(db_session, conn.id, "CVE-2026-0002", severity="Critical",
                 resolved_at=BASE + timedelta(days=20))
    headers = _get_headers(client)

    res = client.get("/vulns/metrics/dwell-time", headers=headers)
    assert res.status_code == 200
    body = res.json()

    overall = body["overall"]
    assert overall["count"] == 2
    assert overall["avg_days"] == 15.0
    assert overall["median_days"] == 15.0
    assert overall["min_days"] == 10.0
    assert overall["max_days"] == 20.0
    assert overall["p90_days"] == 20.0

    assert body["by_severity"]["HIGH"]["count"] == 1
    assert body["by_severity"]["HIGH"]["avg_days"] == 10.0
    assert body["by_severity"]["CRITICAL"]["avg_days"] == 20.0

    assert body["monthly_trend"] == [
        {"month": "2026-05", "resolved_count": 2, "avg_days": 15.0},
    ]


def test_dwell_time_excludes_active_and_reopened(client, db_session):
    _create_user(db_session)
    conn = _create_connection(db_session)
    # ACTIVE sin evento RESOLVED: no cuenta
    _create_vuln(db_session, conn.id, "CVE-2026-0003", status="ACTIVE")
    # Reabierta: tiene un RESOLVED viejo pero su estado volvió a ACTIVE
    _create_vuln(db_session, conn.id, "CVE-2026-0004", status="ACTIVE",
                 resolved_at=BASE + timedelta(days=5))
    headers = _get_headers(client)

    res = client.get("/vulns/metrics/dwell-time", headers=headers)
    assert res.status_code == 200
    assert res.json()["overall"]["count"] == 0


def test_dwell_time_filters_by_connection(client, db_session):
    _create_user(db_session)
    conn_a = _create_connection(db_session, name="conn-a")
    conn_b = _create_connection(db_session, name="conn-b")
    _create_vuln(db_session, conn_a.id, "CVE-2026-0005",
                 resolved_at=BASE + timedelta(days=4))
    _create_vuln(db_session, conn_b.id, "CVE-2026-0006",
                 resolved_at=BASE + timedelta(days=8))
    headers = _get_headers(client)

    res = client.get(f"/vulns/metrics/dwell-time?connection_id={conn_a.id}", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert body["connection_id"] == conn_a.id
    assert body["overall"]["count"] == 1
    assert body["overall"]["avg_days"] == 4.0


def test_dwell_time_multiple_resolved_uses_latest(client, db_session):
    """Si una vulnerabilidad fue resuelta, reabierta y resuelta de nuevo,
    el dwell time se mide hasta el último RESOLVED."""
    _create_user(db_session)
    conn = _create_connection(db_session)
    vuln = _create_vuln(db_session, conn.id, "CVE-2026-0007",
                        resolved_at=BASE + timedelta(days=3))
    db_session.add(VulnerabilityHistory(
        vulnerability_id=vuln.id,
        action="RESOLVED",
        details="segunda resolución",
        timestamp=BASE + timedelta(days=9),
    ))
    db_session.commit()
    headers = _get_headers(client)

    res = client.get("/vulns/metrics/dwell-time", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert body["overall"]["count"] == 1
    assert body["overall"]["avg_days"] == 9.0


def test_metrics_summary(client, db_session):
    """Cubre GET /vulns/metrics/summary en sus DOS rutas: lectura de la vista
    materializada mv_metrics_summary (Postgres/CI) y el fallback en vivo (SQLite/local)."""
    _create_user(db_session)
    conn = _create_connection(db_session)
    # 2 CVEs distintas ACTIVE: una Critical y una High
    _create_vuln(db_session, conn.id, "CVE-2026-1001", severity="Critical", status="ACTIVE")
    _create_vuln(db_session, conn.id, "CVE-2026-1002", severity="High", status="ACTIVE")
    # En Postgres refrescamos la MV para que refleje los datos recien insertados. En SQLite
    # la funcion no existe (falla -> rollback) y el endpoint usa el calculo en vivo (fallback).
    try:
        db_session.execute(text("SELECT refresh_vulnerability_filters();"))
        db_session.commit()
    except Exception:
        db_session.rollback()
    headers = _get_headers(client)

    res = client.get("/vulns/metrics/summary", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 2
    assert body["critical"] == 1
    assert body["high"] == 1
    assert body["medium"] == 0
    assert body["low"] == 0


def test_metrics_summary_by_connection(client, db_session):
    """El resumen se puede filtrar por conexion. Una conexion con datos devuelve sus
    conteos; una conexion sin vulnerabilidades ACTIVE devuelve ceros (fila inexistente
    en la MV -> row None). Cubre la ruta connection_id-especifica y el retorno de ceros."""
    _create_user(db_session)
    conn_a = _create_connection(db_session, name="conn-a")
    conn_b = _create_connection(db_session, name="conn-b")
    _create_vuln(db_session, conn_a.id, "CVE-2026-2001", severity="Critical", status="ACTIVE")
    try:
        db_session.execute(text("SELECT refresh_vulnerability_filters();"))
        db_session.commit()
    except Exception:
        db_session.rollback()
    headers = _get_headers(client)

    # conn_a: tiene 1 CVE Critical activa
    res_a = client.get(f"/vulns/metrics/summary?connection_id={conn_a.id}", headers=headers)
    assert res_a.status_code == 200
    assert res_a.json()["total"] == 1
    assert res_a.json()["critical"] == 1

    # conn_b: sin vulnerabilidades activas -> todo en cero
    res_b = client.get(f"/vulns/metrics/summary?connection_id={conn_b.id}", headers=headers)
    assert res_b.status_code == 200
    assert res_b.json()["total"] == 0
    assert res_b.json()["critical"] == 0


def test_dwell_time_sla_and_active_exposure(client, db_session):
    """Cubre las secciones nuevas: cumplimiento de SLA + exposicion en curso (activas)."""
    _create_user(db_session)
    conn = _create_connection(db_session)
    # 2 criticas resueltas: una en 5d (dentro del SLA de 15d) y otra en 40d (fuera)
    _create_vuln(db_session, conn.id, "CVE-2026-4001", severity="Critical",
                 resolved_at=BASE + timedelta(days=5))
    _create_vuln(db_session, conn.id, "CVE-2026-4002", severity="Critical",
                 resolved_at=BASE + timedelta(days=40))
    # 1 ACTIVE (para exposicion en curso)
    _create_vuln(db_session, conn.id, "CVE-2026-4003", severity="High", status="ACTIVE",
                 first_seen=BASE)
    headers = _get_headers(client)

    body = client.get("/vulns/metrics/dwell-time", headers=headers).json()
    # SLA critica: 1 de 2 dentro del objetivo -> 50%
    assert body["sla"]["by_severity"]["CRITICAL"]["total"] == 2
    assert body["sla"]["by_severity"]["CRITICAL"]["within"] == 1
    assert body["sla"]["by_severity"]["CRITICAL"]["pct"] == 50.0
    assert body["sla"]["overall"]["pct"] == 50.0
    # Exposicion en curso: 1 activa (first_seen en mayo -> >90 dias expuesta a la fecha)
    assert body["active_exposure"]["overall"]["count"] == 1
    assert body["active_exposure"]["overall"]["max_days"] is not None
    assert body["active_exposure"]["overall"]["over_90"] == 1


def test_dwell_time_cache(client, db_session):
    """La 2a llamada devuelve el resultado cacheado (no recalcula). Se agrega otra resuelta entre
    llamadas: sin cache el total seria 2, pero el cache devuelve el valor previo (1)."""
    _create_user(db_session)
    conn = _create_connection(db_session)
    _create_vuln(db_session, conn.id, "CVE-CACHE-1", resolved_at=BASE + timedelta(days=4))
    headers = _get_headers(client)

    first = client.get("/vulns/metrics/dwell-time", headers=headers).json()
    assert first["overall"]["count"] == 1

    _create_vuln(db_session, conn.id, "CVE-CACHE-2", resolved_at=BASE + timedelta(days=6))
    second = client.get("/vulns/metrics/dwell-time", headers=headers).json()
    assert second["overall"]["count"] == 1  # cacheado: no recalculo pese al dato nuevo


def test_dwell_time_python_fallback(client, db_session, monkeypatch):
    """Fuerza el fallback Python (aunque el DB sea Postgres) para cubrir _sla_from_day_lists y
    _active_exposure_python: si _dwell_time_sql falla, get_dwell_time calcula todo en Python."""
    from app.routers import metricsRouter

    def _raise(*args, **kwargs):
        raise RuntimeError("forzar fallback")
    monkeypatch.setattr(metricsRouter, "_dwell_time_sql", _raise)

    _create_user(db_session)
    conn = _create_connection(db_session)
    _create_vuln(db_session, conn.id, "CVE-2026-5001", severity="High",
                 resolved_at=BASE + timedelta(days=10))
    _create_vuln(db_session, conn.id, "CVE-2026-5002", severity="Critical", status="ACTIVE",
                 first_seen=BASE)
    headers = _get_headers(client)

    body = client.get("/vulns/metrics/dwell-time", headers=headers).json()
    assert body["overall"]["count"] == 1
    # High resuelta en 10d cumple el SLA (<=30d)
    assert body["sla"]["overall"]["within"] == 1
    assert body["sla"]["by_severity"]["HIGH"]["pct"] == 100.0
    # 1 activa en exposicion en curso
    assert body["active_exposure"]["overall"]["count"] == 1
