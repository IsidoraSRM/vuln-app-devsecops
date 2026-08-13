"""Tests de GET /vulns: filtros combinables, rangos de score y ordenamiento."""
from datetime import datetime

import pytest
from sqlalchemy import text

from app.models import IS_SQLITE, User, WazuhConnection, WazuhVulnerability
from app.services.authService import hash_password
from app.crypto import encrypt

# helpers


def _create_user(db, username="admin", password="admin"):
    user = User(username=username, password_hash=hash_password(password), is_active=True)
    db.add(user)
    db.commit()
    return user


def _get_headers(client, username="admin", password="admin"):
    res = client.post("/auth/login", data={"username": username, "password": password})
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _seed(db):
    conn = WazuhConnection(
        name="test-conn", indexer_url="https://wazuh.local:9200",
        wazuh_user="admin", wazuh_password=encrypt("secret"), is_active=True,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    rows = [
        ("CVE-2026-0001", "host-a", "openssl", "Critical", 9.8, "ubuntu"),
        ("CVE-2026-0002", "host-a", "curl", "High", 7.5, "ubuntu"),
        ("CVE-2026-0003", "host-b", "bash", "Low", 3.1, "windows"),
    ]
    for cve, agent, pkg, sev, score, platform in rows:
        db.add(WazuhVulnerability(
            connection_id=conn.id, status="ACTIVE", agent_id="001",
            agent_name=agent, package_name=pkg, package_version="1.0",
            cve_id=cve, severity=sev, score_base=score, os_platform=platform,
        ))
    db.commit()
    return conn


def _cves(res):
    return [v["cve_id"] for v in res.json()["items"]]


# tests


def test_filter_by_connection_and_agent(client, db_session):
    _create_user(db_session)
    conn = _seed(db_session)
    headers = _get_headers(client)

    res = client.get(f"/vulns?connection_id={conn.id}&agent_name=host-a", headers=headers)
    assert res.status_code == 200
    assert sorted(_cves(res)) == ["CVE-2026-0001", "CVE-2026-0002"]


def test_filter_by_cve_and_package(client, db_session):
    _create_user(db_session)
    _seed(db_session)
    headers = _get_headers(client)

    res = client.get("/vulns?cve_id=CVE-2026-0003", headers=headers)
    assert _cves(res) == ["CVE-2026-0003"]

    res = client.get("/vulns?package_name=curl", headers=headers)
    assert _cves(res) == ["CVE-2026-0002"]


def test_filter_by_severity_is_case_insensitive(client, db_session):
    _create_user(db_session)
    _seed(db_session)
    headers = _get_headers(client)

    res = client.get("/vulns?severity=critical", headers=headers)
    assert _cves(res) == ["CVE-2026-0001"]


def test_filter_by_score_range(client, db_session):
    _create_user(db_session)
    _seed(db_session)
    headers = _get_headers(client)

    res = client.get("/vulns?score_min=5&score_max=8", headers=headers)
    assert _cves(res) == ["CVE-2026-0002"]


def test_sort_by_score_asc_and_desc(client, db_session):
    _create_user(db_session)
    _seed(db_session)
    headers = _get_headers(client)

    res = client.get("/vulns?sort_key=score_base&sort_order=asc", headers=headers)
    assert _cves(res) == ["CVE-2026-0003", "CVE-2026-0002", "CVE-2026-0001"]

    res = client.get("/vulns?sort_key=score_base&sort_order=desc", headers=headers)
    assert _cves(res) == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]


def test_pagination_totals(client, db_session):
    _create_user(db_session)
    _seed(db_session)
    # /vulns saca el total de mv_vuln_counts cuando no hay filtros avanzados; refrescarla tras el
    # seed para que refleje los datos (en SQLite la fn no existe -> el endpoint usa el conteo en vivo).
    try:
        db_session.execute(text("SELECT refresh_vulnerability_filters();"))
        db_session.commit()
    except Exception:
        db_session.rollback()
    headers = _get_headers(client)

    res = client.get("/vulns?limit=2&page=1", headers=headers)
    body = res.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2
    assert body["page"] == 1
    assert body["limit"] == 2

    res = client.get("/vulns?limit=2&page=2", headers=headers)
    assert len(res.json()["items"]) == 1


def test_filter_by_os_platform(client, db_session):
    _create_user(db_session)
    _seed(db_session)
    headers = _get_headers(client)

    # 1. Filtro simple por una sola plataforma (ubuntu)
    res = client.get("/vulns?os_platform=ubuntu", headers=headers)
    assert res.status_code == 200
    assert sorted(_cves(res)) == ["CVE-2026-0001", "CVE-2026-0002"]

    # 2. Filtro simple por windows
    res = client.get("/vulns?os_platform=windows", headers=headers)
    assert res.status_code == 200
    assert _cves(res) == ["CVE-2026-0003"]

    # 3. Filtro compuesto por múltiples plataformas (ubuntu y windows)
    res = client.get("/vulns?os_platform=ubuntu&os_platform=windows", headers=headers)
    assert res.status_code == 200
    assert sorted(_cves(res)) == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]


def test_totals_via_mv_and_fallback(client, db_session):
    """El total es correcto por AMBOS caminos: la MV mv_vuln_counts (filtro comun = severidad) y el
    conteo en vivo (filtro avanzado = os_platform, que la MV no cubre -> fallback)."""
    _create_user(db_session)
    _seed(db_session)
    try:
        db_session.execute(text("SELECT refresh_vulnerability_filters();"))
        db_session.commit()
    except Exception:
        db_session.rollback()
    headers = _get_headers(client)

    # filtro comun (severidad) -> total via mv_vuln_counts
    res = client.get("/vulns?severity=Critical", headers=headers)
    assert res.json()["total"] == 1
    # filtro avanzado (os_platform) -> total via conteo en vivo (fallback)
    res = client.get("/vulns?os_platform=ubuntu", headers=headers)
    assert res.json()["total"] == 2


def test_mv_count_query_binds_and_counts(db_session):
    """Regresion del binding: `:param::text[]` NO se parsea como bindparam en SQLAlchemy (el `::`
    se come el nombre del parametro) -> list_vulns caia SIEMPRE al conteo lento silenciosamente.
    Corre la MISMA query de la MV (con CAST) y confirma que bindea sin error y cuenta bien."""
    if IS_SQLITE:
        pytest.skip("mv_vuln_counts solo existe en Postgres")
    _create_user(db_session)
    _seed(db_session)
    db_session.execute(text("SELECT refresh_vulnerability_filters();"))
    db_session.commit()
    total = db_session.execute(text("""
        SELECT COALESCE(SUM(n), 0) FROM mv_vuln_counts
        WHERE (:conn IS NULL OR connection_id = :conn)
          AND (:status_u IS NULL OR status = :status_u)
          AND (CAST(:sevs AS text[]) IS NULL OR severity = ANY(CAST(:sevs AS text[])))
    """).bindparams(conn=None, status_u="ACTIVE", sevs=["CRITICAL"])).scalar()
    assert int(total) == 1  # 1 Critical ACTIVE en el seed


def test_date_range_filters_apply_in_both_paths(client, db_session):
    """Regresion #1: detected_before se IGNORABA en el camino del stored procedure (produccion),
    porque el SP solo tenia days_ago. El fallback (SQLite) si lo aplicaba -> el bug se escondia
    (test verde por el resultado del fallback, no por el camino real). Ahora las fechas se aplican
    como filtro ORM en AMBOS caminos. En Postgres este test ejerce el camino SP (el que estaba roto)."""
    _create_user(db_session)
    conn = WazuhConnection(
        name="dates-conn", indexer_url="https://wazuh.local:9200",
        wazuh_user="admin", wazuh_password=encrypt("secret"), is_active=True,
    )
    db_session.add(conn)
    db_session.commit()
    db_session.refresh(conn)
    for cve, fs in [("CVE-OLD", datetime(2020, 1, 1)), ("CVE-NEW", datetime(2026, 1, 1))]:
        db_session.add(WazuhVulnerability(
            connection_id=conn.id, status="ACTIVE", agent_id="001", agent_name="h",
            package_name="pkg", package_version="1.0", cve_id=cve, severity="High",
            score_base=7.5, os_platform="ubuntu", first_seen=fs,
        ))
    db_session.commit()
    headers = _get_headers(client)

    # detected_before=2023 -> SOLO CVE-OLD (2020). CVE-NEW (2026) debe quedar FUERA.
    res = client.get("/vulns?detected_before=2023-01-01T00:00:00", headers=headers)
    cves = _cves(res)
    assert "CVE-OLD" in cves
    assert "CVE-NEW" not in cves  # <- fallaba en el camino SP (Postgres) antes del fix

    # detected_after=2025 -> SOLO CVE-NEW (2026).
    res = client.get("/vulns?detected_after=2025-01-01T00:00:00", headers=headers)
    assert _cves(res) == ["CVE-NEW"]
