from sqlalchemy import text

from app.db import DATABASE_URL
from app.models import WazuhConnection, WazuhVulnerability
from app.crypto import encrypt

IS_SQLITE = DATABASE_URL.startswith("sqlite") if DATABASE_URL else True

# helpers


def _refresh_views(db):
    """En PostgreSQL las vistas materializadas quedan desactualizadas tras insertar
    datos en los tests; hay que refrescarlas para que el plan A las vea.
    En SQLite la función no existe y el endpoint usa el fallback directo."""
    try:
        db.execute(text("SELECT refresh_vulnerability_filters();"))
        db.commit()
    except Exception:
        db.rollback()


def _create_connection(db, name="test-conn"):
    conn = WazuhConnection(
        name=name,
        indexer_url="https://wazuh.local:9200",
        wazuh_user="admin",
        wazuh_password=encrypt("secret"),
        is_active=True,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return conn


def _create_vuln(db, conn_id, cve, agent="host-1", severity="High",
                 os_platform="ubuntu", os_version="22.04"):
    vuln = WazuhVulnerability(
        connection_id=conn_id,
        status="ACTIVE",
        agent_id="001",
        agent_name=agent,
        os_platform=os_platform,
        os_version=os_version,
        package_name="curl",
        package_version="7.81",
        cve_id=cve,
        severity=severity,
    )
    db.add(vuln)
    db.commit()
    return vuln


# tests


def test_filters_json_structure(client, db_session):
    conn = _create_connection(db_session)
    _create_vuln(db_session, conn.id, "CVE-2026-0001", agent="host-ubuntu",
                 severity="High", os_platform="ubuntu", os_version="22.04")
    _create_vuln(db_session, conn.id, "CVE-2026-0002", agent="host-windows",
                 severity="Critical", os_platform="windows", os_version="10")
    _refresh_views(db_session)

    res = client.get("/vulns/filters")
    assert res.status_code == 200
    body = res.json()
    assert sorted(body.keys()) == ["agents", "cves", "os", "packages", "severities"]
    assert body["agents"] == ["host-ubuntu", "host-windows"]
    assert {"platform": "ubuntu", "version": "22.04"} in body["os"]
    assert {"platform": "windows", "version": "10"} in body["os"]


def test_filters_by_connection(client, db_session):
    conn_a = _create_connection(db_session, name="conn-a")
    conn_b = _create_connection(db_session, name="conn-b")
    _create_vuln(db_session, conn_a.id, "CVE-2026-0003", agent="host-a")
    _create_vuln(db_session, conn_b.id, "CVE-2026-0004", agent="host-b")
    _refresh_views(db_session)

    res = client.get(f"/vulns/filters?connection_id={conn_a.id}")
    assert res.status_code == 200
    assert res.json()["agents"] == ["host-a"]


def test_filters_rejects_sql_injection_in_connection_id(client):
    res = client.get("/vulns/filters?connection_id=1 OR 1=1")
    assert res.status_code == 422


def test_filters_fallback_rolls_back_failed_transaction(client, db_session, monkeypatch):
    """El plan A (vistas materializadas) falla en SQLite; el fallback debe hacer
    rollback antes de consultar directo, o en PostgreSQL la transacción queda
    abortada y el endpoint devolvería 500."""
    conn = _create_connection(db_session)
    _create_vuln(db_session, conn.id, "CVE-2026-0005")

    if not IS_SQLITE:
        # Forzar el fallo del plan A también en PostgreSQL eliminando una vista
        db_session.execute(text("DROP MATERIALIZED VIEW IF EXISTS mv_unique_agents CASCADE;"))
        db_session.commit()

    rollback_calls = []
    original_rollback = db_session.rollback

    def spy_rollback():
        rollback_calls.append(1)
        return original_rollback()

    monkeypatch.setattr(db_session, "rollback", spy_rollback)

    res = client.get("/vulns/filters")
    assert res.status_code == 200
    assert res.json()["agents"] == ["host-1"]
    assert rollback_calls, "el fallback debe ejecutar db.rollback() tras el fallo del plan A"

    if not IS_SQLITE:
        # Restaurar la vista para no afectar otros tests ni el teardown
        db_session.execute(text(
            "CREATE MATERIALIZED VIEW IF NOT EXISTS mv_unique_agents AS "
            "SELECT DISTINCT connection_id, agent_name FROM wazuh_vulnerabilities;"
        ))
        db_session.commit()
