from datetime import datetime, timedelta

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
