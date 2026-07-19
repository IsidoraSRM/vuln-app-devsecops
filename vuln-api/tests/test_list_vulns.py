"""Tests de GET /vulns: filtros combinables, rangos de score y ordenamiento."""
from app.models import User, WazuhConnection, WazuhVulnerability
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
        ("CVE-2026-0001", "host-a", "openssl", "Critical", 9.8),
        ("CVE-2026-0002", "host-a", "curl", "High", 7.5),
        ("CVE-2026-0003", "host-b", "bash", "Low", 3.1),
    ]
    for cve, agent, pkg, sev, score in rows:
        db.add(WazuhVulnerability(
            connection_id=conn.id, status="ACTIVE", agent_id="001",
            agent_name=agent, package_name=pkg, package_version="1.0",
            cve_id=cve, severity=sev, score_base=score,
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
    headers = _get_headers(client)

    res = client.get("/vulns?limit=2&page=1", headers=headers)
    body = res.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2
    assert body["page"] == 1
    assert body["limit"] == 2

    res = client.get("/vulns?limit=2&page=2", headers=headers)
    assert len(res.json()["items"]) == 1
