import pytest
from app.models import User, WazuhConnection, WazuhVulnerability
from app.services.authService import hash_password
from app.crypto import encrypt

def _create_user(db, username, role="operator", assigned_connection_id=None, is_active=True):
    user = User(
        username=username, 
        password_hash=hash_password("password123"), 
        role=role, 
        assigned_connection_id=assigned_connection_id,
        is_active=is_active
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def _get_headers(client, username):
    res = client.post("/auth/login", data={"username": username, "password": "password123"})
    return {"Authorization": f"Bearer {res.json()['access_token']}"}

def _create_connection(db, name):
    conn = WazuhConnection(
        name=name,
        indexer_url="https://wazuh.local:9200",
        wazuh_user="admin",
        wazuh_password=encrypt("secret"),
        is_active=True
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return conn

def test_operator_forbidden_actions(client, db_session):
    # Setup
    conn = _create_connection(db_session, "conn-1")
    op = _create_user(db_session, "operator1", role="operator", assigned_connection_id=conn.id)
    headers = _get_headers(client, "operator1")
    
    # 1. Operators cannot create connections
    res = client.post("/wazuh-connections", json={
        "name": "conn-new",
        "indexer_url": "https://new.local",
        "wazuh_user": "u",
        "wazuh_password": "p"
    }, headers=headers)
    assert res.status_code == 403
    
    # 2. Operators cannot update connections
    res = client.put(f"/wazuh-connections/{conn.id}", json={
        "name": "conn-updated",
        "indexer_url": "https://new.local",
        "wazuh_user": "u",
        "wazuh_password": "p"
    }, headers=headers)
    assert res.status_code == 403
    
    # 3. Operators cannot delete connections
    res = client.delete(f"/wazuh-connections/{conn.id}", headers=headers)
    assert res.status_code == 403
    
    # 4. Operators cannot list users
    res = client.get("/users", headers=headers)
    assert res.status_code == 403
    
    # 5. Operators cannot create users
    res = client.post("/users", json={"username": "newuser", "password": "Password123!"}, headers=headers)
    assert res.status_code == 403

def test_operator_data_isolation(client, db_session):
    # Setup
    conn1 = _create_connection(db_session, "conn-1")
    conn2 = _create_connection(db_session, "conn-2")
    
    # Add vulnerabilities to conn1 and conn2
    v1 = WazuhVulnerability(
        connection_id=conn1.id, status="ACTIVE", agent_id="001", agent_name="agent-a",
        package_name="bash", package_version="1.0", cve_id="CVE-2026-0001", severity="High"
    )
    v2 = WazuhVulnerability(
        connection_id=conn2.id, status="ACTIVE", agent_id="002", agent_name="agent-b",
        package_name="openssl", package_version="2.0", cve_id="CVE-2026-0002", severity="Critical"
    )
    db_session.add_all([v1, v2])
    db_session.commit()
    
    # User assigned to conn1
    op1 = _create_user(db_session, "operator1", role="operator", assigned_connection_id=conn1.id)
    headers1 = _get_headers(client, "operator1")
    
    # User assigned to conn2
    op2 = _create_user(db_session, "operator2", role="operator", assigned_connection_id=conn2.id)
    headers2 = _get_headers(client, "operator2")
    
    # Operator 1 lists vulns: should only see CVE-2026-0001
    res1 = client.get("/vulns", headers=headers1)
    assert res1.status_code == 200
    items1 = res1.json()["items"]
    assert len(items1) == 1
    assert items1[0]["cve_id"] == "CVE-2026-0001"
    
    # Operator 2 lists vulns: should only see CVE-2026-0002
    res2 = client.get("/vulns", headers=headers2)
    assert res2.status_code == 200
    items2 = res2.json()["items"]
    assert len(items2) == 1
    assert items2[0]["cve_id"] == "CVE-2026-0002"

def test_superadmin_full_access(client, db_session):
    # Setup
    conn = _create_connection(db_session, "conn-1")
    admin = _create_user(db_session, "superadmin1", role="superadmin")
    headers = _get_headers(client, "superadmin1")
    
    # Superadmin can list connections
    res = client.get("/wazuh-connections", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) == 1
    
    # Superadmin can list users
    res = client.get("/users", headers=headers)
    assert res.status_code == 200
    # Includes superadmin1 and admin (default created by startup)
    assert len(res.json()) >= 1
