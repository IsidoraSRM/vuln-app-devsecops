"""Tests del ciclo de vida de vulnerabilidades en el sync (camino en memoria/ORM):
DETECTED -> actualización -> SEVERITY_CHANGED -> RESOLVED -> REOPENED."""
from datetime import datetime, timedelta

from app.models import WazuhConnection, WazuhVulnerability, VulnerabilityHistory
from app.services.wazuhService import _process_sqlite, _mark_obsolete_sqlite
from app.crypto import encrypt

# helpers


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


def _raw(cve="CVE-2026-1000", severity="High", agent_id="001", pkg="curl"):
    return {
        "agent": {"id": agent_id, "name": "host-1"},
        "host": {"os": {"full": "Ubuntu 22.04", "platform": "ubuntu", "version": "22.04"}},
        "package": {"name": pkg, "version": "1.0", "type": "deb", "architecture": "amd64"},
        "vulnerability": {
            "id": cve, "severity": severity,
            "score": {"base": 7.5, "version": "3.1"},
            "detected_at": None, "published_at": None,
            "description": "desc", "reference": "https://ref",
            "scanner": {"vendor": "wazuh"},
        },
    }


def _history_actions(db, vuln_id):
    rows = db.query(VulnerabilityHistory).filter_by(vulnerability_id=vuln_id).all()
    return [h.action for h in rows]


# tests


def test_process_creates_vuln_with_detected_history(db_session):
    conn = _create_connection(db_session)

    count = _process_sqlite(db_session, conn.id, [_raw()])
    db_session.commit()

    assert count == 1
    vuln = db_session.query(WazuhVulnerability).one()
    assert vuln.status == "ACTIVE"
    assert vuln.cve_id == "CVE-2026-1000"
    assert vuln.agent_name == "host-1"
    assert "DETECTED" in _history_actions(db_session, vuln.id)


def test_process_ignores_entries_without_cve(db_session):
    conn = _create_connection(db_session)
    raw = _raw()
    raw["vulnerability"].pop("id")

    count = _process_sqlite(db_session, conn.id, [raw])
    db_session.commit()

    assert count == 0
    assert db_session.query(WazuhVulnerability).count() == 0


def test_process_deduplicates_within_batch(db_session):
    conn = _create_connection(db_session)

    count = _process_sqlite(db_session, conn.id, [_raw(), _raw()])
    db_session.commit()

    assert count == 1
    assert db_session.query(WazuhVulnerability).count() == 1


def test_process_registers_severity_change(db_session):
    conn = _create_connection(db_session)
    _process_sqlite(db_session, conn.id, [_raw(severity="High")])
    db_session.commit()

    _process_sqlite(db_session, conn.id, [_raw(severity="Critical")])
    db_session.commit()

    vuln = db_session.query(WazuhVulnerability).one()
    assert vuln.severity == "Critical"
    assert "SEVERITY_CHANGED" in _history_actions(db_session, vuln.id)


def test_mark_obsolete_resolves_stale_vulns(db_session):
    conn = _create_connection(db_session)
    _process_sqlite(db_session, conn.id, [_raw()])
    db_session.commit()
    vuln = db_session.query(WazuhVulnerability).one()
    # Simular que el ultimo sync la vio hace una semana
    vuln.last_seen = datetime.now() - timedelta(days=7)
    db_session.commit()

    _mark_obsolete_sqlite(db_session, conn.id, datetime.now())
    db_session.commit()

    vuln = db_session.query(WazuhVulnerability).one()
    assert vuln.status == "RESOLVED"
    assert "RESOLVED" in _history_actions(db_session, vuln.id)


def test_process_reopens_resolved_vuln(db_session):
    conn = _create_connection(db_session)
    _process_sqlite(db_session, conn.id, [_raw()])
    db_session.commit()
    vuln = db_session.query(WazuhVulnerability).one()
    vuln.status = "RESOLVED"
    db_session.commit()

    _process_sqlite(db_session, conn.id, [_raw()])
    db_session.commit()

    vuln = db_session.query(WazuhVulnerability).one()
    assert vuln.status == "ACTIVE"
    assert "REOPENED" in _history_actions(db_session, vuln.id)


def test_full_lifecycle_detected_resolved_reopened(db_session):
    """Ciclo completo: detectada -> desaparece (RESOLVED) -> reaparece (REOPENED)."""
    conn = _create_connection(db_session)

    _process_sqlite(db_session, conn.id, [_raw()])
    db_session.commit()
    vuln = db_session.query(WazuhVulnerability).one()
    vuln.last_seen = datetime.now() - timedelta(days=3)
    db_session.commit()

    _mark_obsolete_sqlite(db_session, conn.id, datetime.now())
    db_session.commit()
    assert db_session.query(WazuhVulnerability).one().status == "RESOLVED"

    _process_sqlite(db_session, conn.id, [_raw()])
    db_session.commit()

    vuln = db_session.query(WazuhVulnerability).one()
    assert vuln.status == "ACTIVE"
    actions = _history_actions(db_session, vuln.id)
    assert actions.count("DETECTED") == 1
    assert actions.count("RESOLVED") == 1
    assert actions.count("REOPENED") == 1
