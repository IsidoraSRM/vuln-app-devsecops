"""Tests del ciclo de vida de vulnerabilidades en el sync (camino en memoria/ORM):
DETECTED -> actualización -> SEVERITY_CHANGED -> RESOLVED -> REOPENED."""
from datetime import datetime, timedelta, timezone

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

    count = _process_sqlite(db_session, conn.id, [_raw()], datetime.now(timezone.utc))
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

    count = _process_sqlite(db_session, conn.id, [raw], datetime.now(timezone.utc))
    db_session.commit()

    assert count == 0
    assert db_session.query(WazuhVulnerability).count() == 0


def test_process_deduplicates_within_batch(db_session):
    conn = _create_connection(db_session)

    count = _process_sqlite(db_session, conn.id, [_raw(), _raw()], datetime.now(timezone.utc))
    db_session.commit()

    assert count == 1
    assert db_session.query(WazuhVulnerability).count() == 1


def test_process_registers_severity_change(db_session):
    conn = _create_connection(db_session)
    _process_sqlite(db_session, conn.id, [_raw(severity="High")], datetime.now(timezone.utc))
    db_session.commit()

    _process_sqlite(db_session, conn.id, [_raw(severity="Critical")], datetime.now(timezone.utc))
    db_session.commit()

    vuln = db_session.query(WazuhVulnerability).one()
    assert vuln.severity == "Critical"
    assert "SEVERITY_CHANGED" in _history_actions(db_session, vuln.id)


def test_mark_obsolete_resolves_stale_vulns(db_session):
    """Una vuln que desaparece MIENTRAS el agente sigue reportando otras (sigue vivo) -> RESOLVED (parche)."""
    conn = _create_connection(db_session)
    # Dos vulns del MISMO agente (001): CVE-A desaparece, CVE-B se sigue viendo (agente presente).
    _process_sqlite(db_session, conn.id, [_raw(cve="CVE-A", pkg="curl"), _raw(cve="CVE-B", pkg="openssl")], datetime.now(timezone.utc))
    db_session.commit()
    now = datetime.now()
    va = db_session.query(WazuhVulnerability).filter_by(cve_id="CVE-A").one()
    vb = db_session.query(WazuhVulnerability).filter_by(cve_id="CVE-B").one()
    va.last_seen = now - timedelta(days=7)      # CVE-A ya no se reporta
    vb.last_seen = now + timedelta(minutes=1)   # CVE-B recien vista -> el agente sigue activo
    db_session.commit()

    _mark_obsolete_sqlite(db_session, conn.id, now)
    db_session.commit()

    va = db_session.query(WazuhVulnerability).filter_by(cve_id="CVE-A").one()
    assert va.status == "RESOLVED"
    assert "RESOLVED" in _history_actions(db_session, va.id)


def test_mark_obsolete_agent_removed(db_session):
    """Si un agente deja de reportar TODO (host dado de baja), sus vulns -> AGENT_REMOVED (no RESOLVED)."""
    conn = _create_connection(db_session)
    _process_sqlite(db_session, conn.id, [_raw(cve="CVE-X", agent_id="999")], datetime.now(timezone.utc))
    db_session.commit()
    now = datetime.now()
    v = db_session.query(WazuhVulnerability).one()
    v.last_seen = now - timedelta(days=7)   # el agente 999 no reporto NADA en este sync
    db_session.commit()

    _mark_obsolete_sqlite(db_session, conn.id, now)
    db_session.commit()

    v = db_session.query(WazuhVulnerability).one()
    assert v.status == "AGENT_REMOVED"
    actions = _history_actions(db_session, v.id)
    assert "AGENT_REMOVED" in actions
    assert "RESOLVED" not in actions


def test_agent_removed_reopens_when_agent_returns(db_session):
    """Una vuln AGENT_REMOVED que reaparece (el agente vuelve) se reabre -> ACTIVE + REOPENED."""
    conn = _create_connection(db_session)
    _process_sqlite(db_session, conn.id, [_raw(cve="CVE-Y", agent_id="777")], datetime.now(timezone.utc))
    db_session.commit()
    v = db_session.query(WazuhVulnerability).one()
    v.status = "AGENT_REMOVED"
    db_session.commit()

    _process_sqlite(db_session, conn.id, [_raw(cve="CVE-Y", agent_id="777")], datetime.now(timezone.utc))
    db_session.commit()

    v = db_session.query(WazuhVulnerability).one()
    assert v.status == "ACTIVE"
    assert "REOPENED" in _history_actions(db_session, v.id)


def test_process_reopens_resolved_vuln(db_session):
    conn = _create_connection(db_session)
    _process_sqlite(db_session, conn.id, [_raw()], datetime.now(timezone.utc))
    db_session.commit()
    vuln = db_session.query(WazuhVulnerability).one()
    vuln.status = "RESOLVED"
    db_session.commit()

    _process_sqlite(db_session, conn.id, [_raw()], datetime.now(timezone.utc))
    db_session.commit()

    vuln = db_session.query(WazuhVulnerability).one()
    assert vuln.status == "ACTIVE"
    assert "REOPENED" in _history_actions(db_session, vuln.id)


def test_full_lifecycle_detected_resolved_reopened(db_session):
    """Ciclo completo: detectada -> desaparece con el agente aun activo (RESOLVED) -> reaparece (REOPENED)."""
    conn = _create_connection(db_session)
    # CVE-keep mantiene al agente 001 "presente"; CVE-life sigue el ciclo.
    _process_sqlite(db_session, conn.id, [_raw(cve="CVE-life", pkg="curl"), _raw(cve="CVE-keep", pkg="openssl")], datetime.now(timezone.utc))
    db_session.commit()
    now = datetime.now()
    life = db_session.query(WazuhVulnerability).filter_by(cve_id="CVE-life").one()
    keep = db_session.query(WazuhVulnerability).filter_by(cve_id="CVE-keep").one()
    life.last_seen = now - timedelta(days=3)      # CVE-life desaparece
    keep.last_seen = now + timedelta(minutes=1)   # el agente sigue reportando CVE-keep
    db_session.commit()

    _mark_obsolete_sqlite(db_session, conn.id, now)
    db_session.commit()
    assert db_session.query(WazuhVulnerability).filter_by(cve_id="CVE-life").one().status == "RESOLVED"

    _process_sqlite(db_session, conn.id, [_raw(cve="CVE-life", pkg="curl")], datetime.now(timezone.utc))
    db_session.commit()

    life = db_session.query(WazuhVulnerability).filter_by(cve_id="CVE-life").one()
    assert life.status == "ACTIVE"
    actions = _history_actions(db_session, life.id)
    assert actions.count("DETECTED") == 1
    assert actions.count("RESOLVED") == 1
    assert actions.count("REOPENED") == 1
