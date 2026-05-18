import logging
import time
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from ..models import WazuhConnection, WazuhVulnerability, VulnerabilityHistory
from ..metrics import SYNC_DURATION_MS, VULN_DETECTED
from ..services.wazuhClientService import fetch_all_vulns
from ..crypto import decrypt
from ..db import SessionLocal

log = logging.getLogger(__name__)

def perform_sync_task(conn_id: int, username: str):
    db = SessionLocal()
    try:
        conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
        if not conn or not conn.is_active:
            return

        log.info("sync_started", extra={"connection_id": conn.id, "connection_name": conn.name, "user": username})
        start = time.monotonic()

        raw_vulns = fetch_all_vulns(
            conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password)
        )
        
        count = process_wazuh_vulnerabilities(db, conn.id, raw_vulns)
        db.commit()

        elapsed_ms = int((time.monotonic() - start) * 1000)
        SYNC_DURATION_MS.observe(elapsed_ms)
        
        log.info("sync_finished", extra={"connection_id": conn.id, "synced_count": count, "elapsed_ms": elapsed_ms})
    except Exception as e:
        db.rollback()
        log.exception("sync_failed", extra={"connection_id": conn_id, "error": str(e)})
    finally:
        db.close()


def process_wazuh_vulnerabilities(db: Session, conn_id: int, raw_vulns: list) -> int:
    count = 0
    seen_vuln_ids = set()

    all_db_vulns = db.query(WazuhVulnerability).filter_by(connection_id=conn_id).all()
    
    vuln_map = {
        (v.agent_id, v.package_name, v.package_version, v.cve_id): v
        for v in all_db_vulns
    }

    processed_keys = set() 

    for v in raw_vulns:
        agent = v.get("agent", {})
        osinfo = (v.get("host") or {}).get("os") or {}
        pkg = v.get("package", {})
        vuln = v.get("vulnerability", {})

        cve_id = vuln.get("id")
        if not cve_id:
            continue

        agent_id = agent.get("id")
        pkg_name = pkg.get("name")
        pkg_version = pkg.get("version")

        key = (agent_id, pkg_name, pkg_version, cve_id)
        
        if key in processed_keys:
            continue
        processed_keys.add(key)

        existing = vuln_map.get(key)

        if existing:
            if existing.id:
                seen_vuln_ids.add(existing.id)
            _handle_existing_vuln_in_memory(existing, vuln)
        else:
            new_vuln = _create_new_vuln_in_memory(conn_id, agent, osinfo, pkg, vuln)
            db.add(new_vuln)
            vuln_map[key] = new_vuln 
            
        count += 1

    for key, db_vuln in vuln_map.items():
        if db_vuln.id and db_vuln.id not in seen_vuln_ids and db_vuln.status == "ACTIVE":
            db_vuln.status = "RESOLVED"
            db_vuln.history.append(VulnerabilityHistory(
                action="RESOLVED",
                details="Ya no es reportada por el agente (Probablemente parcheada)",
            ))

    return count


def _handle_existing_vuln_in_memory(existing: WazuhVulnerability, vuln: dict) -> None:
    if existing.status == "RESOLVED":
        existing.status = "ACTIVE"
        existing.history.append(VulnerabilityHistory(
            action="REOPENED",
            details="La vulnerabilidad fue detectada nuevamente por Wazuh",
        ))

    new_severity = vuln.get("severity")
    if existing.severity != new_severity:
        existing.history.append(VulnerabilityHistory(
            action="SEVERITY_CHANGED",
            details=f"Severidad cambió de {existing.severity} a {new_severity}",
        ))
        existing.severity = new_severity

    existing.score_base = (vuln.get("score") or {}).get("base")
    existing.last_seen = func.now()


def _create_new_vuln_in_memory(conn_id, agent, osinfo, pkg, vuln):
    new_v = WazuhVulnerability(
        connection_id=conn_id,
        status="ACTIVE",
        agent_id=agent.get("id"),
        agent_name=agent.get("name"),
        os_full=osinfo.get("full"),
        os_platform=osinfo.get("platform"),
        os_version=osinfo.get("version"),
        package_name=pkg.get("name"),
        package_version=pkg.get("version"),
        package_type=pkg.get("type"),
        package_arch=pkg.get("architecture"),
        cve_id=vuln.get("id"),
        severity=vuln.get("severity"),
        score_base=(vuln.get("score") or {}).get("base"),
        score_version=(vuln.get("score") or {}).get("version"),
        detected_at=vuln.get("detected_at"),
        published_at=vuln.get("published_at"),
        description=vuln.get("description"),
        reference=vuln.get("reference"),
        scanner_vendor=(vuln.get("scanner") or {}).get("vendor"),
    )
    new_v.history.append(VulnerabilityHistory(
        action="DETECTED",
        details="Vulnerabilidad identificada por primera vez",
    ))
    VULN_DETECTED.inc()
    return new_v
