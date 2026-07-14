import logging
import time
from sqlalchemy.orm import Session
from sqlalchemy.sql import text, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from ..models import WazuhConnection, WazuhVulnerability, VulnerabilityHistory, IS_SQLITE
from ..metrics import SYNC_DURATION_MS, VULN_DETECTED
from ..services.providerFactory import VulnerabilityProviderFactory
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
        
        db_sync_time = db.execute(text("SELECT CURRENT_TIMESTAMP")).scalar()

        provider = VulnerabilityProviderFactory.get_provider(conn.provider_type)
        
        if hasattr(provider, 'fetch_vulnerabilities_batches'):
            batches = provider.fetch_vulnerabilities_batches(conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password))
        else:
            batches = [provider.fetch_vulnerabilities(conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password))]
            
        count = 0
        if IS_SQLITE:
            for raw_vulns in batches:
                count += _process_sqlite(db, conn.id, raw_vulns)
            _mark_obsolete_sqlite(db, conn.id, db_sync_time)
        else:
            _prepare_pg_temp_table(db)
            for raw_vulns in batches:
                count += _process_pg_batch(db, conn.id, raw_vulns)
            _mark_obsolete_pg(db, conn.id, db_sync_time)
            
        db.commit()

        try:
            db.execute(text("SELECT refresh_vulnerability_filters();"))
            db.commit()
            log.info("filters_materialized_views_refreshed", extra={"connection_id": conn.id})
        except Exception as ref_err:
            log.warning("failed_to_refresh_filters_materialized_views", extra={"connection_id": conn.id, "error": str(ref_err)})
            db.rollback()

        elapsed_ms = int((time.monotonic() - start) * 1000)
        SYNC_DURATION_MS.observe(elapsed_ms)
        
        log.info("sync_finished", extra={"connection_id": conn.id, "synced_count": count, "elapsed_ms": elapsed_ms})
    except Exception as e:
        db.rollback()
        log.exception("sync_failed", extra={"connection_id": conn_id, "error": str(e)})
    finally:
        db.close()


def _prepare_pg_temp_table(db: Session):
    db.execute(text("""
        CREATE TEMP TABLE IF NOT EXISTS temp_wazuh_vulns (
            connection_id INTEGER,
            status TEXT,
            agent_id TEXT,
            agent_name TEXT,
            os_full TEXT,
            os_platform TEXT,
            os_version TEXT,
            package_name TEXT,
            package_version TEXT,
            package_type TEXT,
            package_arch TEXT,
            cve_id TEXT,
            severity TEXT,
            score_base NUMERIC,
            score_version TEXT,
            detected_at TIMESTAMP WITH TIME ZONE,
            published_at TIMESTAMP WITH TIME ZONE,
            description TEXT,
            reference TEXT,
            scanner_vendor TEXT
        ) ON COMMIT PRESERVE ROWS;
    """))


def _process_pg_batch(db: Session, conn_id: int, raw_vulns: list) -> int:
    if not raw_vulns:
        return 0
        
    unique_batch_vulns = {}
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
        
        unique_batch_vulns[key] = {
            "connection_id": conn_id,
            "status": "ACTIVE",
            "agent_id": agent_id,
            "agent_name": agent.get("name"),
            "os_full": osinfo.get("full"),
            "os_platform": osinfo.get("platform"),
            "os_version": osinfo.get("version"),
            "package_name": pkg_name,
            "package_version": pkg_version,
            "package_type": pkg.get("type"),
            "package_arch": pkg.get("architecture"),
            "cve_id": cve_id,
            "severity": vuln.get("severity"),
            "score_base": (vuln.get("score") or {}).get("base"),
            "score_version": (vuln.get("score") or {}).get("version"),
            "detected_at": vuln.get("detected_at"),
            "published_at": vuln.get("published_at"),
            "description": vuln.get("description"),
            "reference": vuln.get("reference"),
            "scanner_vendor": (vuln.get("scanner") or {}).get("vendor")
        }
    
    if not unique_batch_vulns:
        return 0
        
    values = list(unique_batch_vulns.values())
    
    db.execute(text("TRUNCATE temp_wazuh_vulns;"))
    
    stmt = text("""
        INSERT INTO temp_wazuh_vulns (
            connection_id, status, agent_id, agent_name, os_full, os_platform, os_version,
            package_name, package_version, package_type, package_arch, cve_id,
            severity, score_base, score_version, detected_at, published_at,
            description, reference, scanner_vendor
        ) VALUES (
            :connection_id, :status, :agent_id, :agent_name, :os_full, :os_platform, :os_version,
            :package_name, :package_version, :package_type, :package_arch, :cve_id,
            :severity, :score_base, :score_version, :detected_at, :published_at,
            :description, :reference, :scanner_vendor
        )
    """)
    db.execute(stmt, values)
    
    # 1. Insert history for reopened
    db.execute(text("""
        INSERT INTO vulnerability_history (vulnerability_id, action, details, timestamp)
        SELECT w.id, 'REOPENED', 'La vulnerabilidad fue detectada nuevamente por Wazuh', CURRENT_TIMESTAMP
        FROM temp_wazuh_vulns t
        JOIN wazuh_vulnerabilities w 
          ON t.connection_id = w.connection_id
         AND t.agent_id = w.agent_id 
         AND t.package_name = w.package_name 
         AND t.package_version = w.package_version 
         AND t.cve_id = w.cve_id
        WHERE w.status = 'RESOLVED';
    """))
    
    # 2. Insert history for severity change
    db.execute(text("""
        INSERT INTO vulnerability_history (vulnerability_id, action, details, timestamp)
        SELECT w.id, 'SEVERITY_CHANGED', 'Severidad cambió de ' || COALESCE(w.severity, 'N/A') || ' a ' || t.severity, CURRENT_TIMESTAMP
        FROM temp_wazuh_vulns t
        JOIN wazuh_vulnerabilities w 
          ON t.connection_id = w.connection_id
         AND t.agent_id = w.agent_id 
         AND t.package_name = w.package_name 
         AND t.package_version = w.package_version 
         AND t.cve_id = w.cve_id
        WHERE w.severity IS DISTINCT FROM t.severity;
    """))

    # 3. UPSERT the actual data and capture new inserts using xmax
    db.execute(text("""
        WITH upsert AS (
            INSERT INTO wazuh_vulnerabilities (
                connection_id, status, agent_id, agent_name, os_full, os_platform, os_version,
                package_name, package_version, package_type, package_arch, cve_id,
                severity, score_base, score_version, detected_at, published_at,
                description, reference, scanner_vendor, last_seen
            )
            SELECT connection_id, status, agent_id, agent_name, os_full, os_platform, os_version,
                   package_name, package_version, package_type, package_arch, cve_id,
                   severity, score_base, score_version, detected_at, published_at,
                   description, reference, scanner_vendor, CURRENT_TIMESTAMP
            FROM temp_wazuh_vulns
            ON CONFLICT ON CONSTRAINT uniq_wazuh_vuln
            DO UPDATE SET
                status = 'ACTIVE',
                agent_name = EXCLUDED.agent_name,
                os_full = EXCLUDED.os_full,
                os_platform = EXCLUDED.os_platform,
                os_version = EXCLUDED.os_version,
                package_type = EXCLUDED.package_type,
                package_arch = EXCLUDED.package_arch,
                severity = EXCLUDED.severity,
                score_base = EXCLUDED.score_base,
                score_version = EXCLUDED.score_version,
                detected_at = EXCLUDED.detected_at,
                published_at = EXCLUDED.published_at,
                description = EXCLUDED.description,
                reference = EXCLUDED.reference,
                scanner_vendor = EXCLUDED.scanner_vendor,
                last_seen = CURRENT_TIMESTAMP
            RETURNING id, xmax
        )
        INSERT INTO vulnerability_history (vulnerability_id, action, details, timestamp)
        SELECT id, 'DETECTED', 'Vulnerabilidad identificada por primera vez', CURRENT_TIMESTAMP
        FROM upsert
        WHERE xmax::text = '0';
    """))
    
    return len(values)

def _mark_obsolete_pg(db: Session, conn_id: int, sync_start_time):
    # Insert history for newly resolved
    db.execute(text("""
        INSERT INTO vulnerability_history (vulnerability_id, action, details, timestamp)
        SELECT id, 'RESOLVED', 'Ya no es reportada por el agente (Probablemente parcheada)', CURRENT_TIMESTAMP
        FROM wazuh_vulnerabilities
        WHERE connection_id = :conn_id 
          AND status = 'ACTIVE' 
          AND last_seen < :sync_start
    """), {"conn_id": conn_id, "sync_start": sync_start_time})
    
    # Mark as resolved
    db.execute(text("""
        UPDATE wazuh_vulnerabilities
        SET status = 'RESOLVED'
        WHERE connection_id = :conn_id 
          AND status = 'ACTIVE' 
          AND last_seen < :sync_start
    """), {"conn_id": conn_id, "sync_start": sync_start_time})

# Original memory-intensive code for SQLite backward compatibility
def _process_sqlite(db: Session, conn_id: int, raw_vulns: list) -> int:
    count = 0
    all_db_vulns = db.query(WazuhVulnerability).filter_by(connection_id=conn_id).all()
    vuln_map = { (v.agent_id, v.package_name, v.package_version, v.cve_id): v for v in all_db_vulns }
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
            _handle_existing_vuln_in_memory(existing, vuln)
        else:
            new_vuln = _create_new_vuln_in_memory(conn_id, agent, osinfo, pkg, vuln)
            db.add(new_vuln)
            vuln_map[key] = new_vuln 
        count += 1
    
    return count

def _mark_obsolete_sqlite(db: Session, conn_id: int, sync_start_time):
    obsolete_vulns = db.query(WazuhVulnerability).filter(
        WazuhVulnerability.connection_id == conn_id,
        WazuhVulnerability.status == 'ACTIVE',
        WazuhVulnerability.last_seen < sync_start_time
    ).all()
    
    for db_vuln in obsolete_vulns:
        db_vuln.status = "RESOLVED"
        db_vuln.history.append(VulnerabilityHistory(
            action="RESOLVED",
            details="Ya no es reportada por el agente (Probablemente parcheada)",
        ))

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
