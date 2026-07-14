from fastapi import APIRouter, Depends, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy.sql import func, text
from typing import Optional, List
from ..db import get_db
from ..models import User, WazuhConnection, WazuhVulnerability
from ..services.authService import get_current_user
from ..services.wazuhService import perform_sync_task

router = APIRouter(prefix="/vulns", tags=["vulnerabilities"])

@router.post("/sync-all", status_code=202)
def sync_all_connections(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    conns = db.query(WazuhConnection).filter(WazuhConnection.is_active == True).all()
    for conn in conns:
        background_tasks.add_task(perform_sync_task, conn.id, current_user.username)
    return {"message": "Sincronización global en segundo plano iniciada."}

@router.get("")
def list_vulns(
    page: int = 1,
    limit: Optional[int] = None,
    connection_id: Optional[int] = None,
    agent_name: Optional[List[str]] = Query(None),
    cve_id: Optional[List[str]] = Query(None),
    package_name: Optional[List[str]] = Query(None),
    severity: Optional[List[str]] = Query(None),
    score_min: Optional[float] = None,
    score_max: Optional[float] = None,
    sort_key: Optional[str] = 'last_seen',
    sort_order: Optional[str] = 'desc',
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(WazuhVulnerability)
    
    if connection_id:
        query = query.filter(WazuhVulnerability.connection_id == connection_id)
    if agent_name:
        query = query.filter(WazuhVulnerability.agent_name.in_(agent_name))
    if cve_id:
        query = query.filter(WazuhVulnerability.cve_id.in_(cve_id))
    if package_name:
        query = query.filter(WazuhVulnerability.package_name.in_(package_name))
    if severity:
        query = query.filter(func.upper(WazuhVulnerability.severity).in_([s.upper() for s in severity]))
    if score_min is not None:
        query = query.filter(WazuhVulnerability.score_base >= score_min)
    if score_max is not None:
        query = query.filter(WazuhVulnerability.score_base <= score_max)

    total_count = query.count()

    if sort_key and hasattr(WazuhVulnerability, sort_key):
        column = getattr(WazuhVulnerability, sort_key)
        if sort_order == 'desc':
            query = query.order_by(column.desc())
        else:
            query = query.order_by(column.asc())
    else:
        query = query.order_by(WazuhVulnerability.last_seen.desc())

    if limit is not None:
        skip = (page - 1) * limit
        query = query.offset(skip).limit(limit)

    vulns = query.all()

    items = [
        {
            "id": v.id,
            "connection_id": v.connection_id,
            "connection_name": v.connection.name if v.connection else None,
            "status": v.status,
            "agent_id": v.agent_id,
            "agent_name": v.agent_name,
            "os_full": v.os_full,
            "os_platform": v.os_platform,
            "os_version": v.os_version,
            "package_name": v.package_name,
            "package_version": v.package_version,
            "package_type": v.package_type,
            "package_arch": v.package_arch,
            "cve_id": v.cve_id,
            "severity": v.severity,
            "score_base": float(v.score_base) if v.score_base else None,
            "score_version": v.score_version,
            "detected_at": v.detected_at,
            "published_at": v.published_at,
            "description": v.description,
            "reference": v.reference,
            "scanner_vendor": v.scanner_vendor,
            "first_seen": v.first_seen,
            "last_seen": v.last_seen,
            "history": [
                {
                    "id": h.id,
                    "action": h.action,
                    "details": h.details,
                    "timestamp": h.timestamp,
                }
                for h in sorted(v.history, key=lambda h: h.timestamp)
            ],
        }
        for v in vulns
    ]

    return {
        "total": total_count,
        "page": page,
        "limit": limit if limit is not None else total_count,
        "items": items
    }

@router.get("/filters")
def get_unique_filters(connection_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Obtiene los valores únicos de filtros desde las vistas materializadas precalculadas."""
    try:
        if connection_id:
            agents_res = db.execute(text("SELECT agent_name FROM mv_unique_agents WHERE connection_id = :conn_id"), {"conn_id": connection_id}).fetchall()
            cves_res = db.execute(text("SELECT cve_id FROM mv_unique_cves WHERE connection_id = :conn_id"), {"conn_id": connection_id}).fetchall()
            packages_res = db.execute(text("SELECT package_name FROM mv_unique_packages WHERE connection_id = :conn_id"), {"conn_id": connection_id}).fetchall()
            severities_res = db.execute(text("SELECT severity FROM mv_unique_severities WHERE connection_id = :conn_id"), {"conn_id": connection_id}).fetchall()
            os_res = db.execute(text("SELECT os_platform, os_version FROM mv_unique_os WHERE connection_id = :conn_id"), {"conn_id": connection_id}).fetchall()
        else:
            agents_res = db.execute(text("SELECT DISTINCT agent_name FROM mv_unique_agents")).fetchall()
            cves_res = db.execute(text("SELECT DISTINCT cve_id FROM mv_unique_cves")).fetchall()
            packages_res = db.execute(text("SELECT DISTINCT package_name FROM mv_unique_packages")).fetchall()
            severities_res = db.execute(text("SELECT DISTINCT severity FROM mv_unique_severities")).fetchall()
            os_res = db.execute(text("SELECT DISTINCT os_platform, os_version FROM mv_unique_os")).fetchall()

        agents = [r[0] for r in agents_res if r[0]]
        cves = [r[0] for r in cves_res if r[0]]
        packages = [r[0] for r in packages_res if r[0]]
        severities = [r[0] for r in severities_res if r[0]]
        os_list = [{"platform": r[0], "version": r[1]} for r in os_res if r[0]]

    except Exception:
        # Fallback para desarrollo local con SQLite sin vistas materializadas
        query = db.query(WazuhVulnerability)
        if connection_id:
            query = query.filter(WazuhVulnerability.connection_id == connection_id)
        
        agents = [r[0] for r in query.with_entities(WazuhVulnerability.agent_name).distinct().all() if r[0]]
        cves = [r[0] for r in query.with_entities(WazuhVulnerability.cve_id).distinct().all() if r[0]]
        packages = [r[0] for r in query.with_entities(WazuhVulnerability.package_name).distinct().all() if r[0]]
        severities = [r[0] for r in query.with_entities(WazuhVulnerability.severity).distinct().all() if r[0]]
        os_query_res = query.with_entities(WazuhVulnerability.os_platform, WazuhVulnerability.os_version).distinct().all()
        os_list = [{"platform": r[0], "version": r[1]} for r in os_query_res if r[0]]

    # Deduplicar os_list (por si acaso hay nulos iterados)
    unique_os = []
    seen = set()
    for os_item in os_list:
        key = (os_item["platform"], os_item["version"])
        if key not in seen:
            seen.add(key)
            unique_os.append(os_item)

    return {
        "agents": sorted(agents),
        "cves": sorted(cves),
        "packages": sorted(packages),
        "severities": sorted(severities),
        "os": unique_os
    }

