from fastapi import APIRouter, Depends, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from typing import Optional, List
from ..db import get_db
from ..models import User, WazuhConnection, WazuhVulnerability
from ..services.authService import get_current_user
from ..services.wazuhService import perform_sync_task

router = APIRouter(prefix="/vulns", tags=["vulnerabilities"])

@router.post("/sync-all")
def sync_all_connections(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    conns = db.query(WazuhConnection).filter(WazuhConnection.is_active == True).all()
    for conn in conns:
        background_tasks.add_task(perform_sync_task, conn.id, current_user.username)
    return {"message": "Sincronización global iniciada en segundo plano."}

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
