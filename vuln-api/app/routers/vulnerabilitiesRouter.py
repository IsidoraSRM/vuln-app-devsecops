import logging

from fastapi import APIRouter, Depends, Query, BackgroundTasks
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql import func, text
from typing import Optional, List
from datetime import datetime
from ..db import get_db
from ..models import User, WazuhConnection, WazuhVulnerability, IS_SQLITE
from ..services.authService import get_current_user
from ..services.wazuhService import perform_sync_task

log = logging.getLogger(__name__)

# Cap para las listas de filtros de ALTA cardinalidad (CVE / paquete). Los dropdowns no pueden
# mostrar (ni el usuario recorrer) cientos de miles de opciones; sin cap, /filters hace un DISTINCT
# sobre toda la tabla (medido: ~631ms a 250k CVEs) y manda un payload enorme. Agentes/severidades/OS
# son de baja cardinalidad y se devuelven completos.
FILTER_LIST_CAP = 1000

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
    os_platform: Optional[List[str]] = Query(None),
    score_min: Optional[float] = None,
    score_max: Optional[float] = None,
    status: Optional[str] = Query(None),
    detected_after: Optional[datetime] = Query(None),
    detected_before: Optional[datetime] = Query(None),
    sort_key: Optional[str] = 'last_seen',
    sort_order: Optional[str] = 'desc',
    cargas_page: int = 1,
    cargas_limit: int = 10,
    cargas_order: str = 'asc',
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Tope de paginacion: sin esto, una llamada con limit=None (o un limit enorme) carga TODA
    # la tabla + su historial (selectinload) a memoria -> OOM a escala de millones. El frontend
    # pagina con limit=50; 500 es un maximo generoso. Para "exportar todo" iria un endpoint aparte.
    MAX_PAGE_LIMIT = 500
    if limit is None or limit > MAX_PAGE_LIMIT:
        limit = MAX_PAGE_LIMIT

    # 1. Detectar si el stored procedure de filtrado esta disponible (Postgres). En SQLite (tests)
    # la sonda falla y se usa el fallback ORM. OJO: las fechas (detected_after/detected_before) NO se
    # pasan al SP -> se aplican como filtro ORM mas abajo, en AMBOS caminos (antes el SP solo tenia
    # days_ago e IGNORABA detected_before, colando filas fuera de rango en produccion).
    sp_exists = False
    try:
        db.execute(text("SELECT 1 FROM sp_filter_vulnerabilities(NULL::TEXT[], NULL::TEXT[], NULL::TEXT[], NULL::TEXT[], NULL::INT) LIMIT 0"))
        sp_exists = True
    except Exception as e:
        # En SQLite la sonda falla siempre (no hay SP) -> esperado, no se loguea. En Postgres NO
        # deberia fallar: si falla, se loguea (no en silencio) porque degradaria TODA la lista al
        # camino lento sin avisar (mismo tipo de bug que el binding `::` que se escondia).
        if not IS_SQLITE:
            log.warning("sp_filter_probe_failed_using_orm_fallback", extra={"error": str(e)})
        db.rollback()
        sp_exists = False

    query = db.query(WazuhVulnerability)
    
    if sp_exists:
        # OPTIMIZACIÓN EXTREMA: En lugar de traer 500,000 IDs a Python y colapsar la RAM,
        # inyectamos el procedimiento almacenado como una subconsulta (SubQuery) nativa.
        # PostgreSQL resolverá todo internamente en milisegundos.
        query = query.filter(text("""
            wazuh_vulnerabilities.id IN (
                SELECT id FROM sp_filter_vulnerabilities(
                    :sevs, :oses, :statuses, :agents
                )
            )
        """).bindparams(
            sevs=severity,
            oses=os_platform,
            statuses=[status] if status else None,
            agents=agent_name,
        ))
    else:
        # Lógica original (Fallback)
        if agent_name:
            query = query.filter(WazuhVulnerability.agent_name.in_(agent_name))
        if severity:
            query = query.filter(func.upper(WazuhVulnerability.severity).in_([s.upper() for s in severity]))
        if os_platform:
            query = query.filter(WazuhVulnerability.os_platform.in_(os_platform))
        if status:
            query = query.filter(func.upper(WazuhVulnerability.status) == status.upper())

    # Filtros de fecha: se aplican en AMBOS caminos (el SP ya NO maneja fechas). Con el semi-join
    # `id IN (SELECT id FROM sp(...))` el planner combina esto con el idx_vuln_first_seen. Antes el
    # camino SP solo recibia days_ago (granularidad de dia) e ignoraba por completo detected_before.
    if detected_after:
        query = query.filter(WazuhVulnerability.first_seen >= detected_after)
    if detected_before:
        query = query.filter(WazuhVulnerability.first_seen <= detected_before)

    # Filtros adicionales que no están en el SP general
    if current_user.role != "superadmin":
        assigned_id = current_user.assigned_connection_id or -1
        query = query.filter(WazuhVulnerability.connection_id == assigned_id)
    else:
        if connection_id:
            query = query.filter(WazuhVulnerability.connection_id == connection_id)

    if cve_id:
        query = query.filter(WazuhVulnerability.cve_id.in_(cve_id))
    if package_name:
        query = query.filter(WazuhVulnerability.package_name.in_(package_name))
    if score_min is not None:
        query = query.filter(WazuhVulnerability.score_base >= score_min)
    if score_max is not None:
        query = query.filter(WazuhVulnerability.score_base <= score_max)

    # Conteo del total. Fast-path: si el filtro es SOLO estado/severidad/conexion (el caso del
    # dashboard), el total sale de mv_vuln_counts (precalculada, ~20 filas -> ~0.1ms) en vez de contar
    # millones de filas via el semi-join id IN (SELECT id FROM sp(...)) (~1.6s a 1M). Con filtros
    # avanzados (os/agente/cve/paquete/score/fecha), que la MV no cubre, cae al conteo en vivo.
    has_advanced_filter = bool(
        os_platform or agent_name or cve_id or package_name
        or score_min is not None or score_max is not None
        or detected_after or detected_before
    )
    total_count = None
    if sp_exists and not has_advanced_filter:
        try:
            if current_user.role != "superadmin":
                eff_conn = current_user.assigned_connection_id or -1
            else:
                eff_conn = connection_id
            # OJO: `:param::text[]` NO se parsea como bindparam en SQLAlchemy (el `::` se come el
            # nombre) -> hay que usar CAST(:param AS text[]). status es un valor unico (sin array).
            total_count = int(db.execute(text("""
                SELECT COALESCE(SUM(n), 0) FROM mv_vuln_counts
                WHERE (:conn IS NULL OR connection_id = :conn)
                  AND (:status_u IS NULL OR status = :status_u)
                  AND (CAST(:sevs AS text[]) IS NULL OR severity = ANY(CAST(:sevs AS text[])))
            """).bindparams(
                conn=eff_conn,
                status_u=status.upper() if status else None,
                sevs=[s.upper() for s in severity] if severity else None,
            )).scalar())
        except Exception as e:
            # NO en silencio: si el fast-path de la MV falla, se loguea (asi un bug como el binding
            # `::` no se esconde) y recien ahi caemos al conteo en vivo.
            log.warning("mv_vuln_counts_fastpath_failed_using_live_count", extra={"error": str(e)})
            db.rollback()
            total_count = None
    if total_count is None:
        # Cap del conteo en vivo (filtros avanzados que no cubre la MV). Contar el total EXACTO de un
        # filtro que matchea 1M+ filas costaba ~3.5s a 4M; el SELECT de la pagina es rapido (para en
        # 500). Contamos solo hasta COUNT_CAP -> el front muestra "N+". Medido a 4M: 3.5s -> ~0.1s.
        COUNT_CAP = 10000
        total_count = db.query(func.count()).select_from(
            query.with_entities(WazuhVulnerability.id).limit(COUNT_CAP).subquery()
        ).scalar()

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

    # OPTIMIZACIÓN EXTREMA 2 (Eager Loading): Evitar problema N+1 Queries
    query = query.options(
        selectinload(WazuhVulnerability.connection),
        selectinload(WazuhVulnerability.history)
    )

    vulns = query.all()

    def parse_dt(val):
        if val is None:
            return None
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val.replace(" ", "T"))
            except Exception:
                return None
        return val

    # Get unique connection IDs in the page's vulns
    conn_ids = set(v.connection_id for v in vulns)
    connection_syncs = {}
    cargas_total = 0
    for cid in conn_ids:
        # Get the total number of sync runs for this connection
        total_runs_for_cid = db.execute(text("""
            SELECT COUNT(DISTINCT timestamp) FROM sync_runs
            WHERE connection_id = :conn_id
        """), {"conn_id": cid}).scalar() or 0
        if total_runs_for_cid > cargas_total:
            cargas_total = total_runs_for_cid

        # Get the unique timestamps of the history events for vulnerabilities in this connection
        # This represents the historical sync runs (cargas) with pagination support
        offset = (cargas_page - 1) * cargas_limit
        timestamps_res = db.execute(text("""
            SELECT DISTINCT timestamp FROM sync_runs
            WHERE connection_id = :conn_id
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset
        """), {"conn_id": cid, "limit": cargas_limit, "offset": offset}).fetchall()
        parsed_ts = []
        for idx, r in enumerate(timestamps_res):
            dt = parse_dt(r[0])
            if dt:
                global_rank = total_runs_for_cid - offset - idx
                parsed_ts.append((dt, global_rank))
        connection_syncs[cid] = sorted(parsed_ts, key=lambda x: x[0], reverse=(cargas_order == 'desc'))

    items = []
    for v in vulns:
        # Map history list
        hist_list = [
            {
                "id": h.id,
                "action": h.action,
                "details": h.details,
                "timestamp": h.timestamp,
            }
            for h in sorted(v.history, key=lambda h: h.timestamp)
        ]
        
        # Calculate cargas status
        sync_ts = connection_syncs.get(v.connection_id, [])
        cargas = []
        for t, rank in sync_ts:
            past_events = []
            for h in hist_list:
                h_ts = parse_dt(h["timestamp"])
                if h_ts and h_ts <= t:
                    past_events.append(h)

            if not past_events:
                status = "white"
            else:
                last_event = past_events[-1]
                if last_event["action"] in ("DETECTED", "REOPENED"):
                    status = "red"
                else:
                    status = "white"
            cargas.append({
                "label": f"Carga {rank}",
                "timestamp": t.isoformat(),
                "status": status
            })

        items.append({
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
            "history": hist_list,
            "cargas": cargas
        })

    return {
        "total": total_count,
        "page": page,
        "limit": limit if limit is not None else total_count,
        "items": items,
        "cargas_total": cargas_total,
        "cargas_page": cargas_page,
        "cargas_limit": cargas_limit,
        "cargas_order": cargas_order
    }

@router.get("/filters")
def get_unique_filters(
    connection_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "superadmin":
        connection_id = current_user.assigned_connection_id or -1

    """Obtiene los valores únicos de filtros desde las vistas materializadas precalculadas."""
    try:
        if connection_id is not None and connection_id != -1:
            agents_res = db.execute(text("SELECT agent_name FROM mv_unique_agents WHERE connection_id = :conn_id"), {"conn_id": connection_id}).fetchall()
            cves_res = db.execute(text("SELECT cve_id FROM mv_unique_cves WHERE connection_id = :conn_id LIMIT :cap"), {"conn_id": connection_id, "cap": FILTER_LIST_CAP}).fetchall()
            packages_res = db.execute(text("SELECT package_name FROM mv_unique_packages WHERE connection_id = :conn_id LIMIT :cap"), {"conn_id": connection_id, "cap": FILTER_LIST_CAP}).fetchall()
            severities_res = db.execute(text("SELECT severity FROM mv_unique_severities WHERE connection_id = :conn_id"), {"conn_id": connection_id}).fetchall()
            os_res = db.execute(text("SELECT os_platform, os_version FROM mv_unique_os WHERE connection_id = :conn_id"), {"conn_id": connection_id}).fetchall()
        elif connection_id == -1:
            agents_res = []
            cves_res = []
            packages_res = []
            severities_res = []
            os_res = []
        else:
            agents_res = db.execute(text("SELECT DISTINCT agent_name FROM mv_unique_agents")).fetchall()
            # Sin DISTINCT: el cap con LIMIT corta rapido (lee :cap filas y para) en vez de agregar
            # las 250k. Se deduplica en Python al final (barato con <= :cap filas).
            cves_res = db.execute(text("SELECT cve_id FROM mv_unique_cves LIMIT :cap"), {"cap": FILTER_LIST_CAP}).fetchall()
            packages_res = db.execute(text("SELECT package_name FROM mv_unique_packages LIMIT :cap"), {"cap": FILTER_LIST_CAP}).fetchall()
            severities_res = db.execute(text("SELECT DISTINCT severity FROM mv_unique_severities")).fetchall()
            os_res = db.execute(text("SELECT DISTINCT os_platform, os_version FROM mv_unique_os")).fetchall()

        agents = [r[0] for r in agents_res if r[0]]
        cves = [r[0] for r in cves_res if r[0]]
        packages = [r[0] for r in packages_res if r[0]]
        severities = [r[0] for r in severities_res if r[0]]
        os_list = [{"platform": r[0], "version": r[1]} for r in os_res if r[0]]

    except Exception as e:
        # Fallback para desarrollo local con SQLite sin vistas materializadas.
        log.warning("filters_mv_read_failed_using_live_query", extra={"error": str(e)})
        db.rollback()
        query = db.query(WazuhVulnerability)
        if connection_id is not None:
            query = query.filter(WazuhVulnerability.connection_id == connection_id)
        
        agents = [r[0] for r in query.with_entities(WazuhVulnerability.agent_name).distinct().all() if r[0]]
        cves = [r[0] for r in query.with_entities(WazuhVulnerability.cve_id).distinct().limit(FILTER_LIST_CAP).all() if r[0]]
        packages = [r[0] for r in query.with_entities(WazuhVulnerability.package_name).distinct().limit(FILTER_LIST_CAP).all() if r[0]]
        severities = [r[0] for r in query.with_entities(WazuhVulnerability.severity).distinct().all() if r[0]]
        os_query_res = query.with_entities(WazuhVulnerability.os_platform, WazuhVulnerability.os_version).distinct().all()
        os_list = [{"platform": r[0], "version": r[1]} for r in os_query_res if r[0]]

    # Deduplicar os_list
    unique_os = []
    seen = set()
    for os_item in os_list:
        key = (os_item["platform"], os_item["version"])
        if key not in seen:
            seen.add(key)
            unique_os.append(os_item)

    return {
        "agents": sorted(agents),
        "cves": sorted(set(cves)),
        "packages": sorted(set(packages)),
        "severities": sorted(severities),
        "os": unique_os
    }

@router.get("/metrics/summary")
def get_metrics_summary(
    connection_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "superadmin":
        connection_id = current_user.assigned_connection_id or -1

    # Ruta rapida: leer el resumen PRE-AGREGADO de mv_metrics_summary (refrescada en cada sync).
    # Evita el COUNT(DISTINCT cve_id) en vivo, que medido tarda ~4.4s a 2M filas POR CADA carga.
    # connection_id con valor -> esa conexion; None -> fila grand-total (connection_id IS NULL).
    try:
        if connection_id is not None:
            row = db.execute(text(
                "SELECT total, critical, high, medium, low FROM mv_metrics_summary WHERE connection_id = :cid"
            ), {"cid": connection_id}).fetchone()
        else:
            row = db.execute(text(
                "SELECT total, critical, high, medium, low FROM mv_metrics_summary WHERE connection_id IS NULL"
            )).fetchone()
        if row is None:
            return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        return {"total": row[0], "critical": row[1], "high": row[2], "medium": row[3], "low": row[4]}
    except Exception as e:
        # Fallback (SQLite/tests o si la MV aun no existe): calculo en vivo (logica original).
        log.warning("metrics_summary_mv_read_failed_using_live_query", extra={"error": str(e)})
        db.rollback()

    # Group by severity and count distinct CVE IDs
    severity_query = db.query(
        WazuhVulnerability.severity,
        func.count(WazuhVulnerability.cve_id.distinct())
    ).filter(WazuhVulnerability.status == "ACTIVE")
    
    if connection_id is not None:
        severity_query = severity_query.filter(WazuhVulnerability.connection_id == connection_id)
        
    severity_counts = severity_query.group_by(WazuhVulnerability.severity).all()

    counts_dict = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }
    for sev, count in severity_counts:
        sev_key = (sev or "UNKNOWN").upper()
        if sev_key in counts_dict:
            counts_dict[sev_key] += count
        else:
            counts_dict["UNKNOWN"] += count

    # Count overall unique CVEs
    total_query = db.query(func.count(WazuhVulnerability.cve_id.distinct())).filter(WazuhVulnerability.status == "ACTIVE")
    if connection_id is not None:
        total_query = total_query.filter(WazuhVulnerability.connection_id == connection_id)
    total = total_query.scalar() or 0

    return {
        "total": total,
        "critical": counts_dict["CRITICAL"],
        "high": counts_dict["HIGH"],
        "medium": counts_dict["MEDIUM"],
        "low": counts_dict["LOW"] + counts_dict["UNKNOWN"]
    }

