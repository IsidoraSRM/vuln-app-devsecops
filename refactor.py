import os
import shutil

base_path = r"c:\Users\Public\Desktop\DevSecOps\vuln-app-devsecops\vuln-api\app"

# Create directories
os.makedirs(os.path.join(base_path, "schemas"), exist_ok=True)
os.makedirs(os.path.join(base_path, "routers"), exist_ok=True)
os.makedirs(os.path.join(base_path, "services"), exist_ok=True)

# Add __init__.py files
open(os.path.join(base_path, "schemas", "__init__.py"), 'w').close()
open(os.path.join(base_path, "routers", "__init__.py"), 'w').close()
open(os.path.join(base_path, "services", "__init__.py"), 'w').close()

metrics_py = """from prometheus_client import Counter, Histogram, make_asgi_app

LOGIN_ATTEMPTS = Counter("login_attempts_total", "Total login attempts")
LOGIN_SUCCESS = Counter("login_success_total", "Total successful logins")
LOGIN_FAILURES = Counter("login_failures_total", "Total failed logins")
VULN_DETECTED = Counter("vulnerabilities_detected_total", "Total vulnerabilities detected")
SYNC_DURATION_MS = Histogram("sync_duration_ms", "Sync duration in ms")

metrics_app = make_asgi_app()
"""
with open(os.path.join(base_path, "metrics.py"), 'w', encoding='utf-8') as f: f.write(metrics_py)


schemas_auth_py = """from pydantic import BaseModel

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str
"""
with open(os.path.join(base_path, "schemas", "auth.py"), 'w', encoding='utf-8') as f: f.write(schemas_auth_py)


schemas_user_py = """from pydantic import BaseModel

class NewUserRequest(BaseModel):
    username: str
    password: str
"""
with open(os.path.join(base_path, "schemas", "user.py"), 'w', encoding='utf-8') as f: f.write(schemas_user_py)


schemas_wazuh_py = """from pydantic import BaseModel

class WazuhConnectionRequest(BaseModel):
    name: str
    indexer_url: str
    wazuh_user: str
    wazuh_password: str

class WazuhConnectionResponse(BaseModel):
    id: int
    name: str
    indexer_url: str
    wazuh_user: str
    is_active: bool
"""
with open(os.path.join(base_path, "schemas", "wazuh.py"), 'w', encoding='utf-8') as f: f.write(schemas_wazuh_py)


services_auth_py = """import re
from fastapi import HTTPException

def validate_strong_password(password: str) -> None:
    errors = []
    if len(password) < 8:
        errors.append("mínimo 8 caracteres")
    if not re.search(r"[A-Z]", password):
        errors.append("al menos una letra mayúscula")
    if not re.search(r"[a-z]", password):
        errors.append("al menos una letra minúscula")
    if not re.search(r"\d", password):
        errors.append("al menos un número")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
        errors.append("al menos un carácter especial (!@#$%^&*...)")
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"La contraseña no es suficientemente robusta: {', '.join(errors)}",
        )
"""
with open(os.path.join(base_path, "services", "auth.py"), 'w', encoding='utf-8') as f: f.write(services_auth_py)


services_wazuh_py = """import logging
import time
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from ..models import WazuhConnection, WazuhVulnerability, VulnerabilityHistory
from ..metrics import SYNC_DURATION_MS, VULN_DETECTED
from ..wazuh_client import fetch_all_vulns
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
"""
with open(os.path.join(base_path, "services", "wazuh.py"), 'w', encoding='utf-8') as f: f.write(services_wazuh_py)


routers_auth_py = """from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Annotated

from ..db import get_db
from ..models import User
from ..metrics import LOGIN_ATTEMPTS, LOGIN_SUCCESS, LOGIN_FAILURES
from ..auth import authenticate_user, create_access_token, get_current_user, hash_password, verify_password
from ..schemas.auth import ChangePasswordRequest
from ..services.auth import validate_strong_password

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    LOGIN_ATTEMPTS.inc()
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        LOGIN_FAILURES.inc()
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")
    LOGIN_SUCCESS.inc()
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/change-password")
def change_password(
    request: ChangePasswordRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    if not verify_password(request.old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="La contraseña antigua es incorrecta")

    if request.old_password == request.new_password:
        raise HTTPException(status_code=400, detail="La nueva contraseña debe ser diferente a la anterior")

    if request.new_password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Las contraseñas nuevas no coinciden")

    validate_strong_password(request.new_password)

    current_user.password_hash = hash_password(request.new_password)
    current_user.is_active = True 
    current_user.is_default_password = False

    db.add(current_user)
    db.commit()

    return {"message": "Contraseña actualizada exitosamente"}
"""
with open(os.path.join(base_path, "routers", "auth.py"), 'w', encoding='utf-8') as f: f.write(routers_auth_py)


routers_users_py = """from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import User
from ..auth import get_current_user, hash_password
from ..schemas.user import NewUserRequest

router = APIRouter(prefix="/users", tags=["users"])

@router.get("/me")
def get_user_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "is_active": current_user.is_active,
        "is_default_password": current_user.is_default_password,
    }

@router.post("")
def create_user(
    request: NewUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    existing = db.query(User).filter(User.username == request.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya esta ocupado. Elige otro.")

    new_user = User(
        username=request.username, 
        password_hash=hash_password(request.password),
        is_default_password=True,
    )
    db.add(new_user)
    db.commit()
    return {"message": "Usuario creado"}

@router.get("")
def list_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username} for u in users]

@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="No puedes eliminarte a ti mismo")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db.delete(user)
    db.commit()
    return {"message": "Usuario eliminado"}
"""
with open(os.path.join(base_path, "routers", "users.py"), 'w', encoding='utf-8') as f: f.write(routers_users_py)


routers_connections_py = """from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from ..db import get_db
from ..models import User, WazuhConnection
from ..auth import get_current_user
from ..schemas.wazuh import WazuhConnectionRequest, WazuhConnectionResponse
from ..wazuh_client import test_connection
from ..crypto import encrypt, decrypt
from ..services.wazuh import perform_sync_task

router = APIRouter(prefix="/wazuh-connections", tags=["connections"])
CONNECTION_NOT_FOUND = "Conexión no encontrada"

@router.get("")
def list_connections(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    conns = db.query(WazuhConnection).all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "indexer_url": c.indexer_url,
            "wazuh_user": c.wazuh_user,
            "is_active": c.is_active,
            "tested": c.tested,
            "last_tested_at": c.last_tested_at,
            "last_test_ok": c.last_test_ok,
        }
        for c in conns
    ]

@router.post("", status_code=201)
def create_connection(
    request: WazuhConnectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if db.query(WazuhConnection).filter(WazuhConnection.name == request.name).first():
        raise HTTPException(status_code=400, detail="Ya existe una conexión con ese nombre")

    ok = test_connection(request.indexer_url, request.wazuh_user, request.wazuh_password)
    if not ok:
        raise HTTPException(status_code=400, detail="No se pudo establecer conexión con el indexador Wazuh")

    conn = WazuhConnection(
        name=request.name,
        indexer_url=request.indexer_url,
        wazuh_user=request.wazuh_user,
        wazuh_password=encrypt(request.wazuh_password),
        tested=True,
        last_tested_at=func.now(),
        last_test_ok=True,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return {"message": "Conexión creada", "id": conn.id}

@router.put("/{conn_id}")
def update_connection(
    conn_id: int,
    request: WazuhConnectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)

    conn.name = request.name
    conn.indexer_url = request.indexer_url
    conn.wazuh_user = request.wazuh_user
    if request.wazuh_password:
        conn.wazuh_password = encrypt(request.wazuh_password)
    db.commit()
    return {"message": "Conexión actualizada"}

@router.delete("/{conn_id}")
def delete_connection(
    conn_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)
    db.delete(conn)
    db.commit()
    return {"message": "Conexión eliminada"}

@router.post("/{conn_id}/test")
def test_wazuh_connection_endpoint(
    conn_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)

    ok = test_connection(conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password))

    conn.tested = True
    conn.last_tested_at = func.now()
    conn.last_test_ok = ok
    db.commit()

    return {"ok": ok, "message": "Conexión exitosa" if ok else "No se pudo conectar"}

@router.post("/{conn_id}/sync")
def sync_connection(
    conn_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)
    if not conn.is_active:
        raise HTTPException(status_code=400, detail="La conexión está inactiva")

    background_tasks.add_task(perform_sync_task, conn.id, current_user.username)
    return {"message": "Sincronización iniciada en segundo plano. Esto puede tomar unos minutos."}
"""
with open(os.path.join(base_path, "routers", "connections.py"), 'w', encoding='utf-8') as f: f.write(routers_connections_py)


routers_vulnerabilities_py = """from fastapi import APIRouter, Depends, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from typing import Optional, List
from ..db import get_db
from ..models import User, WazuhConnection, WazuhVulnerability
from ..auth import get_current_user
from ..services.wazuh import perform_sync_task

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
"""
with open(os.path.join(base_path, "routers", "vulnerabilities.py"), 'w', encoding='utf-8') as f: f.write(routers_vulnerabilities_py)


routers_system_py = """from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy.sql import text
from ..db import SessionLocal

router = APIRouter(tags=["system"])

@router.get("/health")
def health():
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        db.close()
        return JSONResponse(status_code=200, content={"status": "ok", "database": "ok"})
    except Exception as e:
        try:
            db.close()
        except Exception:
            pass
        return JSONResponse(status_code=503, content={"status": "fail", "database": "error", "details": str(e)})

@router.get("/logs")
def recent_logs(lines: int = 200):
    try:
        from ..logging_config import get_recent_logs
        return {"lines": get_recent_logs(lines)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "failed_to_read_logs", "details": str(e)})
"""
with open(os.path.join(base_path, "routers", "system.py"), 'w', encoding='utf-8') as f: f.write(routers_system_py)


main_py = """# app/main.py
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.sql import text

from .db import Base, engine, SessionLocal
from .logging_config import configure_logging
from .models import User
from .auth import hash_password
from .metrics import metrics_app

from .routers import auth, users, connections, vulnerabilities, system

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    OTEL_AVAILABLE = True
except Exception:
    OTEL_AVAILABLE = False

configure_logging()
log = logging.getLogger(__name__)

Base.metadata.create_all(bind=engine)

def setup_timescaledb():
    db = SessionLocal()
    try:
        log.info("initializing_timescaledb_features")
        db.execute(text("SELECT create_hypertable('user_interactions', 'timestamp', if_not_exists => TRUE);"))
        db.execute(text("SELECT create_hypertable('vulnerability_history', 'timestamp', if_not_exists => TRUE);"))
        db.execute(text(\"\"\"
            ALTER TABLE vulnerability_history SET (
                timescaledb.compress,
                timescaledb.compress_segmentby = 'vulnerability_id'
            );
        \"\"\"))
        db.execute(text(\"\"\"
            SELECT add_compression_policy('vulnerability_history', INTERVAL '7 days')
            WHERE NOT EXISTS (
                SELECT 1 FROM timescaledb_information.jobs 
                WHERE proc_name = 'policy_compression' 
                AND hypertable_name = 'vulnerability_history'
            );
        \"\"\"))
        db.commit()
        log.info("timescaledb_setup_complete")
    except Exception as e:
        log.error(f"Error en setup de TimescaleDB: {e}")
        db.rollback()
    finally:
        db.close()

setup_timescaledb()

def create_default_admin():
    db = SessionLocal()
    try:
        admin_exists = db.query(User).filter(User.username == "admin").first()
        if not admin_exists:
            log.info("creating_default_admin_user")
            default_admin = User(
                username="admin", 
                password_hash=hash_password("admin"), 
                is_active=True,
                is_default_password=True,
            )
            db.add(default_admin)
            db.commit()
    finally:
        db.close()

create_default_admin()

app = FastAPI(title="Vulnerability Aggregator API", root_path="/api")

if OTEL_AVAILABLE:
    resource = Resource.create({"service.name": "vuln-api"})
    trace.set_tracer_provider(TracerProvider(resource=resource))
    span_processor = BatchSpanProcessor(ConsoleSpanExporter())
    trace.get_tracer_provider().add_span_processor(span_processor)
    try:
        FastAPIInstrumentor.instrument_app(app)
        RequestsInstrumentor().instrument()
        log.info("opentelemetry_instrumentation_enabled")
    except Exception as e:
        log.warning(f"opentelemetry_instrumentation_failed: {e}")
else:
    log.info("opentelemetry_not_available")

app.mount("/metrics", metrics_app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(connections.router)
app.include_router(vulnerabilities.router)
app.include_router(system.router)
"""

with open(os.path.join(base_path, "main.py"), 'w', encoding='utf-8') as f: f.write(main_py)

print("Refactor completo.")
