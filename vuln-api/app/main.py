# app/main.py
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.sql import text

from .db import Base, engine, SessionLocal
from .logging_config import configure_logging
from .models import User
from .services.authService import hash_password
from .metrics import metrics_app

from .routers import authRouter, usersRouter, connectionsRouter, vulnerabilitiesRouter, systemRouter, metricsRouter

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
        db.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;"))
        db.execute(text("SELECT create_hypertable('user_interactions', 'timestamp', if_not_exists => TRUE);"))
        db.execute(text("SELECT create_hypertable('vulnerability_history', 'timestamp', if_not_exists => TRUE);"))
        db.execute(text("""
            ALTER TABLE vulnerability_history SET (
                timescaledb.compress,
                timescaledb.compress_segmentby = 'vulnerability_id'
            );
        """))
        db.execute(text("""
            SELECT add_compression_policy('vulnerability_history', INTERVAL '7 days')
            WHERE NOT EXISTS (
                SELECT 1 FROM timescaledb_information.jobs 
                WHERE proc_name = 'policy_compression' 
                AND hypertable_name = 'vulnerability_history'
            );
        """))
        db.commit()
        log.info("timescaledb_setup_complete")
    except Exception as e:
        log.error(f"Error en setup de TimescaleDB: {e}")
        db.rollback()
    finally:
        db.close()

setup_timescaledb()

def setup_db_optimizations():
    db = SessionLocal()
    try:
        log.info("creating_database_indexes")
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_vuln_severity ON wazuh_vulnerabilities (severity);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_vuln_agent_name ON wazuh_vulnerabilities (agent_name);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_vuln_cve_id ON wazuh_vulnerabilities (cve_id);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_vuln_package_name ON wazuh_vulnerabilities (package_name);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_vuln_score_base ON wazuh_vulnerabilities (score_base);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_vuln_last_seen ON wazuh_vulnerabilities (last_seen);"))
        # (status, first_seen): index-only scan para la exposicion en curso (activas por antiguedad)
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_vuln_status_first_seen ON wazuh_vulnerabilities (status, first_seen);"))
        db.commit()
    except Exception as e:
        log.warning(f"No se pudieron crear los índices estándar (puede ser SQLite): {e}")
        db.rollback()

    try:
        log.info("creating_materialized_views_and_procedures")
        db.execute(text("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS mv_unique_agents AS 
            SELECT DISTINCT connection_id, agent_name FROM wazuh_vulnerabilities;
        """))
        db.execute(text("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS mv_unique_cves AS 
            SELECT DISTINCT connection_id, cve_id FROM wazuh_vulnerabilities;
        """))
        db.execute(text("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS mv_unique_packages AS 
            SELECT DISTINCT connection_id, package_name FROM wazuh_vulnerabilities;
        """))
        db.execute(text("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS mv_unique_severities AS 
            SELECT DISTINCT connection_id, severity FROM wazuh_vulnerabilities;
        """))
        db.execute(text("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS mv_unique_os AS 
            SELECT DISTINCT connection_id, os_platform, os_version FROM wazuh_vulnerabilities;
        """))
        # Resumen del dashboard PRE-AGREGADO (mv_metrics_summary). Medido: el COUNT(DISTINCT cve_id)
        # en vivo tarda ~4.4s a 2M filas POR CADA carga del dashboard; leerlo de la MV es ~0.5ms.
        # GROUPING SETS ((connection_id),()) da una fila por conexion + una grand-total (connection_id
        # NULL) para "todas las conexiones". El refresh (1 vez por sync) hace el trabajo pesado.
        db.execute(text("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS mv_metrics_summary AS
            SELECT connection_id,
                COUNT(DISTINCT cve_id) AS total,
                COUNT(DISTINCT cve_id) FILTER (WHERE UPPER(severity) = 'CRITICAL') AS critical,
                COUNT(DISTINCT cve_id) FILTER (WHERE UPPER(severity) = 'HIGH') AS high,
                COUNT(DISTINCT cve_id) FILTER (WHERE UPPER(severity) = 'MEDIUM') AS medium,
                COUNT(DISTINCT cve_id) FILTER (WHERE UPPER(severity) NOT IN ('CRITICAL','HIGH','MEDIUM') OR severity IS NULL) AS low
            FROM wazuh_vulnerabilities
            WHERE status = 'ACTIVE'
            GROUP BY GROUPING SETS ((connection_id), ());
        """))
        # Conteos PRE-AGREGADOS por (conexion, estado, severidad) para el TOTAL de la lista /vulns.
        # Contar el subconjunto filtrado en vivo (id IN (SELECT id FROM sp(...))) tarda ~1.6s a 1M;
        # sumar sobre esta MV (~20 filas) es ~0.1ms. list_vulns la usa cuando el filtro es solo
        # estado/severidad/conexion (el caso del dashboard); con filtros avanzados cae al conteo en vivo.
        db.execute(text("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS mv_vuln_counts AS
            SELECT connection_id, UPPER(status) AS status, UPPER(severity) AS severity, COUNT(*) AS n
            FROM wazuh_vulnerabilities
            GROUP BY connection_id, UPPER(status), UPPER(severity);
        """))
        db.execute(text("""
            CREATE OR REPLACE FUNCTION refresh_vulnerability_filters() RETURNS void AS $$
            BEGIN
                REFRESH MATERIALIZED VIEW mv_unique_agents;
                REFRESH MATERIALIZED VIEW mv_unique_cves;
                REFRESH MATERIALIZED VIEW mv_unique_packages;
                REFRESH MATERIALIZED VIEW mv_unique_severities;
                REFRESH MATERIALIZED VIEW mv_unique_os;
                REFRESH MATERIALIZED VIEW mv_metrics_summary;
                REFRESH MATERIALIZED VIEW mv_vuln_counts;
            END;
            $$ LANGUAGE plpgsql;
        """))
        
        # Cargar y ejecutar procedimientos almacenados adicionales
        import os
        sql_path = os.path.join(os.path.dirname(__file__), "db-scripts", "30-stored-procedures.sql")
        if os.path.exists(sql_path):
            log.info("applying_stored_procedures")
            with open(sql_path, "r", encoding="utf-8") as f:
                sql_content = f.read()
                db.execute(text(sql_content))
                
        db.commit()
        log.info("materialized_views_and_procedures_setup_complete")
    except Exception as e:
        log.warning(f"No se pudieron crear las vistas materializadas o los procedimientos almacenados: {e}")
        db.rollback()
    finally:
        db.close()

setup_db_optimizations()

def run_database_migrations():
    from .models import IS_SQLITE
    if not IS_SQLITE:
        db = SessionLocal()
        try:
            log.info("running_database_migrations_for_roles")
            db.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR DEFAULT 'superadmin';"))
            db.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS assigned_connection_id INTEGER REFERENCES wazuh_connections(id) ON DELETE SET NULL;"))
            db.commit()
            log.info("database_migrations_completed")
        except Exception as e:
            log.warning(f"Error during user roles database migration: {e}")
            db.rollback()
        finally:
            db.close()

run_database_migrations()

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
                role="superadmin"
            )
            db.add(default_admin)
            db.commit()
        else:
            if admin_exists.role != "superadmin":
                log.info("updating_existing_admin_role_to_superadmin")
                admin_exists.role = "superadmin"
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

app.include_router(authRouter.router)
app.include_router(usersRouter.router)
app.include_router(connectionsRouter.router)
app.include_router(vulnerabilitiesRouter.router)
app.include_router(systemRouter.router)
app.include_router(metricsRouter.router)
