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
        db.execute(text("""
            CREATE OR REPLACE FUNCTION refresh_vulnerability_filters() RETURNS void AS $$
            BEGIN
                REFRESH MATERIALIZED VIEW mv_unique_agents;
                REFRESH MATERIALIZED VIEW mv_unique_cves;
                REFRESH MATERIALIZED VIEW mv_unique_packages;
                REFRESH MATERIALIZED VIEW mv_unique_severities;
                REFRESH MATERIALIZED VIEW mv_unique_os;
            END;
            $$ LANGUAGE plpgsql;
        """))
        db.commit()
        log.info("materialized_views_setup_complete")
    except Exception as e:
        log.warning(f"No se pudieron crear las vistas materializadas o la función de refresco: {e}")
        db.rollback()
    finally:
        db.close()

setup_db_optimizations()

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

app.include_router(authRouter.router)
app.include_router(usersRouter.router)
app.include_router(connectionsRouter.router)
app.include_router(vulnerabilitiesRouter.router)
app.include_router(systemRouter.router)
app.include_router(metricsRouter.router)
