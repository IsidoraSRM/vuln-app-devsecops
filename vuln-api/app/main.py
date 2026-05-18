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

from .routers import authRouter, usersRouter, connectionsRouter, vulnerabilitiesRouter, systemRouter

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
