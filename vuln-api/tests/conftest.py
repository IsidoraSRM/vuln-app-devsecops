import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

if "DATABASE_URL" not in os.environ:
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from app.main import app
from app.db import Base, get_db

# DATABASE_URL del entorno (CI usa Postgres efimero), fallback SQLite local.
# Los modelos tienen composite PK con autoincrement, que SQLite no soporta,
# por eso en CI necesitamos un Postgres real.
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///:memory:")

if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """Crea una sesión de base de datos limpia para cada test"""
    # Crear todas las tablas
    Base.metadata.create_all(bind=engine)
    
    # Crear sesión
    db = TestingSessionLocal()
    
    try:
        yield db
        # Hacer rollback de cualquier transacción pendiente
        db.rollback()
    finally:
        db.close()
        # Limpiar todas las tablas después de cada test
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    """Crea un cliente de prueba de FastAPI con la DB de prueba"""
    # Sobrescribir la dependencia get_db para usar nuestra DB de prueba
    def override_get_db():
        try:
            yield db_session
        finally:
            # No cerrar la sesión aquí, se cierra en el fixture db_session
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    
    # Crear el cliente de prueba
    with TestClient(app) as test_client:
        yield test_client
    
    # Limpiar los overrides después del test
    app.dependency_overrides.clear()
