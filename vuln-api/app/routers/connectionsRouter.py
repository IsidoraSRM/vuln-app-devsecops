from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from ..db import get_db
from ..models import User, WazuhConnection
from ..services.authService import get_current_user
from ..schemas.wazuhSchema import WazuhConnectionRequest, WazuhConnectionResponse
from ..services.providerFactory import VulnerabilityProviderFactory
from ..crypto import encrypt, decrypt
from ..services.wazuhService import perform_sync_task

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
            "provider_type": c.provider_type,
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

    provider_type = request.provider_type or "wazuh"
    try:
        provider = VulnerabilityProviderFactory.get_provider(provider_type)
        ok = provider.test_connection(request.indexer_url, request.wazuh_user, request.wazuh_password)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))

    if not ok:
        raise HTTPException(status_code=400, detail=f"No se pudo establecer conexión con el indexador ({provider_type})")

    conn = WazuhConnection(
        name=request.name,
        indexer_url=request.indexer_url,
        wazuh_user=request.wazuh_user,
        wazuh_password=encrypt(request.wazuh_password),
        provider_type=provider_type,
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
    conn.provider_type = request.provider_type or "wazuh"
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

    provider = VulnerabilityProviderFactory.get_provider(conn.provider_type)
    ok = provider.test_connection(conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password))

    conn.tested = True
    conn.last_tested_at = func.now()
    conn.last_test_ok = ok
    db.commit()

    return {"ok": ok, "message": "Conexión exitosa" if ok else "No se pudo conectar"}

@router.post("/{conn_id}/sync", status_code=202)
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
    return {"message": "Sincronización en segundo plano iniciada. Esto puede tomar unos minutos."}
