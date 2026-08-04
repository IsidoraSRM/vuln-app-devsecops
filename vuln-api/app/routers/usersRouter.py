from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import User, WazuhConnection
from ..services.authService import get_current_user, hash_password, validate_strong_password
from ..schemas.userSchema import NewUserRequest, UpdateUserRequest

router = APIRouter(prefix="/users", tags=["users"])

@router.get("/me")
def get_user_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "is_active": current_user.is_active,
        "is_default_password": current_user.is_default_password,
        "role": current_user.role,
        "assigned_connection_id": current_user.assigned_connection_id,
    }

@router.post("")
def create_user(
    request: NewUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=403, detail="No tienes permisos para realizar esta acción")

    existing = db.query(User).filter(User.username == request.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya esta ocupado. Elige otro.")

    assigned_id = request.assigned_connection_id
    if assigned_id and assigned_id > 0:
        conn = db.query(WazuhConnection).filter(WazuhConnection.id == assigned_id).first()
        if not conn:
            raise HTTPException(status_code=400, detail="Conexión de Wazuh no encontrada")
    else:
        assigned_id = None

    new_user = User(
        username=request.username, 
        password_hash=hash_password(request.password),
        is_default_password=True,
        role=request.role or "operator",
        assigned_connection_id=assigned_id,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    return {"message": "Usuario creado"}

@router.get("")
def list_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=403, detail="No tienes permisos para realizar esta acción")
    users = db.query(User).all()
    return [
        {
            "id": u.id, 
            "username": u.username,
            "role": u.role,
            "assigned_connection_id": u.assigned_connection_id,
            "assigned_connection_name": u.assigned_connection.name if u.assigned_connection else None,
            "is_active": u.is_active,
            "is_default_password": u.is_default_password
        } for u in users
    ]

@router.put("/{user_id}")
def update_user(
    user_id: int,
    request: UpdateUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=403, detail="No tienes permisos para realizar esta acción")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if request.role:
        if request.role not in ("superadmin", "operator"):
            raise HTTPException(status_code=400, detail="Rol inválido")
        user.role = request.role

    if request.assigned_connection_id is not None:
        if request.assigned_connection_id <= 0:
            user.assigned_connection_id = None
        else:
            conn = db.query(WazuhConnection).filter(WazuhConnection.id == request.assigned_connection_id).first()
            if not conn:
                raise HTTPException(status_code=400, detail="Conexión de Wazuh no encontrada")
            user.assigned_connection_id = request.assigned_connection_id
    else:
        user.assigned_connection_id = None

    if request.password:
        validate_strong_password(request.password)
        user.password_hash = hash_password(request.password)
        user.is_default_password = True

    db.commit()
    return {"message": "Usuario actualizado exitosamente"}

@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=403, detail="No tienes permisos para realizar esta acción")

    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="No puedes eliminarte a ti mismo")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db.delete(user)
    db.commit()
    return {"message": "Usuario eliminado"}
