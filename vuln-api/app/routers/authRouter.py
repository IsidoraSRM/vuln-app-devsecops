from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Annotated

from ..db import get_db
from ..models import User
from ..metrics import LOGIN_ATTEMPTS, LOGIN_SUCCESS, LOGIN_FAILURES
from ..services.authService import authenticate_user, create_access_token, get_current_user, hash_password, verify_password
from ..schemas.authSchema import ChangePasswordRequest
from ..services.authService import validate_strong_password

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
