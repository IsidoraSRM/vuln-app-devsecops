from pydantic import BaseModel
from typing import Optional

class NewUserRequest(BaseModel):
    username: str
    password: str
    role: Optional[str] = "operator"
    assigned_connection_id: Optional[int] = None

class UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    assigned_connection_id: Optional[int] = None
    password: Optional[str] = None
