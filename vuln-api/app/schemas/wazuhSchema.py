from pydantic import BaseModel
from typing import Optional

class WazuhConnectionRequest(BaseModel):
    name: str
    indexer_url: str
    wazuh_user: str
    wazuh_password: str
    provider_type: Optional[str] = "wazuh"

class WazuhConnectionResponse(BaseModel):
    id: int
    name: str
    indexer_url: str
    wazuh_user: str
    provider_type: str
    is_active: bool
