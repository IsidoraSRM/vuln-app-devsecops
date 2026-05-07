from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session


from database import engine, get_db
import models


models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Wazuh Middleware API")

@app.get("/")
def health_check():
    return {"status": "Capa de Integración activa", "db": "Tablas sincronizadas"}