from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy.sql import text
from prometheus_client import REGISTRY
from ..db import SessionLocal

router = APIRouter(tags=["system"])

@router.get("/health")
def health():
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        db.close()
        return JSONResponse(status_code=200, content={"status": "ok", "database": "ok"})
    except Exception as e:
        try:
            db.close()
        except Exception:
            pass
        return JSONResponse(status_code=503, content={"status": "fail", "database": "error", "details": str(e)})

@router.get("/logs")
def recent_logs(lines: int = 200):
    try:
        from ..logging_config import get_recent_logs
        return {"lines": get_recent_logs(lines)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "failed_to_read_logs", "details": str(e)})


@router.get("/metrics-summary")
def metrics_summary():
    """Devuelve las metricas de Prometheus en formato JSON plano para consumo del frontend.
    Se llama 'metrics-summary' (sin slash) porque app.mount('/metrics') captura cualquier /metrics/*.
    """
    result = {}
    for metric in REGISTRY.collect():
        for sample in metric.samples:
            # sample.name incluye sufijos: _total, _created, _bucket, _sum, _count
            if sample.labels:
                key = f"{sample.name}{{{','.join(f'{k}={v}' for k, v in sorted(sample.labels.items()))}}}"
            else:
                key = sample.name
            result[key] = sample.value
    return result
