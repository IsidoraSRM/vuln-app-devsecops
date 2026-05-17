# app/logging_config.py
"""
Logging estructurado en formato JSON para observabilidad.

Cada log line es un objeto JSON con:
- timestamp ISO 8601 UTC
- level (INFO, WARNING, ERROR, etc.)
- logger (modulo origen)
- event (mensaje principal)
- extra fields que el caller pase via logger.info("evento", extra={...})
"""
import json
import logging
import os
import sys
from datetime import datetime, timezone
from collections import deque
from threading import Lock


RESERVED_LOG_RECORD_KEYS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "taskName",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }

        # Cualquier campo extra que el caller haya pasado via `extra={...}` se incluye en el JSON.
        for key, value in record.__dict__.items():
            if key not in RESERVED_LOG_RECORD_KEYS and not key.startswith("_"):
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    
    global _LOG_BUFFER, _LOG_BUFFER_LOCK
    _LOG_BUFFER = deque(maxlen=int(os.getenv("LOG_BUFFER_MAX", "1000")))
    _LOG_BUFFER_LOCK = Lock()

    class InMemoryHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            try:
                line = JsonFormatter().format(record)
                with _LOG_BUFFER_LOCK:
                    _LOG_BUFFER.append(line)
            except Exception:
                pass

    mem_handler = InMemoryHandler()

    root = logging.getLogger()
    # Evitar duplicar handlers si configure_logging() se llama mas de una vez.
    root.handlers = [handler, mem_handler]
    root.setLevel(level)

    # Calmar el ruido de uvicorn duplicando access logs.
    logging.getLogger("uvicorn.access").handlers = [handler]
    logging.getLogger("uvicorn.access").propagate = False
    logging.getLogger("uvicorn.error").handlers = [handler]
    logging.getLogger("uvicorn.error").propagate = False


def get_recent_logs(lines: int = 200):
    try:
        with _LOG_BUFFER_LOCK:
            return list(_LOG_BUFFER)[-int(lines):]
    except Exception:
        return []
