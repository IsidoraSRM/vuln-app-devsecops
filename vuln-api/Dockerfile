FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV UVICORN_HOST=0.0.0.0
ENV UVICORN_PORT=8000
ENV UVICORN_WORKERS=4

EXPOSE 8000

# Varios workers (procesos separados) => sin GIL compartido: las llamadas del dashboard
# (/filters, /vulns, /summary) se atienden en PARALELO en vez de serializarse detras de la mas
# pesada. Ajustable via UVICORN_WORKERS segun las vCPUs de la VM.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${UVICORN_WORKERS}"]