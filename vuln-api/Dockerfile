FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV UVICORN_HOST=0.0.0.0
ENV UVICORN_PORT=8000

EXPOSE 8000

# Un solo proceso a proposito: el buffer de logs en memoria (vista /logs) y el setup de las MV al
# arranque son por-proceso; con varios workers /logs se vuelve inconsistente y el setup choca. El
# rendimiento del dashboard lo sostiene el cap de /filters (no hacia falta paralelismo de procesos).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]