#!/bin/bash
set -e

# Fuerza SSL en las conexiones TCP SOLO si ENFORCE_DB_SSL=true (produccion, donde la
# BD corre con ssl=on y certificados). En dev/CI, sin ese flag, se permiten conexiones
# normales para no romper el arranque de la API (que no usa SSL en esos entornos).
# Antes esto era incondicional y dejaba pg_hba en "SSL obligatorio" aunque SSL estuviera
# apagado -> la API era rechazada con "no pg_hba.conf entry ... no encryption".
if [ "${ENFORCE_DB_SSL}" = "true" ]; then
    echo "=== Forzando SSL en pg_hba.conf (produccion) ==="
    # Reemplaza conexiones "host" (no cifradas) por "hostssl" (cifradas obligatorias).
    sed -i 's/^host /hostssl /g' "$PGDATA/pg_hba.conf"
    echo "=== pg_hba.conf actualizado: SSL obligatorio ==="
else
    echo "=== SSL no forzado (ENFORCE_DB_SSL != true): conexiones normales permitidas ==="
fi
