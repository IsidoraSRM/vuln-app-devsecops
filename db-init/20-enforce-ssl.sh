#!/bin/bash
set -e

echo "=== Configurando Políticas de Conexión en pg_hba.conf ==="

# Modificar pg_hba.conf para reemplazar conexiones "host" (no cifradas) por "hostssl" (cifradas obligatorias)
# Esto asegura que cualquier conexión externa a través de TCP/IP deba usar SSL/TLS.
sed -i 's/^host /hostssl /g' "$PGDATA/pg_hba.conf"

echo "=== pg_hba.conf actualizado para requerir SSL ==="
