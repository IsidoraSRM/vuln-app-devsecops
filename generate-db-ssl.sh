#!/bin/sh
# Genera los certificados TLS para la conexion segura con PostgreSQL.
# Estos archivos NO se versionan (contienen llaves privadas). Ejecutar en el host
# de la base de datos ANTES de desplegar; los compose de la BD montan db-ssl/ en /ssl.
#
# Uso:  sh generate-db-ssl.sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)/db-ssl"
mkdir -p "$DIR"
cd "$DIR"

echo "Generando certificados TLS de la BD en $DIR ..."

# 1. Autoridad certificadora (CA) propia
openssl req -new -x509 -days 3650 -nodes \
    -keyout ca.key -out ca.crt \
    -subj "/CN=vuln-app-db-ca"

# 2. Certificado del servidor, firmado por la CA
openssl req -new -nodes \
    -keyout server.key -out server.csr \
    -subj "/CN=db-api"
openssl x509 -req -in server.csr -days 3650 \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt

# 3. Permisos correctos y limpieza (postgres exige 600 en la llave privada)
chmod 600 server.key ca.key
rm -f server.csr ca.srl

echo "Listo. Certificados generados: ca.crt, ca.key, server.crt, server.key"
echo "La conexion desde la app usa DATABASE_URL con ?sslmode=require"
