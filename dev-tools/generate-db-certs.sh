#!/bin/bash
set -e

CERT_DIR="./db-ssl"
mkdir -p "$CERT_DIR"

echo "Generando certificados SSL para PostgreSQL..."

# 1. Crear CA (Autoridad Certificadora) local
openssl req -new -x509 -days 365 -nodes \
    -out "$CERT_DIR/ca.crt" \
    -keyout "$CERT_DIR/ca.key" \
    -subj "/C=CL/ST=RM/L=Santiago/O=DevSecOps/CN=LocalCA" 2>/dev/null

# 2. Crear clave privada para el servidor Postgres
openssl genrsa -out "$CERT_DIR/server.key" 2048 2>/dev/null

# 3. Crear CSR (Certificate Signing Request) para el servidor
openssl req -new -nodes \
    -out "$CERT_DIR/server.csr" \
    -keyout "$CERT_DIR/server.key" \
    -subj "/C=CL/ST=RM/L=Santiago/O=DevSecOps/CN=db-api" 2>/dev/null

# 4. Firmar el certificado del servidor con nuestra CA local
openssl x509 -req -days 365 \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/server.crt" 2>/dev/null

# Limpiar CSR no necesario
rm -f "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl"

# Asegurar permisos legibles para copiar (el compose los restringirá a 600 dentro del contenedor)
chmod 644 "$CERT_DIR/server.key" "$CERT_DIR/ca.key" "$CERT_DIR/server.crt" "$CERT_DIR/ca.crt"

echo "Certificados generados en $CERT_DIR"
