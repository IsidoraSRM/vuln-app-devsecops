# 1. Crear carpeta para los certificados
$db_ssl_path = "$($PWD.Path)\db-ssl"
New-Item -ItemType Directory -Force -Path $db_ssl_path | Out-Null

$env:MSYS_NO_PATHCONV=1

Write-Host "Generando certificados SSL para PostgreSQL usando Docker..."

# Generar CA
docker run --rm -v "${db_ssl_path}:/ssl" alpine/openssl req -new -x509 -days 365 -nodes -out /ssl/ca.crt -keyout /ssl/ca.key -subj "/C=CL/ST=RM/L=Santiago/O=DevSecOps/CN=LocalCA"

# Generar clave del servidor
docker run --rm -v "${db_ssl_path}:/ssl" alpine/openssl genrsa -out /ssl/server.key 2048

# Generar CSR
docker run --rm -v "${db_ssl_path}:/ssl" alpine/openssl req -new -nodes -out /ssl/server.csr -keyout /ssl/server.key -subj "/C=CL/ST=RM/L=Santiago/O=DevSecOps/CN=db-api"

# Firmar certificado
docker run --rm -v "${db_ssl_path}:/ssl" alpine/openssl x509 -req -days 365 -in /ssl/server.csr -CA /ssl/ca.crt -CAkey /ssl/ca.key -CAcreateserial -out /ssl/server.crt

# Limpiar CSR
Remove-Item -Force "${db_ssl_path}\server.csr", "${db_ssl_path}\ca.srl" -ErrorAction SilentlyContinue

# IMPORTANTE: Cambiar los permisos de los archivos generados en Windows/Linux para que el usuario unprivileged de Postgres (postgres, UID 999) los pueda leer
docker run --rm -v "${db_ssl_path}:/ssl" alpine chmod 644 /ssl/server.key /ssl/ca.key /ssl/server.crt /ssl/ca.crt

Write-Host "Certificados generados exitosamente en ./db-ssl"
