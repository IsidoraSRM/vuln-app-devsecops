# ANTES DE EJECUTAR EN WINDOWS DESHABILITA LAS PROTECCIONES DE WINDOWS SECURITY
# CON EL SIGUIENTE COMANDO: 
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 1. (Omitido: Ya estás en la carpeta correcta)
# 2. Detener contenedores que puedan estar corriendo y limpiar carpetas viejas
docker compose down
Remove-Item -Recurse -Force ./certbot, ./nginx/ssl -ErrorAction SilentlyContinue

# 3. Copiar los archivos de configuración para versión "Local / Sin Dominio"
Copy-Item prod_config/docker-compose.nodomain.yml docker-compose.yml -Force
Copy-Item prod_config/nginx.nodomain.conf frontend/nginx.conf -Force

# 4. Crear la carpeta para los certificados SSL
New-Item -ItemType Directory -Force -Path ./nginx/ssl

# 5. Generar el certificado SSL de prueba (usamos un contenedor para no instalar openssl)
$env:MSYS_NO_PATHCONV=1
$ssl_path = "$($PWD.Path)\nginx\ssl"
docker run --rm -v "${ssl_path}:/ssl" alpine/openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /ssl/nginx-selfsigned.key -out /ssl/nginx-selfsigned.crt -subj "/C=CL/ST=RM/L=Santiago/O=Desarrollo/CN=localhost"

# 6. Construir y levantar la aplicación
docker compose up -d --build
