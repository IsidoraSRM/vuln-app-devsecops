# Guía de Conexión a Wazuh (Local y Producción)

Este documento detalla los pasos y comandos necesarios para levantar un entorno Wazuh de pruebas y cómo conectar la aplicación `vuln-app-devsecops` a cualquier servidor Wazuh (como el del profesor).

---

## Parte 1: Levantar Wazuh Local (Para Pruebas)

Si necesitas volver a levantar el entorno de Wazuh local en tu Windows (Docker Desktop), sigue estos comandos:

1. **Dar permisos de memoria en Windows (WSL2):**
   *Abre PowerShell y ejecuta:*
   ```bash
   wsl -d docker-desktop sysctl -w vm.max_map_count=262144
   ```

2. **Descargar el repositorio oficial de Wazuh:**
   ```bash
   git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0 wazuh-docker
   ```

3. **Generar certificados y levantar contenedores:**
   ```bash
   cd wazuh-docker/single-node
   docker-compose -f generate-indexer-certs.yml run --rm generator
   docker-compose up -d
   ```

4. **Datos de Acceso Local:**
   * **Dashboard Visual:** `https://localhost`
   * **Base de Datos (Indexer):** `https://localhost:9200`
   * **Usuario:** `admin`
   * **Contraseña:** `SecretPassword`

---

## Parte 2: Conectar la Aplicación a Wazuh

Ya sea para tu Wazuh local o para el del profesor, el proceso en la aplicación es idéntico.

### Paso 2.1: Levantar la Aplicación
Debes tener corriendo tu base de datos PostgreSQL local (pgAdmin) y ejecutar el backend y frontend:

**Terminal 1 (Backend):**
```bash
cd vuln-api
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**Terminal 2 (Frontend):**
```bash
cd frontend
npm run dev
```

### Paso 2.2: Registrar la Conexión en la Interfaz
1. Abre tu navegador en `http://localhost:5173`.
2. Inicia sesión en tu aplicación.
3. Ve a la sección para **Agregar Conexión**.
4. Ingresa los datos dependiendo del caso:

**Si es tu Wazuh Local:**
* **URL:** `https://localhost:9200`
* **Usuario:** `admin`
* **Contraseña:** `SecretPassword`

**Si es el Wazuh del Profe:**
* **URL:** `https://<IP-DEL-PROFE>:9200`
* **Usuario:** `admin` (o el que te dé)
* **Contraseña:** `<LA-CLAVE-QUE-TE-DE>`

5. Guarda la conexión y presiona el botón **Sincronizar**. El backend extraerá automáticamente las vulnerabilidades.

---

## Parte 3: Plan B (Si el profe entrega un archivo de Texto Plano)

Si el profesor, por motivos de seguridad o de red, no les da acceso a la IP y en su lugar les entrega un archivo exportado (ej. `vulnerabilidades.json`), el botón de "Sincronizar" no servirá directamente.

**¿Qué hacer en ese caso?**
1. Recibe el archivo `.json`.
2. Ejecutaremos un script en Python (similar al que usamos para inyectar datos de prueba) que lea ese archivo localmente y llame directamente a la función `process_wazuh_vulnerabilities` de tu backend.
3. Esto poblará tu base de datos de PostgreSQL con las vulnerabilidades del archivo exactamente como si se hubieran descargado por red.
