
# Guía para ejecución Local


Esta guía detalla los pasos para ejecutar la aplicación (Frontend y Backend) de forma nativa en tu máquina local para desarrollo, conectándose a una base de datos PostgreSQL local gestionada mediante pgAdmin.

## 1. Configuración de Base de Datos (pgAdmin)

Para desarrollo local, no utilizaremos el contenedor de base de datos de Docker, sino tu propia instancia local.

1. Abre **pgAdmin**.
2. Crea una nueva base de datos vacía (por ejemplo: `vulnerabilidades_db`).

## 2. Configuración de Variables de Entorno

El proyecto usa un archivo `.env` en la raíz para leer las credenciales. Si acabas de clonar el repositorio, copia el archivo de ejemplo:

1. Crea o edita el archivo `.env` en la carpeta principal del proyecto (donde está esta guía).
2. Asegúrate de que las variables de la base de datos coincidan con las de tu pgAdmin:

```env
# URL base para el Frontend conectándose al Backend local
VITE_API_URL=http://localhost:8000

# Credenciales de tu pgAdmin local
POSTGRES_DB=vulnerabilidades_db
POSTGRES_USER=tu_usuario_de_pgadmin
POSTGRES_PASSWORD=tu_contraseña

# Seguridad
ENCRYPTION_KEY=PON_TU_LLAVE_DE_ENCRIPTACION_AQUI
SECRET_KEY=supersecret
```

*Nota: La aplicación armará la URL de conexión automáticamente usando estos datos y asumiendo que el host es `localhost` y el puerto `5432`.*

## 3. Ejecutar el Backend (FastAPI)

El backend utiliza Python y FastAPI. Al ejecutarse por primera vez y conectarse a la base de datos, **creará las tablas automáticamente**.

1. Abre una terminal y navega a la carpeta del backend:
   ```bash
   cd vuln-api
   ```
2. (Recomendado) Crea y activa un entorno virtual de Python:
   ```bash
   python -m venv venv
   
   # En Windows:
   .\venv\Scripts\activate
   # En Linux/Mac:
   source venv/bin/activate
   ```
3. Instala las dependencias necesarias:
   ```bash
   pip install -r requirements.txt
   ```
4. Levanta el servidor de desarrollo:
   ```bash
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
5. Ve a tu **pgAdmin**, refresca la sección "Tables" de tu base de datos y verás que todas las tablas ya han sido creadas.
6. Puedes acceder a la documentación interactiva de la API en: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## 4. Ejecutar el Frontend (Vue / Vite)

El frontend está desarrollado con Vue.js y utiliza Vite como servidor de desarrollo, lo que permite ver los cambios en el código en tiempo real ("Hot Reload").

1. Abre una *nueva* ventana de terminal (manteniendo la del backend abierta) y navega a la carpeta del frontend:
   ```bash
   cd frontend
   ```
2. Instala las dependencias de Node.js:
   ```bash
   npm install
   ```
3. Inicia el servidor web local:
   ```bash
   npm run dev
   ```
4. La consola te arrojará una dirección local (usualmente `http://localhost:5173`). Haz Ctrl+Clic o abre esa URL en tu navegador para ver la aplicación funcionando y conectada a tu backend local.
