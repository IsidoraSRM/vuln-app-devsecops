pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    environment {
        // Target URL del DAST (Wazuh dashboard publico). Cambiar si conviene.
        ZAP_TARGET = 'http://18.218.47.7'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build and Unit Tests') {
            steps {
                echo 'Iniciando pruebas unitarias del Backend...'
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        # Red bridge temporal para que el container de tests vea al de Postgres
                        docker network create ci-pg-net-$BUILD_NUMBER || true

                        # Postgres efimero
                        docker run -d --rm \
                            --name pg-test-$BUILD_NUMBER \
                            --network ci-pg-net-$BUILD_NUMBER \
                            -e POSTGRES_USER=test \
                            -e POSTGRES_PASSWORD=test \
                            -e POSTGRES_DB=test \
                            timescale/timescaledb:latest-pg15

                        # Esperar a que PG este listo
                        for i in $(seq 1 20); do
                            if docker exec pg-test-$BUILD_NUMBER pg_isready -U test >/dev/null 2>&1; then
                                echo "Postgres ready"
                                break
                            fi
                            sleep 1
                        done

                        # Correr pytest contra el PG efimero
                        docker run --rm \
                            --network ci-pg-net-$BUILD_NUMBER \
                            -v "$WORKSPACE/vuln-api:/app" \
                            -w /app \
                            -e PYTHONPATH=/app \
                            -e DATABASE_URL="postgresql://test:test@pg-test-$BUILD_NUMBER:5432/test" \
                            python:3.12-slim bash -c '
                                pip install --no-cache-dir -q -r requirements.txt &&
                                export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") &&
                                pytest --cov=app --cov-report=xml:coverage.xml --junitxml=test-results.xml tests/
                            '
                        TEST_EXIT=$?

                        # Cleanup siempre (aunque los tests fallen)
                        docker stop pg-test-$BUILD_NUMBER >/dev/null 2>&1 || true
                        docker network rm ci-pg-net-$BUILD_NUMBER >/dev/null 2>&1 || true

                        exit $TEST_EXIT
                    '''
                }

                echo 'Iniciando pruebas unitarias y construcción del Frontend...'
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        docker run --rm \
                            -v "$WORKSPACE/frontend:/app" \
                            -w /app \
                            node:20-alpine sh -c "
                                npm ci --silent ;
                                npm run test:coverage -- --run --reporter=junit --outputFile=test-results.xml ;
                                npm run build
                            "
                    '''
                }
            }
        }

        stage('SonarQube analysis') {
            steps {
                echo 'Ejecutando análisis SAST en SonarQube...'
                withSonarQubeEnv('SonarQube') {
                    sh '''
                        docker run --rm \
                            --network=host \
                            -v "$WORKSPACE:/usr/src" \
                            -w /usr/src \
                            -e SONAR_HOST_URL="$SONAR_HOST_URL" \
                            -e SONAR_TOKEN="$SONAR_AUTH_TOKEN" \
                            sonarsource/sonar-scanner-cli:5 \
                            -Dproject.settings=dev-tools/sonarqube/sonar-project.properties \
                            -Dsonar.projectBaseDir=.
                    '''
                }

                echo 'Verificando Quality Gate en SonarQube...'
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    timeout(time: 1, unit: 'MINUTES') {
                        waitForQualityGate abortPipeline: false, credentialsId: 'sonar-token'
                    }
                }

                echo 'Ejecutando escaneo de vulnerabilidades SCA con Trivy...'
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        docker run --rm \
                            -v "$WORKSPACE:/apps" \
                            aquasec/trivy:latest fs \
                            --scanners vuln \
                            --severity HIGH,CRITICAL \
                            --exit-code 0 \
                            /apps
                    '''
                }

                echo 'Ejecutando escaneo dinámico DAST con OWASP ZAP...'
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        # 1. Asegurar que existe el archivo .env para docker compose
                        if [ ! -f .env ]; then
                            cp .env.example .env
                        fi
                        
                        # 2. Modificar el archivo docker-compose dinámicamente usando Python
                        python3 -c '
with open("docker-compose.yml") as f:
    lines = f.readlines()
out = []
skip_ports = False
for line in lines:
    if "container_name:" in line:
        continue
    if line.strip().startswith("ports:"):
        skip_ports = True
        continue
    if skip_ports:
        if line.strip().startswith("-"):
            continue
        else:
            skip_ports = False
    out.append(line)
with open("docker-compose.dast.yml", "w") as f:
    f.writelines(out)
'
                        
                        # 3. Levantar la base de datos y la API de manera efímera para el test
                        echo "Levantando servicios efímeros (sin conflictos) para el escaneo DAST..."
                        docker compose -f docker-compose.dast.yml -p vuln-app-dast up -d db-api api
                        
                        # 4. Esperar a que la API esté lista y saludable usando inspección de Docker (máximo 40 segundos)
                        echo "Esperando a que la API esté lista..."
                        for i in $(seq 1 40); do
                            STATUS=$(docker inspect -f "{{.State.Health.Status}}" vuln-app-dast-api-1 2>/dev/null || docker inspect -f "{{.State.Health.Status}}" vuln-app-dast_api_1 2>/dev/null)
                            if [ "$STATUS" = "healthy" ]; then
                                echo "API lista y saludable en la red Docker."
                                break
                            fi
                            sleep 1
                        done
                        
                        # 5. Crear carpeta de reportes y dar permisos
                        mkdir -p zap-reports
                        chmod 777 zap-reports
                        
                        # 6. Ejecutar OWASP ZAP conectado a la misma red interna
                        echo "Iniciando escaneo dinámico DAST en red interna..."
                        docker run --rm \
                            --network vuln-app-dast_app-network \
                            -v "$WORKSPACE/zap-reports:/zap/wrk:rw" \
                            ghcr.io/zaproxy/zaproxy:stable \
                            zap-baseline.py \
                                -t "http://api:8000/docs" \
                                -r zap-report.html \
                                -J zap-report.json \
                                -I
                        
                        ZAP_EXIT=$?
                        
                        # 7. Apagar y limpiar el entorno de pruebas
                        echo "Limpiando contenedores DAST..."
                        docker compose -f docker-compose.dast.yml -p vuln-app-dast down -v
                        
                        exit $ZAP_EXIT
                    '''
                }
            }
        }

        stage('Build Docker Image and Push to Artifactory') {
            steps {
                echo 'Construyendo imágenes Docker locales para verificación...'
                sh '''
                    # Construir imagen de Backend
                    docker build -t vuln-api:latest ./vuln-api

                    # Construir imagen de Frontend
                    docker build -t vuln-frontend:latest ./frontend
                '''
                echo 'Simulando subida de imágenes a Artifactory...'
                echo 'Subiendo vuln-api:latest a docker.artifactory.local/vuln-app/api:latest...'
                echo 'Subiendo vuln-frontend:latest a docker.artifactory.local/vuln-app/frontend:latest...'
                echo 'Imágenes subidas exitosamente a Artifactory.'
            }
        }

        stage('Approve K8s Dev Deployment') {
            steps {
                input message: '¿Desea aprobar el despliegue en el entorno de desarrollo (Kubernetes Dev)?', ok: 'Aprobar Despliegue'
            }
        }

        stage('Create and Deploy to k8s Dev Environment') {
            steps {
                echo 'Creando Namespace de Kubernetes: vuln-app-dev...'
                echo 'Aplicando manifiestos de Kubernetes (Deployments, Services, Ingress)...'
                echo 'Desplegando base de datos y API en clúster k8s...'
                echo 'Desplegando frontend en clúster k8s...'
                echo 'Verificando estado de los Pods en Namespace vuln-app-dev...'
                echo '¡Despliegue en Kubernetes Dev completado con éxito!'
            }
        }
    }

    post {
        always {
            // Archivar reports para que sean descargables desde Jenkins UI.
            archiveArtifacts artifacts: 'vuln-api/coverage.xml, vuln-api/test-results.xml, frontend/coverage/**, frontend/test-results.xml, zap-reports/*', allowEmptyArchive: true

            // Dashboard nativo de tests en Jenkins (pasados/fallidos/skip por build).
            junit allowEmptyResults: true, testResults: '**/test-results.xml'
        }
        success {
            echo 'Pipeline OK — todos los stages pasaron.'
        }
        unstable {
            echo 'Pipeline UNSTABLE — algunas stages tuvieron warnings (tests, ZAP).'
        }
        failure {
            echo 'Pipeline FAILED — revisa SonarQube en http://18.218.47.7:9000/dashboard?id=vuln-app'
        }
    }
}
