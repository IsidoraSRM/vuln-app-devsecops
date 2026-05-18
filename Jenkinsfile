pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    environment {
        // Target URL del DAST (Wazuh dashboard publico). Cambiar si conviene.
        ZAP_TARGET = 'https://18.191.172.171'
    }

    stages {

        stage('CI: Backend Tests & Coverage') {
            steps {
                // Corre pytest con SQLite in-memory (conftest.py) + coverage XML.
                // PYTHONPATH=/app permite que `from app.main import app` funcione.
                // ENCRYPTION_KEY se genera al vuelo dentro del container (Fernet),
                // solo para que crypto.py se pueda importar. NO es la key de prod.
                // catchError marca UNSTABLE en lugar de FAILURE si algun test falla.
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        docker run --rm \
                            -v "$WORKSPACE/vuln-api:/app" \
                            -w /app \
                            -e PYTHONPATH=/app \
                            python:3.12-slim bash -c '
                                pip install --no-cache-dir -q -r requirements.txt &&
                                export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") &&
                                pytest --cov=app --cov-report=xml:coverage.xml --junitxml=test-results.xml tests/
                            '
                    '''
                }
            }
        }

        stage('CI: Frontend Tests & Build') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    // Separamos tests y build con `;` en lugar de `&&` para que
                    // el build siempre se intente, aunque algun test falle.
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

        stage('SAST: SonarQube Code Analysis') {
            steps {
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
            }
        }

        stage('GATE: SonarQube Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true, credentialsId: 'sonar-token'
                }
            }
        }

        stage('DAST: OWASP ZAP Dynamic Scan') {
            steps {
                // Baseline scan = pasivo, no ataca activamente. Rapido (~2-5 min).
                // catchError no bloquea el pipeline si ZAP encuentra hallazgos.
                // $ZAP_TARGET viene del bloque environment {}, lo expande Bash en la sh.
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p zap-reports
                        chmod 777 zap-reports
                        docker run --rm \
                            -v "$WORKSPACE/zap-reports:/zap/wrk:rw" \
                            -e ZAP_TARGET="$ZAP_TARGET" \
                            ghcr.io/zaproxy/zaproxy:stable \
                            zap-baseline.py \
                                -t "$ZAP_TARGET" \
                                -r zap-report.html \
                                -J zap-report.json \
                                -I
                    '''
                }
            }
        }
    }

    post {
        always {
            // Archivar reports para que sean descargables desde Jenkins UI.
            archiveArtifacts artifacts: 'vuln-api/coverage.xml, vuln-api/test-results.xml, frontend/coverage/**, frontend/test-results.xml, zap-reports/*', allowEmptyArchive: true
        }
        success {
            echo 'Pipeline OK — todos los stages pasaron.'
        }
        unstable {
            echo 'Pipeline UNSTABLE — algunas stages tuvieron warnings (tests, ZAP).'
        }
        failure {
            echo 'Pipeline FAILED — revisa SonarQube en http://18.116.72.101:9000/dashboard?id=vuln-app'
        }
    }
}
