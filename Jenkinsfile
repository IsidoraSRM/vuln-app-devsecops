pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    stages {
        stage('SAST: SonarQube Code Analysis') {
            steps {
                withSonarQubeEnv('sonarqube') {
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
                    waitForQualityGate abortPipeline: true
                }
            }
        }
    }

    post {
        success {
            echo 'Pipeline OK — analisis SonarQube paso el quality gate.'
        }
        failure {
            echo 'Pipeline FAILED — revisa SonarQube en http://18.219.1.206:9000/dashboard?id=vuln-app'
        }
    }
}
