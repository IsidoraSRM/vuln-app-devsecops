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
                script {
                    withSonarQubeEnv('sonarqube') {
                        docker.image('sonarsource/sonar-scanner-cli:latest').inside('--user=root') {
                            sh '''
                                sonar-scanner \
                                    -Dproject.settings=dev-tools/sonarqube/sonar-project.properties \
                                    -Dsonar.projectBaseDir=.
                            '''
                        }
                    }
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
