pipeline {
    agent { docker 'python:2.7' }
    stages {
        stage('test') {
            steps {
                checkout scm
                sh 'python test.py'
            }
        }
    }
}
