pipeline {
    agent any
    stages {
        stage('test') {
            steps {
                checkout scm
                sh 'python test.py'
            }
        }
    }
}
