pipeline {
    agent any
    stages {
        stage('test') {
            checkout scm
            sh 'python test.py'
        }
    }
}
