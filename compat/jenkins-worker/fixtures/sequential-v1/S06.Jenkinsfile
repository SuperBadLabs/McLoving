pipeline {
    agent any
    stages {
        stage('Workspace') {
            steps {
                sh 'printf "payload\\n" > shared.txt'
                sh 'cat shared.txt'
            }
        }
    }
}
