pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'printf "first failed\\n"; exit 7'
                sh 'printf "must not run\\n"'
            }
        }
        stage('Later') {
            steps {
                sh 'printf "must not run\\n"'
            }
        }
    }
}
