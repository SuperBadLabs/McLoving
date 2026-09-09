pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'printf "before\\n"'
                sh 'printf "last failed\\n"; exit 7'
            }
        }
    }
}
