pipeline {
    agent any
    stages {
        stage('Quote') {
            steps {
                sh 'printf "%s\\n" "a b" \'single\' \'$literal\' \'back\\slash\''
            }
        }
    }
}
