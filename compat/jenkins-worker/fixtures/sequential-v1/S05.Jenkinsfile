pipeline {
    agent any
    stages {
        stage('Multiline') {
            steps {
                sh '''printf "first\\n"
printf "%s\\n" "second line"
'''
            }
        }
    }
}
