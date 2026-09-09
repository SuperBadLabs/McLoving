pipeline {
    agent any
    stages {
        stage('Write') {
            steps {
                sh 'mkdir output\nprintf "across\\n" > output/value.txt'
            }
        }
        stage('Read') {
            steps {
                sh 'cat output/value.txt'
            }
        }
    }
}
