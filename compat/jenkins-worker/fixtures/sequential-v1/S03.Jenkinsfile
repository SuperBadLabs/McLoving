pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'export JCOMP_STEP_SENTINEL=first; mkdir nested; cd nested; printf "one\\n"'
                sh 'test "${JCOMP_STEP_SENTINEL-unset}" = unset; test -d nested; printf "two\\n"'
                sh 'rmdir nested; printf "three\\n"'
            }
        }
    }
}
