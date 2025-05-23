pipeline {
    agent any

    environment {
        JDK_TOOL_NAME = 'JDK 21'
        MAVEN_TOOL_NAME = 'Maven 3.9.9'
    }

    options {
        skipStagesAfterUnstable()
        disableConcurrentBuilds abortPrevious: true
    }

    stages {
        stage('Clean') {
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn clean'
                }
            }
        }
        stage('Format Check') {
            options {
                timeout(activity: true, time: 60, unit: 'SECONDS')
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn spotless:check'
                }
            }
        }
        stage('Build') {
            options {
                timeout(activity: true, time: 120, unit: 'SECONDS')
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn -DskipTests=true package'
                }
            }

            post {
                success {
                    archiveArtifacts artifacts: '**/target/*.jar'
                }
            }
        }
        stage('Code Analysis') {
            when {
                anyOf {
                    branch 'main'
                    tag 'v*'
                    changeRequest()
                }
            }
            options {
                timeout(activity: true, time: 240, unit: 'SECONDS')
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    // `package` goal is required here to load modules in reactor and avoid dependency resolve conflicts
                    sh 'mvn -DskipTests=true package pmd:pmd pmd:cpd spotbugs:spotbugs'
                }
            }
            post {
                always {
                    recordIssues enabledForFailure: true, tools: [spotBugs(), cpd(pattern: '**/target/cpd.xml'), pmdParser(pattern: '**/target/pmd.xml')]
                }
            }
        }
        stage('Unit Tests') {
            when {
                anyOf {
                    branch 'main'
                    tag 'v*'
                    changeRequest()
                }
            }
            options {
                timeout(activity: true, time: 180, unit: 'SECONDS')
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn -P coverage -Dskip.failsafe.tests=true test'
                }
            }
            post {
                always {
                    junit testResults: '**/target/surefire-reports/TEST-*.xml'
                }
            }
        }
        stage('Integration Tests') {
            when {
                anyOf {
                    branch 'main'
                    tag 'v*'
                    changeRequest()
                }
            }
            options {
                timeout(activity: true, time: 1800, unit: 'SECONDS')
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn -P coverage -Dskip.surefire.tests=true verify'
                }
            }
            post {
                always {
                    junit testResults: '**/target/failsafe-reports/TEST-*.xml', allowEmptyResults: true
                }
                success {
                    discoverReferenceBuild()
                    recordCoverage(tools: [[ parser: 'JACOCO' ]],
                            id: 'jacoco', name: 'JaCoCo Coverage',
                            sourceCodeRetention: 'LAST_BUILD')
                }
            }
        }
        stage('Deploy to Internal Nexus Repository') {
            when {
                anyOf {
                    branch 'main'
                    tag 'v*'
                }
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    // Tests were already executed separately, so disable tests within this step
                    sh 'mvn -DskipTests=true deploy'
                }
            }
        }
        stage('Build & Deploy Docker Image to Internal Nexus Repository') {
           when {
               anyOf {
                   branch 'main'
                   tag 'v*'
                }
            }
            environment {
                DOCKER_PUSH = credentials('Jenkins-User-Nexus-Repository')
                DOCKER_PUSH_URL = 'hydrogen.cloud.nds.rub.de'
            }
            steps {
                unstash 'jar'
                unstash 'lib'
                sh 'docker build -f ci.Dockerfile -t ${DOCKER_PUSH_URL}/tls-crawler:latest -t ${DOCKER_PUSH_URL}/tls-crawler:${BUILD_TIMESTAMP}_${BUILD_NUMBER} .'
                sh 'docker login -u $DOCKER_PUSH_USR -p $DOCKER_PUSH_PSW $DOCKER_PUSH_URL'
                sh 'docker push ${DOCKER_PUSH_URL}/tls-crawler:latest'
                sh 'docker push ${DOCKER_PUSH_URL}/tls-crawler:${BUILD_TIMESTAMP}_${BUILD_NUMBER}'
            }
        }
    }
    post {
        always {
            recordIssues enabledForFailure: true, tools: [mavenConsole(), java(), javaDoc()]
        }
    }
}
