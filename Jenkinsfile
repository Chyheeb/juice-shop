pipeline {
  agent any
  options { 
    disableConcurrentBuilds()
    timeout(time: 60, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '10'))
  }
  environment {
    IMAGE = "juice-shop:${BUILD_NUMBER}"
  }
  stages {
    stage('Checkout') {
      steps { checkout scm }
    }
    stage('Secrets scan') {
      agent {
        docker {
          image 'zricethezav/gitleaks:v8.21.2'
          args '--entrypoint=""'
          reuseNode true
        }
      }
      steps {
        sh '''
          gitleaks git . \
            --baseline-path .gitleaks-baseline.json \
            --redact \
            --report-format json --report-path gitleaks-report.json \
            --exit-code 1
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
        }
      }
    }
    stage('SAST - SonarQube') {
      agent {
        docker {
          image 'sonarsource/sonar-scanner-cli:latest'
          args '--network devsecops --entrypoint=""'
          reuseNode true
        }
      }
      steps {
        withSonarQubeEnv('SonarQube') {
          // le token vient du credential Jenkins, jamais écrit en clair
          sh 'SONAR_TOKEN="$SONAR_AUTH_TOKEN" SONAR_USER_HOME="$WORKSPACE/.sonar" sonar-scanner'
        }
      }
    }
    stage('Quality Gate') {
      steps {
        timeout(time: 10, unit: 'MINUTES') {
          // attend le verdict de SonarQube (via le webhook) et bloque si ERROR
          waitForQualityGate abortPipeline: true
        }
      }
    }
    stage('Build & Unit tests') {
      agent { docker { image 'node:22'; reuseNode true } }
      steps {
        sh 'rm -rf node_modules frontend/node_modules'
        sh 'npm install --no-audit --no-fund --ignore-scripts'
        sh 'cd frontend && npm install --no-audit --no-fund --legacy-peer-deps'
        sh 'npm run build:frontend'
        sh 'npm run build:server'
        sh 'npm run test:server'
      }
    }
    stage('SCA - Trivy') {
      agent {
        docker {
          image 'aquasec/trivy:latest'
          args '--entrypoint=""'
          reuseNode true
        }
      }
      steps {
        sh '''
          export TRIVY_CACHE_DIR="$WORKSPACE/.trivycache"
          COMMON="--scanners vuln --timeout 20m --no-progress --skip-dirs .sonar --skip-dirs .trivycache"
          # 1. Rapport complet, toutes sévérités (non bloquant, pour l'historique)
          trivy rootfs $COMMON --format json -o trivy-sca-report.json .
          # 2. Contrôle bloquant : HIGH/CRITICAL hors baseline
          trivy rootfs $COMMON --severity HIGH,CRITICAL \
            --ignorefile .trivyignore --skip-db-update --skip-java-db-update --exit-code 1 .
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'trivy-sca-report.json', allowEmptyArchive: true
        }
      }
    }
    stage('Docker build') {
      steps { sh 'docker build --progress=plain -t $IMAGE .' }
    }
    stage('Image scan - Trivy') {
      steps {
        // export de l'image : Trivy n'a jamais accès au socket Docker
        sh 'docker save $IMAGE -o image.tar'
        script {
          docker.image('aquasec/trivy:latest').inside('--entrypoint=""') {
            sh '''
              export TRIVY_CACHE_DIR="$WORKSPACE/.trivycache"
              COMMON="--input image.tar --scanners vuln --timeout 20m --no-progress"
              # 1. Rapport complet (non bloquant)
              trivy image $COMMON --format json -o trivy-image-report.json
              # 2. Contrôle bloquant : HIGH/CRITICAL corrigeables, hors baseline
              trivy image $COMMON --severity HIGH,CRITICAL --ignore-unfixed \
                --ignorefile .trivyignore --skip-db-update --skip-java-db-update --exit-code 1
            '''
          }
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'trivy-image-report.json', allowEmptyArchive: true
          sh 'rm -f image.tar'
        }
      }
    }
    stage('Deploy (staging)') {
      steps {
        sh '''
          docker rm -f juice-shop-staging || true
          docker run -d --name juice-shop-staging --network devsecops -p 3001:3000 $IMAGE
          # garder seulement les 3 dernières images juice-shop
          docker images juice-shop --format "{{.Tag}}" | grep -E "^[0-9]+$" | sort -n | head -n -3 | xargs -r -I{} docker rmi juice-shop:{} || true
          docker image prune -f
        '''
      }
    }
    stage('DAST - OWASP ZAP') {
      steps {
        // laisse le temps à Juice Shop de démarrer
        sh 'sleep 20'
        script {
          docker.image('ghcr.io/zaproxy/zaproxy:stable').inside('--network devsecops --entrypoint=""') {
            sh '''
              mkdir -p /zap/wrk
              # -I : ne pas échouer pour l'instant (phase d'observation)
              zap-baseline.py -t http://juice-shop-staging:3000 -m 2 \
                -r zap-report.html -J zap-report.json -I || true
              cp /zap/wrk/zap-report.html /zap/wrk/zap-report.json "$WORKSPACE"/ || true
            '''
          }
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'zap-report.html,zap-report.json', allowEmptyArchive: true
        }
      }
    }
  }
}
