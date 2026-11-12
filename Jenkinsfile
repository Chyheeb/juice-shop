pipeline {
  // Images des outils épinglées par digest (sha256) : build reproductible et protection supply chain.
  // Mise à jour volontaire et contrôlée (en entreprise : Renovate/Dependabot).
  // Exception : l'image de base de l'application est récupérée avec --pull pour intégrer les correctifs OS.
  agent any
  options {
    quietPeriod(0)   // démarre dès que le commit est détecté
    disableConcurrentBuilds()
    timeout(time: 60, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '10'))
  }
  triggers {
    githubPush()   // build immédiat : webhook GitHub -> ngrok -> Jenkins (/github-webhook/)
  }
  environment {
    IMAGE = "juice-shop:${BUILD_NUMBER}"
    SONAR_PUBLIC_URL = 'http://localhost:9000'   // adresse de SonarQube utilisée dans les liens de l'e-mail
  }
  stages {
    stage('Checkout') {
      steps {
        checkout scm
        // supprime les rapports des builds précédents (on garde les caches .sonar et .trivycache)
        sh 'rm -rf reports *-report.json image.tar && mkdir -p reports'
      }
    }
    stage('Secrets scan') {
      agent {
        docker {
          image 'zricethezav/gitleaks@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46'
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
          image 'sonarsource/sonar-scanner-cli@sha256:38207bba3d98c8ce6f6c051ea2b9f05a24480da78c9ee5945ceafc3d9de02b88'
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
          script {
             def qg = waitForQualityGate()
             writeFile file: 'reports/sonar-quality-gate.txt', text: "Quality Gate : ${qg.status}\n"
             if (qg.status != 'OK') { error "Quality Gate ${qg.status}" }
          }
        }
      }
    }
    stage('IaC scan - Trivy') {
      agent {
        docker {
          image 'aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb'
          args '--entrypoint=""'
          reuseNode true
        }
      }
      steps {
        sh '''
          export TRIVY_CACHE_DIR="$WORKSPACE/.trivycache"
          COMMON="--skip-dirs node_modules --skip-dirs frontend/node_modules --skip-dirs data/static --skip-dirs .sonar --skip-dirs .trivycache --timeout 10m"
          # 1. Rapport complet (non bloquant)
          trivy config $COMMON --ignorefile /dev/null --format json -o trivy-iac-report.json .
          trivy config $COMMON --ignorefile /dev/null --format template --template "@/contrib/html.tpl" -o reports/trivy-iac-report.html .
          # 2. Contrôle bloquant : mauvaise configuration HIGH/CRITICAL hors baseline
          trivy config $COMMON --severity HIGH,CRITICAL --ignorefile .trivyignore-iac.yaml --exit-code 1 .
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'trivy-iac-report.json', allowEmptyArchive: true
          publishHTML(target: [reportName: 'IaC - Trivy', reportDir: 'reports', reportFiles: 'trivy-iac-report.html',
                               keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true])
        }
      }
    }
    stage('Build & Unit tests') {
      agent { docker { image 'node@sha256:e273cf2a19c7334c03f52e2ca933ecdfc3fbfaad49db7b8bc8c3edd9ac34e9c7'; reuseNode true } }
      steps {
        sh 'rm -rf node_modules frontend/node_modules'
        sh 'npm install --no-audit --no-fund --ignore-scripts'
        sh 'cd frontend && npm install --no-audit --no-fund --legacy-peer-deps'
        sh 'npm run build:frontend'
        sh 'npm run build:server'
        sh '''#!/bin/bash -e
             set -o pipefail
             npm run test:server 2>&1 | tee reports/build-test.log
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'frontend/dist/bom/bom.json', allowEmptyArchive: true
        }
      }
    }
    stage('SCA - Trivy') {
      agent {
        docker {
          image 'aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb'
          args '--entrypoint=""'
          reuseNode true
        }
      }
      steps {
        sh '''
          export TRIVY_CACHE_DIR="$WORKSPACE/.trivycache"
          COMMON="--scanners vuln --timeout 20m --no-progress --skip-dirs .sonar --skip-dirs .trivycache"
          # 1. Rapport complet, toutes sévérités (non bloquant, pour l'historique)
          trivy rootfs $COMMON --ignorefile /dev/null --format json -o trivy-sca-report.json .
          trivy rootfs $COMMON --ignorefile /dev/null --skip-db-update --skip-java-db-update \
            --format template --template "@/contrib/html.tpl" -o reports/trivy-sca-report.html .
          # 2. Contrôle bloquant : HIGH/CRITICAL hors baseline
          trivy rootfs $COMMON --severity HIGH,CRITICAL \
            --ignorefile .trivyignore --skip-db-update --skip-java-db-update --exit-code 1 .
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'trivy-sca-report.json', allowEmptyArchive: true
          publishHTML(target: [reportName: 'SCA - Trivy', reportDir: 'reports', reportFiles: 'trivy-sca-report.html',
                               keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true])
        }
      }
    }
    stage('Docker build') {
      steps {
         sh '''#!/bin/bash -e
             set -o pipefail
             docker build --pull --progress=plain -t $IMAGE . 2>&1 | tee reports/docker-build.log
         '''
      }
    }
    stage('Image scan - Trivy') {
      steps {
        // export de l'image : Trivy n'a jamais accès au socket Docker
        sh 'docker save $IMAGE -o image.tar'
        script {
          docker.image('aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb').inside('--entrypoint=""') {
            sh '''
              export TRIVY_CACHE_DIR="$WORKSPACE/.trivycache"
              COMMON="--input image.tar --scanners vuln --timeout 20m --no-progress"
              # 1. Rapport complet (non bloquant)
              trivy image $COMMON --ignorefile /dev/null --format json -o trivy-image-report.json
              trivy image $COMMON --ignorefile /dev/null --skip-db-update --skip-java-db-update \
                --format template --template "@/contrib/html.tpl" -o reports/trivy-image-report.html
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
          publishHTML(target: [reportName: 'Image - Trivy', reportDir: 'reports', reportFiles: 'trivy-image-report.html',
                               keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true])
        }
      }
    }
    stage('DAST - OWASP ZAP') {
      steps {
        // conteneur de test éphémère : ZAP attaque l'image AVANT tout déploiement
        sh '''
          docker rm -f juice-shop-dast || true
          docker run -d --name juice-shop-dast --network devsecops $IMAGE
          sleep 20   # démarrage de Juice Shop
        '''
        script {
          docker.image('ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af').inside('--network devsecops --entrypoint=""') {
            sh '''
              mkdir -p /zap/wrk
              cp "$WORKSPACE/zap-rules.conf" /zap/wrk/
              set +e
              zap-baseline.py -t http://juice-shop-dast:3000 -m 2 \
                -c zap-rules.conf -r zap-report.html -J zap-report.json
              RC=$?
              set -e
              cp /zap/wrk/zap-report.html "$WORKSPACE"/reports/ || true
              cp /zap/wrk/zap-report.json "$WORKSPACE"/ || true
              # 0 = OK, 2 = avertissements seulement (acceptés)
              # 1 = une règle FAIL déclenchée, 3 = erreur du scan => bloquant
              if [ "$RC" -eq 1 ] || [ "$RC" -eq 3 ]; then
                echo "DAST : régression de sécurité détectée (code $RC)"; exit 1
              fi
            '''
          }
        }
      }
      post {
        always {
          sh 'docker rm -f juice-shop-dast || true'   // le conteneur de test est toujours supprimé
          archiveArtifacts artifacts: 'reports/zap-report.html,zap-report.json', allowEmptyArchive: true
          publishHTML(target: [reportName: 'DAST - ZAP', reportDir: 'reports', reportFiles: 'zap-report.html',
                               keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true])
        }
      }
    }
    stage('Deploy (staging)') {
      // dernière étape : n'est atteinte que si TOUS les contrôles (dont le DAST) sont verts
      steps {
        sh '''
          docker rm -f juice-shop-staging || true
          docker run -d --name juice-shop-staging --network devsecops -p 3001:3000 $IMAGE
          # garder seulement les 3 dernières images juice-shop
          docker images juice-shop --format "{{.Tag}}" | grep -E "^[0-9]+$" | sort -n | head -n -3 | xargs -r -I{} docker rmi juice-shop:{} || true
          docker image prune -f
          docker ps --filter name=juice-shop-staging > reports/deploy.log
          docker inspect --format 'Image déployée : {{.Config.Image}}' juice-shop-staging >> reports/deploy.log
        '''
      }
    }
  }
  post {
   always {
    script {
      // métriques Grafana + rapport HTML de synthèse (une panne ne casse jamais le build)
      // withSonarQubeEnv fournit SONAR_HOST_URL et le token (masqué) pour lire les vulnérabilités via l'API
      withSonarQubeEnv('SonarQube') {
        docker.image('python:3.12-alpine').inside('--network devsecops') {
          sh "BUILD_RESULT=${currentBuild.currentResult} BUILD_NO=${env.BUILD_NUMBER} python3 ci/push_metrics.py || true"
          sh "BUILD_RESULT=${currentBuild.currentResult} python3 ci/build_report.py || true"
        }
      }
      archiveArtifacts artifacts: 'reports/pipeline-report.html', allowEmptyArchive: true
      // un e-mail à chaque build : rapport par stage dans le corps, rapports bruts en pièces jointes
      def status = currentBuild.currentResult
      def icon = (status == 'SUCCESS') ? '✅' : '❌'
      emailext(
        subject: "${icon} [DevSecOps] juice-shop #${env.BUILD_NUMBER} - ${status}",
        mimeType: 'text/html',
        body: fileExists('reports/pipeline-report.html')
              ? readFile('reports/pipeline-report.html')
              : "Rapport non généré. Build : ${env.BUILD_URL}",
        attachmentsPattern: 'reports/pipeline-report.html,gitleaks-report.json,trivy-*-report.json,zap-report.json,reports/*.log,reports/sonar-quality-gate.txt,frontend/dist/bom/bom.json',
        to: '$DEFAULT_RECIPIENTS'
      )
    }
    sh '''
      docker images juice-shop --format "{{.Tag}}" | grep -E "^[0-9]+$" | sort -n | head -n -3 \
        | xargs -r -I{} docker rmi juice-shop:{} || true
      docker image prune -f || true
      docker builder prune -f --filter "until=24h" || true
      docker rm -f juice-shop-dast || true
      rm -f image.tar
    '''
   }
  }
}
 