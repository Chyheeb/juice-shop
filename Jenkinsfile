

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
    stage('Docker build') {
      steps { sh 'docker build --progress=plain -t $IMAGE .' }
    }
    stage('Deploy (staging)') {
      steps {
        sh '''
          docker rm -f juice-shop-staging || true
          docker run -d --name juice-shop-staging -p 3001:3000 $IMAGE
          # garder seulement les 3 dernières images juice-shop
          docker images juice-shop --format "{{.Tag}}" | grep -E "^[0-9]+$" | sort -n | head -n -3 | xargs -r -I{} docker rmi juice-shop:{} || true
          docker image prune -f
        '''
      }
    }
  }
}
