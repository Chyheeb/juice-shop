pipeline {
  agent any
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
        // 1. dépendances backend, sans lancer le postinstall imbriqué
        sh 'npm install --no-audit --no-fund --ignore-scripts'
        // 2. dépendances frontend, installées séparément
        sh 'cd frontend && npm install --no-audit --no-fund --legacy-peer-deps'
        // 3. build
        sh 'npm run build:frontend'
        sh 'npm run build:server'
        // 4. tests unitaires
        sh 'npm run test:server'
      }
    }
    stage('Docker build') {
      steps { sh 'docker build -t $IMAGE .' }
    }
    stage('Deploy (staging)') {
      steps {
        sh '''
          docker rm -f juice-shop-staging || true
          docker run -d --name juice-shop-staging -p 3001:3000 $IMAGE
        '''
      }
    }
  }
}
