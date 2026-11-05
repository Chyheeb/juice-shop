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
        sh 'npm install'          
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
          docker run -d --name juice-shop-staging -p 3000:3000 $IMAGE
        '''
      }
    }
  }
}
