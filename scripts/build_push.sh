#!/bin/bash
# scripts/build_push.sh

set -e

# Configuration
PROJECT_ID="semantc-dev"
REGION="us-central1"
REPO="gcr.io"
IMAGE_TAG="latest"
IMAGE_NAME="${REPO}/${PROJECT_ID}/xero-ingestion:${IMAGE_TAG}"

echo "Building and pushing image: ${IMAGE_NAME}"

# Authenticate with GCP
gcloud auth configure-docker gcr.io

# Build and push Docker image
docker build --platform linux/amd64 -t ${IMAGE_NAME} --no-cache .
docker push ${IMAGE_NAME}

echo "Docker image pushed to ${IMAGE_NAME} successfully"