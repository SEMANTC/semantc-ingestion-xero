#!/bin/bash
# scripts/build_push.sh
set -e

# configuration
PROJECT_ID="semantc-sandbox"
REGION="us-central1"
REPO="gcr.io"
IMAGE_TAG="latest"
IMAGE_NAME="${REPO}/${PROJECT_ID}/xero-ingestion:${IMAGE_TAG}"

echo "building and pushing image: ${IMAGE_NAME}"

# authenticate with gcp
gcloud auth configure-docker gcr.io

# build and push docker image
docker build --platform linux/amd64 -t ${IMAGE_NAME} --no-cache .
docker push ${IMAGE_NAME}

echo "Docker image pushed to ${IMAGE_NAME} successfully"