docker build -t xero-ingestion:latest .

docker run \                                     
  -e TENANT_ID="7a94e511-25e3-4b98-978c-2c910a779ade" \
  -e PROJECT_ID="semantc-dev" \
  -e GOOGLE_APPLICATION_CREDENTIALS="/app/service_account.json" \
  -v "$(pwd)/service_account.json:/app/service_account.json:ro" \
xero-ingestion:latest