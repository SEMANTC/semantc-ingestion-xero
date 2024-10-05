import os
from google.cloud import storage
from xero_python.utils import get_logger

logger = get_logger()

# Initialize storage client
storage_client = storage.Client()

tenant_id = os.getenv("TENANT_ID")
bucket_name = f"tenant-{tenant_id}-bucket-xero"

def write_json_to_gcs(file_name: str, content: str) -> None:
    """
    Writes JSON content to a specified GCS bucket
    """
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(file_name)
        blob.upload_from_string(content, content_type='application/json')
        logger.info(f"saved {file_name} to gs://{bucket_name}/{file_name}")
    except Exception as e:
        logger.error(f"failed to upload {file_name} to {bucket_name}: {str(e)}")
        raise