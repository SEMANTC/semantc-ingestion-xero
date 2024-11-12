# xero_python/storage/storage.py
from google.cloud import storage
from xero_python.utils import get_logger

logger = get_logger()

# initialize storage client
storage_client = storage.Client()

def write_json_to_gcs(file_name: str, content: str, bucket_name: str) -> None:
    """
    Write JSON content to Google Cloud Storage
    
    Args:
        file_name (str): Name of the file to write
        content (str): JSON content to write
        bucket_name (str): Name of the GCS bucket (e.g., "user-baph1db9-xero")
    
    Raises:
        Exception: If upload fails
    """
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(file_name)
        blob.upload_from_string(content, content_type='application/json')
        logger.info(f"uploaded {file_name} to bucket {bucket_name}")
    except Exception as e:
        logger.error(f"failed to upload {file_name} to {bucket_name}: {str(e)}")
        raise