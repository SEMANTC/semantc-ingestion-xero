# xero_python/storage/storage.py
from google.cloud import storage
from xero_python.utils import get_logger

logger = get_logger()

# initialize storage client
storage_client = storage.Client()

def write_json_to_gcs(file_name: str, content: str, bucket_name: str) -> None:
    """
    WRITE JSON CONTENT TO GOOGLE CLOUD STORAGE
    
    ARGS:
        file_name (str): name of the file to write
        content (str): json content to write
        bucket_name (str): name of the gcs bucket (e.g., "user-baph1db9-xero")
    
    RAISES:
        EXCEPTION: IF UPLOAD FAILS
    """
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(file_name)
        blob.upload_from_string(content, content_type='application/json')
        logger.info(f"uploaded {file_name} to bucket {bucket_name}")
    except Exception as e:
        logger.error(f"failed to upload {file_name} to {bucket_name}: {str(e)}")
        raise