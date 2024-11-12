# xero_python/external_tables/external_tables.py
from google.cloud import bigquery
from google.cloud import storage
from xero_python.utils import get_logger

logger = get_logger()

def create_external_table(endpoints: dict, dataset_id: str, project_id: str = None) -> None:
    """
    Create BigQuery external tables for Xero data
    
    Args:
        endpoints (dict): Dictionary of endpoints to create tables for
        dataset_id (str): BigQuery dataset ID (e.g., "user_baph1db9_raw")
        project_id (str, optional): GCP project ID. If not provided, uses default client project
    
    Raises:
        Exception: If dataset access or table creation fails
    """
    # initialize BigQuery client with optional project_id
    bigquery_client = bigquery.Client(project=project_id) if project_id else bigquery.Client()
    
    # ensure dataset exists
    try:
        bigquery_client.get_dataset(dataset_id)
    except Exception as e:
        logger.error(f"error accessing dataset {dataset_id}: {str(e)}")
        raise

    # extract bucket name from the dataset_id
    # assuming dataset_id format: "user_baph1db9_raw"
    # convert to bucket format: "user-baph1db9-xero"
    bucket_name = f"user-{dataset_id.split('_')[1]}-xero"

    for endpoint in endpoints.keys():
        table_id = f"{dataset_id}.xero_{endpoint}"

        # define external table schema with payload as JSON and ingestion_time
        schema = [
            bigquery.SchemaField("payload", "JSON", mode="NULLABLE"),
            bigquery.SchemaField("ingestion_time", "TIMESTAMP", mode="REQUIRED"),
        ]

        table_ref = bigquery_client.dataset(dataset_id).table(f"xero_{endpoint}")

        # create external table configuration
        external_config = bigquery.ExternalConfig("NEWLINE_DELIMITED_JSON")
        external_config.source_uris = [f"gs://{bucket_name}/xero_{endpoint}.json"]
        external_config.schema = schema
        external_config.ignore_unknown_values = True
        external_config.max_bad_records = 0

        # create or ensure external table exists
        try:
            table = bigquery.Table(table_ref, schema=schema)
            table.external_data_configuration = external_config
            table = bigquery_client.create_table(table, exists_ok=True)
            logger.info(f"external table {table_id} created or updated")
        except Exception as e:
            logger.error(f"error creating external table {table_id}: {str(e)}")
            continue

        logger.info(f"external table {table_id} is set up to read from {external_config.source_uris[0]}")