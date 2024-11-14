# xero_python/external_tables/external_tables.py
from google.cloud import bigquery
from google.cloud import storage
from xero_python.utils import get_logger

logger = get_logger()

def create_external_table(endpoints: dict, dataset_id: str, bucket_name: str, project_id: str = None) -> None:
    """
    CREATE BIGQUERY EXTERNAL TABLES FOR XERO DATA IN A TERRAFORM-MANAGED DATASET
    
    ARGS:
        endpoints (dict): dictionary of endpoints to create tables for
        dataset_id (str): bigquery dataset id (e.g., "user_baph1db9_raw")
        bucket_name (str): gcs bucket name
        project_id (str, optional): gcp project id. if not provided, uses default client project
    
    RAISES:
        EXCEPTION: IF DATASET ACCESS OR TABLE CREATION FAILS
    """
    # initialize bigquery client with optional project_id
    bigquery_client = bigquery.Client(project=project_id) if project_id else bigquery.Client()
    
    # verify dataset exists (managed by terraform)
    try:
        dataset_ref = bigquery_client.dataset(dataset_id)
        dataset = bigquery_client.get_dataset(dataset_ref)
        logger.info(f"found dataset {dataset_id}")
    except Exception as e:
        logger.error(f"dataset {dataset_id} not found or not accessible: {str(e)}")
        raise

    # create external tables for each endpoint
    for endpoint in endpoints.keys():
        table_id = f"{dataset_id}.xero_{endpoint}"
        logger.info(f"setting up external table {table_id} for bucket path: gs://{bucket_name}/xero_{endpoint}.json")

        # define external table schema with payload as json and ingestion_time
        schema = [
            bigquery.SchemaField("payload", "JSON", mode="NULLABLE"),
            bigquery.SchemaField("ingestion_time", "TIMESTAMP", mode="REQUIRED"),
        ]

        table_ref = dataset_ref.table(f"xero_{endpoint}")

        # create external table configuration
        external_config = bigquery.ExternalConfig("NEWLINE_DELIMITED_JSON")
        external_config.source_uris = [f"gs://{bucket_name}/xero_{endpoint}.json"]
        external_config.schema = schema
        external_config.ignore_unknown_values = True
        external_config.max_bad_records = 0

        # create or update external table
        try:
            table = bigquery.Table(table_ref, schema=schema)
            table.external_data_configuration = external_config
            table = bigquery_client.create_table(table, exists_ok=True)
            logger.info(f"external table {table_id} created or updated")
        except Exception as e:
            logger.error(f"error creating external table {table_id}: {str(e)}", exc_info=True)
            continue

        logger.info(f"external table {table_id} is set up to read from {external_config.source_uris[0]}")