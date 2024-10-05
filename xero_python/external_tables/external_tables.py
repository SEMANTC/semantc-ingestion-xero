import os
from google.cloud import bigquery
from google.cloud import storage
from xero_python.utils import get_logger

logger = get_logger()

bigquery_client = bigquery.Client(project=os.getenv("PROJECT_ID"))

project_id = os.getenv("PROJECT_ID")
tenant_id = os.getenv("TENANT_ID")

formatted_tenant_id = tenant_id.replace("-", "_")
bucket_name = f"tenant-{tenant_id}-bucket-xero"
dataset_id = f"tenant_{formatted_tenant_id}_raw"

def create_external_table(endpoints: dict) -> None:
    try:
        bigquery_client.get_dataset(dataset_id)
    except Exception as e:
        logger.error(f"error accessing dataset {dataset_id}: {str(e)}")
        raise

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