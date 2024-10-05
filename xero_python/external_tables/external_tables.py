import os
from google.cloud import bigquery
from google.cloud import storage
import json
import io
import datetime
from typing import List, Dict, Any
from utils import get_logger

logger = get_logger()

# initialize clients once
bigquery_client = bigquery.Client(project=os.getenv("PROJECT_ID"))
storage_client = storage.Client()

project_id = os.getenv("PROJECT_ID")
tenant_id = os.getenv("TENANT_ID")

formatted_tenant_id = tenant_id.replace("-", "_")

bucket_name = f"tenant-{tenant_id}-bucket-xero"
dataset_id = f"tenant_{formatted_tenant_id}_raw"

def create_external_table(endpoints: str) -> None:
    try:
        bigquery_client.get_dataset(dataset_id)
    except Exception as e:
        logger.error(f"error accessing dataset {dataset_id}: {str(e)}")
        raise

    for endpoint in endpoints.keys():
        table_id = f"{dataset_id}.xero_{endpoint}"

        # define table schema
        schema = [
            bigquery.SchemaField("ingestion_time", "TIMESTAMP", mode="REQUIRED")
        ]

        table_ref = bigquery_client.dataset(dataset_id).table(f"xero_{endpoint}")

        # create or ensure table exists
        try:
            table = bigquery.Table(table_ref, schema=schema)
            table = bigquery_client.create_table(table, exists_ok=True)
            # logger.info(f"{table_id} exists")
        except Exception as e:
            logger.error(f"error creating table {table_id}: {str(e)}")
            continue

        # load data from GCS to BigQuery
        try:
            uri = f"gs://{bucket_name}/xero_{endpoint}.json"
            job_config = bigquery.LoadJobConfig(
                schema=schema,
                source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                write_disposition=bigquery.WriteDisposition.WRITE_APPEND
            )
            load_job = bigquery_client.load_table_from_uri(
                uri,
                table_ref,
                job_config=job_config
            )
            load_job.result()  # wait for the job to complete
            logger.info(f"loaded data into {table_id} from {uri}")
        except Exception as e:
            logger.error(f"error loading data into {table_id} from {uri}: {str(e)}")