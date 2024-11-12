import os
import json
import re
from decimal import Decimal
from enum import Enum
from datetime import datetime, date
import asyncio
from ratelimit import limits, sleep_and_retry
from xero_python.accounting import AccountingApi
from xero_python.api_client import ApiClient, Configuration
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.exceptions import (
    OAuth2TokenGetterError,
    OAuth2TokenSaverError,
    ApiException
)
from storage import write_json_to_gcs
from external_tables import create_external_table
import logging
import requests
from google.auth import default
from google.auth.transport.requests import AuthorizedSession
from token_manager import FirestoreTokenManager, oauth2_token_getter

# Set up logging format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)

RATE_LIMIT_CALLS = 60
RATE_LIMIT_PERIOD = 50  # seconds

def standardize_user_id(user_id: str) -> str:
    """Standardizes user ID for GCP resource naming"""
    return re.sub(r'[^a-zA-Z0-9]', '', user_id[:8]).lower()

def get_resource_names(user_id: str) -> dict:
    """Get standardized resource names for a user"""
    std_id = standardize_user_id(user_id)
    return {
        'gcs_bucket': f"user-{std_id}-xero",
        'transformation_job_uri': f"https://{os.getenv('CLOUD_RUN_REGION', 'us-central1')}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/{os.getenv('PROJECT_ID')}/jobs/job-{std_id}-xero-trn:run",
        'raw_dataset': f"user_{std_id}_raw",
        'transformed_dataset': f"user_{std_id}_transformed"
    }

@sleep_and_retry
@limits(calls=RATE_LIMIT_CALLS, period=RATE_LIMIT_PERIOD)
def rate_limited_api_call(func, *args, **kwargs):
    return func(*args, **kwargs)

def json_serializer(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    elif isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, Enum):
        return obj.value
    else:
        return str(obj)

def save_to_gcs(data, endpoint_name, gcs_bucket_name):
    """
    converts API response data into NDJSON format and uploads to GCS
    each line contains a JSON object with 'payload' and 'ingestion_time'
    """
    # Identify the key that contains the list of items
    list_key = None
    for key, value in data.items():
        if isinstance(value, list):
            list_key = key
            break

    if not list_key:
        logger.error(f"no list found in the response for endpoint {endpoint_name}... skipping")
        return

    items = data[list_key]
    ingestion_time = data.get('ingestion_time', datetime.utcnow().isoformat())

    file_name = f"xero_{endpoint_name}.json"
    lines = []

    for item in items:
        record = {
            "payload": item,
            "ingestion_time": ingestion_time
        }
        try:
            serialized_record = json.dumps(record, default=json_serializer)
            lines.append(serialized_record)
        except TypeError as te:
            logger.error(f"serialization error for {endpoint_name}: {te}")
            continue

    json_content = "\n".join(lines)

    # save to GCS using provided bucket name
    write_json_to_gcs(file_name, json_content, bucket_name=gcs_bucket_name)
    logger.info(f"saved xero_{endpoint_name}.json to gs://{gcs_bucket_name}/{file_name}")

def trigger_transformation_job(transformation_job_uri: str):
    """
    triggers the data transformation Cloud Run job by making an authenticated HTTP POST request
    """
    if not transformation_job_uri:
        logger.error("transformation_job_uri not provided")
        return False

    try:
        credentials, _ = default()
        authed_session = AuthorizedSession(credentials)
        response = authed_session.post(transformation_job_uri)

        if response.status_code in [200, 202]:
            logger.info("transformation job triggered successfully.")
            return True
        else:
            logger.error(f"failed to trigger transformation job. Status Code: {response.status_code}, Response: {response.text}")
            return False
    except Exception as e:
        logger.error(f"exception occurred while triggering transformation job: {e}")
        return False

def get_paginated_data(accounting_api, api_call, tenant_id, params):
    """
    Helper function to handle pagination for supported endpoints
    Returns combined results for paginated endpoints or single call results for non-paginated endpoints
    """
    logger.debug(f"Making paginated call to {api_call} with tenant_id: {tenant_id}")
    
    # Define endpoints that support pagination and their specific parameters
    paginated_endpoints = {
        'get_bank_transactions': {'key': 'bank_transactions', 'params': ['page', 'page_size']},
        'get_contacts': {'key': 'contacts', 'params': ['page', 'page_size']},
        'get_credit_notes': {'key': 'credit_notes', 'params': ['page', 'page_size']},
        'get_invoices': {'key': 'invoices', 'params': ['page', 'page_size']},
        'get_linked_transactions': {'key': 'linked_transactions', 'params': ['page']},  # removed page_size
        'get_manual_journals': {'key': 'manual_journals', 'params': ['page', 'page_size']},
        'get_prepayments': {'key': 'prepayments', 'params': ['page', 'page_size']},
        'get_payments': {'key': 'payments', 'params': ['page', 'page_size']},
        'get_overpayments': {'key': 'overpayments', 'params': ['page', 'page_size']},
        'get_quotes': {'key': 'quotes', 'params': ['page']},
        'get_purchase_orders': {'key': 'purchase_orders', 'params': ['page', 'page_size']},
        'get_journals': {'key': 'journals', 'params': ['offset']},
    }

    base_params = {'xero_tenant_id': tenant_id}  # Add tenant_id to base params
    call_params = {**base_params, **params}  # Combine with other params
    
    logger.debug(f"Call parameters for {api_call}: {call_params}")

    if api_call not in paginated_endpoints:
        func = getattr(accounting_api, api_call)
        return rate_limited_api_call(func, **call_params)
        
    endpoint_config = paginated_endpoints[api_call]
    all_items = []
    page = 1
    page_size = 100
    
    while True:
        pagination_params = {}
        if 'page' in endpoint_config['params']:
            pagination_params['page'] = page
        if 'page_size' in endpoint_config['params']:
            pagination_params['page_size'] = page_size
        if 'offset' in endpoint_config['params']:
            pagination_params['offset'] = (page - 1) * page_size

        # Combine all parameters
        current_call_params = {**call_params, **pagination_params}
        
        logger.debug(f"Making API call to {api_call} with params: {current_call_params}")
        func = getattr(accounting_api, api_call)
        result = rate_limited_api_call(
            func, 
            **current_call_params
        )
        
        if not isinstance(result, dict):
            result = result.to_dict()
            
        items_key = endpoint_config['key']
        items = result.get(items_key, [])
        
        if not items:
            break
            
        all_items.extend(items)
        logger.info(f"Retrieved page {page} for {api_call} with {len(items)} items")
        
        if len(items) < page_size:
            break
            
        page += 1
    
    result[items_key] = all_items
    logger.info(f"Total {len(all_items)} items retrieved for {api_call}")
    return result

async def main():
    failed_calls = []
    successful_endpoints = {}

    try:
        # Get user_id from environment
        user_id = os.getenv("USER_ID")
        if not user_id:
            raise ValueError("USER_ID environment variable must be set")

        logger.info(f"Starting ingestion for user_id: {user_id}")

        # Get standardized resource names
        resource_names = get_resource_names(user_id)
        
        # Initialize FirestoreTokenManager with user_id
        token_manager = FirestoreTokenManager(user_id)
        
        # Get initial token and tenant_id
        token = await token_manager.get_token()
        tenant_id = token_manager.tenant_id

        logger.info(f"Retrieved tenant_id: {tenant_id}")
        if not tenant_id:
            raise ValueError("No tenant_id available from token manager")

        # Get client credentials from Secret Manager
        client_id, client_secret = await token_manager.get_client_credentials()
        logger.info("Retrieved client credentials from Secret Manager")

        # Initialize configuration and OAuth2Token
        configuration = Configuration()
        oauth2_token = OAuth2Token(
            client_id=client_id,
            client_secret=client_secret
        )
        oauth2_token.update_token(**token)
        configuration.oauth2_token = oauth2_token

        # Initialize ApiClient with synchronous token getter wrapper
        api_client = ApiClient(configuration=configuration)
        def token_getter():
            # Store the initial token we already have
            return token  # Use the token we already retrieved earlier

        # Set the token getter
        api_client.oauth2_token_getter(token_getter)

        # Initialize AccountingApi
        accounting_api = AccountingApi(api_client=api_client)

        logger.info(f"Making API calls with tenant_id: {tenant_id}")

        # List of API calls to make
        api_calls = [
            ('get_accounts', {}),
            ('get_bank_transactions', {}),
            ('get_bank_transfers', {}),
            ('get_batch_payments', {}),
            ('get_branding_themes', {}),
            ('get_budgets', {}),
            ('get_contact_groups', {}),
            ('get_contacts', {}),
            ('get_credit_notes', {}),
            ('get_currencies', {}),
            ('get_employees', {}),
            ('get_expense_claims', {}),
            ('get_invoice_reminders', {}),
            ('get_invoices', {}),
            ('get_items', {}),
            ('get_journals', {}),
            ('get_linked_transactions', {}),
            ('get_manual_journals', {}),
            ('get_organisation_actions', {}),
            ('get_organisations', {}),
            ('get_overpayments', {}),
            ('get_payment_services', {}),
            ('get_payments', {}),
            ('get_prepayments', {}),
            ('get_purchase_orders', {}),
            ('get_quotes', {}),
            ('get_receipts', {}),
            ('get_repeating_invoices', {}),
            ('get_report_balance_sheet', {}),
            ('get_report_bank_summary', {}),
            ('get_report_budget_summary', {}),
            ('get_report_executive_summary', {}),
            ('get_report_profit_and_loss', {}),
            ('get_report_trial_balance', {}),
            ('get_reports_list', {}),
            ('get_tax_rates', {}),
            ('get_tracking_categories', {}),
            ('get_users', {})
        ]

        # Make API calls and save results
        for api_call, params in api_calls:
            attempt = 0
            max_attempts = 2
            while attempt < max_attempts:
                try:
                    logger.info(f"Calling {api_call}")
                    
                    result = get_paginated_data(accounting_api, api_call, tenant_id, params)

                    if not isinstance(result, dict):
                        result = result.to_dict()

                    result['ingestion_time'] = datetime.utcnow().isoformat()

                    endpoint_name = api_call.replace("get_", "")
                    save_to_gcs(result, endpoint_name, resource_names['gcs_bucket'])

                    logger.info(f"Successfully processed and saved data from {api_call}")
                    successful_endpoints[endpoint_name] = {}
                    break

                except ApiException as e:
                    if e.status == 401 and 'tokenexpired' in e.body.decode('utf-8'):
                        logger.warning(f"Unauthorized error for {api_call}, attempting to refresh token")
                        try:
                            # Force token refresh
                            new_token = await token_manager.get_token()  # This will refresh if needed
                            oauth2_token.update_token(**new_token)
                            configuration.oauth2_token = oauth2_token
                            token = new_token  # Update our stored token
                            api_client.oauth2_token_getter(lambda: token)  # Update the token getter with new token
                            attempt += 1
                            logger.info(f"Token refreshed... retrying {api_call} (Attempt {attempt}/{max_attempts})")
                        except Exception as refresh_e:
                            logger.error(f"Failed to refresh token for {api_call}: {refresh_e}")
                            failed_calls.append((api_call, str(e)))
                            break
                    else:
                        logger.error(f"Error in {api_call}: {str(e)}")
                        failed_calls.append((api_call, str(e)))
                        break
                except Exception as e:
                    logger.error(f"Unexpected error in {api_call}: {str(e)}")
                    failed_calls.append((api_call, str(e)))
                    break

        # After all API calls, load data to BigQuery
        if successful_endpoints:
            create_external_table(
                endpoints=successful_endpoints,
                dataset_id=resource_names['raw_dataset'],
                bucket_name=resource_names['gcs_bucket'],
                project_id=os.getenv('PROJECT_ID')
            )

            logger.info("Triggering the data transformation job")
            transformation_triggered = trigger_transformation_job(resource_names['transformation_job_uri'])
            if transformation_triggered:
                logger.info("Data transformation job has been triggered successfully")
            else:
                logger.error("Failed to trigger the data transformation job")

    except OAuth2TokenGetterError as e:
        logger.error(f"Error getting token: {e}")
    except OAuth2TokenSaverError as e:
        logger.error(f"Error saving token: {e}")
    except Exception as e:
        logger.error(f"Error: {e}")
        if hasattr(e, 'body'):
            logger.error(f"Response body: {e.body}")
    finally:
        if failed_calls:
            logger.warning(f"Completed with failures in {len(failed_calls)} API calls:")
            for call, error in failed_calls:
                logger.warning(f"- {call}: {error}")
        else:
            logger.info("All API calls completed successfully")

if __name__ == "__main__":
    # Set up logging configuration
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Run the async main function
    asyncio.run(main())