import os
import json
from decimal import Decimal
from enum import Enum
from datetime import datetime, date
from ratelimit import limits, sleep_and_retry
from xero_python.accounting import AccountingApi
from xero_python.api_client import ApiClient, Configuration
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.token_manager.token_manager import TokenManager, oauth2_token_getter
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

logger = logging.getLogger(__name__)

RATE_LIMIT_CALLS = 60
RATE_LIMIT_PERIOD = 50  # seconds

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

def save_to_gcs(data, endpoint_name):
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
            continue  # skip this record and continue with others

    # join all JSON objects with newline characters
    json_content = "\n".join(lines)

    # save to GCS
    write_json_to_gcs(file_name, json_content)
    logger.info(f"saved xero_{endpoint_name}.json to gs://{os.getenv('GCS_BUCKET_NAME')}/{file_name}")

def trigger_transformation_job():
    """
    triggers the data transformation Cloud Run job by making an authenticated HTTP POST request
    """
    transformation_job_uri = os.getenv("TRANSFORMATION_JOB_URI")
    if not transformation_job_uri:
        logger.error("TRANSFORMATION_JOB_URI environment variable is not set.")
        return False

    try:
        # obtain default credentials
        credentials, _ = default()
        authed_session = AuthorizedSession(credentials)

        # make the POST request to trigger the transformation job
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
    # Define endpoints that support pagination and their specific parameters
    paginated_endpoints = {
        'get_bank_transactions': {'key': 'bank_transactions', 'params': ['page', 'page_size']},
        'get_contacts': {'key': 'contacts', 'params': ['page', 'page_size']},
        'get_credit_notes': {'key': 'credit_notes', 'params': ['page', 'page_size']},
        'get_invoices': {'key': 'invoices', 'params': ['page', 'page_size']},
        'get_linked_transactions': {'linked_transactions': 'linked', 'params': ['page', 'page_size']},
        'get_manual_journals': {'key': 'manual_journals', 'params': ['page', 'page_size']},
        'get_prepayments': {'key': 'prepayments', 'params': ['page', 'page_size']},
        'get_payments': {'key': 'payments', 'params': ['page', 'page_size']},
        'get_overpayments': {'key': 'overpayments', 'params': ['page', 'page_size']},
        'get_quotes': {'key': 'quotes', 'params': ['page']},  # some endpoints only support 'page'
        'get_purchase_orders': {'key': 'purchase_orders', 'params': ['page', 'page_size']},
        'get_journals': {'key': 'journals', 'params': ['offset']},  # journals uses offset instead
    }
    
    if api_call not in paginated_endpoints:
        # For non-paginated endpoints, just make a single call
        func = getattr(accounting_api, api_call)
        return rate_limited_api_call(func, xero_tenant_id=tenant_id, **params)
        
    # For paginated endpoints
    endpoint_config = paginated_endpoints[api_call]
    all_items = []
    page = 1
    page_size = 100  # Maximum page size
    
    while True:
        # Prepare pagination parameters based on endpoint configuration
        pagination_params = {}
        if 'page' in endpoint_config['params']:
            pagination_params['page'] = page
        if 'page_size' in endpoint_config['params']:
            pagination_params['page_size'] = page_size
        if 'offset' in endpoint_config['params']:
            pagination_params['offset'] = (page - 1) * page_size

        # Combine with other parameters
        call_params = {**params, **pagination_params}
        
        func = getattr(accounting_api, api_call)
        result = rate_limited_api_call(
            func, 
            xero_tenant_id=tenant_id, 
            **call_params
        )
        
        # Convert result to dict if it's not already
        if not isinstance(result, dict):
            result = result.to_dict()
            
        # Get the list of items using the endpoint-specific key
        items_key = endpoint_config['key']
        items = result.get(items_key, [])
        
        if not items:
            break
            
        all_items.extend(items)
        logger.info(f"Retrieved page {page} for {api_call} with {len(items)} items")
        
        # Check if we got less than a full page
        if len(items) < page_size:
            break
            
        page += 1
    
    # Return combined result with all items
    result[items_key] = all_items
    logger.info(f"Total {len(all_items)} items retrieved for {api_call}")
    return result

def main():
    failed_calls = []
    successful_endpoints = {}

    try:
        # initialize TokenManager and get token
        token_manager = TokenManager()
        token = token_manager.get_token()
        logger.debug(f"initial token: access_token={token['access_token'][:4]}..., expires_at={token['expires_at']}")

        # initialize configuration and OAuth2Token
        configuration = Configuration()
        oauth2_token = OAuth2Token(
            client_id=token_manager.app_id,
            client_secret=token_manager.app_secret
        )
        oauth2_token.update_token(**token)
        configuration.oauth2_token = oauth2_token

        # initialize ApiClient
        api_client = ApiClient(configuration=configuration)
        api_client.oauth2_token_getter(oauth2_token_getter)

        # initialize AccountingApi
        accounting_api = AccountingApi(api_client=api_client)

        # retrieve tenant_id
        tenant_id = os.getenv("TENANT_ID")
        if not tenant_id:
            raise ValueError("TENANT_ID environment variable must be set.")

        # list of API calls to make
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

        # make API calls and save results
        for api_call, params in api_calls:
            attempt = 0
            max_attempts = 2
            while attempt < max_attempts:
                try:
                    logger.info(f"Calling {api_call}")
                    
                    # use pagination helper function
                    result = get_paginated_data(accounting_api, api_call, tenant_id, params)

                    # convert result to dict if it's not already
                    if not isinstance(result, dict):
                        result = result.to_dict()

                    # add ingestion time
                    result['ingestion_time'] = datetime.utcnow().isoformat()

                    # save to GCS in NDJSON format
                    endpoint_name = api_call.replace("get_", "")
                    save_to_gcs(result, endpoint_name)

                    logger.info(f"successfully processed and saved data from {api_call}")
                    successful_endpoints[endpoint_name] = {}
                    break

                except ApiException as e:
                    if e.status == 401 and 'tokenexpired' in e.body.decode('utf-8'):
                        logger.warning(f"unauthorized error for {api_call}, attempting to refresh token.")
                        try:
                            # force TokenManager to refresh token
                            new_tokens = token_manager.refresh_token(token['refresh_token'], token['scope'])
                            # update OAuth2Token with new token
                            oauth2_token.update_token(**new_tokens)
                            # update the ApiClient with new token
                            configuration.oauth2_token = oauth2_token
                            token = new_tokens
                            attempt += 1
                            logger.info(f"token refreshed... retrying {api_call} (Attempt {attempt}/{max_attempts})")
                        except Exception as refresh_e:
                            logger.error(f"failed to refresh token for {api_call}: {refresh_e}")
                            failed_calls.append((api_call, str(e)))
                            break
                    else:
                        logger.error(f"error in {api_call}: {str(e)}")
                        failed_calls.append((api_call, str(e)))
                        break
                except Exception as e:
                    logger.error(f"unexpected error in {api_call}: {str(e)}")
                    failed_calls.append((api_call, str(e)))
                    break

        # after all API calls, load data to BigQuery
        if successful_endpoints:
            create_external_table(successful_endpoints)

            # trigger the transformation job after successful ingestion
            logger.info("triggering the data transformation job")
            transformation_triggered = trigger_transformation_job()
            if transformation_triggered:
                logger.info("data transformation job has been triggered successfully")
            else:
                logger.error("failed to trigger the data transformation job")

    except OAuth2TokenGetterError as e:
        logger.error(f"error getting token: {e}")
    except OAuth2TokenSaverError as e:
        logger.error(f"error saving token: {e}")
    except Exception as e:
        logger.error(f"error: {e}")
        if hasattr(e, 'body'):
            logger.error(f"response body: {e.body}")
    finally:
        if failed_calls:
            logger.warning(f"completed with failures in {len(failed_calls)} API calls:")
            for call, error in failed_calls:
                logger.warning(f"- {call}: {error}")
        else:
            logger.info("all API calls completed successfully")

if __name__ == "__main__":
    main()