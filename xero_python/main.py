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
    # identify the key that contains the list of items
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

def main():
    failed_calls = []
    successful_endpoints = {}

    try:
        # initialize TokenManager and get token
        token_manager = TokenManager()
        token = token_manager.get_token()
        logger.debug(f"initial token: access_token={token['access_token'][:4]}..., expires_at={token['expires_at']}")

        # initialize Configuration and OAuth2Token
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

        # Initialize AccountingApi
        accounting_api = AccountingApi(api_client=api_client)

        # Retrieve tenant_id
        tenant_id = os.getenv("TENANT_ID")
        if not tenant_id:
            raise ValueError("TENANT_ID environment variable must be set.")

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

        # make API calls and save results
        for api_call, params in api_calls:
            attempt = 0
            max_attempts = 2
            while attempt < max_attempts:
                try:
                    logger.info(f"calling {api_call}")
                    func = getattr(accounting_api, api_call)
                    result = rate_limited_api_call(func, xero_tenant_id=tenant_id, **params)

                    # convert result to dict if it's not already
                    if not isinstance(result, dict):
                        result = result.to_dict()

                    # add ingestion time
                    result['ingestion_time'] = datetime.utcnow().isoformat()

                    # save to GCS in NDJSON format
                    save_to_gcs(result, api_call)

                    logger.info(f"Successfully processed and saved data from {api_call}")
                    successful_endpoints[api_call] = {}  # Add to successful endpoints
                    break  # success, exit the retry loop
                except ApiException as e:
                    if e.status == 401 and 'tokenexpired' in e.body.decode('utf-8'):
                        logger.warning(f"unauthorized error for {api_call}, attempting to refresh token.")
                        try:
                            # Force TokenManager to refresh token
                            new_tokens = token_manager.refresh_token(token['refresh_token'], token['scope'])
                            # Update OAuth2Token with new token
                            oauth2_token.update_token(**new_tokens)
                            # Update the ApiClient with new token
                            configuration.oauth2_token = oauth2_token
                            token = new_tokens
                            attempt += 1
                            logger.info(f"token refreshed... retrying {api_call} (Attempt {attempt}/{max_attempts})")
                        except Exception as refresh_e:
                            logger.error(f"failed to refresh token for {api_call}: {refresh_e}")
                            failed_calls.append((api_call, str(e)))
                            break  # Stop retrying this API call
                    else:
                        logger.error(f"Error in {api_call}: {str(e)}")
                        failed_calls.append((api_call, str(e)))
                        break  # Stop retrying this API call
                except Exception as e:
                    logger.error(f"Unexpected error in {api_call}: {str(e)}")
                    failed_calls.append((api_call, str(e)))
                    break  # Stop retrying this API call

        # After all API calls, load data to BigQuery
        if successful_endpoints:
            create_external_table(successful_endpoints)

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