# xero-python/main.py

import os
import json
from datetime import datetime
from ratelimit import limits, sleep_and_retry
from xero_python.accounting import AccountingApi
from xero_python.api_client import ApiClient, Configuration
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.token_manager.token_manager import TokenManager, oauth2_token_getter, oauth2_token_saver
from xero_python.exceptions import OAuth2TokenGetterError, OAuth2TokenSaverError
from xero_python.utils import get_logger
from storage import write_json_to_gcs

logger = get_logger()

RATE_LIMIT_CALLS = 60
RATE_LIMIT_PERIOD = 50  # seconds

@sleep_and_retry
@limits(calls=RATE_LIMIT_CALLS, period=RATE_LIMIT_PERIOD)
def rate_limited_api_call(func, *args, **kwargs):
    return func(*args, **kwargs)

def save_to_gcs(data, endpoint_name):
    bucket_name = os.getenv("GCS_BUCKET_NAME")
    bucket_name = "client-7a94e511-25e3-4b98-978c-2c910a779ade-bucket-xero"
    if not bucket_name:
        raise ValueError("GCS_BUCKET_NAME environment variable must be set.")
    
    file_name = f"xero_{endpoint_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    json_content = json.dumps(data, default=str, indent=2)
    write_json_to_gcs(bucket_name, file_name, json_content)

def main():
    try:
        # Initialize TokenManager and get credentials
        token_manager = TokenManager()
        client_id, client_secret = token_manager.app_id, token_manager.app_secret

        # Initialize Configuration and OAuth2Token
        configuration = Configuration()
        token = oauth2_token_getter()
        oauth2_token = OAuth2Token(client_id=client_id, client_secret=client_secret)
        oauth2_token.update_token(**token)
        configuration.oauth2_token = oauth2_token

        # Initialize ApiClient
        api_client = ApiClient(configuration=configuration)
        api_client.oauth2_token_getter(oauth2_token_getter)
        api_client.oauth2_token_saver(oauth2_token_saver)

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

        # Make API calls and save results
        for api_call, params in api_calls:
            try:
                logger.info(f"Calling {api_call}")
                func = getattr(accounting_api, api_call)
                result = rate_limited_api_call(func, xero_tenant_id=tenant_id, **params)
                
                # Convert result to dict if it's not already
                if not isinstance(result, dict):
                    result = result.to_dict()
                
                # Add ingestion time
                result['ingestion_time'] = datetime.utcnow().isoformat()
                
                # Save to GCS
                save_to_gcs(result, api_call)
                
                logger.info(f"Successfully processed and saved data from {api_call}")
            except Exception as e:
                logger.error(f"Error in {api_call}: {str(e)}")

    except OAuth2TokenGetterError as e:
        logger.error(f"Error getting token: {e}")
    except OAuth2TokenSaverError as e:
        logger.error(f"Error saving token: {e}")
    except Exception as e:
        logger.error(f"Error: {e}")
        if hasattr(e, 'body'):
            logger.error(f"Response body: {e.body}")

if __name__ == "__main__":
    main()