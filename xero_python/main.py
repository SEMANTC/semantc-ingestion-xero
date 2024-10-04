# xero_python/main.py

import os
import json
import time
from xero_python.accounting import AccountingApi
from xero_python.api_client import ApiClient, Configuration
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.token_manager import oauth2_token_getter, oauth2_token_saver
from xero_python.exceptions import OAuth2TokenGetterError, OAuth2TokenSaverError

def main():
    try:
        # Initialize Configuration without setting OAuth2Token initially
        configuration = Configuration()

        # Initialize OAuth2Token with token getter and saver callbacks
        oauth2_token = OAuth2Token(
            token_getter=oauth2_token_getter,
            token_saver=oauth2_token_saver
        )

        # Assign the OAuth2Token to the configuration
        configuration.oauth2_token = oauth2_token

        # Initialize ApiClient with the configured Configuration
        api_client = ApiClient(
            configuration=configuration,
            oauth2_token_getter=oauth2_token_getter,
            oauth2_token_saver=oauth2_token_saver
        )

        # Initialize AccountingApi with the configured ApiClient
        accounting_api = AccountingApi(api_client=api_client)

        # Retrieve tenant_id from environment variables
        tenant_id = os.getenv("CLIENT_ID")
        if not tenant_id:
            raise ValueError("TENANT_ID environment variable must be set.")

        # Call get_accounts to retrieve the chart of accounts
        accounts = accounting_api.get_accounts(xero_tenant_id=tenant_id)

        # Print the retrieved accounts
        print("Accounts:")
        for account in accounts.accounts:
            print(f"Account Code: {account.code}, Name: {account.name}")

    except OAuth2TokenGetterError as e:
        print(f"Error getting token: {e}")
    except OAuth2TokenSaverError as e:
        print(f"Error saving token: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()