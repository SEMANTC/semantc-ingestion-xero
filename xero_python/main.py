# xero_python/main.py

import os
from xero_python.accounting import AccountingApi
from xero_python.api_client import ApiClient, Configuration
from xero_python.api_client.token_manager import oauth2_token_getter, oauth2_token_saver
from xero_python.exceptions import OAuth2TokenGetterError, OAuth2TokenSaverError

def main():
    try:
        # Initialize Configuration
        configuration = Configuration()

        # Initialize ApiClient with token getter and saver
        api_client = ApiClient(
            configuration=configuration,
            oauth2_token_getter=oauth2_token_getter,
            oauth2_token_saver=oauth2_token_saver
        )

        # Initialize AccountingApi
        accounting_api = AccountingApi(api_client=api_client)

        # Get tenant_id from environment variable
        tenant_id = os.getenv("CLIENT_ID")
        if not tenant_id:
            raise ValueError("CLIENT_ID environment variable must be set.")

        # Call get_accounts
        accounts = accounting_api.get_accounts(xero_tenant_id=tenant_id)
        for account in accounts.accounts:
            # print(f"Account Code: {account.code}, Name: {account.name}")
            print(account)

    except OAuth2TokenGetterError as e:
        print(f"Error getting token: {e}")
    except OAuth2TokenSaverError as e:
        print(f"Error saving token: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()