# xero_python/main.py

import os
from xero_python.accounting import AccountingApi
from xero_python.api_client import ApiClient, Configuration, OAuth2Token
from xero_python.token_manager import TokenManager, oauth2_token_getter, oauth2_token_saver

# Initialize TokenManager
token_manager = TokenManager()

# Initialize Configuration with OAuth2Token
oauth2_token = OAuth2Token(
    client_id=token_manager.client_id_env,  # Use client_id_env
    client_secret=token_manager.client_secret
)

configuration = Configuration(
    oauth2_token=oauth2_token
)

# Initialize ApiClient with token getter and saver
api_client = ApiClient(
    configuration=configuration,
    oauth2_token_getter=oauth2_token_getter,
    oauth2_token_saver=oauth2_token_saver
)

# Initialize AccountingApi with the configured ApiClient
accounting_api = AccountingApi(api_client=api_client)

def fetch_accounts():
    try:
        # Retrieve the token
        token = oauth2_token_getter()
        
        # Option 1: If client_id is part of the token (unlikely)
        if 'xero_client_id' in token:
            client_id = token['xero_client_id']
        
        accounts = accounting_api.get_accounts(xero_client_id=client_id)
        for account in accounts.accounts:
            print(f"Account Code: {account.code}, Name: {account.name}")
    except Exception as e:
        print(f"Error: {e}")

def main():
    fetch_accounts()

if __name__ == "__main__":
    main()