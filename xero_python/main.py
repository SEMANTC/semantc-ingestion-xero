# xero_python/main.py

import os
import json
from xero_python.token_manager import TokenManager, oauth2_token_getter, oauth2_token_saver
from xero_python.exceptions import OAuth2TokenGetterError, OAuth2TokenSaverError

def main():
    # Initialize TokenManager
    token_manager = TokenManager()
    
    try:
        # Get current token
        token = oauth2_token_getter()
        print("Current Token:")
        print(json.dumps(token, indent=2))
        
        # Refresh the token
        if 'refresh_token' in token:
            refreshed_token = token_manager.refresh_access_token(token['refresh_token'])
            print("\nRefreshed Token:")
            print(json.dumps(refreshed_token, indent=2))
        else:
            print("No refresh token available.")
    
    except OAuth2TokenGetterError as e:
        print(f"Error getting token: {e}")
    except OAuth2TokenSaverError as e:
        print(f"Error saving token: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()