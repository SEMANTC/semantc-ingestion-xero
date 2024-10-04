# xero_python/token_manager.py

import os
import json
import time
from threading import Lock
from google.cloud import secretmanager
from requests_oauthlib import OAuth2Session

from xero_python.exceptions import (
    SecretManagerError,
    TokenRetrievalError,
    OAuth2TokenGetterError,
    OAuth2TokenSaverError
)

from xero_python.utils import get_logger

logger = get_logger()

# Initialize Secret Manager client
client = secretmanager.SecretManagerServiceClient()

class TokenManager:
    """
    Manages OAuth2 tokens using Google Secret Manager.
    """
    def __init__(self):
        self.project_id = os.getenv("PROJECT_ID")
        self.api_client = os.getenv("CLIENT_ID")
        if not self.project_id or not self.api_client:
            raise ValueError("PROJECT_ID and CLIENT_ID environment variables must be set.")
        self.lock = Lock()
        self.token_cache = {}
        # Retrieve application credentials
        self.app_id, self.app_secret = self.get_app_credentials()

    def get_secret(self, secret_id: str) -> str:
        try:
            name = f"projects/{self.project_id}/secrets/{secret_id}/versions/latest"
            response = client.access_secret_version(name=name)
            secret = response.payload.data.decode('UTF-8')
            logger.debug(f"Retrieved secret '{secret_id}'")
            return secret
        except Exception as e:
            logger.error(f"Failed to access secret '{secret_id}': {e}")
            raise SecretManagerError(f"Failed to access secret '{secret_id}'") from e

    def get_app_credentials(self) -> tuple:
        app_id = self.get_secret("core-client-id-xero")
        app_secret = self.get_secret("core-client-secret-xero")
        return app_id, app_secret

    def retrieve_tokens(self) -> dict:
        try:
            secret_id = f"client-{self.api_client}-token-xero"
            logger.debug(f"Accessing secret_id: {secret_id}")
            tokens_json = self.get_secret(secret_id)
            tokens = json.loads(tokens_json)
            required = {'access_token', 'refresh_token', 'expires_in', 'token_type', 'scope'}
            if not required.issubset(tokens.keys()):
                logger.error("Incomplete token data")
                raise TokenRetrievalError("Incomplete token data")
            # Calculate 'expires_at' if not present
            if 'expires_at' not in tokens:
                tokens['expires_at'] = time.time() + tokens.get('expires_in', 1800)
            return tokens
        except Exception as e:
            logger.error(f"Error retrieving tokens: {e}")
            raise TokenRetrievalError(f"Error retrieving tokens: {e}") from e

    def store_tokens(self, tokens: dict):
        try:
            secret_id = f"client-{self.api_client}-token-xero"
            parent = f"projects/{self.project_id}/secrets/{secret_id}"
            payload = json.dumps(tokens).encode("UTF-8")
            client.add_secret_version(parent=parent, payload={"data": payload})
            logger.info("Stored refreshed tokens")
        except Exception as e:
            logger.error(f"Error storing tokens: {e}")
            raise SecretManagerError(f"Failed to store tokens: {e}") from e

    def refresh_access_token(self, refresh_token: str) -> dict:
        """
        Refreshes the OAuth2 access token using the refresh token.
        """
        if not refresh_token:
            logger.error("No refresh token available")
            raise TokenRetrievalError("Missing refresh token")
        try:
            oauth = OAuth2Session(self.app_id, token={
                'refresh_token': refresh_token,
                'token_type': 'Bearer'
            })
            new_tokens = oauth.refresh_token(
                'https://identity.xero.com/connect/token',
                client_id=self.app_id,
                client_secret=self.app_secret
            )
            new_tokens['expires_at'] = time.time() + new_tokens.get('expires_in', 1800)
            return new_tokens
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise TokenRetrievalError(f"Token refresh failed: {e}") from e

    def get_token(self) -> dict:
        with self.lock:
            cached = self.token_cache.get(self.app_id)
            if cached and cached.get('expires_at', 0) > time.time():
                logger.debug("Using cached token")
                return cached
            tokens = self.retrieve_tokens()
            if tokens.get('expires_at', 0) < time.time():
                tokens = self.refresh_access_token(tokens.get('refresh_token'))
                self.store_tokens(tokens)
            self.token_cache[self.app_id] = tokens
            return tokens

    def save_token(self, token: dict):
        with self.lock:
            self.store_tokens(token)
            self.token_cache[self.app_id] = token
            logger.debug("Saved new token")

# Initialize TokenManager
token_manager = TokenManager()

# Define oauth2_token_getter callback
def oauth2_token_getter():
    try:
        token = token_manager.get_token()
        return token
    except Exception as e:
        logger.error(f"Token retrieval failed: {e}")
        raise OAuth2TokenGetterError("Failed to get OAuth2 token") from e

# Define oauth2_token_saver callback
def oauth2_token_saver(token):
    try:
        token_manager.save_token(token)
    except Exception as e:
        logger.error(f"Token saving failed: {e}")
        raise OAuth2TokenSaverError("Failed to save OAuth2 token") from e