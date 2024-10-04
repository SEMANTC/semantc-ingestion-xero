import os
import json
import time
import base64
import requests
from threading import Lock
from google.cloud import secretmanager

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
    refresh_token_url = "https://identity.xero.com/connect/token"

    def __init__(self):
        self.project_id = os.getenv("PROJECT_ID")
        self.tenant_id = os.getenv("TENANT_ID")
        if not self.project_id or not self.tenant_id:
            raise ValueError("PROJECT_ID and TENANT_ID environment variables must be set.")
        self.lock = Lock()
        self.token_cache = {}
        self.app_id, self.app_secret = self.get_app_credentials()

    def get_secret(self, secret_id: str) -> str:
        try:
            name = f"projects/{self.project_id}/secrets/{secret_id}/versions/latest"
            response = client.access_secret_version(name=name)
            secret = response.payload.data.decode('UTF-8')
            logger.debug(f"retrieved secret '{secret_id}'")
            return secret
        except Exception as e:
            logger.error(f"failed to access secret '{secret_id}': {e}")
            raise SecretManagerError(f"failed to access secret '{secret_id}'") from e

    def get_app_credentials(self) -> tuple:
        app_id = self.get_secret("core-client-id-xero")
        app_secret = self.get_secret("core-client-secret-xero")
        return app_id, app_secret

    def retrieve_tokens(self) -> dict:
        try:
            secret_id = f"client-{self.tenant_id}-token-xero"
            logger.debug(f"accessing secret_id: {secret_id}")
            tokens_json = self.get_secret(secret_id)
            tokens = json.loads(tokens_json)
            print(tokens)
            required = {'access_token', 'refresh_token', 'expires_in', 'token_type', 'scope'}
            if not required.issubset(tokens.keys()):
                logger.error("incomplete token data")
                raise TokenRetrievalError("Incomplete token data")
            if 'expires_at' not in tokens:
                tokens['expires_at'] = time.time() + tokens.get('expires_in', 1800)
            return tokens
        except Exception as e:
            logger.error(f"error retrieving tokens: {e}")
            raise TokenRetrievalError(f"error retrieving tokens: {e}") from e

    def store_tokens(self, tokens: dict):
        try:
            secret_id = f"client-{self.tenant_id}-token-xero"
            parent = f"projects/{self.project_id}/secrets/{secret_id}"
            payload = json.dumps(tokens).encode("UTF-8")
            client.add_secret_version(parent=parent, payload={"data": payload})
            logger.info("Stored refreshed tokens")
        except Exception as e:
            logger.error(f"error storing tokens: {e}")
            raise SecretManagerError(f"failed to store tokens: {e}") from e

    def refresh_token(self, refresh_token, scope):
        post_data = {
            "grant_type": "refresh_token",
            "scope": " ".join(scope) if isinstance(scope, (list, tuple)) else scope,
            "refresh_token": refresh_token,
            "client_id": self.app_id,
            "client_secret": self.app_secret,
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            response = requests.post(
                self.refresh_token_url,
                data=post_data,
                headers=headers,
            )
            status = response.status_code
            headers = response.headers

            if status != 200:
                raise Exception(
                    "refresh token status {} {} {!r}".format(status, response.text, headers)
                )

            new_tokens = response.json()
            new_tokens['expires_at'] = time.time() + new_tokens.get('expires_in', 1800)
            return new_tokens
        except requests.RequestException as e:
            logger.error(f"token refresh failed: {e}")
            raise TokenRetrievalError(f"token refresh failed: {e}")

    def get_token(self):
        with self.lock:
            tokens = self.retrieve_tokens()
            current_time = time.time()
            
            if tokens.get('expires_at', 0) < current_time:
                try:
                    new_tokens = self.refresh_token(tokens['refresh_token'], tokens['scope'])
                    self.store_tokens(new_tokens)
                    return new_tokens
                except Exception as e:
                    logger.error(f"failed to refresh token: {e}")
                    raise TokenRetrievalError("token expired and refresh failed. manual reauthorization may be required.")
            return tokens

# Initialize TokenManager
token_manager = TokenManager()

def oauth2_token_getter():
    try:
        token = token_manager.get_token()
        return token
    except Exception as e:
        logger.error(f"token retrieval failed: {e}")
        raise OAuth2TokenGetterError("failed to get OAuth2 token") from e

def oauth2_token_saver(token):
    try:
        token_manager.store_tokens(token)
    except Exception as e:
        logger.error(f"token saving failed: {e}")
        raise OAuth2TokenSaverError("failed to save OAuth2 token") from e