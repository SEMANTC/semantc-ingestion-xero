import os
import json
import time
import requests
import jwt  # PyJWT library
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

# initialize Secret Manager client
client = secretmanager.SecretManagerServiceClient()

class TokenManager:
    refresh_token_url = "https://identity.xero.com/connect/token"
    expiration_buffer = 60  # seconds

    def __init__(self):
        self.project_id = os.getenv("PROJECT_ID")
        self.tenant_id = os.getenv("TENANT_ID")
        if not self.project_id or not self.tenant_id:
            raise ValueError("PROJECT_ID and TENANT_ID environment variables must be set.")
        self.lock = Lock()
        self.app_id, self.app_secret = self.get_app_credentials()

    def get_secret(self, secret_id: str) -> str:
        try:
            name = f"projects/{self.project_id}/secrets/{secret_id}/versions/latest"
            response = client.access_secret_version(name=name)
            secret = response.payload.data.decode('UTF-8')
            # logger.debug(f"retrieved secret '{secret_id}': {secret[:4]}...")
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
            tokens_json = self.get_secret(secret_id)
            tokens = json.loads(tokens_json)
            required = {'access_token', 'refresh_token', 'expires_in', 'token_type', 'scope'}
            if not required.issubset(tokens.keys()):
                logger.error("incomplete token data")
                raise TokenRetrievalError("incomplete token data")
            
            # if 'expires_at' is missing, parse it from the jwt
            if 'expires_at' not in tokens:
                tokens['expires_at'] = self.parse_expiration(tokens['access_token'])
                # logger.debug(f"set 'expires_at' to {tokens['expires_at']}")
            # else:
            #     logger.debug(f"retrieved 'expires_at': {tokens['expires_at']}")
            
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
            logger.info("stored refreshed tokens")
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
            # logger.debug(f"requesting token refresh with data: {post_data}")
            response = requests.post(
                self.refresh_token_url,
                data=post_data,
                headers=headers,
            )
            status = response.status_code
            headers_resp = response.headers

            if status != 200:
                logger.error(
                    f"failed to refresh token. status: {status}, response: {response.text}, headers: {headers_resp}"
                )
                raise TokenRetrievalError(
                    f"refresh token request failed with status {status}"
                )

            new_tokens = response.json()
            new_tokens['expires_at'] = self.parse_expiration(new_tokens['access_token'])

            # Retain the old refresh_token if a new one isn't provided
            if 'refresh_token' not in new_tokens:
                new_tokens['refresh_token'] = refresh_token
                # logger.debug("no new refresh_token provided; retaining the existing one")

            logger.info("token refreshed successfully")
            # logger.debug(f"new tokens: access_token={new_tokens['access_token'][:4]}..., expires_at={new_tokens['expires_at']}")
            return new_tokens
        except requests.RequestException as e:
            logger.error(f"token refresh failed: {e}")
            raise TokenRetrievalError(f"token refresh failed: {e}") from e

    def parse_expiration(self, access_token: str) -> float:
        try:
            # Decode the JWT without verification to extract 'exp'
            decoded = jwt.decode(access_token, options={"verify_signature": False})
            exp = decoded.get('exp')
            if not exp:
                logger.error("no 'exp' field found in access_token.")
                raise TokenRetrievalError("no 'exp' field found in access_token.")
            
            # Subtract buffer to account for clock skew
            expires_at = exp - self.expiration_buffer
            # logger.debug(f"parsed 'exp' from JWT: {exp}, set 'expires_at' to: {expires_at}")
            return expires_at
        except jwt.DecodeError as e:
            logger.error(f"failed to decode access_token JWT: {e}")
            raise TokenRetrievalError(f"failed to decode access_token JWT: {e}") from e

    def get_token(self):
        with self.lock:
            tokens = self.retrieve_tokens()
            current_time = time.time()
            expires_at = tokens.get('expires_at', 0)
            # logger.debug(f"current time: {current_time}, Token expires at: {expires_at}")

            if expires_at < current_time:
                logger.info("token expired, attempting to refresh.")
                try:
                    new_tokens = self.refresh_token(tokens['refresh_token'], tokens['scope'])
                    self.store_tokens(new_tokens)
                    return new_tokens
                except Exception as e:
                    logger.error(f"failed to refresh token: {e}")
                    raise TokenRetrievalError("token expired and refresh failed. Manual reauthorization may be required.")
            # else:
            #     logger.debug("token is still valid.")
            return tokens

def oauth2_token_getter():
    try:
        token_manager = TokenManager()
        token = token_manager.get_token()
        # logger.debug(f"oauth2_token_getter retrieved token: access_token={token['access_token'][:4]}..., expires_at={token['expires_at']}")
        return token
    except Exception as e:
        logger.error(f"token retrieval failed: {e}")
        raise OAuth2TokenGetterError("failed to get OAuth2 token") from e