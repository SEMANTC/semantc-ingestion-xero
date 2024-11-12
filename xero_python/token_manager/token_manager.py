# xero_python/token_manager/token_manager.py
import os
import json
import time
import requests
import jwt
import asyncio
import aiohttp
from google.cloud import firestore
from google.cloud import secretmanager
from cryptography.fernet import Fernet
from google.cloud.firestore import AsyncClient

from xero_python.exceptions import (
    SecretManagerError,
    TokenRetrievalError,
    OAuth2TokenGetterError,
    OAuth2TokenSaverError
)

from xero_python.utils import get_logger

logger = get_logger()

class FirestoreTokenManager:
    """
    Manages OAuth tokens using Firestore, while keeping client credentials in Secret Manager.
    Retrieves tenant information and manages tokens for Xero integration.
    """
    refresh_token_url = "https://identity.xero.com/connect/token"
    expiration_buffer = 60  # seconds

    def __init__(self, user_id: str):
        if not user_id:
            raise ValueError("user_id must be provided")
            
        self.user_id = user_id
        self.tenant_id = None  # Will be populated when needed
        self.lock = asyncio.Lock()  # Changed to asyncio.Lock
        self.db = AsyncClient()  # Changed to AsyncClient
        self.sm_client = secretmanager.SecretManagerServiceClient()
        
        # Initialize encryption
        self.encryption_key = os.getenv('TOKEN_ENCRYPTION_KEY')
        if not self.encryption_key:
            raise ValueError("TOKEN_ENCRYPTION_KEY environment variable must be set")
        self.fernet = Fernet(self.encryption_key.encode())
        
        # Get project ID for Secret Manager
        self.project_id = os.getenv('PROJECT_ID')
        if not self.project_id:
            raise ValueError("PROJECT_ID environment variable must be set")
            
        # Initialize client credentials as None - will be fetched when needed
        self.app_id = None
        self.app_secret = None

    def get_secret(self, secret_id: str) -> str:
        """Retrieves a secret from Secret Manager"""
        try:
            name = f"projects/{self.project_id}/secrets/{secret_id}/versions/latest"
            response = self.sm_client.access_secret_version(name=name)
            return response.payload.data.decode('UTF-8')
        except Exception as e:
            logger.error(f"Failed to access secret '{secret_id}': {e}")
            raise SecretManagerError(f"Failed to access secret '{secret_id}'") from e

    async def get_client_credentials(self) -> tuple:
        """Gets Xero client credentials from Secret Manager"""
        if self.app_id and self.app_secret:
            return self.app_id, self.app_secret
            
        try:
            self.app_id = self.get_secret("core-client-id-xero")
            self.app_secret = self.get_secret("core-client-secret-xero")
            return self.app_id, self.app_secret
        except Exception as e:
            logger.error(f"Failed to get client credentials: {e}")
            raise TokenRetrievalError("Failed to get client credentials") from e

    async def get_tenant_id(self) -> str:
        """Retrieves Xero tenant ID from Firestore connectors collection"""
        if self.tenant_id:
            return self.tenant_id
            
        doc_ref = (self.db
                  .collection('users')
                  .document(self.user_id)
                  .collection('integrations')
                  .document('connectors'))
        
        doc = await doc_ref.get()  # Using async get
        if not doc.exists:
            raise TokenRetrievalError(f"No connector configuration found for user {self.user_id}")
            
        data = doc.to_dict()
        xero_config = data.get('xero', {})
        tenant_id = xero_config.get('tenantId')
        
        if not tenant_id:
            raise TokenRetrievalError(f"No Xero tenant ID found for user {self.user_id}")
            
        self.tenant_id = tenant_id
        return tenant_id

    def _get_token_doc_ref(self):
        """Gets reference to the token document in Firestore"""
        if not self.tenant_id:
            raise ValueError("tenant_id not initialized - call get_tenant_id() first")
            
        return (self.db
                .collection('users')
                .document(self.user_id)
                .collection('integrations')
                .document('credentials')
                .collection('xero')
                .document(self.tenant_id))

    def _encrypt_tokens(self, tokens: dict) -> str:
        """Encrypts token data before storing in Firestore"""
        tokens_json = json.dumps(tokens)
        encrypted_data = self.fernet.encrypt(tokens_json.encode())
        return encrypted_data.decode()

    def _decrypt_tokens(self, encrypted_data: str) -> dict:
        """Decrypts token data retrieved from Firestore"""
        decrypted_data = self.fernet.decrypt(encrypted_data.encode())
        return json.loads(decrypted_data)

    async def store_tokens(self, tokens: dict):
        """Stores encrypted tokens in Firestore"""
        try:
            encrypted_tokens = self._encrypt_tokens(tokens)
            
            doc_ref = self._get_token_doc_ref()
            await doc_ref.set({
                'encryptedData': encrypted_tokens,
                'lastUpdated': firestore.SERVER_TIMESTAMP
            })
            
            logger.info(f"Stored refreshed tokens for user {self.user_id}")
        except Exception as e:
            logger.error(f"Error storing tokens: {e}")
            raise TokenStorageError(f"Failed to store tokens: {e}") from e

    async def retrieve_tokens(self) -> dict:
        """Retrieves and decrypts tokens from Firestore"""
        try:
            # Ensure we have the tenant_id
            if not self.tenant_id:
                await self.get_tenant_id()
                
            doc_ref = self._get_token_doc_ref()
            doc = await doc_ref.get()
            
            if not doc.exists:
                raise TokenRetrievalError("No tokens found for this user/tenant")
                
            data = doc.to_dict()
            encrypted_tokens = data.get('encryptedData')
            if not encrypted_tokens:
                raise TokenRetrievalError("No encrypted token data found")
                
            tokens = self._decrypt_tokens(encrypted_tokens)
            
            required = {'access_token', 'refresh_token', 'expires_in', 'token_type', 'scope'}
            if not required.issubset(tokens.keys()):
                raise TokenRetrievalError("Incomplete token data")
            
            if 'expires_at' not in tokens:
                tokens['expires_at'] = self.parse_expiration(tokens['access_token'])
                
            return tokens
            
        except Exception as e:
            logger.error(f"Error retrieving tokens: {e}")
            raise TokenRetrievalError(f"Error retrieving tokens: {e}") from e

    def parse_expiration(self, access_token: str) -> float:
        """Parses token expiration from JWT"""
        try:
            decoded = jwt.decode(access_token, options={"verify_signature": False})
            exp = decoded.get('exp')
            if not exp:
                raise TokenRetrievalError("No 'exp' field found in access_token")
            return exp - self.expiration_buffer
        except jwt.DecodeError as e:
            raise TokenRetrievalError(f"Failed to decode access_token JWT: {e}") from e

    async def refresh_token(self, refresh_token: str, scope: str | list):
        """Refreshes the OAuth token"""
        client_id, client_secret = await self.get_client_credentials()
        
        post_data = {
            "grant_type": "refresh_token",
            "scope": " ".join(scope) if isinstance(scope, (list, tuple)) else scope,
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(self.refresh_token_url, data=post_data, headers=headers) as response:
                    if response.status != 200:
                        raise TokenRetrievalError(
                            f"Refresh token request failed with status {response.status}"
                        )

                    new_tokens = await response.json()
                    new_tokens['expires_at'] = self.parse_expiration(new_tokens['access_token'])

                    if 'refresh_token' not in new_tokens:
                        new_tokens['refresh_token'] = refresh_token

                    await self.store_tokens(new_tokens)
                    
                    logger.info(f"Token refreshed successfully for user {self.user_id}")
                    return new_tokens
                    
            except aiohttp.ClientError as e:
                logger.error(f"Token refresh failed: {e}")
                raise TokenRetrievalError(f"Token refresh failed: {e}") from e

    async def get_token(self):
        """Main method to get a valid token, refreshing if necessary"""
        async with self.lock:
            tokens = await self.retrieve_tokens()
            current_time = time.time()
            expires_at = tokens.get('expires_at', 0)

            if expires_at < current_time:
                logger.info("Token expired, attempting to refresh")
                try:
                    return await self.refresh_token(tokens['refresh_token'], tokens['scope'])
                except Exception as e:
                    logger.error(f"Failed to refresh token: {e}")
                    raise TokenRetrievalError("Token expired and refresh failed. Manual reauthorization may be required.")
                    
            return tokens

async def oauth2_token_getter(user_id: str):
    """OAuth2 token getter function for the Xero client"""
    try:
        token_manager = FirestoreTokenManager(user_id)
        return await token_manager.get_token()
    except Exception as e:
        logger.error(f"Token retrieval failed: {e}")
        raise OAuth2TokenGetterError("Failed to get OAuth2 token") from e