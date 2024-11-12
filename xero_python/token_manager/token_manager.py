import os
import json
import time
import requests
import jwt
import asyncio
import aiohttp
import base64
from google.cloud import firestore
from google.cloud import secretmanager
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xero_python.exceptions import (
    SecretManagerError,
    TokenRetrievalError,
    OAuth2TokenGetterError,
    OAuth2TokenSaverError
)

from xero_python.utils import get_logger

logger = get_logger()

class TokenEncryption:
    """Handles encryption/decryption compatible with frontend Node.js implementation"""
    IV_LENGTH = 12
    AUTH_TAG_LENGTH = 16
    KEY_LENGTH = 32

    def __init__(self, encryption_key: str):
        self.key = self._normalize_key(encryption_key)

    def _normalize_key(self, key: str) -> bytes:
        """Normalize key to exactly 32 bytes, matching Node.js implementation"""
        try:
            # Try base64 decode first
            buffer = base64.b64decode(key)
        except:
            buffer = key.encode()

        if len(buffer) < self.KEY_LENGTH:
            # Pad if too short
            buffer = buffer + os.urandom(self.KEY_LENGTH - len(buffer))
        elif len(buffer) > self.KEY_LENGTH:
            # Hash if too long
            digest = hashes.Hash(hashes.SHA256())
            digest.update(buffer)
            buffer = digest.finalize()

        return buffer

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data using AES-256-GCM"""
        try:
            # Decode base64
            buffer = base64.b64decode(encrypted_data)
            
            # Extract parts
            iv = buffer[:self.IV_LENGTH]
            auth_tag = buffer[-self.AUTH_TAG_LENGTH:]
            ciphertext = buffer[self.IV_LENGTH:-self.AUTH_TAG_LENGTH]

            # Create AESGCM cipher
            aesgcm = AESGCM(self.key)
            
            # Decrypt
            plaintext = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
            return plaintext.decode('utf-8')

        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise TokenRetrievalError(f"Failed to decrypt token: {str(e)}")

    def encrypt(self, text: str) -> str:
        """Encrypt data using AES-256-GCM"""
        try:
            # Generate random IV
            iv = os.urandom(self.IV_LENGTH)
            
            # Create AESGCM cipher
            aesgcm = AESGCM(self.key)
            
            # Encrypt
            ciphertext = aesgcm.encrypt(iv, text.encode(), None)
            
            # Combine IV + ciphertext[:-16] + auth_tag[last 16 bytes]
            combined = iv + ciphertext[:-self.AUTH_TAG_LENGTH] + ciphertext[-self.AUTH_TAG_LENGTH:]
            
            # Return base64 encoded result
            return base64.b64encode(combined).decode('utf-8')

        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise TokenStorageError(f"Failed to encrypt token: {str(e)}")

class FirestoreTokenManager:
    """Manages OAuth tokens using Firestore and matches frontend encryption"""
    refresh_token_url = "https://identity.xero.com/connect/token"
    expiration_buffer = 60  # seconds

    def __init__(self, user_id: str):
        if not user_id:
            raise ValueError("user_id must be provided")
            
        self.user_id = user_id
        self.tenant_id = None
        self.lock = asyncio.Lock()
        self.db = firestore.AsyncClient()
        self.sm_client = secretmanager.SecretManagerServiceClient()
        
        # Initialize encryption
        encryption_key = os.getenv('TOKEN_ENCRYPTION_KEY')
        if not encryption_key:
            raise ValueError("TOKEN_ENCRYPTION_KEY environment variable must be set")
        self.encryption = TokenEncryption(encryption_key)
        
        # Get project ID for Secret Manager
        self.project_id = os.getenv('PROJECT_ID')
        if not self.project_id:
            raise ValueError("PROJECT_ID environment variable must be set")
            
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
        
        doc = await doc_ref.get()
        if not doc.exists:
            raise TokenRetrievalError(f"No connector configuration found for user {self.user_id}")
            
        data = doc.to_dict()
        xero_config = data.get('xero', {})
        tenant_id = xero_config.get('tenantId')
        
        if not tenant_id:
            raise TokenRetrievalError(f"No Xero tenant ID found for user {self.user_id}")
            
        self.tenant_id = tenant_id
        return tenant_id

    def _get_credentials_ref(self):
        """Gets reference to the credentials document in Firestore"""
        return (self.db
                .collection('users')
                .document(self.user_id)
                .collection('integrations')
                .document('credentials'))

    def _decrypt_token(self, encrypted_token: str) -> str:
        """Decrypts a single token"""
        return self.encryption.decrypt(encrypted_token)

    def _encrypt_token(self, token: str) -> str:
        """Encrypts a single token"""
        return self.encryption.encrypt(token)

    async def store_tokens(self, tokens: dict):
        """Stores tokens in Firestore"""
        try:
            # Encrypt tokens and prepare for storage
            xero_data = {
                'accessToken': self._encrypt_token(tokens['access_token']),
                'refreshToken': self._encrypt_token(tokens['refresh_token']),
                'scope': ' '.join(tokens['scope']) if isinstance(tokens['scope'], (list, tuple)) else tokens['scope'],
                'tokenType': tokens['token_type'],
                'expiresAt': tokens['expires_at'],
                'lastUpdated': firestore.SERVER_TIMESTAMP
            }
            
            doc_ref = self._get_credentials_ref()
            await doc_ref.set({'xero': xero_data}, merge=True)
            
            logger.info(f"Stored refreshed tokens for user {self.user_id}")
        except Exception as e:
            logger.error(f"Error storing tokens: {e}")
            raise TokenStorageError(f"Failed to store tokens: {e}") from e

    async def retrieve_tokens(self) -> dict:
        """Retrieves and decrypts tokens from Firestore"""
        try:
            doc_ref = self._get_credentials_ref()
            doc = await doc_ref.get()
            
            if not doc.exists:
                raise TokenRetrievalError("No credentials document found")
                
            data = doc.to_dict()
            xero_data = data.get('xero', {})
            
            if not xero_data:
                raise TokenRetrievalError("No Xero token data found")

            # Check required fields
            required_fields = {'accessToken', 'refreshToken', 'scope', 'tokenType', 'expiresAt'}
            if not all(field in xero_data for field in required_fields):
                raise TokenRetrievalError("Incomplete token data in Firestore")
            
            # Decrypt tokens and convert to OAuth format
            tokens = {
                'access_token': self._decrypt_token(xero_data['accessToken']),
                'refresh_token': self._decrypt_token(xero_data['refreshToken']),
                'scope': xero_data['scope'].split(' ') if isinstance(xero_data['scope'], str) else xero_data['scope'],
                'token_type': xero_data['tokenType'],
                'expires_at': xero_data['expiresAt'],
                'expires_in': 1800  # Default 30 minutes
            }
            
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