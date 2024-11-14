# xero_python/token_manager/token_manager.py
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
    """HANDLES ENCRYPTION/DECRYPTION COMPATIBLE WITH FRONTEND NODE.JS IMPLEMENTATION"""
    IV_LENGTH = 12
    AUTH_TAG_LENGTH = 16
    KEY_LENGTH = 32

    def __init__(self, encryption_key: str):
        self.key = self._normalize_key(encryption_key)

    def _normalize_key(self, key: str) -> bytes:
        """NORMALIZE KEY TO EXACTLY 32 BYTES, MATCHING NODE.JS IMPLEMENTATION"""
        try:
            # try base64 decode first
            buffer = base64.b64decode(key)
        except:
            buffer = key.encode()

        if len(buffer) < self.KEY_LENGTH:
            # pad if too short
            buffer = buffer + os.urandom(self.KEY_LENGTH - len(buffer))
        elif len(buffer) > self.KEY_LENGTH:
            # hash if too long
            digest = hashes.Hash(hashes.SHA256())
            digest.update(buffer)
            buffer = digest.finalize()

        return buffer

    def decrypt(self, encrypted_data: str) -> str:
        """DECRYPT DATA USING AES-256-GCM"""
        try:
            # decode base64
            buffer = base64.b64decode(encrypted_data)
            
            # extract parts
            iv = buffer[:self.IV_LENGTH]
            auth_tag = buffer[-self.AUTH_TAG_LENGTH:]
            ciphertext = buffer[self.IV_LENGTH:-self.AUTH_TAG_LENGTH]

            # create aesgcm cipher
            aesgcm = AESGCM(self.key)
            
            # decrypt
            plaintext = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
            return plaintext.decode('utf-8')

        except Exception as e:
            logger.error(f"decryption error: {str(e)}")
            raise TokenRetrievalError(f"failed to decrypt token: {str(e)}")

    def encrypt(self, text: str) -> str:
        """ENCRYPT DATA USING AES-256-GCM"""
        try:
            # generate random IV
            iv = os.urandom(self.IV_LENGTH)
            
            # create AESGCM cipher
            aesgcm = AESGCM(self.key)
            
            # encrypt
            ciphertext = aesgcm.encrypt(iv, text.encode(), None)
            
            # combine IV + ciphertext[:-16] + auth_tag[last 16 bytes]
            combined = iv + ciphertext[:-self.AUTH_TAG_LENGTH] + ciphertext[-self.AUTH_TAG_LENGTH:]
            
            # return base64 encoded result
            return base64.b64encode(combined).decode('utf-8')

        except Exception as e:
            logger.error(f"encryption error: {str(e)}")
            raise TokenStorageError(f"failed to encrypt token: {str(e)}")

class FirestoreTokenManager:
    """MANAGES OAUTH TOKENS USING FIRESTORE AND MATCHES FRONTEND ENCRYPTION"""
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
        """RETRIEVES A SECRET FROM SECRET MANAGER"""
        try:
            name = f"projects/{self.project_id}/secrets/{secret_id}/versions/latest"
            response = self.sm_client.access_secret_version(name=name)
            return response.payload.data.decode('UTF-8')
        except Exception as e:
            logger.error(f"failed to access secret '{secret_id}': {e}")
            raise SecretManagerError(f"failed to access secret '{secret_id}'") from e

    async def get_client_credentials(self) -> tuple:
        """GETS XERO CLIENT CREDENTIALS FROM SECRET MANAGER"""
        if self.app_id and self.app_secret:
            return self.app_id, self.app_secret
            
        try:
            self.app_id = self.get_secret("core-client-id-xero")
            self.app_secret = self.get_secret("core-client-secret-xero")
            return self.app_id, self.app_secret
        except Exception as e:
            logger.error(f"failed to get client credentials: {e}")
            raise TokenRetrievalError("failed to get client credentials") from e

    async def get_tenant_id(self) -> str:
        """RETRIEVES XERO TENANT ID FROM FIRESTORE CONNECTORS COLLECTION"""
        if self.tenant_id:
            return self.tenant_id
        
        try:
            logger.info(f"attempting to get tenant_id for user: {self.user_id}")
            
            doc_ref = (self.db
                    .collection('users')
                    .document(self.user_id)
                    .collection('integrations')
                    .document('connectors'))
            
            logger.debug(f"fetching document from: {doc_ref.path}")
            doc = await doc_ref.get()
            
            if not doc.exists:
                logger.error(f"no connector configuration found for user {self.user_id}")
                raise TokenRetrievalError(f"no connector configuration found for user {self.user_id}")
                
            data = doc.to_dict()
            logger.debug(f"retrieved connector data: {data}")
            
            xero_config = data.get('xero', {})
            logger.debug(f"xero config: {xero_config}")
            
            tenant_id = xero_config.get('tenantId')
            logger.info(f"found tenant_id: {tenant_id}")
            
            if not tenant_id:
                logger.error(f"no Xero tenant ID found for user {self.user_id}")
                raise TokenRetrievalError(f"no Xero tenant ID found for user {self.user_id}")
                
            self.tenant_id = tenant_id
            return tenant_id
            
        except Exception as e:
            logger.error(f"error retrieving tenant_id: {e}")
            raise TokenRetrievalError(f"error retrieving tenant_id: {e}")

    def _get_credentials_ref(self):
        """GETS REFERENCE TO THE CREDENTIALS DOCUMENT IN FIRESTORE"""
        return (self.db
                .collection('users')
                .document(self.user_id)
                .collection('integrations')
                .document('credentials'))

    def _decrypt_token(self, encrypted_token: str) -> str:
        """DECRYPTS A SINGLE TOKEN"""
        return self.encryption.decrypt(encrypted_token)

    def _encrypt_token(self, token: str) -> str:
        """ENCRYPTS A SINGLE TOKEN"""
        return self.encryption.encrypt(token)

    async def store_tokens(self, tokens: dict):
        """STORES TOKENS IN FIRESTORE"""
        try:
            # encrypt tokens and prepare for storage
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
            
            logger.info(f"stored refreshed tokens for user {self.user_id}")
        except Exception as e:
            logger.error(f"error storing tokens: {e}")
            raise TokenStorageError(f"failed to store tokens: {e}") from e

    async def retrieve_tokens(self) -> dict:
        """RETRIEVES AND DECRYPTS TOKENS FROM FIRESTORE"""
        try:
            doc_ref = self._get_credentials_ref()
            doc = await doc_ref.get()
            
            if not doc.exists:
                raise TokenRetrievalError("No credentials document found")
                
            data = doc.to_dict()
            xero_data = data.get('xero', {})
            
            if not xero_data:
                raise TokenRetrievalError("No Xero token data found")

            # check required fields
            required_fields = {'accessToken', 'refreshToken', 'scope', 'tokenType', 'expiresAt'}
            if not all(field in xero_data for field in required_fields):
                raise TokenRetrievalError("Incomplete token data in Firestore")
            
            # decrypt tokens and convert to OAuth format
            tokens = {
                'access_token': self._decrypt_token(xero_data['accessToken']),
                'refresh_token': self._decrypt_token(xero_data['refreshToken']),
                'scope': xero_data['scope'].split(' ') if isinstance(xero_data['scope'], str) else xero_data['scope'],
                'token_type': xero_data['tokenType'],
                'expires_at': xero_data['expiresAt'],
                'expires_in': 1800  # default 30 minutes
            }
            
            return tokens
            
        except Exception as e:
            logger.error(f"error retrieving tokens: {e}")
            raise TokenRetrievalError(f"error retrieving tokens: {e}") from e

    def parse_expiration(self, access_token: str) -> float:
        """PARSES TOKEN EXPIRATION FROM JWT"""
        try:
            decoded = jwt.decode(access_token, options={"verify_signature": False})
            exp = decoded.get('exp')
            if not exp:
                raise TokenRetrievalError("No 'exp' field found in access_token")
            return exp - self.expiration_buffer
        except jwt.DecodeError as e:
            raise TokenRetrievalError(f"Failed to decode access_token JWT: {e}") from e

    async def refresh_token(self, refresh_token: str, scope: str | list):
        """REFRESHES THE OAUTH TOKEN"""
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
                            f"refresh token request failed with status {response.status}"
                        )

                    new_tokens = await response.json()
                    new_tokens['expires_at'] = self.parse_expiration(new_tokens['access_token'])

                    if 'refresh_token' not in new_tokens:
                        new_tokens['refresh_token'] = refresh_token

                    await self.store_tokens(new_tokens)
                    
                    logger.info(f"token refreshed successfully for user {self.user_id}")
                    return new_tokens
                    
            except aiohttp.ClientError as e:
                logger.error(f"token refresh failed: {e}")
                raise TokenRetrievalError(f"token refresh failed: {e}") from e

    async def get_token(self):
        """MAIN METHOD TO GET A VALID TOKEN, REFRESHING IF NECESSARY"""
        async with self.lock:
            # get tenant_id first
            if not self.tenant_id:
                await self.get_tenant_id()
                
            tokens = await self.retrieve_tokens()
            current_time = time.time()
            expires_at = tokens.get('expires_at', 0)

            if expires_at < current_time:
                logger.info("token expired, attempting to refresh")
                try:
                    return await self.refresh_token(tokens['refresh_token'], tokens['scope'])
                except Exception as e:
                    logger.error(f"failed to refresh token: {e}")
                    raise TokenRetrievalError("token expired and refresh failed. manual reauthorization may be required.")
                    
            return tokens

async def oauth2_token_getter(user_id: str):
    """OAUTH2 TOKEN GETTER FUNCTION FOR THE XERO CLIENT"""
    try:
        token_manager = FirestoreTokenManager(user_id)
        return await token_manager.get_token()
    except Exception as e:
        logger.error(f"token retrieval failed: {e}")
        raise OAuth2TokenGetterError("failed to get OAuth2 token") from e