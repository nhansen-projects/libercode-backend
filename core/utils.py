import os
import base64
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings


class SecurityUtils:
    """
    Security utilities for encryption, decryption, and password hashing.
    """
    
    @staticmethod
    def generate_fernet_key():
        """
        Generate a new Fernet key for symmetric encryption.
        
        Returns:
            str: Base64 encoded Fernet key
        """
        return Fernet.generate_key().decode('utf-8')
    
    @staticmethod
    def generate_aes_key():
        """
        Generate a new AES-256 key.
        
        Returns:
        str: Base64 encoded AES key
        """
        key = os.urandom(32)  # 256 bits for AES-256
        return base64.b64encode(key).decode('utf-8')
    
    @staticmethod
    def get_key_fingerprint(key: str) -> str:
        """
        Generate a fingerprint for an encryption key.
        
        Args:
            key (str): Base64 encoded encryption key
            
        Returns:
            str: Base64URL encoded SHA-256 fingerprint
        """
        key_bytes = base64.b64decode(key.encode('utf-8'))
        fingerprint = hashlib.sha256(key_bytes).digest()
        return base64.urlsafe_b64encode(fingerprint).decode('utf-8').rstrip('=')
    
    @staticmethod
    def generate_salt():
        """
        Generate a random salt for password hashing.
        
        Returns:
            str: Hex encoded salt
        """
        return secrets.token_hex(16)  # 128-bit salt
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> dict:
        """
        Hash a password using SHA-256 with salt.
        
        Args:
            password (str): The password to hash
            salt (str, optional): Existing salt. If None, generates a new salt.
        
        Returns:
            dict: Dictionary containing 'hash' and 'salt'
        """
        if salt is None:
            salt = SecurityUtils.generate_salt()
        
        # Convert salt from hex to bytes
        salt_bytes = bytes.fromhex(salt)
        
        # Hash the password with salt using PBKDF2 with increased iterations
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=310000,  # Increased from 100,000 to 310,000 for better security
            backend=default_backend()
        )
        
        # Encode password and hash it
        password_bytes = password.encode('utf-8')
        hash_bytes = kdf.derive(password_bytes)
        
        # Return as hex strings
        return {
            'hash': hash_bytes.hex(),
            'salt': salt
        }
    
    @staticmethod
    def verify_password(password: str, stored_hash: str, salt: str) -> bool:
        """
        Verify a password against a stored hash and salt.
        
        Args:
            password (str): The password to verify
            stored_hash (str): The stored password hash (hex string)
            salt (str): The salt used in hashing (hex string or raw text)
        
        Returns:
            bool: True if password matches, False otherwise
        """
        # 1) Direct comparison: handles case where frontend already hashed the password
        if secrets.compare_digest(password, stored_hash):
            return True
            
        # 2) Preferred path: PBKDF2-HMAC-SHA256 with 310k iterations (server standard)
        new_hash_data = SecurityUtils.hash_password(password, salt)
        if secrets.compare_digest(new_hash_data['hash'], stored_hash):
            return True
        
        # 3) Fallbacks for clients that may have sent a simple SHA-256 hash with a salt
        try:
            pwd_bytes = password.encode('utf-8')
            # If salt looks like hex, treat as hex bytes; else use raw bytes
            if all(c in '0123456789abcdef' for c in salt) and len(salt) % 2 == 0:
                salt_bytes = bytes.fromhex(salt)
            else:
                salt_bytes = salt.encode('utf-8')
        except Exception:
            salt_bytes = salt.encode('utf-8')
        
        # SHA-256(password + salt)
        sha_ps = hashlib.sha256(pwd_bytes + salt_bytes).hexdigest()
        if secrets.compare_digest(sha_ps, stored_hash):
            return True
        
        # SHA-256(salt + password)
        sha_sp = hashlib.sha256(salt_bytes + pwd_bytes).hexdigest()
        if secrets.compare_digest(sha_sp, stored_hash):
            return True
        
        return False
    
    @staticmethod
    def encrypt_with_fernet(data: str, key: str) -> str:
        """
        Encrypt data using Fernet symmetric encryption.
        
        Args:
            data (str): Data to encrypt
            key (str): Fernet key (base64 encoded)
        
        Returns:
            str: Encrypted data (base64 encoded)
        """
        fernet = Fernet(key.encode('utf-8'))
        encrypted_data = fernet.encrypt(data.encode('utf-8'))
        return encrypted_data.decode('utf-8')
    
    @staticmethod
    def decrypt_with_fernet(encrypted_data: str, key: str) -> str:
        """
        Decrypt data using Fernet symmetric encryption.
        
        Args:
            encrypted_data (str): Encrypted data (base64 encoded)
            key (str): Fernet key (base64 encoded)
        
        Returns:
            str: Decrypted data
        
        Raises:
            Exception: If decryption fails
        """
        fernet = Fernet(key.encode('utf-8'))
        decrypted_data = fernet.decrypt(encrypted_data.encode('utf-8'))
        return decrypted_data.decode('utf-8')
    
    @staticmethod
    def encrypt_with_aes(data: str, key: str) -> str:
        """
        Encrypt data using AES-256 in GCM mode (more secure than CBC).
        
        Args:
            data (str): Data to encrypt
            key (str): AES key (base64 encoded)
        
        Returns:
            str: Encrypted data in format: nonce:tag:ciphertext (base64 encoded)
        """
        # Decode key from base64
        key_bytes = base64.b64decode(key.encode('utf-8'))
        
        # Generate random nonce (GCM doesn't use IV, it uses nonce)
        nonce = os.urandom(16)
        
        # Encrypt using GCM mode (authenticated encryption)
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
        
        # Get authentication tag
        tag = encryptor.tag
        
        # Combine nonce, tag, and ciphertext
        result = nonce + tag + encrypted_data
        return base64.b64encode(result).decode('utf-8')
    
    @staticmethod
    def decrypt_with_aes(encrypted_data: str, key: str) -> str:
        """
        Decrypt data using AES-256 in GCM mode.
        
        Args:
            encrypted_data (str): Encrypted data in format: nonce:tag:ciphertext (base64 encoded)
            key (str): AES key (base64 encoded)
        
        Returns:
            str: Decrypted data
        
        Raises:
            Exception: If decryption fails
        """
        # Decode key and encrypted data from base64
        key_bytes = base64.b64decode(key.encode('utf-8'))
        combined_data = base64.b64decode(encrypted_data.encode('utf-8'))
        
        # Extract nonce, tag, and ciphertext
        nonce = combined_data[:16]
        tag = combined_data[16:32]
        ciphertext = combined_data[32:]
        
        # Decrypt using GCM mode
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        return decrypted_data.decode('utf-8')
    
    @staticmethod
    def decrypt_aes_gcm_with_format(payload: dict, key: str) -> str:
        """
        Decrypt AES-GCM encrypted data with the specific format:
        {
          "iv": "base64url-encoded-iv",
          "data": "base64url-encoded-encrypted-data",
          "keyFingerprint": "base64url-encoded-key-fingerprint"
        }
        
        The 'data' field is expected to contain the ciphertext followed by the tag (default for many GCM implementations).
        
        Args:
            payload (dict): The encrypted payload
            key (str): Base64 encoded AES key
            
        Returns:
            str: Decrypted data
            
        Raises:
            ValueError: If the key fingerprint doesn't match
            Exception: If decryption fails
        """
        # Verify fingerprint if provided
        if 'keyFingerprint' in payload:
            expected_fingerprint = SecurityUtils.get_key_fingerprint(key)
            # base64url might or might not have padding, get_key_fingerprint rstrips it
            provided_fingerprint = payload['keyFingerprint'].rstrip('=')
            if provided_fingerprint != expected_fingerprint:
                raise ValueError("Key fingerprint mismatch")
        
        # Decode components from base64url
        # We need to add padding if necessary for urlsafe_b64decode
        def b64url_decode(s):
            padding = '=' * (4 - len(s) % 4)
            return base64.urlsafe_b64decode(s + padding)
            
        key_bytes = base64.b64decode(key.encode('utf-8'))
        nonce = b64url_decode(payload['iv'])
        combined_data = b64url_decode(payload['data'])
        
        # In many GCM implementations (like Web Crypto API), the tag is appended to the ciphertext
        # Default tag length is 16 bytes
        tag_length = 16
        ciphertext = combined_data[:-tag_length]
        tag = combined_data[-tag_length:]
        
        # Decrypt using GCM mode
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        return decrypted_data.decode('utf-8')
    
    @staticmethod
    def get_active_encryption_key():
        """
        Get the currently active encryption key from settings or database.
        
        Returns:
            str: Active encryption key
        
        Raises:
            Exception: If no active key is found
        """
        # First try to get from settings
        if hasattr(settings, 'ACTIVE_ENCRYPTION_KEY'):
            return settings.ACTIVE_ENCRYPTION_KEY
        
        # Fallback: try to get from database (will be implemented in EncryptionKey model)
        from .models import EncryptionKey
        try:
            key = EncryptionKey.objects.get(is_active=True)
            return key.key
        except EncryptionKey.DoesNotExist:
            raise Exception("No active encryption key found")
    
    @staticmethod
    def generate_jwt_payload(user):
        """
        Generate JWT payload for a user.
        
        Args:
            user: Django user object
        
        Returns:
            dict: JWT payload
        """
        return {
            'user_id': user.id,
            'username': user.username,
            'email': getattr(user, 'email', ''),
        }