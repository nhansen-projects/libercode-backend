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
        
        # Hash the password with salt using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
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
            stored_hash (str): The stored password hash
            salt (str): The salt used in hashing
        
        Returns:
            bool: True if password matches, False otherwise
        """
        # Hash the provided password with the same salt
        new_hash_data = SecurityUtils.hash_password(password, salt)
        
        # Compare the hashes using constant-time comparison
        return secrets.compare_digest(new_hash_data['hash'], stored_hash)
    
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
        Encrypt data using AES-256 in CBC mode.
        
        Args:
            data (str): Data to encrypt
            key (str): AES key (base64 encoded)
        
        Returns:
            str: Encrypted data in format: iv:ciphertext (base64 encoded)
        """
        # Decode key from base64
        key_bytes = base64.b64decode(key.encode('utf-8'))
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad the data
        pad_length = 16 - (len(data) % 16)
        padded_data = data + chr(pad_length) * pad_length
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data.encode('utf-8')) + encryptor.finalize()
        
        # Combine IV and ciphertext
        result = iv + encrypted_data
        return base64.b64encode(result).decode('utf-8')
    
    @staticmethod
    def decrypt_with_aes(encrypted_data: str, key: str) -> str:
        """
        Decrypt data using AES-256 in CBC mode.
        
        Args:
            encrypted_data (str): Encrypted data in format: iv:ciphertext (base64 encoded)
            key (str): AES key (base64 encoded)
        
        Returns:
            str: Decrypted data
        
        Raises:
            Exception: If decryption fails
        """
        # Decode key and encrypted data from base64
        key_bytes = base64.b64decode(key.encode('utf-8'))
        combined_data = base64.b64decode(encrypted_data.encode('utf-8'))
        
        # Extract IV and ciphertext
        iv = combined_data[:16]
        ciphertext = combined_data[16:]
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        pad_length = decrypted_padded_data[-1]
        decrypted_data = decrypted_padded_data[:-pad_length]
        
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