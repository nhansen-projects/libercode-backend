#!/usr/bin/env python

import os
import sys
import django

# Setup Django
sys.path.insert(0, '/home/nh/workspace/libercode-backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'libercode.settings')
django.setup()

from core.utils import SecurityUtils

def test_security_utils():
    print("Testing SecurityUtils...")
    
    # Test salt generation
    salt1 = SecurityUtils.generate_salt()
    salt2 = SecurityUtils.generate_salt()
    print(f"Generated salts: {salt1[:16]}..., {salt2[:16]}...")
    assert len(salt1) == 32  # 128-bit salt in hex
    assert salt1 != salt2
    
    # Test password hashing
    password = "test_password_123"
    hash_data = SecurityUtils.hash_password(password, salt1)
    print(f"Password hash: {hash_data['hash'][:32]}...")
    print(f"Salt: {hash_data['salt'][:16]}...")
    
    # Test password verification
    is_valid = SecurityUtils.verify_password(password, hash_data['hash'], hash_data['salt'])
    print(f"Password verification: {is_valid}")
    assert is_valid
    
    is_invalid = SecurityUtils.verify_password("wrong_password", hash_data['hash'], hash_data['salt'])
    print(f"Invalid password verification: {is_invalid}")
    assert not is_invalid
    
    # Test Fernet key generation and encryption
    fernet_key = SecurityUtils.generate_fernet_key()
    print(f"Fernet key: {fernet_key[:20]}...")
    
    test_data = "Hello, this is a secret message!"
    encrypted = SecurityUtils.encrypt_with_fernet(test_data, fernet_key)
    print(f"Encrypted data: {encrypted[:32]}...")
    
    decrypted = SecurityUtils.decrypt_with_fernet(encrypted, fernet_key)
    print(f"Decrypted data: {decrypted}")
    assert decrypted == test_data
    
    # Test AES key generation and encryption
    aes_key = SecurityUtils.generate_aes_key()
    print(f"AES key: {aes_key[:20]}...")
    
    encrypted_aes = SecurityUtils.encrypt_with_aes(test_data, aes_key)
    print(f"AES encrypted data: {encrypted_aes[:32]}...")
    
    decrypted_aes = SecurityUtils.decrypt_with_aes(encrypted_aes, aes_key)
    print(f"AES decrypted data: {decrypted_aes}")
    assert decrypted_aes == test_data
    
    print("All SecurityUtils tests passed!")

if __name__ == "__main__":
    test_security_utils()