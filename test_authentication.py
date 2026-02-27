#!/usr/bin/env python

import os
import sys
import django
import json

# Setup Django
sys.path.insert(0, '/home/nh/workspace/libercode-backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'libercode.settings')
django.setup()

from django.test import RequestFactory
from core.api_views import UserCreateView, LoginView
from core.models import User, EncryptionKey
from core.utils import SecurityUtils

def test_authentication_flow():
    print("Testing authentication flow...")
    
    # Create a request factory
    factory = RequestFactory()
    
    # Test 1: User registration with legacy format (plain password)
    print("\n1. Testing legacy registration (plain password)...")
    request = factory.post('/api/register/', {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'testpass123'
    }, format='json')
    
    view = UserCreateView.as_view()
    response = view(request)
    
    print(f"Registration response status: {response.status_code}")
    if response.status_code == 201:
        data = response.data
        print(f"User created: {data['user']['username']}")
        print(f"JWT tokens generated: access={bool(data['tokens']['access'])}, refresh={bool(data['tokens']['refresh'])}")
    else:
        print(f"Registration failed: {response.data}")
    
    # Test 2: User registration with new secure format (password_hash + salt)
    print("\n2. Testing secure registration (password_hash + salt)...")
    password = "securepass123"
    salt = SecurityUtils.generate_salt()
    hash_data = SecurityUtils.hash_password(password, salt)
    
    request = factory.post('/api/register/', {
        'username': 'secureuser',
        'email': 'secure@example.com',
        'password_hash': hash_data['hash'],
        'salt': hash_data['salt']
    }, format='json')
    
    view = UserCreateView.as_view()
    response = view(request)
    
    print(f"Secure registration response status: {response.status_code}")
    if response.status_code == 201:
        data = response.data
        print(f"Secure user created: {data['user']['username']}")
        print(f"JWT tokens generated: access={bool(data['tokens']['access'])}, refresh={bool(data['tokens']['refresh'])}")
    else:
        print(f"Secure registration failed: {response.data}")
    
    # Test 3: Legacy login (plain credentials)
    print("\n3. Testing legacy login (plain credentials)...")
    request = factory.post('/api/login/', {
        'username': 'testuser',
        'password': 'testpass123'
    }, format='json')
    
    view = LoginView.as_view()
    response = view(request)
    
    print(f"Legacy login response status: {response.status_code}")
    if response.status_code == 200:
        data = response.data
        print(f"Login successful for: {data['user']['username']}")
        print(f"JWT tokens generated: access={bool(data['tokens']['access'])}, refresh={bool(data['tokens']['refresh'])}")
    else:
        print(f"Legacy login failed: {response.data}")
    
    # Test 4: Secure login (encrypted credentials)
    print("\n4. Testing secure login (encrypted credentials)...")
    
    # First, generate an encryption key
    try:
        encryption_key = EncryptionKey.generate_fernet_key("Test encryption key")
        print(f"Generated encryption key: {encryption_key.key_type}")
    except Exception as e:
        print(f"Could not generate encryption key: {e}")
        return
    
    # Encrypt credentials
    credentials = {
        'username': 'secureuser',
        'password': password
    }
    encrypted_credentials = SecurityUtils.encrypt_with_fernet(
        json.dumps(credentials), 
        encryption_key.key
    )
    
    request = factory.post('/api/login/', {
        'encrypted_credentials': encrypted_credentials,
        'decryption_key': encryption_key.key,
        'key_type': 'fernet'
    }, format='json')
    
    view = LoginView.as_view()
    response = view(request)
    
    print(f"Secure login response status: {response.status_code}")
    if response.status_code == 200:
        data = response.data
        print(f"Secure login successful for: {data['user']['username']}")
        print(f"JWT tokens generated: access={bool(data['tokens']['access'])}, refresh={bool(data['tokens']['refresh'])}")
    else:
        print(f"Secure login failed: {response.data}")
    
    print("\nAuthentication flow testing completed!")

if __name__ == "__main__":
    test_authentication_flow()