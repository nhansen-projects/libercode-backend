#!/usr/bin/env python

import os
import sys
import django

# Setup Django
sys.path.insert(0, '/home/nh/workspace/libercode-backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'libercode.settings')
django.setup()

from django.core.management import call_command

def test_management_command():
    print("Testing encryption key management command...")
    
    try:
        # Test generating Fernet key
        print("\n1. Generating Fernet encryption key...")
        call_command('generate_encryption_keys', '--key-type', 'fernet', '--description', 'Test Fernet key')
        
        # Test generating AES key
        print("\n2. Generating AES encryption key...")
        call_command('generate_encryption_keys', '--key-type', 'aes', '--description', 'Test AES key')
        
        # Test generating both keys
        print("\n3. Generening both encryption keys...")
        call_command('generate_encryption_keys', '--key-type', 'both', '--description', 'Test both keys')
        
        print("\nManagement command testing completed!")
        
    except Exception as e:
        print(f"Error testing management command: {e}")

if __name__ == "__main__":
    test_management_command()