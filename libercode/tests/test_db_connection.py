import os
import sys
import django

# Add the project directory to the path
import pathlib
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Set up Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'libercode.settings')
django.setup()

from django.db import connection
from django.db.utils import OperationalError

def test_connection():
    try:
        # Attempt to connect to the database
        with connection.cursor() as cursor:
            cursor.execute("SELECT version();")
            version = cursor.fetchone()
            print("✓ Database connection successful!")
            print(f"✓ PostgreSQL version: {version[0]}")
            return True
    except OperationalError as e:
        print("✗ Database connection failed!")
        print(f"✗ Error: {e}")
        return False
    except Exception as e:
        print("✗ Unexpected error!")
        print(f"✗ Error: {e}")
        return False

if __name__ == "__main__":
    print("Testing database connection...")
    print(f"Host: {os.environ.get('DB_HOST', 'db')}")
    print(f"Port: {os.environ.get('DB_PORT', '5432')}")
    print(f"Database: {os.environ.get('DB_NAME', 'notesDB')}")
    print(f"User: {os.environ.get('DB_USER', 'admin')}")
    print("-" * 50)

    success = test_connection()
    sys.exit(0 if success else 1)
