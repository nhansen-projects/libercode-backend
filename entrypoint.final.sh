#!/bin/sh

# Exit immediately if any command fails
set -e

# Change to the correct working directory
cd /app

echo "=== Starting Application ==="
echo "Working directory: $(pwd)"
echo "Python version: $(python --version)"

# Function to check if required environment variables are set
check_env_vars() {
    MISSING=0
    
    if [ -z "$SECRET_KEY" ]; then
        echo "❌ ERROR: SECRET_KEY environment variable is not set!"
        MISSING=1
    else
        echo "✅ SECRET_KEY is set"
    fi
    
    if [ -z "$JWT_SIGNING_KEY" ]; then
        echo "❌ ERROR: JWT_SIGNING_KEY environment variable is not set!"
        MISSING=1
    else
        echo "✅ JWT_SIGNING_KEY is set"
    fi
    
    if [ $MISSING -eq 1 ]; then
        echo ""
        echo "Available environment variables:"
        env | grep -E '(SECRET|JWT|DB|DEBUG)' || echo "None found"
        exit 1
    fi
}

# Check environment variables
check_env_vars

# Wait for the database to be ready
if [ "$DB_HOST" = "db" ]; then
    echo "Waiting for database to be ready..."
    
    # Try using nc first, fall back to Python if not available
    if command -v nc >/dev/null 2>&1; then
        echo "Using nc to test database connection..."
        RETRY_COUNT=0
        while ! nc -z "$DB_HOST" "$DB_PORT"; do
            RETRY_COUNT=$((RETRY_COUNT + 1))
            if [ $RETRY_COUNT -ge 30 ]; then
                echo "❌ Could not connect to database after 30 attempts"
                exit 1
            fi
            sleep 1
        done
    else
        echo "nc not available, using Python to test database connection..."
        RETRY_COUNT=0
        while [ $RETRY_COUNT -lt 30 ]; do
            if python -c "
import socket
s = socket.socket()
s.settimeout(1)
try:
    s.connect(('$DB_HOST', $DB_PORT))
    s.close()
    exit(0)
except:
    exit(1)
" 2>/dev/null; then
                break
            fi
            RETRY_COUNT=$((RETRY_COUNT + 1))
            sleep 1
        done
        
        if [ $RETRY_COUNT -eq 30 ]; then
            echo "❌ Could not connect to database after 30 attempts"
            exit 1
        fi
    fi
    
    echo "✅ Database is ready!"
else
    echo "Database host is not 'db', skipping connection check"
fi

# Apply database migrations
echo "Applying database migrations..."
python manage.py migrate

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Start the application
echo "Starting Django application..."
echo "================================="
exec "$@"