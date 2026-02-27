# Docker Configuration Troubleshooting Guide

## Common Issues and Solutions

### 1. "SECRET_KEY must be set in environment variables"

**Symptoms:**
- Docker build fails with `ValueError: SECRET_KEY must be set in environment variables`
- Application crashes on startup with missing environment variables

**Solutions:**

#### Solution A: Verify docker-compose.yml
Ensure your `docker-compose.yml` has all required environment variables:

```yaml
services:
  web:
    environment:
      - SECRET_KEY=your-secret-key-here
      - JWT_SIGNING_KEY=your-jwt-key-here
      - DEBUG=1
      - ALLOWED_HOSTS=localhost,127.0.0.1
      - DB_HOST=db
      - DB_NAME=notesDB
      - DB_USER=admin
      - DB_PASSWORD=password
```

#### Solution B: Use .env file
Create a `.env` file in your project root:

```bash
# .env file
DEBUG=True
SECRET_KEY=your-secret-key-here
JWT_SIGNING_KEY=your-jwt-key-here
ALLOWED_HOSTS=localhost,127.0.0.1
DB_NAME=notesDB
DB_USER=admin
DB_PASSWORD=password
DB_HOST=db
DB_PORT=5432
```

Then reference it in docker-compose.yml:

```yaml
services:
  web:
    env_file:
      - .env
```

#### Solution C: Test environment variables
Check if variables are available in the container:

```bash
docker-compose run web sh -c "env | grep SECRET_KEY"
docker-compose run web sh -c "python -c 'import os; print(os.environ.get(\"SECRET_KEY\"))'"
```

#### Solution D: Use alternative Dockerfile (for development only)
If you're still having issues, try the alternative Dockerfile:

```bash
cp Dockerfile.alternative Dockerfile
docker-compose build --no-cache
```

**⚠️ WARNING:** The alternative Dockerfile embeds environment variables in the image, which is **not secure for production**. Use only for development.

### 2. "nc: not found" Error

**Symptoms:**
- Entrypoint script fails with `nc: not found`
- Database connection waiting fails

**Solution:**
The Dockerfile now includes `netcat` installation. If you're still seeing this:

1. Rebuild your containers:
```bash
docker-compose build --no-cache
```

2. The entrypoint script has a fallback method using Python sockets, so it should work even without `nc`.

### 3. Database Connection Issues

**Symptoms:**
- "Could not connect to database"
- Database migrations fail
- Application hangs waiting for database

**Solutions:**

#### Solution A: Verify database service
Check if the database container is running:

```bash
docker-compose ps
docker logs libercode-backend-db-1
```

#### Solution B: Check database credentials
Ensure your database credentials match between:
- `docker-compose.yml` (PostgreSQL environment)
- Django settings (DATABASES configuration)
- Application environment variables

#### Solution C: Manual database check
Connect to the database manually:

```bash
docker-compose exec db psql -U admin -d notesDB
```

#### Solution D: Increase wait time
Modify the entrypoint script to wait longer:
```bash
# In entrypoint.sh, change:
sleep 5  # Increase to sleep 10 or sleep 15
```

### 4. Static Files Collection Issues

**Symptoms:**
- `collectstatic` command fails
- Missing static files in production

**Solutions:**

#### Solution A: Check STATIC_ROOT
Ensure your `settings.py` has:

```python
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATIC_URL = '/static/'
```

#### Solution B: Create directory manually
Add this to your Dockerfile before collectstatic:

```dockerfile
RUN mkdir -p /app/staticfiles
```

#### Solution C: Skip collectstatic in development
Modify the entrypoint script to skip collectstatic in DEBUG mode:

```bash
# In entrypoint.sh:
if [ "$DEBUG" != "1" ]; then
    echo "Collecting static files..."
    python manage.py collectstatic --noinput
fi
```

### 5. Debugging Tips

#### Check environment variables in container:
```bash
docker-compose run web env
docker-compose run web sh -c "printenv"
```

#### Test Django settings directly:
```bash
docker-compose run web python -c "
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'libercode.settings')
django.setup()
from django.conf import settings
print('SECRET_KEY:', settings.SECRET_KEY[:10] + '...')
print('DEBUG:', settings.DEBUG)
"
```

#### Check database connection:
```bash
docker-compose run web python -c "
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'libercode.settings')
django.setup()
from django.db import connection
print('Database connection successful:', connection.ensure_connection())
"
```

### 6. Clean Build and Start

Sometimes a clean start helps:

```bash
# Stop and remove all containers
docker-compose down -v

# Remove old images
docker rmi libercode-backend-web

# Build fresh
docker-compose build --no-cache

# Start with clean state
docker-compose up
```

### 7. Alternative Development Setup

For faster development, use the alternative Dockerfile:

```bash
# Use alternative Dockerfile (for development only)
cp Dockerfile.alternative Dockerfile

# Build and run
docker-compose build --no-cache
docker-compose up
```

## Production Deployment Checklist

1. ✅ Use proper secrets management (AWS Secrets Manager, HashiCorp Vault, etc.)
2. ✅ Never embed secrets in Docker images
3. ✅ Use different secrets for each environment
4. ✅ Rotate secrets regularly
5. ✅ Use HTTPS and secure cookie settings
6. ✅ Set `DEBUG=False` in production
7. ✅ Configure proper ALLOWED_HOSTS
8. ✅ Set up proper database backups
9. ✅ Configure logging and monitoring
10. ✅ Use a production-ready web server (gunicorn, uwsgi)

## Getting Help

If you're still experiencing issues:

1. Check the logs: `docker-compose logs web`
2. Check database logs: `docker-compose logs db`
3. Try the alternative Dockerfile for development
4. Ensure all environment variables are correctly set
5. Verify your Docker and Docker Compose versions are up to date