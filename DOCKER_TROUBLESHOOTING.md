# Docker Configuration Troubleshooting Guide
              
For all intents and purposes, the docker files should work out of the box, but since we've experienced issues with Docker and Docker Compose over the course of development, we've compiled this guide as references to troubleshoot common problems.
The project is now configured for production using Gunicorn as the WSGI server.

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
      - DB_USER=postgres
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
DB_USER=postgres
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
docker compose run web sh -c "env | grep SECRET_KEY"
docker compose run web sh -c "python -c 'import os; print(os.environ.get(\"SECRET_KEY\"))'"
```

#### Solution D: Use alternative Dockerfile (for development only)
If you're still having issues, try the alternative Dockerfile:

```bash
cp Dockerfile.alternative Dockerfile
docker-compose build --no-cache
```

**WARNING:** The alternative Dockerfile embeds environment variables in the image, which is **not secure for production**. Use only for development.

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

2. The database service has a healthcheck in `docker-compose.yml`, so the application will wait until it's ready before starting.

### 3. Database Connection Issues

**Symptoms:**
- "Could not connect to database"
- Database migrations fail
- Application hangs waiting for database

**Solutions:**

#### Solution A: Verify database service
Check if the database container is running:

```bash
docker compose ps
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
docker compose exec db psql -U postgres -d notesDB
```

#### Solution D: Increase database startup time
If the database takes longer to start, you can adjust the `healthcheck` settings in `docker-compose.yml`:
```yaml
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d notesDB"]
      interval: 10s
      timeout: 5s
      retries: 10
```

### 4. Password Authentication Failed / Role "postgres" does not exist

**Symptoms:**
- Database logs show `FATAL: password authentication failed for user "postgres"`
- Database logs show `FATAL: role "postgres" does not exist`
- Connection failures when using standard PostgreSQL tools

**Solution:**
These errors occur due to mismatches between the expected database user/password and what is actually stored in the persistent Docker volume.

1. **Role "postgres" does not exist**: This happens when `POSTGRES_USER` was initially set to something other than `postgres` (like `admin`). The default user is not created if a custom one is specified.
2. **Password authentication failed**: This happens when the `DB_PASSWORD` in your `.env` or `docker-compose.yml` does not match the password used when the database was first initialized.

We have updated the project to use the default `postgres` user with the password `password`. If you still see these errors, your existing Docker volume is still using the old credentials.

#### Path C: External Connection Attempts (Security)

If your Django application starts successfully and you see "Applying migrations... OK" in the `web` logs, but later see `FATAL: password authentication failed for user "postgres"` in the `db` logs, it is very likely that **external bots or scanners** are trying to connect to your database from the internet.

By default, exposing port `5432:5432` on a public server allows anyone to try and guess your database password.

**To fix this:**
1.  Update `docker-compose.yml` to bind the database port only to the local machine:
    ```yaml
    db:
      ports:
        - "127.0.0.1:5432:5432"
    ```
2.  Or remove the `ports` mapping entirely if you only need the Django app to connect to the database (it uses the internal Docker network).

**⚠️ WARNING: Resetting will delete all data in your database.**

#### Path A: Resetting the Volume (Recommended for Clean Starts)

1.  Stop the containers and remove the volumes:
    ```bash
    docker compose down -v
    ```

2.  Start the containers again (this will re-initialize the DB with the `postgres` user and `password` password):
    ```bash
    docker compose up -d
    ```

3.  Check the logs to confirm the error is gone:
    ```bash
    docker compose logs -f db
    ```

##### Path B: Manual Update (No Data Loss)

If you cannot delete the data, you must manually create/update the `postgres` role inside the running container using the OLD credentials (e.g., if your old user was `admin` and password was `admin`):

```bash
# Create the postgres role if it doesn't exist
docker-compose exec db psql -U admin -d notesDB -c "CREATE ROLE postgres WITH LOGIN SUPERUSER PASSWORD 'password';"

# OR update the password if the role exists but authentication fails
docker-compose exec db psql -U postgres -d notesDB -c "ALTER ROLE postgres WITH PASSWORD 'password';"
```

### 5. Static Files Collection Issues

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
If you want to skip `collectstatic` during development, you can modify the `command` in `docker-compose.yml` to remove it.

### 6. Debugging Tips

#### Check environment variables in container:
```bash
docker compose run web env
docker compose run web sh -c "printenv"
```

#### Test Django settings directly:
```bash
docker compose run web python -c "
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
docker compose run web python -c "
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'libercode.settings')
django.setup()
from django.db import connection
print('Database connection successful:', connection.ensure_connection())
"
```

### 7. Clean Build and Start

Sometimes a clean start helps:

```bash
# Stop and remove all containers and volumes
docker compose down -v

# Remove old images
docker rmi libercode-backend-web

# Build fresh
docker compose build --no-cache

# Start with clean state
docker compose up -d
```

### 8. Alternative Development Setup

For faster development, use the alternative Dockerfile:

```bash
# Use alternative Dockerfile (for development only)
cp Dockerfile.alternative Dockerfile

# Build and run
docker-compose build --no-cache
docker-compose up
```

## Production Deployment Checklist

1. db_query_simple.py Use proper secrets management (AWS Secrets Manager, HashiCorp Vault, etc.)
2. Never embed secrets in Docker images
3. Use different secrets for each environment
4. Rotate secrets regularly
5. Use HTTPS and secure cookie settings
6. Set `DEBUG=False` in production
7. Configure proper ALLOWED_HOSTS
8. Set up proper database backups
9. Configure logging and monitoring
10. Use a production-ready web server (gunicorn, uwsgi)

## Getting Help

If you're still experiencing issues:

1. Check the logs: `docker compose logs web`
2. Check database logs: `docker compose logs db`
3. Try the alternative Dockerfile for development
4. Ensure all environment variables are correctly set
5. Verify your Docker and Docker Compose versions are up to date