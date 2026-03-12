# Final Dockerfile - Production Ready with Proper Environment Handling

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Use gunicorn to start application in production
CMD ["sh", "-c", "python manage.py migrate && python manage.py collectstatic --noinput && gunicorn libercode.wsgi:application --bind 0.0.0.0:8080 --workers 3"]