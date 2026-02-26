# Libercode Backend

## Setup 

- `core/`: Main Django application
- `libercode/`: Project configuration and settings
- `manage.py`: Django management script
- `requirements.txt`: Python dependencies
- `.venv/`: Virtual environment (not committed to git)

## Docker Compose

This project includes Docker configuration for easy setup and development.

### Prerequisites
- Docker Engine (v20.10+)
- Docker Compose v2 (included with Docker)

### Starting the Application

```bash
# Build and start containers
docker compose up -d

# View running containers
docker compose ps

# View logs
docker compose logs web

# Stop containers
docker compose down
```
The application will be available at:
- Web Interface: `http://localhost:8000`
- API: `http://localhost:8000/api/entries/`
- Admin: `http://localhost:8000/admin/`