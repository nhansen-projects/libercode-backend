# Libercode Backend

## Setup 

- `core/`: Main Django application
- `libercode/`: Project configuration and settings
- `manage.py`: Django management script
- `requirements.txt`: Python dependencies
- `.venv/`: Virtual environment (not committed to git)

## Docker Compose

This project includes Docker configuration for easy setup and development.

### Environment Files

- `.env.dev`: Local development defaults.
- `.env.prod`: Production values (replace placeholders before deploy).

Both files are used by `docker-compose.yml` profiles.

### Prerequisites
- Docker Engine (v20.10+)
- Docker Compose v2 (included with Docker)

### Starting Development

```bash
# Build and start dev containers
docker compose --profile dev up --build -d

# View running containers
docker compose ps

# View logs for dev web service
docker compose logs web-dev

# Stop containers
docker compose down
```

### Starting Production Profile

```bash
# Build and start prod containers
docker compose --profile prod up --build -d

# View logs for prod web service
docker compose logs web-prod

# Stop containers
docker compose --profile prod down
```

Production notes (Nginx):
- Backend container is exposed on host `localhost:8080`.
- Frontend is expected at `https://libercode.augustdev.work` (or `:8090` if explicitly used).
- Configure Nginx to proxy `/api` to `http://127.0.0.1:8080`.

The application will be available at:
- Web Interface: `http://localhost:8000`
- API: `http://localhost:8000/api/entries/`
- Admin: `http://localhost:8000/admin/`