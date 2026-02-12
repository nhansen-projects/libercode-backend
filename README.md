# libercode-backend

This is the backend for the libercode project, built with Django.

## Prerequisites

- Docker Desktop
- Docker Compose

## Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/nhansen-projects/libercode-backend
   cd libercode-backend
   ```

2. **Ensure Docker Desktop is running**, then start the services:
   ```bash
   docker-compose up
   ```
   
   This will:
   - Start PostgreSQL database (notesDB)
   - Run Django migrations automatically
   - Start the Django development server on `http://localhost:8000`

## Running the Project

```bash
docker-compose up
```

The server will be available at `http://localhost:8000/`.

To stop the services:
```bash
docker-compose down
```

## Project Structure

- `manage.py`: Django's command-line utility for administrative tasks
- `libercode/`: Django project configuration package
  - `settings.py`: Project settings and configuration
  - `urls.py`: URL routing configuration
  - `wsgi.py` / `asgi.py`: WSGI/ASGI application entry points
  - `tests/`: Project-level integration tests
- `core/`: Core Django application
  - `models.py`: Database models (Tag, Entry, Favorite)
  - `views.py`: View logic
  - `admin.py`: Django admin configuration
  - `tests/`: App-specific unit tests
- `requirements.txt`: Production dependencies
- `requirements-dev.txt`: Development dependencies
- `Dockerfile` / `docker-compose.yml`: Docker configuration
- `.env.example`: Environment variables template
