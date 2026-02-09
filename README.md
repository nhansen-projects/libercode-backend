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

- `libercode/`: Contains the Django project and applications.
  - `manage.py`: Django's command-line utility for administrative tasks.
  - `libercode/`: Project configuration (settings, URLs, etc.).
- `venv/`: Python virtual environment (should be ignored by git).
- `.gitignore`: Specifies files for Git to ignore.
