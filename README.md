# Libercode Backend

## Setup Instructions

### 1. Create and Activate Virtual Environment

This project requires Python dependencies to be installed in a virtual environment.

#### For Fish Shell (detected as your current shell):

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
. .venv/bin/activate.fish

# Install dependencies
pip install -r requirements.txt
```

#### For Bash/Zsh Shells:

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Running Django Management Commands

Always make sure to activate the virtual environment before running any Django commands:

#### For Fish Shell:
```bash
. .venv/bin/activate.fish
python manage.py check
python manage.py migrate
python manage.py runserver
```

#### For Bash/Zsh Shells:
```bash
source .venv/bin/activate
python manage.py check
python manage.py migrate
python manage.py runserver
```

### 3. Common Issues

**Error: "Couldn't import Django"**

This means the virtual environment is not activated. Make sure to run the activation command for your shell before running Django commands.

**Error: "No module named django"**

This also indicates the virtual environment is not activated or dependencies are not installed. Run the activation command and then `pip install -r requirements.txt`.

### 4. Development Workflow

1. Always activate the virtual environment first
2. Install new dependencies with `pip install package-name`
3. Update requirements.txt with `pip freeze > requirements.txt`
4. Run tests with `python manage.py test`

## Project Structure

- `core/`: Main Django application
- `libercode/`: Project configuration and settings
- `manage.py`: Django management script
- `requirements.txt`: Python dependencies
- `.venv/`: Virtual environment (not committed to git)

## Running with Docker (Recommended)

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

### Running Management Commands

```bash
# Run Django management commands in the container
docker compose exec web python manage.py check
docker compose exec web python manage.py createsuperuser
```

## Running the Development Server (Without Docker)

```bash
# Activate virtual environment
. .venv/bin/activate.fish  # or source .venv/bin/activate for bash/zsh

# Start development server
python manage.py runserver
```

The server will be available at `http://localhost:8000`