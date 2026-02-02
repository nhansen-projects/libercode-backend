# libercode-backend

This is the backend for the libercode project, built with Django.

## Prerequisites

- Python 3.10+
- `pip` (Python package manager)
- `venv` (Python virtual environment module)

## Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd libercode-backend
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Navigate to the Django project directory:**
   ```bash
   cd libercode
   ```

## Running the Project

1. **Run migrations:**
   ```bash
   python manage.py migrate
   ```

2. **Start the development server:**
   ```bash
   python manage.py runserver
   ```
   The server will be available at `http://127.0.0.1:8000/`.

## Project Structure

- `libercode/`: Contains the Django project and applications.
  - `manage.py`: Django's command-line utility for administrative tasks.
  - `libercode/`: Project configuration (settings, URLs, etc.).
- `venv/`: Python virtual environment (should be ignored by git).
- `.gitignore`: Specifies files for Git to ignore.