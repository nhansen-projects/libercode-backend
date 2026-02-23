"""
Test settings for pytest - uses SQLite in-memory database
"""
from libercode.settings import *  # noqa: F401, F403

# Override database to use SQLite for tests
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}
