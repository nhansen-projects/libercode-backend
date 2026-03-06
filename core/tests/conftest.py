import pytest

@pytest.fixture(autouse=True)
def disable_rest_framework_throttling(settings):
    """Disable throttling for all tests."""
    settings.REST_FRAMEWORK = getattr(settings, "REST_FRAMEWORK", {})
    settings.REST_FRAMEWORK.update({
        "DEFAULT_THROTTLE_CLASSES": [],
        "DEFAULT_THROTTLE_RATES": {},
    })
