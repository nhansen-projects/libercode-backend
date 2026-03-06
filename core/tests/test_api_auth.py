import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

User = get_user_model()


@pytest.fixture
def api_client():
    """Provide an API client for testing."""
    return APIClient()


@pytest.fixture
def test_user(db):
    """Create a test user."""
    return User.objects.create_user(
        username='testuser',
        password='testpass123'
    )


class TestUserRegistration:
    """Tests for user registration endpoint."""

    @pytest.mark.django_db
    def test_register_new_user_success(self, api_client):
        """Test successful user registration."""
        response = api_client.post('/api/register/', {
            'username': 'newuser',
            'password': 'newpass123'
        }, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['user']['username'] == 'newuser'
        assert 'access' in response.data['tokens']
        assert 'refresh_expires' in response.data['tokens']
        assert User.objects.filter(username='newuser').exists()

    @pytest.mark.django_db
    def test_register_duplicate_username(self, api_client, test_user):
        """Test registration with duplicate username returns 400."""
        response = api_client.post('/api/register/', {
            'username': 'testuser',  # Already exists
            'password': 'pass123'
        }, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'username' in response.data or 'error' in response.data or 'message' in response.data

    @pytest.mark.django_db
    def test_register_missing_username(self, api_client):
        """Test registration without username."""
        response = api_client.post('/api/register/', {
            'password': 'pass123'
        }, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'username' in response.data

    @pytest.mark.django_db
    def test_register_missing_password(self, api_client):
        """Test registration without password."""
        response = api_client.post('/api/register/', {
            'username': 'testuser2',
        }, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'password' in response.data


class TestUserLogin:
    """Tests for user login endpoint."""

    @pytest.mark.django_db
    def test_login_success(self, api_client, test_user):
        """Test successful login returns token."""
        response = api_client.post('/api/login/', {
            'username': 'testuser',
            'password': 'testpass123'
        }, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['user']['username'] == 'testuser'
        assert 'access' in response.data['tokens']
        assert 'refresh_expires' in response.data['tokens']

    @pytest.mark.django_db
    def test_login_invalid_password(self, api_client, test_user):
        """Test login with invalid password."""
        response = api_client.post('/api/login/', {
            'username': 'testuser',
            'password': 'wrongpass'
        }, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert 'Invalid username or password' in response.data['error']

    @pytest.mark.django_db
    def test_login_nonexistent_user(self, api_client):
        """Test login with nonexistent username."""
        response = api_client.post('/api/login/', {
            'username': 'doesnotexist',
            'password': 'anypass'
        }, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert 'Invalid username or password' in response.data['error']

    @pytest.mark.django_db
    def test_login_missing_username(self, api_client):
        """Test login without username."""
        response = api_client.post('/api/login/', {
            'password': 'testpass'
        }, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'Both username and password are required' in response.data['error']

    @pytest.mark.django_db
    def test_login_missing_password(self, api_client):
        """Test login without password."""
        response = api_client.post('/api/login/', {
            'username': 'testuser'
        }, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'Both username and password are required' in response.data['error']


class TestTokenRefresh:
    """Tests for token refresh endpoint."""

    @pytest.mark.django_db
    def test_token_refresh_success(self, api_client, test_user):
        """Test successful token refresh."""
        # First login to get a token
        login_response = api_client.post('/api/login/', {
            'username': 'testuser',
            'password': 'testpass123'
        }, format='json')

        refresh_token = login_response.data['tokens']['refresh']

        # Refresh the token
        response = api_client.post('/api/token/refresh/', {
            'refresh': refresh_token
        }, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'access_expires' in response.data

    @pytest.mark.django_db
    def test_token_refresh_missing_token(self, api_client):
        """Test token refresh without token."""
        response = api_client.post('/api/token/refresh/', {}, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'Refresh token is required' in str(response.data)

    @pytest.mark.django_db
    def test_token_refresh_invalid_token(self, api_client):
        """Test token refresh with invalid token."""
        response = api_client.post('/api/token/refresh/', {
            'refresh': 'invalid-token-string'
        }, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert 'Invalid refresh token' in str(response.data)


class TestLogout:
    """Tests for logout endpoint."""

    @pytest.mark.django_db
    def test_logout_with_token(self, api_client, test_user):
        """Test logout with valid token."""
        # Disable CSRF checks for API testing
        api_client.enforce_csrf_checks = False
        
        # Login first
        login_response = api_client.post('/api/login/', {
            'username': 'testuser',
            'password': 'testpass123'
        }, format='json')

        token = login_response.data['tokens']['access']

        # Logout with token (JWT uses Bearer prefix)
        response = api_client.post(
            '/api/logout/',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            format='json'
        )

        assert response.status_code == status.HTTP_200_OK
        assert 'Logout successful' in str(response.data) or 'logged out' in str(response.data)

    @pytest.mark.django_db
    def test_logout_without_token(self, api_client):
        """Test logout without token still returns success."""
        # Disable CSRF checks for API testing
        api_client.enforce_csrf_checks = False
        
        response = api_client.post('/api/logout/', format='json')

        assert response.status_code == status.HTTP_200_OK
