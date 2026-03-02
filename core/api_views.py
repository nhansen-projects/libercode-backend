from rest_framework import generics, permissions, status, exceptions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from django.db import models
from django.db.models import Q
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from .models import Entry, Tag, Favorite, AuthToken, User, EncryptionKey
from .serializers import EntrySerializer, TagSerializer, FavoriteSerializer, UserSerializer
from .utils import SecurityUtils
import datetime
import json
import logging
from django.core.cache import cache

# Set up logging
logger = logging.getLogger(__name__)


class CustomTokenAuthentication(BaseAuthentication):
    """
    Custom token authentication using AuthToken model.
    
    This authentication method uses token-based authentication where tokens
    are stored in the database and have expiration dates.
    """
    
    def authenticate(self, request):
        """
        Authenticate the request using token-based authentication.
        
        Args:
            request: The HTTP request object
            
        Returns:
            tuple: (user, token) if authentication succeeds, None otherwise
        """
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Token '):
            return None

        token_key = auth_header.split(' ')[1]

        try:
            token = AuthToken.objects.get(token=token_key)

            if not token.is_valid():
                token.delete()
                return None

            token.extend()

            return (token.user, token)

        except AuthToken.DoesNotExist:
            return None

    def authenticate_header(self, request):
        """Return the authentication header name."""
        return 'Token'


class EntryListCreateView(generics.ListCreateAPIView):
    """
    API endpoint for listing and creating entries.
    
    Supports:
    - GET: List entries with filtering, searching, and ordering
    - POST: Create new entries (authenticated users only)
    
    Access control:
    - Authenticated users: Can see shared entries OR their own entries
    - Unauthenticated users: Can only see shared entries
    """
    
    serializer_class = EntrySerializer
    pagination_class = PageNumberPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'body', 'tags__value']
    ordering_fields = ['title', 'created_at', 'shared']
    ordering = ['-created_at']
    authentication_classes = [CustomTokenAuthentication, JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = Entry.objects.filter(author=self.request.user).select_related('author').prefetch_related('tags')

        tag = self.request.query_params.get('tag', None)
        if tag:
            queryset = queryset.filter(tags__value__iexact=tag)

        return queryset.distinct()

    def perform_create(self, serializer):
        if hasattr(self.request, 'user') and self.request.user.is_authenticated:
            serializer.save(author=self.request.user)
        else:
            raise exceptions.NotAuthenticated("Authentication required to create entries.")


class EntryRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = EntrySerializer
    queryset = Entry.objects.all()
    authentication_classes = [CustomTokenAuthentication, JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Entry.objects.filter(author=self.request.user)

    def perform_update(self, serializer):
        serializer.save()

    def perform_destroy(self, instance):
        instance.delete()

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(
                {"result": "Success", "message": "Entry deleted successfully."},
                status=status.HTTP_200_OK,
            )
        except exceptions.APIException as exc:
            logger.warning(f"API Exception in entry deletion: {exc.detail}")
            return Response(
                {"result": "Fail", "message": str(exc.detail)},
                status=exc.status_code,
            )
        except Exception as exc:
            logger.error(f"Unexpected error in entry deletion: {exc}", exc_info=True)
            return Response(
                {"result": "Fail", "message": "An unexpected error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class TagListCreateView(generics.ListCreateAPIView):
    serializer_class = TagSerializer
    queryset = Tag.objects.all()
    pagination_class = PageNumberPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['value']
    ordering_fields = ['value', 'created_at']
    ordering = ['value']
    authentication_classes = [CustomTokenAuthentication, JWTAuthentication]


class TagRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TagSerializer
    queryset = Tag.objects.all()
    authentication_classes = [CustomTokenAuthentication, JWTAuthentication]


class FavoriteListCreateView(generics.ListCreateAPIView):
    serializer_class = FavoriteSerializer
    pagination_class = PageNumberPagination
    authentication_classes = [CustomTokenAuthentication, JWTAuthentication]

    def get_queryset(self):
        return Favorite.objects.filter(user=self.request.user).select_related('entry', 'user')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class FavoriteRetrieveDestroyView(generics.RetrieveDestroyAPIView):
    serializer_class = FavoriteSerializer
    authentication_classes = [CustomTokenAuthentication, JWTAuthentication]

    def get_queryset(self):
        return Favorite.objects.filter(user=self.request.user)


class UserEntriesView(generics.ListAPIView):
    serializer_class = EntrySerializer
    pagination_class = PageNumberPagination
    authentication_classes = [CustomTokenAuthentication, JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Entry.objects.filter(author=user).order_by('-created_at')


class UserFavoritesView(generics.ListAPIView):
    serializer_class = FavoriteSerializer
    pagination_class = PageNumberPagination
    authentication_classes = [CustomTokenAuthentication, JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Favorite.objects.filter(user=user).select_related('entry').order_by('-created_at')


# Views
class UserCreateView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]
    queryset = get_user_model().objects.all()

    def create(self, request, *args, **kwargs):
        # Basic rate limiting by IP for registration
        client_ip = self._get_client_ip(request)
        if not client_ip or len(client_ip) > 45:  # IPv6 max length
            logger.warning(f"Invalid IP address: {client_ip}")
            return Response(
                {'error': 'Invalid request'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        cache_key = f'registration_attempts_{client_ip}'
        
        # Allow 5 registration attempts per minute
        attempts = cache.get(cache_key, 0)
        if attempts >= 5:
            logger.warning(f"Registration rate limit exceeded for IP: {client_ip}")
            return Response(
                {'error': 'Too many registration attempts. Please try again later.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        cache.set(cache_key, attempts + 1, 60)  # 60 seconds timeout
        
        # Input validation - prevent excessively large payloads
        try:
            request_data = request.data.copy()
            
            # Validate input sizes to prevent DoS
            if len(str(request_data)) > 10000:  # Reasonable limit
                return Response(
                    {'error': 'Request data too large'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            logger.warning(f"Invalid request data format: {e}")
            return Response(
                {'error': 'Invalid request data format'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = self.get_serializer(data=request_data)
        serializer.is_valid(raise_exception=True)

        user_data = serializer.validated_data
        
        # Validate username and email
        username = user_data.get('username', '')
        email = user_data.get('email', '')
        
        # Basic username validation
        if not username or len(username) < 3 or len(username) > 150:
            return Response(
                {'error': 'Username must be between 3 and 150 characters'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Basic email validation if provided
        if email and len(email) > 254:  # RFC 5321 max length
            return Response(
                {'error': 'Email address too long'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Handle different registration formats
        password_data = request_data.get('password', '')
        password_hash = request_data.get('password_hash', '')
        salt = request_data.get('salt', '')
        
        # Validate password data
        if password_data:
            # Legacy format: plain password (hash server-side)
            if len(password_data) < 8:
                return Response(
                    {'error': 'Password must be at least 8 characters'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if len(password_data) > 128:
                return Response(
                    {'error': 'Password too long'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        if password_hash and salt:
            # New secure format: password_hash + salt from Flutter client
            # Validate hash and salt formats
            if not all(c in '0123456789abcdef' for c in password_hash):
                return Response(
                    {'error': 'Invalid password hash format'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if len(password_hash) != 64:  # SHA-256 hash should be 64 hex chars
                return Response(
                    {'error': 'Invalid password hash length'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if not all(c in '0123456789abcdef' for c in salt):
                return Response(
                    {'error': 'Invalid salt format'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if len(salt) != 32:  # 128-bit salt should be 32 hex chars
                return Response(
                    {'error': 'Invalid salt length'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        if not (password_data or (password_hash and salt)):
            return Response(
                {'error': 'Either password or password_hash+salt required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            if password_hash and salt:
                # New secure format: password_hash + salt from Flutter client
                user = User.objects.create_user(
                    username=user_data['username'],
                    email=user_data.get('email', ''),
                    password=password_hash,
                    salt=salt
                )
                return self._generate_auth_response(user)
            elif password_data:
                # Legacy format: plain password (hash server-side)
                # Use our custom password hashing with salt
                user = User.objects.create_user(
                    username=user_data['username'],
                    email=user_data.get('email', '')
                )
                user.set_password(password_data)
                user.save()
                
                return self._generate_auth_response(user)
            else:
                return Response(
                    {'error': 'Either password or password_hash+salt required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            logger.error(f"User creation failed: {e}", exc_info=True)
            return Response(
                {'error': 'User creation failed. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _generate_auth_response(self, user):
        """Generate JWT tokens for authentication response"""
        try:
            refresh = RefreshToken.for_user(user)
            
            # Generate auth token
            token = AuthToken.generate_token(user)

            return Response({
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                },
                'tokens': {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'access_expires': refresh.access_token.payload['exp'],
                    'refresh_expires': refresh.payload['exp'],
                },
                'token': token.token,
                'expires_at': token.expires_at.isoformat(),
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Token generation failed for user {user.username}: {e}", exc_info=True)
            return Response(
                {'error': 'Authentication token generation failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_client_ip(self, request):
        """Get client IP address from request with validation"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Get first IP in the list (most trusted)
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        
        # Basic IP validation
        if not ip:
            return None
        
        # Remove any port numbers or extra characters
        ip = ip.split(':')[0].strip()
        
        # Validate IP format (basic check)
        if len(ip) > 45:  # IPv6 max length
            return None
        
        return ip


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        # Basic rate limiting by IP
        client_ip = self._get_client_ip(request)
        if not client_ip or len(client_ip) > 45:  # IPv6 max length
            logger.warning(f"Invalid IP address: {client_ip}")
            return Response(
                {"error": "Invalid request"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        cache_key = f"login_attempts_{client_ip}"
        # Allow 10 login attempts per minute
        attempts = cache.get(cache_key, 0)
        if attempts >= 10:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return Response(
                {'error': 'Too many login attempts. Please try again later.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        cache.set(cache_key, attempts + 1, 60)  # 60 seconds timeout
        
        # Handle different login formats
        if 'encrypted_credentials' in request.data:
            # New secure format: encrypted credentials
            return self._handle_encrypted_login(request)
        elif 'encryption_key' in request.data:
            # Frontend format: encrypted username/password with encryption_key
            return self._handle_frontend_encrypted_login(request)
        else:
            # Legacy format: plain credentials
            return self._handle_legacy_login(request)
    
    def _get_client_ip(self, request):
        """Get client IP address from request with validation"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            # Get first IP in the list (most trusted)
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR", "")
        
        # Basic IP validation
        if not ip:
            return None
        
        # Remove any port numbers or extra characters
        ip = ip.split(":")[0].strip()
        
        # Validate IP format (basic check)
        if len(ip) > 45:  # IPv6 max length
            return None
        
        return ip
    def _handle_encrypted_login(self, request):
        """Handle login with encrypted credentials"""
        encrypted_credentials = request.data.get('encrypted_credentials')
        decryption_key = request.data.get('decryption_key')
        key_type = request.data.get('key_type', 'fernet')
        
        # Input validation
        if not encrypted_credentials or not decryption_key:
            return Response(
                {'error': 'Both encrypted_credentials and decryption_key are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate key type
        if key_type not in ['fernet', 'aes']:
            return Response(
                {'error': 'Unsupported key_type'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate input lengths to prevent DoS
        if len(encrypted_credentials) > 10000:  # Reasonable limit for encrypted data
            return Response(
                {'error': 'Encrypted credentials too large'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if len(decryption_key) > 1000:  # Reasonable limit for decryption keys
            return Response(
                {'error': 'Decryption key too large'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get the appropriate encryption key
            if key_type == 'fernet':
                decrypted_data = SecurityUtils.decrypt_with_fernet(encrypted_credentials, decryption_key)
            elif key_type == 'aes':
                decrypted_data = SecurityUtils.decrypt_with_aes(encrypted_credentials, decryption_key)
            
            # Parse decrypted credentials
            try:
                credentials = json.loads(decrypted_data)
            except json.JSONDecodeError:
                return Response(
                    {'error': 'Invalid decrypted data format'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            username = credentials.get('username')
            password = credentials.get('password')
            
            if not username or not password:
                return Response(
                    {'error': 'Invalid decrypted credentials format'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate username and password lengths
            if len(username) > 150 or len(password) > 128:
                return Response(
                    {'error': 'Invalid credential lengths'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Authenticate user
            user = self._authenticate_user(username, password)
            if user is None:
                return Response(
                    {'error': 'Invalid username or password'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            return self._generate_jwt_response(user)
            
        except Exception as e:
            import traceback
            print(f"Frontend login error: {e}")
            traceback.print_exc()
            return Response(
                {'error': 'Decryption failed'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def _handle_frontend_encrypted_login(self, request):
        """Handle login with frontend's encrypted format"""
        encrypted_username = request.data.get('username')
        encrypted_password = request.data.get('password')
        encryption_key = request.data.get('encryption_key')
        
        if not encrypted_username or not encrypted_password or not encryption_key:
            return Response(
                {'error': 'Username, password, and encryption_key are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Decode the base64 encryption key (try both standard and URL-safe)
            import base64
            try:
                encryption_key_bytes = base64.urlsafe_b64decode(encryption_key)
            except:
                encryption_key_bytes = base64.b64decode(encryption_key)
            encryption_key_base64 = base64.b64encode(encryption_key_bytes).decode('utf-8')
            
            # Decrypt username and password using AES
            # The frontend encrypts data as JSON: {"iv": "...", "data": "..."}
            # We need to manually decrypt this format since the backend's decrypt_with_aes
            # expects a different format (iv + ciphertext concatenated)
            username = self._decrypt_frontend_format(encrypted_username, encryption_key_base64)
            password = self._decrypt_frontend_format(encrypted_password, encryption_key_base64)
            
            if not username or not password:
                return Response(
                    {'error': 'Invalid decrypted credentials format'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Authenticate user
            user = self._authenticate_user(username, password)
            if user is None:
                return Response(
                    {'error': 'Invalid username or password'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            return self._generate_jwt_response(user)
            
        except Exception as e:
            return Response(
                {'error': f'Decryption failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

    def _handle_legacy_login(self, request):
        """Handle login with plain credentials"""
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response(
                {'error': 'Both username and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = self._authenticate_user(username, password)

        if user is None:
            return Response(
                {'error': 'Invalid username or password'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        return self._generate_jwt_response(user)
    
    def _authenticate_user(self, username, password):
        """Authenticate user with both legacy and new password formats"""
        try:
            user = User.objects.get(username=username)
            
            # Log for debugging (be careful not to log full password in production)
            # Masking password for security
            masked_password = password[:2] + '*' * (len(password) - 2) if len(password) > 2 else '***'
            print(f"Authenticating user: {username}")
            print(f"Stored hash: {user.password[:10]}...")
            print(f"Stored salt: {user.salt}")
            print(f"Provided (decrypted) password starts with: {masked_password[:10]}...")

            # First try Django's default authentication (for legacy users)
            if not user.salt:
                if user.check_password(password):
                    print("Legacy authentication successful")
                    return user
            
            # Then try custom password verification (for new format users)
            if user.salt:
                if SecurityUtils.verify_password(password, user.password, user.salt):
                    print("Custom authentication successful")
                    return user
            
            print("Authentication failed")
            return None
        except User.DoesNotExist:
            print(f"User {username} not found")
            return None
    
    def _decrypt_frontend_format(self, encrypted_json, key_base64):
        """Decrypt data encrypted in frontend's JSON format"""
        import json
        
        try:
            # Try parsing as JSON
            payload = json.loads(encrypted_json)
        except (ValueError, TypeError):
            # If not JSON, it might be the old format (nonce+tag+ciphertext)
            return SecurityUtils.decrypt_with_aes(encrypted_json, key_base64)

        # Check if it's the new format (iv, data, keyFingerprint)
        if 'iv' in payload and 'data' in payload:
            return SecurityUtils.decrypt_aes_gcm_with_format(payload, key_base64)
        
        # Check if it's the other frontend format (nonce, tag, data)
        if 'nonce' in payload and 'tag' in payload and 'data' in payload:
            import base64
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            nonce = base64.urlsafe_b64decode(payload['nonce'])
            tag = base64.urlsafe_b64decode(payload['tag'])
            encrypted_data = base64.urlsafe_b64decode(payload['data'])
            
            key_bytes = base64.b64decode(key_base64.encode('utf-8'))
            
            cipher = Cipher(
                algorithms.AES(key_bytes),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
            return decrypted.decode('utf-8')
            
        raise ValueError("Unknown encrypted data format")

    def _generate_jwt_response(self, user):
        """Generate JWT tokens for authentication response"""
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'tokens': {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'access_expires': refresh.access_token.payload['exp'],
                'refresh_expires': refresh.payload['exp'],
            }
        })


class LogoutView(APIView):
    def post(self, request):
        # Handle token-based authentication logout
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Token '):
            token_key = auth_header.split(' ')[1]
            try:
                token = AuthToken.objects.get(token=token_key)
                token.delete()
                return Response({'message': 'Successfully logged out'})
            except AuthToken.DoesNotExist:
                pass

        # For JWT, logout is typically handled client-side by removing tokens
        return Response({'message': 'Logout successful - remove tokens client-side'}, status=status.HTTP_200_OK)


class TokenRefreshView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh_token = request.data.get('refresh')

        if not refresh_token:
            return Response(
                {'error': 'Refresh token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            
            return Response({
                'access': access_token,
                'access_expires': refresh.access_token.payload['exp'],
            })

        except TokenError as e:
            return Response(
                {'error': f'Invalid refresh token: {str(e)}'},
                status=status.HTTP_401_UNAUTHORIZED
            )


def custom_exception_handler(exc, context):
    from rest_framework.views import exception_handler

    response = exception_handler(exc, context)

    if response is not None:
        # Log the original error for debugging
        logger.warning(f"API Exception: {exc}")
        
        response.data = {
            'error': True,
            'message': response.data.get('detail', 'An error occurred'),
            'status_code': response.status_code,
        }
    else:
        # Log unexpected errors for debugging
        logger.error(f"Unexpected error: {exc}", exc_info=True)
        
        # For unexpected errors, return a generic message to avoid information leakage
        response = Response({
            'error': True,
            'message': 'An unexpected error occurred',
            'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return response
