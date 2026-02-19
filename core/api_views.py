from rest_framework import generics, permissions, status, exceptions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from django.db import models
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


class CustomTokenAuthentication:
    def authenticate(self, request):
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
        return 'Token'


class EntryListCreateView(generics.ListCreateAPIView):
    serializer_class = EntrySerializer
    pagination_class = PageNumberPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'body', 'tags__value']
    ordering_fields = ['title', 'created_at', 'shared']
    ordering = ['-created_at']
    authentication_classes = [CustomTokenAuthentication]
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get_queryset(self):
        queryset = Entry.objects.all().select_related('author')

        if hasattr(self.request, 'user') and self.request.user.is_authenticated:
            queryset = queryset.filter(shared=True)

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
    authentication_classes = [CustomTokenAuthentication]

    def get_queryset(self):
        queryset = super().get_queryset()

        # Only allow users to access their own entries unless shared
        if not self.request.user.is_staff:
            queryset = queryset.filter(
                models.Q(author=self.request.user) | models.Q(shared=True)
            )

        return queryset


class TagListCreateView(generics.ListCreateAPIView):
    serializer_class = TagSerializer
    queryset = Tag.objects.all()
    pagination_class = PageNumberPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['value']
    ordering_fields = ['value', 'created_at']
    ordering = ['value']
    authentication_classes = [CustomTokenAuthentication]


class TagRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TagSerializer
    queryset = Tag.objects.all()
    authentication_classes = [CustomTokenAuthentication]


class FavoriteListCreateView(generics.ListCreateAPIView):
    serializer_class = FavoriteSerializer
    pagination_class = PageNumberPagination
    authentication_classes = [CustomTokenAuthentication]

    def get_queryset(self):
        return Favorite.objects.filter(user=self.request.user).select_related('entry')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class FavoriteRetrieveDestroyView(generics.RetrieveDestroyAPIView):
    serializer_class = FavoriteSerializer
    authentication_classes = [CustomTokenAuthentication]

    def get_queryset(self):
        return Favorite.objects.filter(user=self.request.user)


class UserEntriesView(generics.ListAPIView):
    serializer_class = EntrySerializer
    pagination_class = PageNumberPagination
    authentication_classes = [CustomTokenAuthentication]

    def get_queryset(self):
        user = self.request.user
        return Entry.objects.filter(author=user).order_by('-created_at')


class UserFavoritesView(generics.ListAPIView):
    serializer_class = FavoriteSerializer
    pagination_class = PageNumberPagination
    authentication_classes = [CustomTokenAuthentication]

    def get_queryset(self):
        user = self.request.user
        return Favorite.objects.filter(user=user).select_related('entry').order_by('-created_at')


# Views
class UserCreateView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]
    queryset = User.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_data = serializer.validated_data
        
        # Handle different registration formats
        password_data = request.data.get('password')
        password_hash = request.data.get('password_hash')
        salt = request.data.get('salt')
        
        if password_hash and salt:
            # New secure format: password_hash + salt from Flutter client
            user_data['password'] = password_hash
            user_data['salt'] = salt
        elif password_data:
            # Legacy format: plain password (hash server-side)
            # Use our custom password hashing with salt
            user = User()
            user.username = user_data['username']
            user.email = user_data.get('email', '')
            user.set_password(password_data)
            user.save()
            
            return self._generate_auth_response(user)
        else:
            return Response(
                {'error': 'Either password or password_hash+salt required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create user with hashed password and salt
        user = User.objects.create_user(
            username=user_data['username'],
            email=user_data.get('email', ''),
            password=user_data['password'],
            salt=user_data.get('salt')
        )
        
        return self._generate_auth_response(user)
    
    def _generate_auth_response(self, user):
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
        }, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        # Handle different login formats
        if 'encrypted_credentials' in request.data:
            # New secure format: encrypted credentials
            return self._handle_encrypted_login(request)
        else:
            # Legacy format: plain credentials
            return self._handle_legacy_login(request)
    
    def _handle_encrypted_login(self, request):
        """Handle login with encrypted credentials"""
        encrypted_credentials = request.data.get('encrypted_credentials')
        decryption_key = request.data.get('decryption_key')
        key_type = request.data.get('key_type', 'fernet')
        
        if not encrypted_credentials or not decryption_key:
            return Response(
                {'error': 'Both encrypted_credentials and decryption_key are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get the appropriate encryption key
            if key_type == 'fernet':
                decrypted_data = SecurityUtils.decrypt_with_fernet(encrypted_credentials, decryption_key)
            elif key_type == 'aes':
                decrypted_data = SecurityUtils.decrypt_with_aes(encrypted_credentials, decryption_key)
            else:
                return Response(
                    {'error': 'Unsupported key_type'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Parse decrypted credentials
            credentials = json.loads(decrypted_data)
            username = credentials.get('username')
            password = credentials.get('password')
            
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
            
            # Check if user has salt (new format)
            if user.salt:
                # Use our custom password verification
                if SecurityUtils.verify_password(password, user.password, user.salt):
                    return user
            else:
                # Fallback to Django's default authentication for legacy users
                if user.check_password(password):
                    return user
            
            return None
        except User.DoesNotExist:
            return None
    
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
        # For JWT, logout is typically handled client-side by removing tokens
        # But we can implement token blacklisting if needed
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
        response.data = {
            'error': True,
            'message': response.data.get('detail', str(exc)),
            'status_code': response.status_code,
        }
    else:
        response = Response({
            'error': True,
            'message': str(exc),
            'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return response
