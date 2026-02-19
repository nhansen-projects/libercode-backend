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
from .models import Entry, Tag, Favorite, AuthToken
from .serializers import EntrySerializer, TagSerializer, FavoriteSerializer, UserSerializer
import datetime


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
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Entry.objects.filter(author=user).order_by('-created_at')


class UserFavoritesView(generics.ListAPIView):
    serializer_class = FavoriteSerializer
    pagination_class = PageNumberPagination
    authentication_classes = [CustomTokenAuthentication]
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
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Hash password
        user_data = serializer.validated_data
        user_data['password'] = make_password(user_data['password'])

        user = get_user_model().objects.create(**user_data)

        # Generate auth token
        token = AuthToken.generate_token(user)

        return Response({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'token': token.token,
            'expires_at': token.expires_at.isoformat(),
        }, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response(
                {'error': 'Both username and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(username=username, password=password)

        if user is None:
            return Response(
                {'error': 'Invalid username or password'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Generate/refresh token
        token, created = AuthToken.objects.get_or_create(user=user)
        if not created:
            token.extend()

        return Response({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'token': token.token,
            'expires_at': token.expires_at.isoformat(),
        })


class LogoutView(APIView):
    def post(self, request):
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Token '):
            token_key = auth_header.split(' ')[1]
            try:
                token = AuthToken.objects.get(token=token_key)
                token.delete()
                return Response({'message': 'Successfully logged out'})
            except AuthToken.DoesNotExist:
                pass

        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)


class TokenRefreshView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        token_key = request.data.get('token')

        if not token_key:
            return Response(
                {'error': 'Token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            token = AuthToken.objects.get(token=token_key)

            if not token.is_valid():
                token.delete()
                return Response(
                    {'error': 'Token has expired'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            token.extend()

            return Response({
                'token': token.token,
                'expires_at': token.expires_at.isoformat(),
            })

        except AuthToken.DoesNotExist:
            return Response(
                {'error': 'Invalid token'},
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
