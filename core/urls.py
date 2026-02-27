from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views

# Import API views unconditionally; if import fails, it's a real setup error we should see
from . import api_views
from rest_framework.routers import DefaultRouter

# Create a router for API views (reserved for future use)
router = DefaultRouter()

api_urls = [
    # Authentication URLs
    path('api/register/', api_views.UserCreateView.as_view(), name='api-register'),
    path('api/login/', api_views.LoginView.as_view(), name='api-login'),
    path('api/logout/', api_views.LogoutView.as_view(), name='api-logout'),
    path('api/token/refresh/', api_views.TokenRefreshView.as_view(), name='api-token-refresh'),

    # API URLs
    path('api/entries/', api_views.EntryListCreateView.as_view(), name='api-entry-list'),
    path('api/entries/<int:pk>/', api_views.EntryRetrieveUpdateDestroyView.as_view(), name='api-entry-detail'),

    path('api/tags/', api_views.TagListCreateView.as_view(), name='api-tag-list'),
    path('api/tags/<int:pk>/', api_views.TagRetrieveUpdateDestroyView.as_view(), name='api-tag-detail'),

    path('api/favorites/', api_views.FavoriteListCreateView.as_view(), name='api-favorite-list'),
    path('api/favorites/<int:pk>/', api_views.FavoriteRetrieveDestroyView.as_view(), name='api-favorite-detail'),

    path('api/me/entries/', api_views.UserEntriesView.as_view(), name='api-user-entries'),
    path('api/me/favorites/', api_views.UserFavoritesView.as_view(), name='api-user-favorites'),
]

urlpatterns = [
    # Root URL - redirect to entry list
    path('', views.EntryListView.as_view(), name='home'),
    
    # Authentication URLs
    path('accounts/login/', views.CustomLoginView.as_view(), name='login'),
    path('accounts/logout/', views.CustomLogoutView.as_view(), name='logout'),
    path('accounts/register/', views.RegisterView.as_view(), name='register'),
    path('accounts/profile/', views.ProfileView.as_view(), name='profile'),
    
    # Password reset URLs
    path('accounts/password_reset/', auth_views.PasswordResetView.as_view(template_name='registration/password_reset_form.html'), name='password_reset'),
    path('accounts/password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='registration/password_reset_done.html'), name='password_reset_done'),
    path('accounts/reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='registration/password_reset_confirm.html'), name='password_reset_confirm'),
    path('accounts/reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='registration/password_reset_complete.html'), name='password_reset_complete'),
    
    # Web interface URLs
    path('entries/', views.EntryListView.as_view(), name='entry-list'),
    path('entries/<int:pk>/', views.EntryDetailView.as_view(), name='entry-detail'),
    path('entries/create/', views.EntryCreateView.as_view(), name='entry-create'),
    path('entries/<int:pk>/update/', views.EntryUpdateView.as_view(), name='entry-update'),
    path('entries/<int:pk>/delete/', views.EntryDeleteView.as_view(), name='entry-delete'),
    
    path('tags/', views.TagListView.as_view(), name='tag-list'),
    path('tags/<int:pk>/', views.TagDetailView.as_view(), name='tag-detail'),
    path('tags/create/', views.TagCreateView.as_view(), name='tag-create'),
    path('tags/<int:pk>/update/', views.TagUpdateView.as_view(), name='tag-update'),
    path('tags/<int:pk>/delete/', views.TagDeleteView.as_view(), name='tag-delete'),
    
    path('favorites/', views.user_favorites, name='favorites'),
    path('entries/<int:entry_id>/toggle-favorite/', views.toggle_favorite, name='toggle-favorite'),
    path('api-docs/', views.APIDocumentationView.as_view(), name='api-docs'),
] + api_urls