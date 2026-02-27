from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.urls import reverse
from django.utils.html import format_html
from . import models


@admin.register(models.User)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'date_joined')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    ordering = ('username',)
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'email', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_superuser'),
        }),
    )


@admin.register(models.EncryptionKey)
class EncryptionKeyAdmin(admin.ModelAdmin):
    list_display = ('id', 'key_type', 'is_active', 'created_at', 'deactivated_at', 'description')
    list_filter = ('key_type', 'is_active')
    search_fields = ('description',)
    readonly_fields = ('key', 'created_at', 'deactivated_at')
    fieldsets = (
        (None, {
            'fields': ('key_type', 'is_active', 'description')
        }),
        ('Key Information', {
            'fields': ('key', 'created_at', 'deactivated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(models.Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ("id", "value", "created_at", "entry_count")
    search_fields = ("value",)
    ordering = ("value",)
    
    def entry_count(self, obj):
        return obj.entries.count()
    entry_count.short_description = "Entries"
    
    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related('entries')


@admin.register(models.Entry)
class EntryAdmin(admin.ModelAdmin):
    list_display = ("id", "title", "author", "shared", "created_at", "tag_list", "view_on_site_link")
    list_filter = ("shared", "created_at", "tags")
    search_fields = ("title", "body", "tags__value")
    autocomplete_fields = ("author",)
    filter_horizontal = ("tags",)
    readonly_fields = ("created_at", "preview_link")
    fieldsets = (
        (None, {
            'fields': ('title', 'author', 'shared', 'tags')
        }),
        ('Content', {
            'fields': ('body',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'preview_link'),
            'classes': ('collapse',)
        })
    )
    
    def tag_list(self, obj):
        return ", ".join([tag.value for tag in obj.tags.all()])
    tag_list.short_description = "Tags"
    
    def view_on_site_link(self, obj):
        if obj.pk:
            try:
                url = reverse('entry-detail', args=[obj.pk])
                return format_html('<a href="{}" target="_blank">View on site</a>', url)
            except Exception:
                return "-"
        return "-"
    view_on_site_link.short_description = "View"
    view_on_site_link.allow_tags = True
    
    def preview_link(self, obj):
        if obj.pk:
            try:
                url = reverse('entry-detail', args=[obj.pk])
                return format_html('<a href="{}" target="_blank">Preview entry</a>', url)
            except Exception:
                return "-"
        return "-"
    preview_link.short_description = "Preview"


@admin.register(models.Favorite)
class FavoriteAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "entry", "created_at", "entry_title")
    autocomplete_fields = ("user", "entry")
    search_fields = ("user__username", "entry__title")
    list_filter = ("created_at",)
    
    def entry_title(self, obj):
        return obj.entry.title
    entry_title.short_description = "Entry Title"
    entry_title.admin_order_field = "entry__title"
