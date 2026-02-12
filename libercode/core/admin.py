from django.contrib import admin
from . import models


@admin.register(models.Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ("id", "value", "created_at")
    search_fields = ("value",)


@admin.register(models.Entry)
class EntryAdmin(admin.ModelAdmin):
    list_display = ("id", "title", "author", "shared", "created_at")
    list_filter = ("shared", "created_at")
    search_fields = ("title", "body")
    autocomplete_fields = ("author",)
    filter_horizontal = ("tags",)


@admin.register(models.Favorite)
class FavoriteAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "entry", "created_at")
    autocomplete_fields = ("user", "entry")
