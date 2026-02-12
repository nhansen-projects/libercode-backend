from django.conf import settings
from django.db import models


class Tag(models.Model):
    value = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["value"]
        indexes = [
            models.Index(fields=["value"], name="idx_tag_value"),
        ]

    def __str__(self) -> str:
        return self.value


class Entry(models.Model):
    title = models.CharField(max_length=255)
    body = models.TextField(help_text="Content of the post")
    shared = models.BooleanField(default=False)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="entries",
        db_column="created_by",
    )
    tags = models.ManyToManyField(Tag, related_name="entries", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at"], name="idx_entry_created_at"),
        ]

    def __str__(self) -> str:
        return self.title


class Favorite(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="favorites",
    )
    entry = models.ForeignKey(
        Entry,
        on_delete=models.CASCADE,
        related_name="favorited_by",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "entry")
        indexes = [
            models.Index(fields=["user", "entry"], name="idx_fav_user_entry"),
        ]

    def __str__(self) -> str:
        return f"{self.user} → {self.entry}"
