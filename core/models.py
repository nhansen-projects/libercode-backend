from django.conf import settings
from django.db import models
import secrets
import datetime

class AuthToken(models.Model):
    """
    authentication token model
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='auth_token'
    )
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    def __str__(self):
        return f"Token for {self.user.username}"
    
    def is_valid(self):
        return self.expires_at > datetime.datetime.now(datetime.timezone.utc)
    
    def extend(self):
        self.expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            seconds=settings.SIMPLE_AUTH['TOKEN_LIFETIME']
        )
        self.save()
    
    @classmethod
    def generate_token(cls, user):
        cls.objects.filter(user=user).delete()
        
        token = secrets.token_urlsafe(48)
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            seconds=settings.SIMPLE_AUTH['TOKEN_LIFETIME']
        )
        
        return cls.objects.create(
            user=user,
            token=token,
            expires_at=expires_at
        )


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
