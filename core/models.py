from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password
import secrets
import datetime

class User(AbstractUser):
    """
    Custom user model with salt for password hashing
    """
    salt = models.CharField(max_length=64, blank=True, null=True)
    
    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'
    
    def __str__(self):
        return self.username
    
    def set_password(self, raw_password):
        """
        Set password with custom hashing including salt
        """
        from .utils import SecurityUtils
        
        # Generate salt if not exists
        if not self.salt:
            self.salt = SecurityUtils.generate_salt()
        
        # Hash password with salt
        hash_data = SecurityUtils.hash_password(raw_password, self.salt)
        self.password = hash_data['hash']
    
    def check_password(self, raw_password):
        """
        Check password against stored hash with salt
        """
        from .utils import SecurityUtils
        
        if not self.salt:
            # Fallback to Django's default password checking for legacy users
            # But first check if this is actually a Django-hashed password
            from django.contrib.auth.hashers import check_password as django_check_password
            return django_check_password(raw_password, self.password)
        
        # Verify password with salt
        return SecurityUtils.verify_password(raw_password, self.password, self.salt)


class EncryptionKey(models.Model):
    """
    Model to manage encryption keys for secure credential storage
    """
    key = models.CharField(max_length=255, unique=True)
    key_type = models.CharField(max_length=20, choices=[
        ('fernet', 'Fernet'),
        ('aes', 'AES')
    ])
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    deactivated_at = models.DateTimeField(null=True, blank=True)
    description = models.CharField(max_length=255, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'encryption key'
        verbose_name_plural = 'encryption keys'
    
    def __str__(self):
        status = "active" if self.is_active else "inactive"
        return f"{self.key_type} key ({status}) - {self.created_at.strftime('%Y-%m-%d')}"
    
    @classmethod
    def generate_fernet_key(cls, description="Auto-generated Fernet key"):
        """
        Generate and save a new Fernet encryption key
        """
        from .utils import SecurityUtils
        
        # Deactivate all existing Fernet keys
        cls.objects.filter(key_type='fernet', is_active=True).update(
            is_active=False,
            deactivated_at=datetime.datetime.now(datetime.timezone.utc)
        )
        
        # Generate and save new key
        key_value = SecurityUtils.generate_fernet_key()
        return cls.objects.create(
            key=key_value,
            key_type='fernet',
            is_active=True,
            description=description
        )
    
    @classmethod
    def generate_aes_key(cls, description="Auto-generated AES key"):
        """
        Generate and save a new AES encryption key
        """
        from .utils import SecurityUtils
        
        # Deactivate all existing AES keys
        cls.objects.filter(key_type='aes', is_active=True).update(
            is_active=False,
            deactivated_at=datetime.datetime.now(datetime.timezone.utc)
        )
        
        # Generate and save new key
        key_value = SecurityUtils.generate_aes_key()
        return cls.objects.create(
            key=key_value,
            key_type='aes',
            is_active=True,
            description=description
        )
    
    @classmethod
    def get_active_key(cls, key_type='fernet'):
        """
        Get the currently active key of specified type
        """
        try:
            return cls.objects.get(key_type=key_type, is_active=True)
        except cls.DoesNotExist:
            return None


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
    last_edited = models.DateTimeField(auto_now=True)

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
