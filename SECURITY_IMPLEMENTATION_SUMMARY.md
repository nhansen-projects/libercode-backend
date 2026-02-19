# Django Backend Security Implementation Summary

This document provides a comprehensive overview of the security implementation for the Django backend, including encrypted credentials, hashed passwords, and JWT authentication.

## Implementation Overview

### 1. Security Utilities (`core/utils.py`)

**Features:**
- **Fernet Key Generation**: Secure symmetric encryption keys using cryptography.fernet
- **AES-256 Encryption**: Advanced encryption standard with CBC mode
- **Password Hashing**: SHA-256 with PBKDF2 and random salts
- **Salt Generation**: 128-bit random salts for password hashing
- **JWT Payload Generation**: Standardized JWT payload structure

**Usage Examples:**
```python
from core.utils import SecurityUtils

# Generate encryption keys
fernet_key = SecurityUtils.generate_fernet_key()
aes_key = SecurityUtils.generate_aes_key()

# Password hashing with salt
salt = SecurityUtils.generate_salt()
hash_data = SecurityUtils.hash_password("my_password", salt)
is_valid = SecurityUtils.verify_password("my_password", hash_data['hash'], hash_data['salt'])

# Data encryption/decryption
encrypted = SecurityUtils.encrypt_with_fernet("secret_data", fernet_key)
decrypted = SecurityUtils.decrypt_with_fernet(encrypted, fernet_key)
```

### 2. Custom User Model (`core/models.py`)

**Extended AbstractUser with:**
- `salt` field for password hashing
- Custom `set_password()` method with salt generation
- Custom `check_password()` method with salt verification
- Backward compatibility with Django's default password hashing

**Database Schema:**
```sql
CREATE TABLE core_user (
    id SERIAL PRIMARY KEY,
    password VARCHAR(128) NOT NULL,
    last_login TIMESTAMP WITH TIME ZONE,
    is_superuser BOOLEAN NOT NULL,
    username VARCHAR(150) UNIQUE NOT NULL,
    first_name VARCHAR(150),
    last_name VARCHAR(150),
    email VARCHAR(254),
    is_staff BOOLEAN NOT NULL,
    is_active BOOLEAN NOT NULL,
    date_joined TIMESTAMP WITH TIME ZONE NOT NULL,
    salt VARCHAR(64)  -- NEW: For password hashing
);
```

### 3. Encryption Key Management (`core/models.py`)

**Features:**
- Stores Fernet and AES encryption keys
- Automatic key rotation
- Active/inactive key tracking
- Audit trail with timestamps

**Model Fields:**
- `key`: Base64 encoded encryption key
- `key_type`: 'fernet' or 'aes'
- `is_active`: Boolean flag for active keys
- `created_at`: Timestamp of key creation
- `deactivated_at`: Timestamp when key was deactivated
- `description`: Human-readable description

**Management Commands:**
```bash
# Generate encryption keys
python manage.py generate_encryption_keys --key-type fernet --description "Production Fernet Key"
python manage.py generate_encryption_keys --key-type aes --description "Production AES Key"
python manage.py generate_encryption_keys --key-type both --description "Production Keys"

# Force key rotation
python manage.py generate_encryption_keys --key-type fernet --force
```

### 4. Authentication Views (`core/api_views.py`)

**Updated Views:**

#### UserCreateView (Registration)
- **Legacy Format**: Accepts plain password, hashes server-side
- **Secure Format**: Accepts pre-hashed password + salt from Flutter client
- **Response**: JWT tokens (access + refresh)

**Request Formats:**

**Legacy (Plain Password):**
```json
{
    "username": "user1",
    "email": "user@example.com", 
    "password": "plain_password"
}
```

**Secure (Pre-hashed):**
```json
{
    "username": "user1",
    "email": "user@example.com",
    "password_hash": "hashed_password_hex",
    "salt": "random_salt_hex"
}
```

#### LoginView
- **Legacy Format**: Plain username/password
- **Secure Format**: Encrypted credentials with decryption key
- **Response**: JWT tokens (access + refresh)

**Request Formats:**

**Legacy (Plain Credentials):**
```json
{
    "username": "user1",
    "password": "plain_password"
}
```

**Secure (Encrypted Credentials):**
```json
{
    "encrypted_credentials": "base64_encrypted_data",
    "decryption_key": "encryption_key",
    "key_type": "fernet"  // or "aes"
}
```

### 5. JWT Configuration (`libercode/settings.py`)

**Settings:**
```python
# Custom user model
AUTH_USER_MODEL = 'core.User'

# REST Framework with JWT
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ),
    # ... other settings
}

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': 'your-secret-key-here',
    'VERIFYING_KEY': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}
```

### 6. API Endpoints

**Authentication URLs:**
- `POST /api/register/` - User registration
- `POST /api/login/` - User login
- `POST /api/logout/` - User logout
- `POST /api/token/refresh/` - Refresh JWT tokens

**Request/Response Examples:**

**Registration (Legacy):**
```bash
POST /api/register/
Content-Type: application/json

{
    "username": "testuser",
    "email": "test@example.com",
    "password": "testpass123"
}
```

**Response:**
```json
{
    "user": {
        "id": 1,
        "username": "testuser",
        "email": "test@example.com"
    },
    "tokens": {
        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "access_expires": 1735689600,
        "refresh_expires": 1735776000
    }
}
```

**Login (Secure):**
```bash
POST /api/login/
Content-Type: application/json

{
    "encrypted_credentials": "gAAAAABkLQAAAAAAAAAA...",
    "decryption_key": "7-swevQk4BMggGZDjSGQ...",
    "key_type": "fernet"
}
```

### 7. Backward Compatibility

**Legacy User Support:**
- Users without `salt` field use Django's default password hashing
- Gradual migration path for existing users
- Mixed authentication support during transition period

**Migration Strategy:**
1. Deploy new backend with both authentication methods
2. Update Flutter app to use secure format
3. Gradually migrate users to new format
4. Phase out legacy authentication after full migration

## Deployment Instructions

### 1. Database Setup

**For new installations:**
```bash
# Apply all migrations
python manage.py migrate

# Generate encryption keys
python manage.py generate_encryption_keys --key-type both --description "Initial production keys"
```

**For existing installations:**
```bash
# Backup your database first!
pg_dump -U admin -d notesDB > backup.sql

# Apply new migrations
python manage.py migrate

# Generate encryption keys
python manage.py generate_encryption_keys --key-type both --description "Production keys"
```

### 2. Environment Configuration

Update your `.env` file:
```env
# Database settings
DB_NAME=notesDB
DB_USER=admin
DB_PASSWORD=your_secure_password
DB_HOST=localhost
DB_PORT=5432

# Security settings
SECRET_KEY=your-very-secure-secret-key-here
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,api.yourdomain.com

# JWT settings (optional, can use settings.py defaults)
JWT_SIGNING_KEY=your-jwt-signing-key-here
```

### 3. Flutter Client Integration

**Registration (Secure Format):**
```dart
// Generate salt and hash password client-side
String salt = generateSecureSalt();
String passwordHash = hashPasswordWithSalt(password, salt);

// Send to backend
var response = await http.post(
    Uri.parse('https://api.yourdomain.com/api/register/'),
    body: jsonEncode({
        'username': username,
        'email': email,
        'password_hash': passwordHash,
        'salt': salt
    }),
    headers: {'Content-Type': 'application/json'}
);
```

**Login (Secure Format):**
```dart
// Encrypt credentials
String encryptionKey = await getActiveEncryptionKey(); // From secure storage
String encryptedCredentials = encryptWithFernet(
    jsonEncode({'username': username, 'password': password}),
    encryptionKey
);

// Send to backend
var response = await http.post(
    Uri.parse('https://api.yourdomain.com/api/login/'),
    body: jsonEncode({
        'encrypted_credentials': encryptedCredentials,
        'decryption_key': encryptionKey,
        'key_type': 'fernet'
    }),
    headers: {'Content-Type': 'application/json'}
);
```

### 4. Security Best Practices

**Database Security:**
- Use strong database passwords
- Restrict database access to backend servers only
- Enable PostgreSQL SSL connections
- Regularly rotate database passwords

**Application Security:**
- Keep `SECRET_KEY` and `JWT_SIGNING_KEY` secure
- Use environment variables for sensitive configuration
- Enable Django's security middleware
- Set `DEBUG=False` in production
- Use HTTPS for all communications

**Key Management:**
- Rotate encryption keys periodically
- Store encryption keys securely (not in code repository)
- Use hardware security modules (HSM) for production keys if possible
- Implement key backup and recovery procedures

## Testing

### Unit Tests

Run the security utilities tests:
```bash
python test_security_utils.py
```

### Integration Tests

Test the authentication flow:
```bash
python test_authentication.py
```

### Management Command Tests

Test encryption key generation:
```bash
python test_management_command.py
```

## Troubleshooting

**Common Issues:**

1. **Migration errors**: If you encounter migration issues, try:
   ```bash
   python manage.py migrate --fake
   python manage.py makemigrations
   python manage.py migrate
   ```

2. **Missing cryptography module**: Install with:
   ```bash
   pip install cryptography
   ```

3. **Database connection issues**: Verify your `.env` settings and PostgreSQL configuration.

4. **JWT token issues**: Ensure `SIMPLE_JWT` settings match between frontend and backend.

## API Documentation

### Authentication Endpoints

**POST /api/register/**
- Register a new user
- Supports both legacy (plain password) and secure (hashed password + salt) formats

**POST /api/login/**
- Authenticate user
- Supports both legacy (plain credentials) and secure (encrypted credentials) formats

**POST /api/logout/**
- Invalidate current session (client-side token removal for JWT)

**POST /api/token/refresh/**
- Refresh access token using refresh token

### Request/Response Examples

**Token Refresh:**
```bash
POST /api/token/refresh/
Content-Type: application/json

{
    "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
    "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "access_expires": 1735689600
}
```

## Migration Guide

### From Legacy to Secure Authentication

1. **Phase 1 - Backend Update**:
   - Deploy updated backend with both authentication methods
   - Monitor for any issues

2. **Phase 2 - Flutter App Update**:
   - Update Flutter app to use secure authentication
   - Implement client-side password hashing
   - Implement credential encryption

3. **Phase 3 - User Migration**:
   - Gradually migrate users to new format
   - Provide fallback to legacy format during transition

4. **Phase 4 - Legacy Deprecation**:
   - Remove legacy authentication support
   - Require all clients to use secure format

## Security Audit Checklist

- [ ] Custom user model with salt field implemented
- [ ] Password hashing with PBKDF2 and random salts
- [ ] Fernet and AES encryption utilities working
- [ ] Encryption key management system in place
- [ ] JWT authentication configured
- [ ] Backward compatibility with legacy authentication
- [ ] Management command for key rotation
- [ ] Secure API endpoints for authentication
- [ ] Proper error handling and validation
- [ ] Database migrations applied
- [ ] Environment variables configured securely
- [ ] HTTPS enforced in production
- [ ] Regular key rotation schedule established

## Conclusion

This implementation provides a comprehensive security solution for the Django backend, including:

- **Secure Password Storage**: SHA-256 hashing with random salts
- **Encrypted Credentials**: Fernet and AES encryption for data in transit
- **JWT Authentication**: Stateless, secure token-based authentication
- **Key Management**: Secure encryption key storage and rotation
- **Backward Compatibility**: Smooth transition from legacy systems

The system is designed to work seamlessly with Flutter clients while maintaining compatibility with existing web interfaces.