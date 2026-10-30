"""
Django settings for SentinelShield: Advanced Intrusion Detection & Web Protection System.
"""

from pathlib import Path
import os
import sys

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Add apps directory to sys.path so apps can be imported cleanly if needed
sys.path.insert(0, str(BASE_DIR))

# Try loading .env file if available
env_path = BASE_DIR / '.env'
if env_path.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
    except ImportError:
        pass

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

SECRET_KEY = os.environ.get(
    'SECRET_KEY',
    'django-insecure-sentinelshield-soc-defense-matrix-academic-key-9021!'
)

DEBUG = os.environ.get('DEBUG', 'True').lower() in ('true', '1', 'yes')

ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get('ALLOWED_HOSTS', '127.0.0.1,localhost,testserver,[::1]').split(',')
    if host.strip()
]

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party apps
    'rest_framework',
    'corsheaders',

    # SentinelShield modular applications
    'apps.accounts',
    'apps.inspector',
    'apps.detections',
    'apps.traffic',
    'apps.alerts',
    'apps.ratelimit',
    'apps.simulation',
    'apps.audit',
    'apps.reporting',
    'apps.dashboard',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

    # SentinelShield Request Inspection & Decision Enforcement Pipeline
    'apps.inspector.middleware.SecurityInspectorMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'apps.dashboard.context_processors.sentinel_context',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Cache configuration for sliding-window rate limiting & inspection cache
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'sentinelshield-in-memory-cache',
    }
}

# Custom User Model
AUTH_USER_MODEL = 'accounts.User'

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 8},
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Django REST Framework Settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticatedOrReadOnly',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
}

# CORS Settings
CORS_ALLOW_ALL_ORIGINS = DEBUG
CORS_ALLOW_CREDENTIALS = True

# SentinelShield Security Engine Configuration
SENTINEL_MODE = os.environ.get('SENTINEL_MODE', 'ENFORCE').upper()  # 'MONITOR', 'FLAG', 'ENFORCE'
SENTINEL_BODY_LIMIT_BYTES = int(os.environ.get('SENTINEL_BODY_LIMIT_BYTES', 262144))  # 256 KB
SENTINEL_RATE_LIMIT_THRESHOLD = int(os.environ.get('SENTINEL_RATE_LIMIT_THRESHOLD', 60))
SENTINEL_RATE_LIMIT_WINDOW_SECS = int(os.environ.get('SENTINEL_RATE_LIMIT_WINDOW_SECS', 60))
SENTINEL_RATE_LIMIT_BLOCK_SECS = int(os.environ.get('SENTINEL_RATE_LIMIT_BLOCK_SECS', 300))
SENTINEL_AUTH_RATE_LIMIT_THRESHOLD = int(os.environ.get('SENTINEL_AUTH_RATE_LIMIT_THRESHOLD', 10))
SENTINEL_AUTH_RATE_LIMIT_WINDOW_SECS = int(os.environ.get('SENTINEL_AUTH_RATE_LIMIT_WINDOW_SECS', 60))

# Trusted proxies for extracting client IP from X-Forwarded-For safely
# By default empty - will only use REMOTE_ADDR unless explicitly listed
SENTINEL_TRUSTED_PROXIES = [
    ip.strip()
    for ip in os.environ.get('SENTINEL_TRUSTED_PROXIES', '').split(',')
    if ip.strip()
]

# Explicit exclusions from security blocking (health check, static assets, etc.)
SENTINEL_EXCLUDED_PATH_PREFIXES = [
    '/static/',
    '/media/',
    '/favicon.ico',
    '/api/v1/system/health/',
]

LOGIN_URL = '/auth/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/auth/login/'
