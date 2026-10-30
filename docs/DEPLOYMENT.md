# SentinelShield Deployment & Production Path

## 1. Local Development Architecture

- **Operating System:** Windows, macOS, or Linux.
- **Python Version:** 3.12+ (tested on Python 3.13.5).
- **Database:** SQLite3 (`db.sqlite3`).
- **Cache Backend:** `django.core.cache.backends.locmem.LocMemCache`.
- **WSGI Server:** Django development server (`manage.py runserver`).

## 2. Production Architecture Path

When migrating SentinelShield from an academic sandbox to an enterprise staging or production environment, follow these steps:

### A. Environment Configuration (`.env`)
```bash
DEBUG=False
SECRET_KEY=generate-a-strong-random-50-character-key
ALLOWED_HOSTS=soc.yourorg.com,10.0.0.10
SENTINEL_MODE=ENFORCE
SENTINEL_BODY_LIMIT_BYTES=262144
SENTINEL_RATE_LIMIT_THRESHOLD=60
SENTINEL_RATE_LIMIT_WINDOW_SECS=60
SENTINEL_RATE_LIMIT_BLOCK_SECS=300
SENTINEL_TRUSTED_PROXIES=10.0.0.1,10.0.0.2
```

### B. PostgreSQL Database Configuration
Install psycopg2:
```bash
pip install psycopg2-binary
```
Configure `DATABASES` in `config/settings.py`:
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'sentinelshield_db',
        'USER': 'sentinel_user',
        'PASSWORD': 'strong_secure_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

### C. Distributed Redis Caching (For Multi-Worker Rate Limiting)
In-memory caching is per-worker; in multi-worker environments (Gunicorn/Uvicorn), rate limits must be tracked centrally in Redis:
```bash
pip install redis django-redis
```
Configure `CACHES` in `config/settings.py`:
```python
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}
```

### D. Web Server & WSGI Setup (Gunicorn + Nginx)
Run Gunicorn with multiple workers:
```bash
gunicorn config.wsgi:application --workers 4 --bind 127.0.0.1:8000
```

Nginx Reverse Proxy configuration:
```nginx
server {
    listen 443 ssl http2;
    server_name soc.yourorg.com;

    ssl_certificate /etc/ssl/certs/sentinelshield.crt;
    ssl_certificate_key /etc/ssl/private/sentinelshield.key;

    location /static/ {
        alias /path/to/sentinelshield/staticfiles/;
    }

    location /media/ {
        alias /path/to/sentinelshield/media/;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
