from django.apps import AppConfig

class RatelimitConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.ratelimit'
    verbose_name = 'Rate Limiting & IP Activity Telemetry'
