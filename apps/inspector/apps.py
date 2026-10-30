from django.apps import AppConfig

class InspectorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.inspector'
    verbose_name = 'HTTP Request Inspector & Enforcement Pipeline'
