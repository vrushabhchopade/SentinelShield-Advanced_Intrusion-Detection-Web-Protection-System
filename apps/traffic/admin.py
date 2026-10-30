from django.contrib import admin
from .models import SecurityEvent

@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ('event_id', 'timestamp', 'source_ip', 'http_method', 'sanitized_path', 'decision', 'category', 'severity')
    list_filter = ('decision', 'category', 'severity', 'environment', 'analyst_reviewed')
    search_fields = ('event_id', 'source_ip', 'sanitized_path', 'safe_message')
    readonly_fields = ('event_id', 'timestamp', 'processing_time_ms')
