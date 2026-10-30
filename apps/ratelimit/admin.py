from django.contrib import admin
from .models import RateLimitEvent

@admin.register(RateLimitEvent)
class RateLimitEventAdmin(admin.ModelAdmin):
    list_display = ('event_id', 'source_ip', 'path', 'request_count', 'threshold', 'action_taken', 'created_at', 'expiry_time')
    list_filter = ('action_taken', 'created_at')
    search_fields = ('source_ip', 'path')
    readonly_fields = ('event_id', 'created_at')
