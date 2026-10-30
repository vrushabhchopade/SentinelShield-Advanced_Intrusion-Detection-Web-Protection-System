from django.contrib import admin
from .models import SecurityAlert

@admin.register(SecurityAlert)
class SecurityAlertAdmin(admin.ModelAdmin):
    list_display = ('alert_id', 'title', 'severity', 'status', 'category', 'source_ip', 'occurrence_count', 'last_seen')
    list_filter = ('severity', 'status', 'category')
    search_fields = ('alert_id', 'title', 'source_ip', 'analyst_notes')
    readonly_fields = ('alert_id', 'created_at', 'updated_at')
