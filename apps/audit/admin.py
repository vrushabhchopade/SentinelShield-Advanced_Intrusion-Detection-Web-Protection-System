from django.contrib import admin
from .models import AuditLog

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('log_id', 'timestamp', 'actor', 'action', 'target_object', 'ip_address')
    list_filter = ('action', 'timestamp')
    search_fields = ('actor', 'target_object', 'ip_address', 'metadata')
    readonly_fields = ('log_id', 'timestamp')
