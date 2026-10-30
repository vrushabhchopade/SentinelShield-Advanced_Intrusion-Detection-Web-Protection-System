from rest_framework import serializers
from .models import AuditLog

class AuditLogSerializer(serializers.ModelSerializer):
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id', 'log_id', 'actor', 'action', 'action_display',
            'target_object', 'timestamp', 'ip_address', 'metadata'
        ]
        read_only_fields = ['id', 'log_id', 'timestamp']
