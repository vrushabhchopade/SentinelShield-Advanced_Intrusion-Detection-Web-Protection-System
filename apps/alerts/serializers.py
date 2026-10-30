from rest_framework import serializers
from .models import SecurityAlert
from apps.traffic.serializers import SecurityEventSerializer

class SecurityAlertSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    category_display = serializers.CharField(source='get_category_display', read_only=True)
    assigned_analyst_username = serializers.CharField(source='assigned_analyst.username', read_only=True, default=None)
    events_count = serializers.IntegerField(source='events.count', read_only=True)

    class Meta:
        model = SecurityAlert
        fields = [
            'id', 'alert_id', 'title', 'severity', 'severity_display',
            'status', 'status_display', 'category', 'category_display',
            'source_ip', 'occurrence_count', 'first_seen', 'last_seen',
            'assigned_analyst', 'assigned_analyst_username', 'analyst_notes',
            'events_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'alert_id', 'first_seen', 'created_at', 'updated_at']

class SecurityAlertDetailSerializer(SecurityAlertSerializer):
    events = SecurityEventSerializer(many=True, read_only=True)

    class Meta(SecurityAlertSerializer.Meta):
        fields = SecurityAlertSerializer.Meta.fields + ['events']
