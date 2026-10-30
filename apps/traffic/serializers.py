from rest_framework import serializers
from .models import SecurityEvent

class SecurityEventSerializer(serializers.ModelSerializer):
    decision_display = serializers.CharField(source='get_decision_display', read_only=True)
    category_display = serializers.CharField(source='get_category_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    reviewed_by_username = serializers.CharField(source='reviewed_by.username', read_only=True, default=None)

    class Meta:
        model = SecurityEvent
        fields = [
            'id', 'event_id', 'timestamp', 'source_ip', 'http_method',
            'sanitized_path', 'query_params', 'headers', 'body_preview',
            'decision', 'decision_display', 'category', 'category_display',
            'severity', 'severity_display', 'matched_rule_ids', 'safe_message',
            'processing_time_ms', 'environment', 'analyst_reviewed',
            'analyst_classification', 'reviewed_by_username', 'reviewed_at'
        ]
        read_only_fields = ['id', 'event_id', 'timestamp', 'processing_time_ms']
