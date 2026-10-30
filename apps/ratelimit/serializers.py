from rest_framework import serializers
from .models import RateLimitEvent

class RateLimitEventSerializer(serializers.ModelSerializer):
    action_taken_display = serializers.CharField(source='get_action_taken_display', read_only=True)

    class Meta:
        model = RateLimitEvent
        fields = [
            'id', 'event_id', 'source_ip', 'path', 'request_count',
            'threshold', 'window_seconds', 'action_taken', 'action_taken_display',
            'created_at', 'expiry_time'
        ]
        read_only_fields = ['id', 'event_id', 'created_at']
