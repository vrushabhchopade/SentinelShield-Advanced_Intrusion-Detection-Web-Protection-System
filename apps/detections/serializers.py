from rest_framework import serializers
from .models import DetectionRule

class DetectionRuleSerializer(serializers.ModelSerializer):
    category_display = serializers.CharField(source='get_category_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)

    class Meta:
        model = DetectionRule
        fields = [
            'id', 'rule_id', 'name', 'category', 'category_display',
            'severity', 'severity_display', 'enabled', 'description',
            'pattern', 'target_components', 'version', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
