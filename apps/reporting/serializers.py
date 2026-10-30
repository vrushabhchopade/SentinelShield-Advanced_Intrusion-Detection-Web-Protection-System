from rest_framework import serializers
from .models import PracticalReport

class PracticalReportSerializer(serializers.ModelSerializer):
    generated_by_username = serializers.CharField(source='generated_by.username', read_only=True, default=None)

    class Meta:
        model = PracticalReport
        fields = [
            'id', 'report_id', 'title', 'reporting_period', 'summary',
            'metrics', 'methodology', 'findings', 'recommendations',
            'file_path', 'report_format', 'generated_by_username', 'created_at'
        ]
        read_only_fields = ['id', 'report_id', 'created_at', 'file_path']
