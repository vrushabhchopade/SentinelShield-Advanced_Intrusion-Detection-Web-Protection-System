from rest_framework import serializers
from .models import TestRun, TestCaseResult

class TestCaseResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestCaseResult
        fields = [
            'id', 'case_id', 'scenario_name', 'category', 'payload_sample',
            'target_component', 'expected_classification', 'actual_classification',
            'matched_rules', 'passed', 'duration_ms', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']

class TestRunSerializer(serializers.ModelSerializer):
    executed_by_username = serializers.CharField(source='executed_by.username', read_only=True, default=None)
    results = TestCaseResultSerializer(many=True, read_only=True)

    class Meta:
        model = TestRun
        fields = [
            'id', 'run_id', 'suite_name', 'total_cases', 'passed_cases',
            'failed_cases', 'duration_ms', 'metrics', 'executed_by_username',
            'created_at', 'results'
        ]
        read_only_fields = ['id', 'run_id', 'created_at']
