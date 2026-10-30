from django.contrib import admin
from .models import TestRun, TestCaseResult

class TestCaseResultInline(admin.TabularInline):
    model = TestCaseResult
    extra = 0
    readonly_fields = ('case_id', 'scenario_name', 'category', 'expected_classification', 'actual_classification', 'passed', 'duration_ms')

@admin.register(TestRun)
class TestRunAdmin(admin.ModelAdmin):
    list_display = ('run_id', 'suite_name', 'passed_cases', 'total_cases', 'duration_ms', 'created_at')
    inlines = [TestCaseResultInline]
    readonly_fields = ('run_id', 'created_at', 'duration_ms')
