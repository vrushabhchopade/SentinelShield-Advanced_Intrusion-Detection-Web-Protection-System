import uuid
from django.db import models
from django.conf import settings

class TestRun(models.Model):
    run_id = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        default=uuid.uuid4
    )
    suite_name = models.CharField(max_length=255)
    total_cases = models.PositiveIntegerField(default=0)
    passed_cases = models.PositiveIntegerField(default=0)
    failed_cases = models.PositiveIntegerField(default=0)
    duration_ms = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    executed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='executed_test_runs'
    )
    metrics = models.JSONField(
        default=dict,
        help_text="Precision, recall, accuracy, TP, TN, FP, FN"
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Test Run'
        verbose_name_plural = 'Test Runs'

    def __str__(self):
        return f"[{self.run_id}] {self.suite_name} - {self.passed_cases}/{self.total_cases} Passed"


class TestCaseResult(models.Model):
    test_run = models.ForeignKey(
        TestRun,
        on_delete=models.CASCADE,
        related_name='results'
    )
    case_id = models.CharField(max_length=64)
    scenario_name = models.CharField(max_length=255)
    category = models.CharField(max_length=64)
    payload_sample = models.TextField(blank=True)
    target_component = models.CharField(max_length=64, default="query")
    expected_classification = models.CharField(max_length=32)  # 'BLOCKED', 'ALLOWED', etc.
    actual_classification = models.CharField(max_length=32)
    matched_rules = models.JSONField(default=list, blank=True)
    passed = models.BooleanField(default=False, db_index=True)
    duration_ms = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['id']
        verbose_name = 'Test Case Result'
        verbose_name_plural = 'Test Case Results'

    def __str__(self):
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] {self.case_id}: {self.scenario_name} (Exp: {self.expected_classification}, Got: {self.actual_classification})"
