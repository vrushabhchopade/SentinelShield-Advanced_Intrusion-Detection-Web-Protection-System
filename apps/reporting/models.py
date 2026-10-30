import uuid
from django.db import models
from django.conf import settings

class ReportFormat(models.TextChoices):
    PDF = 'PDF', 'Formatted PDF Document'
    CSV = 'CSV', 'Comma-Separated Telemetry'
    JSON = 'JSON', 'Structured JSON Archive'

class PracticalReport(models.Model):
    report_id = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        default=uuid.uuid4
    )
    title = models.CharField(max_length=255)
    reporting_period = models.CharField(max_length=100, default="Last 24 Hours")
    summary = models.TextField(blank=True)
    metrics = models.JSONField(default=dict, blank=True)
    methodology = models.TextField(blank=True)
    findings = models.TextField(blank=True)
    recommendations = models.TextField(blank=True)
    file_path = models.CharField(max_length=512, blank=True)
    report_format = models.CharField(
        max_length=16,
        choices=ReportFormat.choices,
        default=ReportFormat.PDF
    )
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='generated_reports'
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Practical Report'
        verbose_name_plural = 'Practical Reports'

    def __str__(self):
        return f"[{self.report_id}] {self.title} ({self.report_format} - {self.created_at:%Y-%m-%d})"
