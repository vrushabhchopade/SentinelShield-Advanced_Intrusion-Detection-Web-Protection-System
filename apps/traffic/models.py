import uuid
from django.db import models
from django.conf import settings
from apps.detections.models import AttackCategory, RuleSeverity

class SecurityDecision(models.TextChoices):
    ALLOWED = 'ALLOWED', 'Allowed (Clean/Policy)'
    FLAGGED = 'FLAGGED', 'Flagged (Monitor Mode)'
    BLOCKED = 'BLOCKED', 'Blocked (Enforcement Active)'
    RATE_LIMITED = 'RATE_LIMITED', 'Rate Limited (HTTP 429)'

class TrafficEnvironment(models.TextChoices):
    REAL = 'REAL', 'Live Production / Localhost'
    SIMULATION = 'SIMULATION', 'SOC Simulator'
    LAB = 'LAB', 'Safe Testing Lab'

class AnalystClassification(models.TextChoices):
    TRUE_POSITIVE = 'TRUE_POSITIVE', 'True Positive (Actual Threat)'
    FALSE_POSITIVE = 'FALSE_POSITIVE', 'False Positive (Benign Traffic)'
    UNDETERMINED = 'UNDETERMINED', 'Undetermined / In Triage'

class SecurityEvent(models.Model):
    event_id = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        default=uuid.uuid4
    )
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    source_ip = models.GenericIPAddressField(db_index=True)
    http_method = models.CharField(max_length=12, default="GET")
    sanitized_path = models.CharField(max_length=1024, db_index=True)
    query_params = models.JSONField(default=dict, blank=True)
    headers = models.JSONField(default=dict, blank=True)
    body_preview = models.CharField(max_length=512, blank=True)
    decision = models.CharField(
        max_length=20,
        choices=SecurityDecision.choices,
        default=SecurityDecision.ALLOWED,
        db_index=True
    )
    category = models.CharField(
        max_length=32,
        choices=AttackCategory.choices,
        default=AttackCategory.NORMAL,
        db_index=True
    )
    severity = models.CharField(
        max_length=16,
        choices=RuleSeverity.choices,
        default=RuleSeverity.INFO,
        db_index=True
    )
    matched_rule_ids = models.JSONField(default=list, blank=True)
    safe_message = models.TextField(blank=True)
    processing_time_ms = models.FloatField(default=0.0)
    environment = models.CharField(
        max_length=20,
        choices=TrafficEnvironment.choices,
        default=TrafficEnvironment.REAL,
        db_index=True
    )
    analyst_reviewed = models.BooleanField(default=False, db_index=True)
    analyst_classification = models.CharField(
        max_length=32,
        choices=AnalystClassification.choices,
        blank=True,
        null=True
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_events'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'decision']),
            models.Index(fields=['category', 'severity']),
            models.Index(fields=['source_ip', 'timestamp']),
        ]
        verbose_name = 'Security Event'
        verbose_name_plural = 'Security Events'

    def __str__(self):
        return f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] {self.decision} {self.source_ip} {self.http_method} {self.sanitized_path} ({self.category})"
