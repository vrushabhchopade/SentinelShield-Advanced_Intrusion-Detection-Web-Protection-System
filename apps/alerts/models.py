import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from apps.detections.models import AttackCategory, RuleSeverity
from apps.traffic.models import SecurityEvent

class AlertStatus(models.TextChoices):
    OPEN = 'OPEN', 'Open (New / Unassigned)'
    INVESTIGATING = 'INVESTIGATING', 'Under Investigation'
    ACKNOWLEDGED = 'ACKNOWLEDGED', 'Acknowledged by Analyst'
    RESOLVED = 'RESOLVED', 'Resolved / Remediated'
    FALSE_POSITIVE = 'FALSE_POSITIVE', 'Closed as False Positive'

class SecurityAlert(models.Model):
    alert_id = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        default=uuid.uuid4
    )
    title = models.CharField(max_length=255)
    severity = models.CharField(
        max_length=16,
        choices=RuleSeverity.choices,
        default=RuleSeverity.HIGH,
        db_index=True
    )
    status = models.CharField(
        max_length=20,
        choices=AlertStatus.choices,
        default=AlertStatus.OPEN,
        db_index=True
    )
    category = models.CharField(
        max_length=32,
        choices=AttackCategory.choices,
        default=AttackCategory.NORMAL,
        db_index=True
    )
    source_ip = models.GenericIPAddressField(db_index=True)
    occurrence_count = models.PositiveIntegerField(default=1)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now, db_index=True)
    assigned_analyst = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_alerts'
    )
    analyst_notes = models.TextField(blank=True)
    events = models.ManyToManyField(
        SecurityEvent,
        blank=True,
        related_name='alerts'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-last_seen']
        verbose_name = 'Security Alert'
        verbose_name_plural = 'Security Alerts'

    def __str__(self):
        return f"[{self.alert_id}] {self.title} - {self.severity} ({self.status})"
