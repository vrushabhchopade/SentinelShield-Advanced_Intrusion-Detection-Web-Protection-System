import uuid
from django.db import models

class RateLimitAction(models.TextChoices):
    THROTTLED = 'THROTTLED', 'HTTP 429 Too Many Requests'
    TEMPORARY_BLOCK = 'TEMPORARY_BLOCK', 'Temporary Cooldown Restriction'
    MONITORED = 'MONITORED', 'Alert Only (Monitor Policy)'

class RateLimitEvent(models.Model):
    event_id = models.CharField(
        max_length=64,
        unique=True,
        default=uuid.uuid4
    )
    source_ip = models.GenericIPAddressField(db_index=True)
    path = models.CharField(max_length=512)
    request_count = models.PositiveIntegerField()
    threshold = models.PositiveIntegerField()
    window_seconds = models.PositiveIntegerField()
    action_taken = models.CharField(
        max_length=32,
        choices=RateLimitAction.choices,
        default=RateLimitAction.THROTTLED
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    expiry_time = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Rate Limit Event'
        verbose_name_plural = 'Rate Limit Events'

    def __str__(self):
        return f"[{self.created_at:%Y-%m-%d %H:%M:%S}] {self.source_ip} - {self.request_count}/{self.threshold} reqs ({self.action_taken})"
