from django.db import models
from django.conf import settings

class AttackCategory(models.TextChoices):
    NORMAL = 'NORMAL', 'Legitimate Traffic'
    SQLI = 'SQLI', 'SQL Injection (SQLi)'
    XSS = 'XSS', 'Cross-Site Scripting (XSS)'
    PATH_TRAVERSAL = 'PATH_TRAVERSAL', 'Path Traversal / LFI'
    CMD_INJECTION = 'CMD_INJECTION', 'Command Injection (CMDi)'
    MALFORMED_HEADER = 'MALFORMED_HEADER', 'Malformed / Suspicious Headers'
    RATE_LIMIT = 'RATE_LIMIT', 'Rate Limiting / Volume Flood'
    AUTH_BURST = 'AUTH_BURST', 'Authentication Brute Force'

class RuleSeverity(models.TextChoices):
    INFO = 'INFO', 'Informational'
    LOW = 'LOW', 'Low Risk'
    MEDIUM = 'MEDIUM', 'Medium Risk'
    HIGH = 'HIGH', 'High Risk'
    CRITICAL = 'CRITICAL', 'Critical Alert'

class DetectionRule(models.Model):
    rule_id = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="Canonical identifier e.g. SQLI-001, XSS-002"
    )
    name = models.CharField(max_length=255)
    category = models.CharField(
        max_length=32,
        choices=AttackCategory.choices,
        db_index=True
    )
    severity = models.CharField(
        max_length=16,
        choices=RuleSeverity.choices,
        default=RuleSeverity.MEDIUM,
        db_index=True
    )
    enabled = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Whether this rule actively participates in heuristic inspection"
    )
    description = models.TextField(blank=True)
    pattern = models.TextField(
        help_text="Safe regular expression or structured signature pattern"
    )
    target_components = models.JSONField(
        default=list,
        help_text="List of request components inspected, e.g. ['path', 'query', 'body', 'headers']"
    )
    version = models.CharField(max_length=32, default="1.0")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_rules'
    )

    class Meta:
        ordering = ['rule_id']
        verbose_name = 'Detection Rule'
        verbose_name_plural = 'Detection Rules'

    def __str__(self):
        status = "ENABLED" if self.enabled else "DISABLED"
        return f"[{self.rule_id}] {self.name} ({self.category} - {self.severity} - {status})"
