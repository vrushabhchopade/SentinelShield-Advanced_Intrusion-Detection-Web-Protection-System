import uuid
from django.db import models

class AuditAction(models.TextChoices):
    RULE_CREATED = 'RULE_CREATED', 'Detection Rule Created'
    RULE_UPDATED = 'RULE_UPDATED', 'Detection Rule Updated'
    RULE_TOGGLED = 'RULE_TOGGLED', 'Detection Rule Toggled'
    RULE_DELETED = 'RULE_DELETED', 'Detection Rule Deleted'
    POLICY_CHANGED = 'POLICY_CHANGED', 'Security Policy Configuration Changed'
    ALERT_UPDATED = 'ALERT_UPDATED', 'Security Alert Status / Note Updated'
    TEST_RUN = 'TEST_RUN', 'Attack Simulation Run Executed'
    DATA_RESET = 'DATA_RESET', 'Disposable Development Data Reset'
    AUTH_LOGIN = 'AUTH_LOGIN', 'User Session Login'
    AUTH_LOGOUT = 'AUTH_LOGOUT', 'User Session Logout'

class AuditLog(models.Model):
    log_id = models.CharField(
        max_length=64,
        unique=True,
        default=uuid.uuid4
    )
    actor = models.CharField(
        max_length=150,
        default="SYSTEM",
        help_text="Username of operator or 'SYSTEM'"
    )
    action = models.CharField(
        max_length=64,
        choices=AuditAction.choices,
        db_index=True
    )
    target_object = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    ip_address = models.CharField(max_length=45, blank=True, default="127.0.0.1")
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'

    def __str__(self):
        return f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] {self.actor} performed {self.action} on {self.target_object}"
