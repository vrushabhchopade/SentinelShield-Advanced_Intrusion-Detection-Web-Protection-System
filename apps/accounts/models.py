from django.contrib.auth.models import AbstractUser
from django.db import models

class UserRole(models.TextChoices):
    ADMIN = 'ADMIN', 'Security Administrator'
    ANALYST = 'ANALYST', 'SOC Threat Analyst'
    VIEWER = 'VIEWER', 'Academic / Read-Only Viewer'

class User(AbstractUser):
    role = models.CharField(
        max_length=20,
        choices=UserRole.choices,
        default=UserRole.ANALYST,
        db_index=True,
        help_text="Role determining SOC operational permissions"
    )
    department = models.CharField(
        max_length=100,
        default="Cybersecurity Operations",
        blank=True
    )
    badge_number = models.CharField(
        max_length=32,
        blank=True,
        default="SOC-7701"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def is_admin_role(self):
        return self.role == UserRole.ADMIN or self.is_superuser

    @property
    def is_analyst_role(self):
        return self.role in (UserRole.ADMIN, UserRole.ANALYST) or self.is_staff or self.is_superuser

    @property
    def is_viewer_role(self):
        return True

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
