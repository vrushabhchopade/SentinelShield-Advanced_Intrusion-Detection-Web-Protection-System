"""
URL Configuration for SentinelShield Platform.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

from apps.dashboard.views import (
    login_view,
    logout_view,
    soc_dashboard_view,
    live_inspector_view,
    attack_simulation_lab_view,
    security_event_logs_view,
    alert_management_view,
    rate_limiting_view,
    detection_rules_view,
    analytics_reports_view,
    practical_journal_view,
    system_settings_view,
    notifications_help_view,
)

urlpatterns = [
    # Admin Panel
    path('admin/', admin.site.urls),

    # Authentication
    path('auth/login/', login_view, name='auth-login'),
    path('auth/logout/', logout_view, name='auth-logout'),

    # SOC Operational Screens
    path('', RedirectView.as_view(url='/dashboard/', permanent=False)),
    path('dashboard/', soc_dashboard_view, name='soc-dashboard'),
    path('dashboard/inspector/', live_inspector_view, name='live-request-inspector'),
    path('dashboard/simulation/', attack_simulation_lab_view, name='attack-simulation-lab'),
    path('dashboard/events/', security_event_logs_view, name='security-event-logs'),
    path('dashboard/alerts/', alert_management_view, name='alert-management'),
    path('dashboard/ratelimit/', rate_limiting_view, name='rate-limiting-ip-activity'),
    path('dashboard/rules/', detection_rules_view, name='detection-rules'),
    path('dashboard/analytics/', analytics_reports_view, name='analytics-reports'),
    path('dashboard/journal/', practical_journal_view, name='practical-journal'),
    path('dashboard/settings/', system_settings_view, name='system-settings'),
    path('dashboard/help/', notifications_help_view, name='notifications-help'),

    # REST APIs
    path('api/v1/', include('config.api_urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
