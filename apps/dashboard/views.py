"""
Django UI Views for SentinelShield SOC Platform (12 Screens).
"""

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count, Avg
from django.conf import settings
from django.utils import timezone

from apps.traffic.models import SecurityEvent, SecurityDecision
from apps.alerts.models import SecurityAlert, AlertStatus
from apps.detections.models import DetectionRule, AttackCategory, RuleSeverity
from apps.ratelimit.models import RateLimitEvent
from apps.simulation.models import TestRun
from apps.reporting.models import PracticalReport
from apps.audit.models import AuditLog, AuditAction
from apps.audit.utils import record_audit

def login_view(request):
    if request.user.is_authenticated:
        return redirect('soc-dashboard')

    if request.method == 'POST':
        u = request.POST.get('username', '').strip()
        p = request.POST.get('password', '').strip()
        user = authenticate(request, username=u, password=p)
        if user is not None:
            login(request, user)
            record_audit(user, AuditAction.AUTH_LOGIN, f"User:{user.username}", ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'))
            next_url = request.GET.get('next', 'soc-dashboard')
            return redirect(next_url)
        else:
            messages.error(request, 'Invalid credentials. Please verify your badge/username and password.')

    return render(request, 'auth/login.html')


def logout_view(request):
    if request.user.is_authenticated:
        record_audit(request.user, AuditAction.AUTH_LOGOUT, f"User:{request.user.username}", ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'))
        logout(request)
    return redirect('auth-login')


def soc_dashboard_view(request):
    total_events = SecurityEvent.objects.count()
    malicious_count = SecurityEvent.objects.filter(decision__in=[SecurityDecision.BLOCKED, SecurityDecision.FLAGGED]).count()
    blocked_count = SecurityEvent.objects.filter(decision=SecurityDecision.BLOCKED).count()
    allowed_count = SecurityEvent.objects.filter(decision=SecurityDecision.ALLOWED).count()
    rate_limited_count = SecurityEvent.objects.filter(decision=SecurityDecision.RATE_LIMITED).count()

    recent_events = SecurityEvent.objects.all().order_by('-timestamp')[:10]
    active_alerts = SecurityAlert.objects.filter(status__in=[AlertStatus.OPEN, AlertStatus.INVESTIGATING]).order_by('-last_seen')[:5]

    safe_ratio = round((allowed_count / total_events * 100.0), 1) if total_events > 0 else 100.0
    mitigation_rate = round((blocked_count / malicious_count * 100.0), 1) if malicious_count > 0 else 100.0

    context = {
        'page_title': 'SOC Operations Dashboard',
        'active_nav': 'soc-dashboard',
        'total_events': total_events,
        'malicious_count': malicious_count,
        'blocked_count': blocked_count,
        'allowed_count': allowed_count,
        'rate_limited_count': rate_limited_count,
        'safe_ratio': safe_ratio,
        'mitigation_rate': mitigation_rate,
        'recent_events': recent_events,
        'active_alerts': active_alerts,
    }
    return render(request, 'dashboard/soc_dashboard.html', context)


def live_inspector_view(request):
    context = {
        'page_title': 'Live Request Inspector',
        'active_nav': 'live-request-inspector',
    }
    return render(request, 'dashboard/live_request_inspector.html', context)


def attack_simulation_lab_view(request):
    test_runs = TestRun.objects.all().order_by('-created_at')[:5]
    latest_run = test_runs.first() if test_runs.exists() else None
    context = {
        'page_title': 'Attack Simulation Lab',
        'active_nav': 'attack-simulation-lab',
        'test_runs': test_runs,
        'latest_run': latest_run,
    }
    return render(request, 'dashboard/attack_simulation_lab.html', context)


def security_event_logs_view(request):
    events = SecurityEvent.objects.all().order_by('-timestamp')[:50]
    context = {
        'page_title': 'Security Event Logs',
        'active_nav': 'security-event-logs',
        'events': events,
        'categories': AttackCategory.choices,
        'decisions': SecurityDecision.choices,
        'severities': RuleSeverity.choices,
    }
    return render(request, 'dashboard/security_event_logs.html', context)


def alert_management_view(request):
    alerts = SecurityAlert.objects.all().order_by('-last_seen')
    context = {
        'page_title': 'Alert Management & Triage',
        'active_nav': 'alert-management',
        'alerts': alerts,
        'statuses': AlertStatus.choices,
    }
    return render(request, 'dashboard/alert_management.html', context)


def rate_limiting_view(request):
    rate_events = RateLimitEvent.objects.all().order_by('-created_at')[:30]
    context = {
        'page_title': 'Rate Limiting & IP Activity',
        'active_nav': 'rate-limiting-ip-activity',
        'rate_events': rate_events,
        'threshold': getattr(settings, 'SENTINEL_RATE_LIMIT_THRESHOLD', 60),
        'window_secs': getattr(settings, 'SENTINEL_RATE_LIMIT_WINDOW_SECS', 60),
        'block_secs': getattr(settings, 'SENTINEL_RATE_LIMIT_BLOCK_SECS', 300),
    }
    return render(request, 'dashboard/rate_limiting.html', context)


def detection_rules_view(request):
    rules = DetectionRule.objects.all().order_by('rule_id')
    context = {
        'page_title': 'Detection Rule Management',
        'active_nav': 'detection-rules',
        'rules': rules,
        'categories': AttackCategory.choices,
        'severities': RuleSeverity.choices,
    }
    return render(request, 'dashboard/detection_rules.html', context)


def analytics_reports_view(request):
    reports = PracticalReport.objects.all().order_by('-created_at')[:10]
    context = {
        'page_title': 'Analytics & Reports',
        'active_nav': 'analytics-reports',
        'reports': reports,
    }
    return render(request, 'dashboard/analytics_reports.html', context)


def practical_journal_view(request):
    latest_run = TestRun.objects.order_by('-created_at').first()
    context = {
        'page_title': 'Practical Journal & Academic Submission',
        'active_nav': 'practical-journal',
        'latest_run': latest_run,
    }
    return render(request, 'dashboard/practical_journal.html', context)


def system_settings_view(request):
    if request.method == 'POST':
        new_mode = request.POST.get('sentinel_mode', 'ENFORCE').upper()
        if new_mode in ('MONITOR', 'FLAG', 'ENFORCE'):
            settings.SENTINEL_MODE = new_mode
            record_audit(
                request.user if request.user.is_authenticated else None,
                AuditAction.POLICY_CHANGED,
                "Settings:SENTINEL_MODE",
                metadata={'new_mode': new_mode}
            )
            messages.success(request, f'Security engine mode updated to: {new_mode}')

    audit_logs = AuditLog.objects.all().order_by('-timestamp')[:15]
    context = {
        'page_title': 'System Settings',
        'active_nav': 'system-settings',
        'sentinel_mode': getattr(settings, 'SENTINEL_MODE', 'ENFORCE'),
        'audit_logs': audit_logs,
    }
    return render(request, 'dashboard/system_settings.html', context)


def notifications_help_view(request):
    context = {
        'page_title': 'Notifications & Help Center',
        'active_nav': 'notifications-help',
    }
    return render(request, 'dashboard/notifications_help.html', context)
