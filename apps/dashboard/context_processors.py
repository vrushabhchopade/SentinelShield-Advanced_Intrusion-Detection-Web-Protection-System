from django.conf import settings
from apps.alerts.models import SecurityAlert, AlertStatus
from apps.traffic.models import SecurityEvent, SecurityDecision

def sentinel_context(request):
    """
    Context processor providing active SOC operational state to all templates.
    """
    open_alerts_count = 0
    try:
        open_alerts_count = SecurityAlert.objects.filter(
            status__in=[AlertStatus.OPEN, AlertStatus.INVESTIGATING]
        ).count()
    except Exception:
        pass

    user_role = "GUEST"
    user_badge = "GUEST-00"
    user_name = "Visitor"
    if request.user and request.user.is_authenticated:
        user_name = request.user.get_full_name() or request.user.username
        user_role = getattr(request.user, 'get_role_display', lambda: 'Analyst')()
        user_badge = getattr(request.user, 'badge_number', 'SOC-7701')

    return {
        'SENTINEL_VERSION': 'v2.4',
        'SENTINEL_MODE': getattr(settings, 'SENTINEL_MODE', 'ENFORCE'),
        'OPEN_ALERTS_COUNT': open_alerts_count,
        'CURRENT_USER_NAME': user_name,
        'CURRENT_USER_ROLE': user_role,
        'CURRENT_USER_BADGE': user_badge,
        'ENGINE_STATUS': 'ACTIVE',
    }
