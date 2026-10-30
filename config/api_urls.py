"""
API URL Routing for SentinelShield (/api/v1/).
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.dashboard.api_views import (
    DashboardSummaryAPIView,
    DashboardTrafficAPIView,
    SecurityEventViewSet,
    SecurityAlertViewSet,
    DetectionRuleViewSet,
    RateLimitViewSet,
    AnalyticsAPIView,
    PracticalReportViewSet,
    TestRunViewSet,
    SimulationInspectAPIView,
    SystemHealthAPIView,
    SystemResetDemoAPIView,
    AuditLogViewSet,
)

router = DefaultRouter()
router.register('events', SecurityEventViewSet, basename='events')
router.register('alerts', SecurityAlertViewSet, basename='alerts')
router.register('rules', DetectionRuleViewSet, basename='rules')
router.register('rate-limits', RateLimitViewSet, basename='rate-limits')
router.register('reports', PracticalReportViewSet, basename='reports')
router.register('test-runs', TestRunViewSet, basename='test-runs')
router.register('system/audit', AuditLogViewSet, basename='audit')

urlpatterns = [
    path('dashboard/summary/', DashboardSummaryAPIView.as_view(), name='api-dashboard-summary'),
    path('dashboard/traffic/', DashboardTrafficAPIView.as_view(), name='api-dashboard-traffic'),
    path('analytics/', AnalyticsAPIView.as_view(), name='api-analytics'),
    path('simulation/inspect/', SimulationInspectAPIView.as_view(), name='api-simulation-inspect'),
    path('system/health/', SystemHealthAPIView.as_view(), name='api-system-health'),
    path('system/reset-demo-data/', SystemResetDemoAPIView.as_view(), name='api-reset-demo-data'),
    path('', include(router.urls)),
]
