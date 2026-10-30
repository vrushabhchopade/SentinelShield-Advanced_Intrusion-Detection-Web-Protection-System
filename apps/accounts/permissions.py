from rest_framework import permissions
from .models import UserRole

class IsAdminUserRole(permissions.BasePermission):
    """Allows access only to administrator role users or superusers."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_admin_role)

class IsAnalystUserRole(permissions.BasePermission):
    """Allows access to analysts and administrators."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_analyst_role)

class IsViewerOrAbove(permissions.BasePermission):
    """Allows read access to all authenticated users."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)
