from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    role_display = serializers.CharField(source='get_role_display', read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'role', 'role_display', 'department', 'badge_number',
            'is_staff', 'is_superuser', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
