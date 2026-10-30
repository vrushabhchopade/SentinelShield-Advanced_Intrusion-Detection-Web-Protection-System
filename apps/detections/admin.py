from django.contrib import admin
from .models import DetectionRule

@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ('rule_id', 'name', 'category', 'severity', 'enabled', 'version', 'updated_at')
    list_filter = ('category', 'severity', 'enabled')
    search_fields = ('rule_id', 'name', 'description', 'pattern')
    list_editable = ('enabled',)
