from django.contrib import admin
from .models import PracticalReport

@admin.register(PracticalReport)
class PracticalReportAdmin(admin.ModelAdmin):
    list_display = ('report_id', 'title', 'reporting_period', 'report_format', 'created_at')
    list_filter = ('report_format', 'created_at')
    search_fields = ('report_id', 'title', 'summary')
    readonly_fields = ('report_id', 'created_at')
