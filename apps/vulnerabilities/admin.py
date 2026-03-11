from django.contrib import admin
from .models import Vulnerability, VulnerabilityAIAnalysis


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'title_short', 'severity', 'status', 'agent_ip', 'discovered_at', 'due_date')
    list_filter = ('severity', 'status')
    search_fields = ('cve_id', 'title', 'agent_ip')
    ordering = ('-discovered_at',)
    date_hierarchy = 'discovered_at'

    def title_short(self, obj):
        return obj.title[:60]
    title_short.short_description = 'Title'


@admin.register(VulnerabilityAIAnalysis)
class VulnerabilityAIAnalysisAdmin(admin.ModelAdmin):
    list_display = ('vulnerability', 'risk_level', 'urgency', 'model_used', 'analyzed_at')
    list_filter = ('risk_level', 'urgency')
    search_fields = ('vulnerability__cve_id', 'vulnerability__title')
    ordering = ('-analyzed_at',)
    readonly_fields = ('analyzed_at', 'updated_at')
