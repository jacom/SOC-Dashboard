from django.contrib import admin
from .models import SLAPolicy


@admin.register(SLAPolicy)
class SLAPolicyAdmin(admin.ModelAdmin):
    list_display = ('severity', 'response_hours', 'resolve_hours', 'is_active', 'updated_at')
    list_filter = ('is_active', 'severity')
    ordering = ('severity',)
