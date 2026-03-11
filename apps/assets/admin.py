from django.contrib import admin
from .models import Asset


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ('agent_ip', 'agent_name', 'hostname', 'owner', 'department', 'asset_type', 'machine_type', 'criticality')
    list_filter = ('criticality', 'asset_type', 'machine_type')
    search_fields = ('agent_ip', 'agent_name', 'hostname', 'owner', 'department')
    ordering = ('agent_ip',)
