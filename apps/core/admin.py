from django.contrib import admin
from .models import UserProfile, AuditLog


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'department', 'phone', 'created_at')
    list_filter = ('role',)
    search_fields = ('user__username', 'user__email', 'department')
    ordering = ('user__username',)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'user', 'action', 'target_type', 'target_id', 'ip_address')
    list_filter = ('action', 'target_type')
    search_fields = ('user__username', 'detail', 'target_id')
    ordering = ('-timestamp',)
    readonly_fields = ('timestamp', 'user', 'action', 'target_type', 'target_id', 'detail', 'ip_address')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
