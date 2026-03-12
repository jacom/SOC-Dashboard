from django.contrib import admin
from .models import MISApiKey


@admin.register(MISApiKey)
class MISApiKeyAdmin(admin.ModelAdmin):
    list_display  = ('name', 'masked_key', 'is_active', 'created_at', 'last_used_at')
    list_filter   = ('is_active',)
    readonly_fields = ('key', 'created_at', 'last_used_at')
    fields        = ('name', 'is_active', 'key', 'created_at', 'last_used_at')

    def has_change_permission(self, request, obj=None):
        # อนุญาตแค่เปลี่ยน name และ is_active เท่านั้น
        return True

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if not change:
            # แสดง key เต็มครั้งเดียวหลังสร้าง
            self.message_user(
                request,
                f'API Key สำหรับ "{obj.name}": {obj.key}  ← บันทึกไว้ จะไม่แสดงอีก',
                level='WARNING',
            )
