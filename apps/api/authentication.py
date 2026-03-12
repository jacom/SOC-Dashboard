from django.utils import timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import MISApiKey


class MISApiKeyAuthentication(BaseAuthentication):
    """
    ตรวจสอบ API Key จาก header: X-API-Key: <key>
    """

    def authenticate(self, request):
        key = request.headers.get('X-Api-Key') or request.GET.get('api_key')
        if not key:
            return None  # ไม่มี key → ให้ permission class จัดการเอง

        try:
            api_key = MISApiKey.objects.get(key=key, is_active=True)
        except MISApiKey.DoesNotExist:
            raise AuthenticationFailed('Invalid or inactive API key')

        # อัปเดต last_used_at
        MISApiKey.objects.filter(pk=api_key.pk).update(last_used_at=timezone.now())

        # คืน (user=None, auth=api_key) — ไม่ผูกกับ Django user
        return (None, api_key)

    def authenticate_header(self, request):
        return 'X-Api-Key'
