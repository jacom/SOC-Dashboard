import secrets
from django.db import models


class MISApiKey(models.Model):
    name        = models.CharField(max_length=100, help_text='ชื่อ client เช่น MIS Dashboard')
    key         = models.CharField(max_length=64, unique=True, editable=False)
    is_active   = models.BooleanField(default=True)
    created_at  = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = 'MIS API Key'
        verbose_name_plural = 'MIS API Keys'

    def __str__(self):
        status = 'Active' if self.is_active else 'Inactive'
        return f'{self.name} [{status}]'

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = secrets.token_hex(32)  # 64-char hex
        super().save(*args, **kwargs)

    @property
    def masked_key(self):
        return f'{self.key[:8]}...{self.key[-4:]}'
