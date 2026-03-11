from django.db import models


class SLAPolicy(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
        ('INFO', 'Info'),
    ]
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, unique=True)
    response_hours = models.FloatField(help_text='ชั่วโมงที่ต้องตอบสนอง (dismiss หรือ escalate)')
    resolve_hours = models.FloatField(help_text='ชั่วโมงที่ต้องแก้ไข (incident resolved)')
    is_active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['severity']
        app_label = 'sla'
        verbose_name = 'SLA Policy'
        verbose_name_plural = 'SLA Policies'

    def __str__(self):
        return f'{self.severity}: respond {self.response_hours}h / resolve {self.resolve_hours}h'
