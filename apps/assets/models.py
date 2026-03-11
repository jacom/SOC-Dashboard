from django.db import models


class Asset(models.Model):
    CRITICALITY = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    ASSET_TYPE = [
        ('server', 'Server'),
        ('workstation', 'Workstation'),
        ('network', 'Network Device'),
        ('other', 'Other'),
    ]
    MACHINE_TYPE = [
        ('physical', 'Physical'),
        ('vm', 'Virtual Machine (VM)'),
    ]

    agent_ip     = models.GenericIPAddressField(unique=True, help_text='IP ที่ใช้ใน Wazuh agent')
    agent_name   = models.CharField(max_length=200, blank=True, help_text='ชื่อ agent ใน Wazuh')
    hostname     = models.CharField(max_length=200, blank=True, help_text='Hostname จริงของเครื่อง')
    owner        = models.CharField(max_length=200, blank=True, help_text='ผู้ดูแล/เจ้าของเครื่อง')
    owner_email  = models.EmailField(blank=True, help_text='อีเมลเจ้าของ/ผู้ดูแล สำหรับรับแจ้งเตือน')
    department   = models.CharField(max_length=200, blank=True, help_text='แผนก / หน่วยงาน')
    asset_type   = models.CharField(max_length=20, choices=ASSET_TYPE, default='workstation')
    machine_type = models.CharField(max_length=10, choices=MACHINE_TYPE, default='physical')
    criticality  = models.CharField(max_length=10, choices=CRITICALITY, default='MEDIUM')
    location     = models.CharField(max_length=200, blank=True, help_text='ห้อง / อาคาร / ชั้น')
    image        = models.ImageField(upload_to='assets/', null=True, blank=True, help_text='รูปภาพ server/เครื่อง')
    notes        = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['agent_ip']

    def __str__(self):
        return f'{self.agent_ip} ({self.agent_name or self.hostname or "unknown"})'

    def criticality_color(self):
        return {
            'CRITICAL': 'danger',
            'HIGH': 'warning',
            'MEDIUM': 'info',
            'LOW': 'secondary',
        }.get(self.criticality, 'secondary')
