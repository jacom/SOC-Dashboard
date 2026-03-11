from django.db import models
from django.contrib.auth.models import User


class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('mitigated', 'Mitigated'),
        ('resolved', 'Resolved'),
        ('accepted', 'Risk Accepted'),
    ]

    title         = models.CharField(max_length=500)
    cve_id        = models.CharField(max_length=30, blank=True, help_text='CVE-YYYY-XXXXX')
    asset         = models.ForeignKey(
        'assets.Asset',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='vulnerabilities',
    )
    agent_ip      = models.GenericIPAddressField(null=True, blank=True)
    severity      = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='MEDIUM')
    status        = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    description   = models.TextField(blank=True)
    remediation   = models.TextField(blank=True)
    discovered_at = models.DateField()
    due_date      = models.DateField(null=True, blank=True)
    resolved_at   = models.DateField(null=True, blank=True)
    created_by    = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True, blank=True,
    )
    created_at    = models.DateTimeField(auto_now_add=True)
    updated_at    = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-discovered_at', '-created_at']
        app_label = 'vulnerabilities'

    def __str__(self):
        return f'[{self.severity}] {self.title[:60]}'

    @property
    def severity_color(self):
        return {
            'CRITICAL': 'danger',
            'HIGH': 'warning',
            'MEDIUM': 'info',
            'LOW': 'secondary',
        }.get(self.severity, 'secondary')

    @property
    def status_color(self):
        return {
            'open': 'danger',
            'in_progress': 'warning',
            'mitigated': 'info',
            'resolved': 'success',
            'accepted': 'secondary',
        }.get(self.status, 'secondary')

    @property
    def is_overdue(self):
        if self.due_date and self.status not in ('resolved', 'accepted'):
            from django.utils import timezone
            return timezone.localdate() > self.due_date
        return False


class VulnerabilityAIAnalysis(models.Model):
    vulnerability  = models.OneToOneField(
        Vulnerability, on_delete=models.CASCADE, related_name='ai_analysis'
    )
    risk_level     = models.CharField(max_length=20, blank=True)
    exploitability = models.TextField(blank=True)
    urgency        = models.CharField(max_length=20, blank=True)
    urgency_reason = models.TextField(blank=True)
    impact         = models.TextField(blank=True)
    remediation    = models.TextField(blank=True)
    remediation_th = models.TextField(blank=True)
    summary_th     = models.TextField(blank=True)
    model_used     = models.CharField(max_length=100, blank=True)
    analyzed_at    = models.DateTimeField(auto_now_add=True)
    updated_at     = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'vulnerabilities'

    def __str__(self):
        return f'AI Analysis for [{self.vulnerability.cve_id}] {self.vulnerability.title[:40]}'
