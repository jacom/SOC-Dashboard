import uuid
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('admin',   'Administrator'),
        ('analyst', 'Analyst'),
        ('viewer',  'Viewer'),
    ]
    user       = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role       = models.CharField(max_length=10, choices=ROLE_CHOICES, default='analyst')
    department = models.CharField(max_length=200, blank=True)
    phone      = models.CharField(max_length=50, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'core'

    def __str__(self):
        return f'{self.user.username} ({self.role})'

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_analyst(self):
        return self.role in ('admin', 'analyst')


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)


class AuditLog(models.Model):
    ACTION_CHOICES = [
        # Alert
        ('alert_dismiss',    'Alert: Dismiss'),
        ('alert_undismiss',  'Alert: Undismiss'),
        ('alert_ai',         'Alert: AI Analysis'),
        # Incident
        ('incident_create',  'Incident: Create'),
        ('incident_edit',    'Incident: Edit'),
        ('incident_status',  'Incident: Status Change'),
        ('incident_delete',  'Incident: Delete'),
        # Vulnerability
        ('vuln_add',         'Vulnerability: Add'),
        ('vuln_edit',        'Vulnerability: Edit'),
        ('vuln_delete',      'Vulnerability: Delete'),
        ('vuln_ai',          'Vulnerability: AI Analysis'),
        # User
        ('user_add',         'User: Add'),
        ('user_edit',        'User: Edit'),
        ('user_delete',      'User: Delete'),
        ('user_toggle',      'User: Toggle Active'),
        # Auth
        ('login',            'Login'),
        ('logout',           'Logout'),
        # Other
        ('other',            'Other'),
    ]

    user       = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    action     = models.CharField(max_length=30, choices=ACTION_CHOICES)
    target_type = models.CharField(max_length=50, blank=True)   # e.g. 'Alert', 'Incident'
    target_id  = models.CharField(max_length=50, blank=True)    # pk of affected object
    detail     = models.TextField(blank=True)                   # human-readable summary
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp  = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'core'
        ordering = ['-timestamp']

    def __str__(self):
        return f'[{self.timestamp:%Y-%m-%d %H:%M}] {self.user} — {self.action}'


class LicenseInfo(models.Model):
    """Singleton — always pk=1. Stores instance identity and active license key."""
    PLAN_CHOICES = [
        ('TRIAL', 'Trial (30 days)'),
        ('PRO',   'Professional'),
        ('ENT',   'Enterprise'),
    ]
    STATUS_CHOICES = [
        ('valid',   'Valid'),
        ('expired', 'Expired'),
        ('invalid', 'Invalid'),
        ('none',    'No License'),
    ]

    instance_id  = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    license_key  = models.CharField(max_length=60, blank=True)
    plan         = models.CharField(max_length=10, choices=PLAN_CHOICES, blank=True)
    status       = models.CharField(max_length=10, choices=STATUS_CHOICES, default='none')
    expires_at   = models.DateField(null=True, blank=True)
    activated_at = models.DateTimeField(null=True, blank=True)
    installed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'core'
        verbose_name = 'License Info'

    def __str__(self):
        return f'License [{self.status}] {self.plan} expires {self.expires_at}'

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj
