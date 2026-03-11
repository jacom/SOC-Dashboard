from django.db import migrations


DEFAULT_POLICIES = [
    {'severity': 'CRITICAL', 'response_hours': 1.0,   'resolve_hours': 4.0},
    {'severity': 'HIGH',     'response_hours': 4.0,   'resolve_hours': 24.0},
    {'severity': 'MEDIUM',   'response_hours': 24.0,  'resolve_hours': 72.0},
    {'severity': 'LOW',      'response_hours': 72.0,  'resolve_hours': 168.0},
    {'severity': 'INFO',     'response_hours': 168.0, 'resolve_hours': 720.0},
]


def seed_policies(apps, schema_editor):
    SLAPolicy = apps.get_model('sla', 'SLAPolicy')
    for p in DEFAULT_POLICIES:
        SLAPolicy.objects.get_or_create(
            severity=p['severity'],
            defaults={
                'response_hours': p['response_hours'],
                'resolve_hours': p['resolve_hours'],
                'is_active': True,
            }
        )


def unseed_policies(apps, schema_editor):
    SLAPolicy = apps.get_model('sla', 'SLAPolicy')
    severities = [p['severity'] for p in DEFAULT_POLICIES]
    SLAPolicy.objects.filter(severity__in=severities).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('sla', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(seed_policies, reverse_code=unseed_policies),
    ]
