from django.db import migrations

SMTP_CONFIGS = [
    {'key': 'SMTP_HOST',     'label': 'SMTP Host',       'group': 'email', 'is_secret': False, 'description': 'e.g. smtp.gmail.com', 'value': ''},
    {'key': 'SMTP_PORT',     'label': 'SMTP Port',       'group': 'email', 'is_secret': False, 'description': '587 (TLS) or 465 (SSL)', 'value': '587'},
    {'key': 'SMTP_USER',     'label': 'SMTP Username',   'group': 'email', 'is_secret': False, 'description': 'Email sender username', 'value': ''},
    {'key': 'SMTP_PASSWORD', 'label': 'SMTP Password',   'group': 'email', 'is_secret': True,  'description': 'Email sender password or app password', 'value': ''},
    {'key': 'SMTP_FROM',     'label': 'From Address',    'group': 'email', 'is_secret': False, 'description': 'e.g. soc-alert@example.com', 'value': ''},
    {'key': 'SMTP_TLS',      'label': 'Use TLS',         'group': 'email', 'is_secret': False, 'description': 'true / false', 'value': 'true'},
]


def add_smtp(apps, schema_editor):
    IntegrationConfig = apps.get_model('config_app', 'IntegrationConfig')
    for cfg in SMTP_CONFIGS:
        IntegrationConfig.objects.get_or_create(
            key=cfg['key'],
            defaults={k: v for k, v in cfg.items() if k != 'key'},
        )


def remove_smtp(apps, schema_editor):
    IntegrationConfig = apps.get_model('config_app', 'IntegrationConfig')
    IntegrationConfig.objects.filter(key__in=[c['key'] for c in SMTP_CONFIGS]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0009_add_threat_intel_keys'),
    ]
    operations = [
        migrations.RunPython(add_smtp, remove_smtp),
    ]
