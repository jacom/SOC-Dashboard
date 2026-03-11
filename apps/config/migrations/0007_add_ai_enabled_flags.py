from django.db import migrations

NEW_CONFIGS = [
    {
        'key':         'OLLAMA_ENABLED',
        'label':       'Ollama Enabled',
        'group':       'system',
        'is_secret':   False,
        'description': 'เปิด/ปิด Ollama AI ในการวิเคราะห์ alert (true/false)',
        'value':       'true',
    },
    {
        'key':         'OPENAI_ENABLED',
        'label':       'Chat AI Enabled',
        'group':       'system',
        'is_secret':   False,
        'description': 'เปิด/ปิด Chat AI (OpenAI-compatible) ในการวิเคราะห์ alert (true/false)',
        'value':       'true',
    },
]


def add_configs(apps, schema_editor):
    IntegrationConfig = apps.get_model('config_app', 'IntegrationConfig')
    for cfg in NEW_CONFIGS:
        IntegrationConfig.objects.get_or_create(
            key=cfg['key'],
            defaults={k: v for k, v in cfg.items() if k != 'key'},
        )


def remove_configs(apps, schema_editor):
    IntegrationConfig = apps.get_model('config_app', 'IntegrationConfig')
    IntegrationConfig.objects.filter(key__in=[c['key'] for c in NEW_CONFIGS]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0006_add_notify_ai_source'),
    ]

    operations = [
        migrations.RunPython(add_configs, remove_configs),
    ]
