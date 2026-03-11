from django.db import migrations

NEW_CONFIGS = [
    # Chat AI (OpenAI-compatible)
    {'key': 'OPENAI_URL',     'label': 'API Base URL',  'group': 'openai', 'is_secret': False,
     'description': 'e.g. https://api.openai.com  หรือ  http://localhost:11434 (Ollama)', 'value': ''},
    {'key': 'OPENAI_MODEL',   'label': 'Model',         'group': 'openai', 'is_secret': False,
     'description': 'e.g. gpt-4o-mini  หรือ  qwen2.5:1.5b', 'value': 'gpt-4o-mini'},
    {'key': 'OPENAI_API_KEY', 'label': 'API Key',       'group': 'openai', 'is_secret': True,
     'description': 'sk-... (OpenAI) หรือว่างถ้าใช้ Ollama local', 'value': ''},
    # MOPH Notify
    {'key': 'MOPH_NOTIFY_URL',        'label': 'MOPH Notify Base URL', 'group': 'moph', 'is_secret': False,
     'description': 'e.g. https://notify.moph.go.th', 'value': ''},
    {'key': 'MOPH_NOTIFY_CLIENT_KEY', 'label': 'Client Key',           'group': 'moph', 'is_secret': True,
     'description': 'ส่งใน header: client-key', 'value': ''},
    {'key': 'MOPH_NOTIFY_SECRET_KEY', 'label': 'Secret Key',           'group': 'moph', 'is_secret': True,
     'description': 'ส่งใน header: secret-key', 'value': ''},
    # MOPH Header Images
    {'key': 'MOPH_IMG_CRITICAL', 'label': 'CRITICAL Header Image', 'group': 'moph', 'is_secret': False,
     'description': 'URL รูปภาพ header สำหรับ alert ระดับ CRITICAL', 'value': ''},
    {'key': 'MOPH_IMG_HIGH',     'label': 'HIGH Header Image',     'group': 'moph', 'is_secret': False,
     'description': 'URL รูปภาพ header สำหรับ alert ระดับ HIGH', 'value': ''},
    {'key': 'MOPH_IMG_MEDIUM',   'label': 'MEDIUM Header Image',   'group': 'moph', 'is_secret': False,
     'description': 'URL รูปภาพ header สำหรับ alert ระดับ MEDIUM', 'value': ''},
    {'key': 'MOPH_IMG_LOW',      'label': 'LOW Header Image',      'group': 'moph', 'is_secret': False,
     'description': 'URL รูปภาพ header สำหรับ alert ระดับ LOW', 'value': ''},
    {'key': 'MOPH_IMG_INFO',     'label': 'INFO Header Image',     'group': 'moph', 'is_secret': False,
     'description': 'URL รูปภาพ header สำหรับ alert ระดับ INFO', 'value': ''},
]


def add_configs(apps, schema_editor):
    IntegrationConfig = apps.get_model('config_app', 'IntegrationConfig')
    for cfg in NEW_CONFIGS:
        IntegrationConfig.objects.get_or_create(
            key=cfg['key'],
            defaults={
                'value':       cfg['value'],
                'label':       cfg['label'],
                'group':       cfg['group'],
                'is_secret':   cfg['is_secret'],
                'description': cfg['description'],
            }
        )


def remove_configs(apps, schema_editor):
    IntegrationConfig = apps.get_model('config_app', 'IntegrationConfig')
    IntegrationConfig.objects.filter(key__in=[c['key'] for c in NEW_CONFIGS]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0004_add_autodismiss_config'),
    ]

    operations = [
        migrations.RunPython(add_configs, remove_configs),
    ]
