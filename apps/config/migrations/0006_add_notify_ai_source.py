from django.db import migrations

NEW_CONFIG = {
    'key':         'NOTIFY_AI_SOURCE',
    'label':       'AI Source for Notify',
    'group':       'system',
    'is_secret':   False,
    'description': 'เลือก AI ที่ใช้วิเคราะห์ก่อนส่ง LINE notify: ollama / chatgpt / both',
    'value':       'both',
}


def add_config(apps, schema_editor):
    IntegrationConfig = apps.get_model('config_app', 'IntegrationConfig')
    IntegrationConfig.objects.get_or_create(
        key=NEW_CONFIG['key'],
        defaults={k: v for k, v in NEW_CONFIG.items() if k != 'key'},
    )


def remove_config(apps, schema_editor):
    IntegrationConfig = apps.get_model('config_app', 'IntegrationConfig')
    IntegrationConfig.objects.filter(key=NEW_CONFIG['key']).delete()


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0005_add_openai_moph_configs'),
    ]

    operations = [
        migrations.RunPython(add_config, remove_config),
    ]
