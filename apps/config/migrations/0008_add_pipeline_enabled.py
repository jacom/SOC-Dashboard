from django.db import migrations


def seed_pipeline_enabled(apps, schema_editor):
    IntegrationConfig = apps.get_model('config_app', 'IntegrationConfig')
    IntegrationConfig.objects.get_or_create(
        key='PIPELINE_ENABLED',
        defaults={
            'value': 'false',
            'label': 'Pipeline Enabled',
            'group': 'system',
            'is_secret': False,
            'description': 'เปิด/ปิด pipeline แจ้งเตือน (AI Analysis + LINE Notify + TheHive)',
        },
    )


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0007_add_ai_enabled_flags'),
    ]

    operations = [
        migrations.RunPython(seed_pipeline_enabled, migrations.RunPython.noop),
    ]
