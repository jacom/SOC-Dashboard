from django.db import migrations


def seed(apps, schema_editor):
    IntegrationConfig = apps.get_model('config_app', 'IntegrationConfig')
    for key, label in [
        ('ABUSEIPDB_API_KEY', 'AbuseIPDB API Key'),
        ('VIRUSTOTAL_API_KEY', 'VirusTotal API Key'),
    ]:
        IntegrationConfig.objects.get_or_create(
            key=key,
            defaults={'value': '', 'label': label, 'group': 'threat_intel', 'is_secret': True, 'description': ''},
        )


class Migration(migrations.Migration):
    dependencies = [('config_app', '0008_add_pipeline_enabled')]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
