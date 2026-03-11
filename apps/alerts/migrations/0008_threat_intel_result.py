from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('alerts', '0007_alert_suppress_rule'),
    ]

    operations = [
        migrations.CreateModel(
            name='ThreatIntelResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(db_index=True)),
                ('provider', models.CharField(choices=[('abuseipdb', 'AbuseIPDB'), ('virustotal', 'VirusTotal')], max_length=20)),
                ('is_malicious', models.BooleanField(default=False)),
                ('score', models.IntegerField(default=0, help_text='AbuseIPDB: abuse confidence %, VT: malicious vote count')),
                ('country', models.CharField(blank=True, max_length=10)),
                ('isp', models.CharField(blank=True, max_length=200)),
                ('domain', models.CharField(blank=True, max_length=200)),
                ('raw_data', models.JSONField(default=dict)),
                ('checked_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['-checked_at'],
                'unique_together': {('ip_address', 'provider')},
            },
        ),
    ]
