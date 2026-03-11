from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('alerts', '0008_threat_intel_result'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Playbook',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True)),
                ('rule_ids', models.TextField(blank=True, help_text='Comma-separated rule IDs, e.g. 92058,92059')),
                ('rule_groups', models.TextField(blank=True, help_text='Comma-separated rule groups, e.g. authentication_failed,web')),
                ('severity_filter', models.CharField(
                    blank=True, max_length=50,
                    help_text='Only apply to these severities, comma-separated. Empty = all.'
                )),
                ('steps', models.JSONField(default=list, help_text='List of step strings')),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='PlaybookRun',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('completed_steps', models.JSONField(default=list, help_text='List of completed step indices')),
                ('notes', models.TextField(blank=True)),
                ('started_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('alert', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='playbook_runs',
                    to='alerts.alert',
                )),
                ('playbook', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='runs',
                    to='alerts.playbook',
                )),
                ('completed_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-updated_at'],
                'unique_together': {('alert', 'playbook')},
            },
        ),
    ]
