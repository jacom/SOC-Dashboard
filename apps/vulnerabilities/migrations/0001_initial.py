import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('assets', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Vulnerability',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=500)),
                ('cve_id', models.CharField(blank=True, help_text='CVE-YYYY-XXXXX', max_length=30)),
                ('agent_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('severity', models.CharField(
                    choices=[
                        ('CRITICAL', 'Critical'),
                        ('HIGH', 'High'),
                        ('MEDIUM', 'Medium'),
                        ('LOW', 'Low'),
                    ],
                    default='MEDIUM',
                    max_length=10,
                )),
                ('status', models.CharField(
                    choices=[
                        ('open', 'Open'),
                        ('in_progress', 'In Progress'),
                        ('mitigated', 'Mitigated'),
                        ('resolved', 'Resolved'),
                        ('accepted', 'Risk Accepted'),
                    ],
                    default='open',
                    max_length=20,
                )),
                ('description', models.TextField(blank=True)),
                ('remediation', models.TextField(blank=True)),
                ('discovered_at', models.DateField()),
                ('due_date', models.DateField(blank=True, null=True)),
                ('resolved_at', models.DateField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('asset', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='vulnerabilities',
                    to='assets.asset',
                )),
                ('created_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-discovered_at', '-created_at'],
            },
        ),
    ]
