from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = []

    operations = [
        migrations.CreateModel(
            name='Asset',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('agent_ip', models.GenericIPAddressField(unique=True, help_text='IP ที่ใช้ใน Wazuh agent')),
                ('agent_name', models.CharField(max_length=200, blank=True)),
                ('hostname', models.CharField(max_length=200, blank=True)),
                ('owner', models.CharField(max_length=200, blank=True)),
                ('department', models.CharField(max_length=200, blank=True)),
                ('asset_type', models.CharField(
                    max_length=20,
                    choices=[('server','Server'),('workstation','Workstation'),('network','Network Device'),('other','Other')],
                    default='workstation',
                )),
                ('criticality', models.CharField(
                    max_length=10,
                    choices=[('CRITICAL','Critical'),('HIGH','High'),('MEDIUM','Medium'),('LOW','Low')],
                    default='MEDIUM',
                )),
                ('location', models.CharField(max_length=200, blank=True)),
                ('notes', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={'ordering': ['agent_ip']},
        ),
    ]
