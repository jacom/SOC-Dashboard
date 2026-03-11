import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0004_auditlog'),
    ]

    operations = [
        migrations.CreateModel(
            name='LicenseInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('instance_id', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('license_key', models.CharField(blank=True, max_length=60)),
                ('plan', models.CharField(blank=True, choices=[('TRIAL', 'Trial (30 days)'), ('PRO', 'Professional'), ('ENT', 'Enterprise')], max_length=10)),
                ('status', models.CharField(choices=[('valid', 'Valid'), ('expired', 'Expired'), ('invalid', 'Invalid'), ('none', 'No License')], default='none', max_length=10)),
                ('expires_at', models.DateField(blank=True, null=True)),
                ('activated_at', models.DateTimeField(blank=True, null=True)),
                ('installed_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'License Info',
                'app_label': 'core',
            },
        ),
    ]
