from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='SLAPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('severity', models.CharField(
                    choices=[
                        ('CRITICAL', 'Critical'),
                        ('HIGH', 'High'),
                        ('MEDIUM', 'Medium'),
                        ('LOW', 'Low'),
                        ('INFO', 'Info'),
                    ],
                    max_length=10,
                    unique=True,
                )),
                ('response_hours', models.FloatField(help_text='ชั่วโมงที่ต้องตอบสนอง (dismiss หรือ escalate)')),
                ('resolve_hours', models.FloatField(help_text='ชั่วโมงที่ต้องแก้ไข (incident resolved)')),
                ('is_active', models.BooleanField(default=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'SLA Policy',
                'verbose_name_plural': 'SLA Policies',
                'ordering': ['severity'],
            },
        ),
    ]
