from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('alerts', '0006_add_dismissed_field'),
    ]

    operations = [
        migrations.CreateModel(
            name='AlertSuppressRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rule_id', models.CharField(db_index=True, max_length=50)),
                ('agent_ip', models.GenericIPAddressField(blank=True, null=True,
                    help_text='เว้นว่างเพื่อ suppress ทุก agent')),
                ('reason', models.TextField(blank=True, help_text='เหตุผลที่ suppress')),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={'ordering': ['-created_at']},
        ),
        migrations.AlterUniqueTogether(
            name='alertsuppressrule',
            unique_together={('rule_id', 'agent_ip')},
        ),
    ]
