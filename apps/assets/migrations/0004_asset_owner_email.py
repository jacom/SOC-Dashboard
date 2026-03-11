from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('assets', '0003_alter_asset_agent_name_alter_asset_department_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='asset',
            name='owner_email',
            field=models.EmailField(blank=True, help_text='อีเมลเจ้าของ/ผู้ดูแล สำหรับรับแจ้งเตือน'),
        ),
    ]
