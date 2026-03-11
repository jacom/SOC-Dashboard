from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('assets', '0001_initial')]

    operations = [
        migrations.AddField(
            model_name='asset',
            name='machine_type',
            field=models.CharField(
                max_length=10,
                choices=[('physical', 'Physical'), ('vm', 'Virtual Machine (VM)')],
                default='physical',
            ),
        ),
        migrations.AddField(
            model_name='asset',
            name='image',
            field=models.ImageField(
                upload_to='assets/',
                null=True, blank=True,
                help_text='รูปภาพ server/เครื่อง',
            ),
        ),
    ]
