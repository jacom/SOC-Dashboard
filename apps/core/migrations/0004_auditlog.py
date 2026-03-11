from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        ('core', '0003_alter_userprofile_id'),
    ]
    operations = [
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('action', models.CharField(max_length=30, choices=[
                    ('alert_dismiss','Alert: Dismiss'),('alert_undismiss','Alert: Undismiss'),
                    ('alert_ai','Alert: AI Analysis'),('incident_create','Incident: Create'),
                    ('incident_edit','Incident: Edit'),('incident_status','Incident: Status Change'),
                    ('incident_delete','Incident: Delete'),('vuln_add','Vulnerability: Add'),
                    ('vuln_edit','Vulnerability: Edit'),('vuln_delete','Vulnerability: Delete'),
                    ('vuln_ai','Vulnerability: AI Analysis'),('user_add','User: Add'),
                    ('user_edit','User: Edit'),('user_delete','User: Delete'),
                    ('user_toggle','User: Toggle Active'),('login','Login'),
                    ('logout','Logout'),('other','Other'),
                ])),
                ('target_type', models.CharField(blank=True, max_length=50)),
                ('target_id', models.CharField(blank=True, max_length=50)),
                ('detail', models.TextField(blank=True)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='audit_logs', to='auth.user')),
            ],
            options={'app_label': 'core', 'ordering': ['-timestamp']},
        ),
    ]
