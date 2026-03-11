from django.db import migrations


def seed(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    UserProfile = apps.get_model('core', 'UserProfile')
    for user in User.objects.all():
        role = 'admin' if user.is_superuser else 'analyst'
        UserProfile.objects.get_or_create(user=user, defaults={'role': role})


class Migration(migrations.Migration):
    dependencies = [('core', '0001_userprofile')]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
