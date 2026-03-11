from django.apps import AppConfig

class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.core'

    def ready(self):
        import apps.core.models  # noqa — registers signals
        from django.contrib.auth.signals import user_logged_in, user_logged_out

        def on_login(sender, request, user, **kwargs):
            try:
                from apps.core.models import AuditLog
                ip = (request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                      or request.META.get('REMOTE_ADDR'))
                AuditLog.objects.create(user=user, action='login',
                    target_type='User', target_id=str(user.pk),
                    detail=f'Login: {user.username}', ip_address=ip or None)
            except Exception:
                pass

        def on_logout(sender, request, user, **kwargs):
            try:
                from apps.core.models import AuditLog
                ip = (request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                      or request.META.get('REMOTE_ADDR'))
                AuditLog.objects.create(user=user, action='logout',
                    target_type='User', target_id=str(user.pk) if user else '',
                    detail=f'Logout: {user.username if user else "unknown"}',
                    ip_address=ip or None)
            except Exception:
                pass

        user_logged_in.connect(on_login)
        user_logged_out.connect(on_logout)
