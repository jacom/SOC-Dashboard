from django.conf import settings


def app_version(request):
    return {'APP_VERSION': settings.APP_VERSION}


def user_role(request):
    role = 'viewer'
    if request.user.is_authenticated:
        try:
            role = request.user.profile.role
        except Exception:
            pass
    return {'user_role': role}
