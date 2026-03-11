from django.shortcuts import redirect

# ── License status injected into every request ────────────────────────────────
class LicenseMiddleware:
    """Attach license status to every request as request.license_status."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from .license import get_license_status
        try:
            request.license_status = get_license_status()
        except Exception:
            request.license_status = {'status': 'none', 'warn': False, 'grace_ok': True,
                                       'grace_days_left': 30, 'plan': None, 'expires_at': None,
                                       'instance_id': ''}
        return self.get_response(request)


# ── OTP ───────────────────────────────────────────────────────────────────────
# Paths that never require OTP verification
OTP_EXEMPT_PATHS = [
    '/login/',
    '/logout/',
    '/2fa/',
    '/api/',
    '/static/',
]


class OTPRequiredMiddleware:
    """
    If a user has already enrolled a confirmed TOTP device but has not yet
    verified this session, redirect them to the OTP verify page.
    Users WITHOUT a device are NOT forced — they can opt-in via /2fa/setup/.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            path = request.path_info
            exempt = any(path.startswith(p) for p in OTP_EXEMPT_PATHS) or path.startswith('/admin/')
            if not exempt and not request.user.is_verified():
                from django_otp.plugins.otp_totp.models import TOTPDevice
                has_device = TOTPDevice.objects.filter(
                    user=request.user, confirmed=True
                ).exists()
                if has_device:
                    # User enrolled 2FA but hasn't verified this session yet
                    return redirect('/2fa/verify/?next=' + request.path_info)
                # No device → allow through; banner in base.html encourages setup
        return self.get_response(request)
