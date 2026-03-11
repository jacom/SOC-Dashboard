import io
import base64
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp import login as otp_login


@login_required
def otp_setup(request):
    """First-time TOTP setup: show QR code, confirm with 6-digit code."""
    user = request.user

    # If already verified this session, skip
    if user.is_verified():
        return redirect('/')

    # Get or create an unconfirmed device
    device = TOTPDevice.objects.filter(user=user, confirmed=False).first()
    if not device:
        # Remove any old unconfirmed devices first
        TOTPDevice.objects.filter(user=user, confirmed=False).delete()
        device = TOTPDevice.objects.create(
            user=user,
            name=f'{user.username} Authenticator',
            confirmed=False,
        )

    # Build TOTP URI and QR code
    totp_uri = device.config_url  # otpauth://totp/...
    qr_image = _make_qr_png(totp_uri)

    # Extract base32 secret from config_url for manual entry display
    import re as _re
    _m = _re.search(r'secret=([A-Z2-7]+)', device.config_url)
    base32_secret = _m.group(1) if _m else ''

    error = None
    if request.method == 'POST':
        code = request.POST.get('code', '').strip()
        if device.verify_token(code):
            device.confirmed = True
            device.save()
            otp_login(request, device)
            return redirect(request.GET.get('next', '/'))
        error = 'รหัสไม่ถูกต้อง กรุณาตรวจสอบเวลาบนโทรศัพท์และลองใหม่'

    return render(request, '2fa/setup.html', {
        'qr_image': qr_image,
        'totp_uri': totp_uri,
        'device': device,
        'base32_secret': base32_secret,
        'error': error,
    })


@login_required
def otp_verify(request):
    """Subsequent logins: enter TOTP code to verify session."""
    user = request.user

    if user.is_verified():
        return redirect(request.GET.get('next', '/'))

    # Check user actually has a confirmed device
    device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
    if not device:
        return redirect('/2fa/setup/')

    error = None
    if request.method == 'POST':
        code = request.POST.get('code', '').strip()
        if device.verify_token(code):
            otp_login(request, device)
            return redirect(request.GET.get('next', '/'))
        error = 'รหัสไม่ถูกต้อง กรุณาลองใหม่'

    return render(request, '2fa/verify.html', {'error': error})


@login_required
def otp_disable(request):
    """Admin-only: disable OTP for a specific user."""
    from apps.core.decorators import admin_required
    if not request.user.is_verified():
        return redirect('/2fa/verify/?next=' + request.path_info)
    try:
        role = request.user.profile.role
    except Exception:
        role = 'viewer'
    if role != 'admin':
        from django.http import HttpResponseForbidden
        return HttpResponseForbidden('ต้องเป็น Admin เท่านั้น')

    if request.method == 'POST':
        pk = request.POST.get('user_pk')
        if pk:
            TOTPDevice.objects.filter(user_id=pk).delete()
            from apps.core.audit import audit
            audit(request, 'other', 'User', pk, f'Reset 2FA for user pk={pk}')
            return JsonResponse({'ok': True})
        return JsonResponse({'ok': False, 'error': 'user_pk required'}, status=400)
    return JsonResponse({'ok': False, 'error': 'POST required'}, status=405)


def _make_qr_png(data: str) -> str:
    """Return base64-encoded PNG of a QR code."""
    import qrcode
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=6, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode()
