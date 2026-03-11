"""
SOC Dashboard — License Validation
===================================
Key format:  SOC-{PLAN}-{EXPIRY_YYYYMMDD}-{SIGNATURE}
Example:     SOC-PRO-20261231-A3F8B2C1D4E5F6A7

SIGNATURE = HMAC-SHA256( "{instance_id}|{plan}|{expiry}", VENDOR_SECRET )[:16].upper()

VENDOR_SECRET อยู่ใน settings.LICENSE_VENDOR_SECRET
ใส่ใน .env:  LICENSE_VENDOR_SECRET=<random 64 hex chars>
"""

import hmac
import hashlib
import re
from datetime import date

from django.conf import settings
from django.utils import timezone

# ── Key pattern ───────────────────────────────────────────────────────────────
_KEY_RE = re.compile(
    r'^SOC-(TRIAL|PRO|ENT)-(\d{8})-([A-F0-9]{16})$'
)

PLAN_LABELS = {
    'TRIAL': 'Trial',
    'PRO':   'Professional',
    'ENT':   'Enterprise',
}


def _vendor_secret() -> bytes:
    secret = getattr(settings, 'LICENSE_VENDOR_SECRET', '')
    if not secret:
        raise ValueError('LICENSE_VENDOR_SECRET not set in settings / .env')
    return secret.encode()


def _sign(instance_id: str, plan: str, expiry: str) -> str:
    """Return 16-char uppercase HMAC signature."""
    message = f'{instance_id}|{plan}|{expiry}'.encode()
    sig = hmac.new(_vendor_secret(), message, hashlib.sha256).hexdigest()
    return sig[:16].upper()


def validate_key(license_key: str, instance_id: str) -> dict:
    """
    Validate a license key for the given instance_id.

    Returns dict:
        {
            'valid':   bool,
            'plan':    str | None,
            'expiry':  date | None,
            'expired': bool,
            'error':   str | None,
        }
    """
    m = _KEY_RE.match(license_key.strip().upper())
    if not m:
        return {'valid': False, 'plan': None, 'expiry': None,
                'expired': False, 'error': 'รูปแบบ License Key ไม่ถูกต้อง'}

    plan, expiry_str, sig = m.group(1), m.group(2), m.group(3)

    # Verify signature
    try:
        expected = _sign(str(instance_id), plan, expiry_str)
    except ValueError as e:
        return {'valid': False, 'plan': None, 'expiry': None,
                'expired': False, 'error': str(e)}

    if not hmac.compare_digest(expected, sig):
        return {'valid': False, 'plan': None, 'expiry': None,
                'expired': False, 'error': 'License Key ไม่ถูกต้อง (signature mismatch)'}

    # Parse expiry date
    try:
        expiry = date(int(expiry_str[:4]), int(expiry_str[4:6]), int(expiry_str[6:8]))
    except ValueError:
        return {'valid': False, 'plan': None, 'expiry': None,
                'expired': False, 'error': 'วันหมดอายุใน License Key ไม่ถูกต้อง'}

    expired = date.today() > expiry

    return {
        'valid':   True,
        'plan':    plan,
        'expiry':  expiry,
        'expired': expired,
        'error':   None,
    }


def get_license_status() -> dict:
    """
    Load LicenseInfo from DB and return current status dict.
    Used by middleware + template context.
    """
    from .models import LicenseInfo
    info = LicenseInfo.get()

    grace_days = getattr(settings, 'LICENSE_GRACE_DAYS', 30)
    grace_ok = (date.today() - info.installed_at.date()).days <= grace_days

    if not info.license_key:
        return {
            'status':    'none',
            'plan':      None,
            'expires_at': None,
            'instance_id': str(info.instance_id),
            'grace_ok':  grace_ok,
            'grace_days_left': max(0, grace_days - (date.today() - info.installed_at.date()).days),
            'warn':      not grace_ok,
        }

    if info.status == 'invalid':
        return {
            'status':    'invalid',
            'plan':      None,
            'expires_at': None,
            'instance_id': str(info.instance_id),
            'grace_ok':  False,
            'grace_days_left': 0,
            'warn':      True,
        }

    expired = info.expires_at and date.today() > info.expires_at
    return {
        'status':    'expired' if expired else 'valid',
        'plan':      info.plan,
        'expires_at': info.expires_at,
        'instance_id': str(info.instance_id),
        'grace_ok':  not expired,
        'grace_days_left': 0,
        'warn':      expired,
    }


def activate_key(license_key: str) -> dict:
    """
    Validate and save license key to DB.
    Returns same dict as validate_key + 'saved' bool.
    """
    from .models import LicenseInfo
    info = LicenseInfo.get()
    result = validate_key(license_key, str(info.instance_id))

    if result['valid']:
        info.license_key  = license_key.strip().upper()
        info.plan         = result['plan']
        info.expires_at   = result['expiry']
        info.status       = 'expired' if result['expired'] else 'valid'
        info.activated_at = timezone.now()
        info.save()
        result['saved'] = True
    else:
        info.license_key = license_key.strip().upper()
        info.status = 'invalid'
        info.save()
        result['saved'] = False

    return result
