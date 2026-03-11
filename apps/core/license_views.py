from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from .decorators import admin_required
from .license import activate_key, get_license_status, PLAN_LABELS
from .models import LicenseInfo


@login_required
@admin_required
def license_page(request):
    info = LicenseInfo.get()
    lic  = get_license_status()
    return render(request, 'core/license.html', {
        'lic':         lic,
        'info':        info,
        'plan_labels': PLAN_LABELS,
    })


@login_required
@admin_required
@require_http_methods(['POST'])
def license_activate(request):
    import json
    try:
        data = json.loads(request.body)
        key  = data.get('license_key', '').strip()
    except (ValueError, KeyError):
        return JsonResponse({'ok': False, 'error': 'Invalid request'}, status=400)

    if not key:
        return JsonResponse({'ok': False, 'error': 'กรุณากรอก License Key'})

    result = activate_key(key)
    if result['saved']:
        return JsonResponse({
            'ok':      True,
            'plan':    result['plan'],
            'expiry':  result['expiry'].isoformat() if result['expiry'] else None,
            'expired': result['expired'],
        })
    return JsonResponse({'ok': False, 'error': result['error']})
