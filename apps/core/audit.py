"""Helper to write audit log entries."""


def audit(request, action, target_type='', target_id='', detail=''):
    """Write an AuditLog entry. Safe to call anywhere — never raises."""
    try:
        from .models import AuditLog
        ip = (
            request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
            or request.META.get('REMOTE_ADDR')
        )
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action=action,
            target_type=target_type,
            target_id=str(target_id),
            detail=detail,
            ip_address=ip or None,
        )
    except Exception:
        pass
