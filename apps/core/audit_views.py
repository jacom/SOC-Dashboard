from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render
from .models import AuditLog
from .decorators import admin_required


@admin_required
def audit_log(request):
    qs = AuditLog.objects.select_related('user').all()

    # Filters
    action_filter = request.GET.get('action', '')
    user_filter   = request.GET.get('user', '')
    date_from     = request.GET.get('date_from', '')
    date_to       = request.GET.get('date_to', '')

    if action_filter:
        qs = qs.filter(action=action_filter)
    if user_filter:
        qs = qs.filter(user__username__icontains=user_filter)
    if date_from:
        qs = qs.filter(timestamp__date__gte=date_from)
    if date_to:
        qs = qs.filter(timestamp__date__lte=date_to)

    paginator = Paginator(qs, 50)
    page = paginator.get_page(request.GET.get('page', 1))

    return render(request, 'core/audit_log.html', {
        'logs': page,
        'action_choices': AuditLog.ACTION_CHOICES,
        'action_filter': action_filter,
        'user_filter': user_filter,
        'date_from': date_from,
        'date_to': date_to,
    })
