import json
from datetime import timedelta, date as date_type

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from .models import SLAPolicy
from apps.incidents.models import Incident
from apps.vulnerabilities.models import Vulnerability


@login_required
def sla_dashboard(request):
    policies = {p.severity: p for p in SLAPolicy.objects.filter(is_active=True)}
    now   = timezone.now()
    today = now.date()

    sev_order   = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    sev_colors  = {'CRITICAL': 'danger', 'HIGH': 'warning', 'MEDIUM': 'info', 'LOW': 'success'}

    # ── Incident SLA ─────────────────────────────────────────────────────────
    # Uses resolve_hours: created_at → (Resolved/Closed updated_at)
    inc_stats = []
    for sev in sev_order:
        policy = policies.get(sev)
        qs = Incident.objects.filter(severity=sev)
        total = qs.count()

        if total == 0:
            inc_stats.append({
                'severity': sev, 'color': sev_colors[sev],
                'total': 0, 'policy': policy,
                'resolved': 0, 'compliant': 0, 'breached': 0, 'pct': 0,
            })
            continue

        if not policy:
            inc_stats.append({
                'severity': sev, 'color': sev_colors[sev],
                'total': total, 'policy': None,
                'resolved': 0, 'compliant': 0, 'breached': 0, 'pct': 0,
            })
            continue

        threshold = timedelta(hours=policy.resolve_hours)
        resolved_qs = qs.filter(status__in=['Resolved', 'Closed'])
        resolved_count = resolved_qs.count()

        compliant = sum(
            1 for inc in resolved_qs
            if (inc.updated_at - inc.created_at) <= threshold
        )

        breached = qs.filter(
            status__in=['New', 'InProgress'],
            created_at__lt=now - threshold,
        ).count()

        pct = round(compliant / total * 100) if total > 0 else 0
        inc_stats.append({
            'severity': sev, 'color': sev_colors[sev],
            'total': total, 'policy': policy,
            'resolved': resolved_count, 'compliant': compliant,
            'breached': breached, 'pct': pct,
        })

    # Breached incident list
    breached_incidents = []
    for sev, policy in policies.items():
        if sev not in sev_order:
            continue
        threshold = timedelta(hours=policy.resolve_hours)
        qs = Incident.objects.filter(
            severity=sev,
            status__in=['New', 'InProgress'],
            created_at__lt=now - threshold,
        ).order_by('created_at')[:15]
        for inc in qs:
            overdue_h = (now - inc.created_at).total_seconds() / 3600 - policy.resolve_hours
            breached_incidents.append({'inc': inc, 'overdue_h': round(overdue_h, 1), 'policy': policy})
    breached_incidents.sort(key=lambda x: x['inc'].created_at)

    # ── Vulnerability SLA ─────────────────────────────────────────────────────
    # Uses resolve_hours converted to days: discovered_at → resolved_at
    vuln_stats = []
    for sev in sev_order:
        policy = policies.get(sev)
        qs = Vulnerability.objects.filter(severity=sev)
        total = qs.count()

        if total == 0:
            vuln_stats.append({
                'severity': sev, 'color': sev_colors[sev],
                'total': 0, 'policy': policy,
                'resolved': 0, 'compliant': 0, 'breached': 0, 'pct': 0,
            })
            continue

        if not policy:
            vuln_stats.append({
                'severity': sev, 'color': sev_colors[sev],
                'total': total, 'policy': None,
                'resolved': 0, 'compliant': 0, 'breached': 0, 'pct': 0,
            })
            continue

        threshold_days = policy.resolve_hours / 24.0

        # Resolved = mitigated / resolved / accepted
        resolved_qs = qs.filter(status__in=['resolved', 'mitigated', 'accepted'])
        resolved_count = resolved_qs.count()

        compliant = 0
        for v in resolved_qs:
            end_date = v.resolved_at or today
            if (end_date - v.discovered_at).days <= threshold_days:
                compliant += 1

        breach_date = today - timedelta(days=threshold_days)
        breached = qs.filter(
            status__in=['open', 'in_progress'],
            discovered_at__lt=breach_date,
        ).count()

        pct = round(compliant / total * 100) if total > 0 else 0
        vuln_stats.append({
            'severity': sev, 'color': sev_colors[sev],
            'total': total, 'policy': policy,
            'resolved': resolved_count, 'compliant': compliant,
            'breached': breached, 'pct': pct,
        })

    # Breached vulnerability list
    breached_vulns = []
    for sev, policy in policies.items():
        if sev not in sev_order:
            continue
        threshold_days = policy.resolve_hours / 24.0
        breach_date = today - timedelta(days=threshold_days)
        qs = Vulnerability.objects.filter(
            severity=sev,
            status__in=['open', 'in_progress'],
            discovered_at__lt=breach_date,
        ).order_by('discovered_at')[:15]
        for v in qs:
            overdue_days = (today - v.discovered_at).days - threshold_days
            breached_vulns.append({'vuln': v, 'overdue_days': round(overdue_days, 1), 'policy': policy})
    breached_vulns.sort(key=lambda x: x['vuln'].discovered_at)

    all_policies = SLAPolicy.objects.all().order_by('severity')

    return render(request, 'sla/dashboard.html', {
        'inc_stats':          inc_stats,
        'vuln_stats':         vuln_stats,
        'breached_incidents': breached_incidents,
        'breached_vulns':     breached_vulns,
        'all_policies':       all_policies,
        'policies':           policies,
        'now':                now,
    })


@login_required
@require_http_methods(['GET', 'POST'])
def policy_edit(request, pk):
    policy = get_object_or_404(SLAPolicy, pk=pk)
    if request.method == 'GET':
        return JsonResponse({
            'id': policy.pk,
            'severity': policy.severity,
            'response_hours': policy.response_hours,
            'resolve_hours': policy.resolve_hours,
            'is_active': policy.is_active,
        })
    try:
        data = json.loads(request.body)
        policy.response_hours = float(data['response_hours'])
        policy.resolve_hours = float(data['resolve_hours'])
        policy.save()
        return JsonResponse({'ok': True})
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        return JsonResponse({'ok': False, 'error': str(e)}, status=400)


@login_required
@require_http_methods(['POST'])
def policy_save(request):
    try:
        data = json.loads(request.body)
        severity = data['severity']
        response_hours = float(data['response_hours'])
        resolve_hours = float(data['resolve_hours'])
        SLAPolicy.objects.update_or_create(
            severity=severity,
            defaults={
                'response_hours': response_hours,
                'resolve_hours': resolve_hours,
            }
        )
        return JsonResponse({'ok': True})
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        return JsonResponse({'ok': False, 'error': str(e)}, status=400)
