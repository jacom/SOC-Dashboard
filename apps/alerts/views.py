from urllib.parse import urlencode

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.db.models import Case, IntegerField, Value, When
from .models import Alert


@login_required
def alert_list(request):
    qs = Alert.objects.select_related('ai_analysis').prefetch_related('incidents')

    severity      = request.GET.get('severity', '')
    agent         = request.GET.get('agent', '')
    date_from     = request.GET.get('date_from', '')
    date_to       = request.GET.get('date_to', '')
    search        = request.GET.get('search', '')
    sort          = request.GET.get('sort', 'severity')
    show_dismissed = request.GET.get('dismissed', '') == '1'

    if not show_dismissed:
        qs = qs.filter(dismissed=False)

    if severity:
        qs = qs.filter(severity=severity)
    if agent:
        qs = qs.filter(agent_name__icontains=agent)
    if date_from:
        qs = qs.filter(timestamp__date__gte=date_from)
    if date_to:
        qs = qs.filter(timestamp__date__lte=date_to)
    if search:
        qs = qs.filter(rule_description__icontains=search)

    _sev_asc = Case(
        When(severity='CRITICAL', then=Value(0)),
        When(severity='HIGH',     then=Value(1)),
        When(severity='MEDIUM',   then=Value(2)),
        When(severity='LOW',      then=Value(3)),
        When(severity='INFO',     then=Value(4)),
        default=Value(5), output_field=IntegerField(),
    )

    if sort == 'severity':
        qs = qs.order_by(_sev_asc, '-timestamp')
    elif sort == '-severity':
        qs = qs.order_by(_sev_asc.desc(), '-timestamp')
    elif sort == '-time':
        qs = qs.order_by('timestamp')
    elif sort == 'agent':
        qs = qs.order_by('agent_name', '-timestamp')
    elif sort == '-agent':
        qs = qs.order_by('-agent_name', '-timestamp')
    elif sort == 'level':
        qs = qs.order_by('-rule_level', '-timestamp')
    elif sort == '-level':
        qs = qs.order_by('rule_level', '-timestamp')
    else:  # 'time' default
        qs = qs.order_by('-timestamp')

    # Pagination
    from django.core.paginator import Paginator
    _valid_sizes = {50, 100, 500, 1000}
    try:
        per_page = int(request.GET.get('per_page', 50))
    except (ValueError, TypeError):
        per_page = 50
    if per_page not in _valid_sizes:
        per_page = 50
    paginator = Paginator(qs, per_page)
    page = request.GET.get('page', 1)
    alerts = paginator.get_page(page)

    # Smart page range
    current = alerts.number
    total   = paginator.num_pages
    delta   = 2
    pages   = sorted(set(
        [1, total] +
        list(range(max(1, current - delta), min(total, current + delta) + 1))
    ))
    page_range = []
    prev = None
    for p in pages:
        if prev and p - prev > 1:
            page_range.append('...')
        page_range.append(p)
        prev = p

    agents = Alert.objects.values_list('agent_name', flat=True).distinct().order_by('agent_name')

    # Query string with current filters (without sort/page) — used by sort header links
    filter_qs = urlencode({k: v for k, v in {
        'severity': severity, 'agent': agent,
        'date_from': date_from, 'date_to': date_to, 'search': search,
        'per_page': per_page,
    }.items() if v})

    dismissed_count = Alert.objects.filter(dismissed=True).count()

    context = {
        'alerts': alerts,
        'agents': agents,
        'severity_choices': Alert.SEVERITY,
        'page_range': page_range,
        'filter_qs': filter_qs,
        'dismissed_count': dismissed_count,
        'show_dismissed': show_dismissed,
        'per_page': per_page,
        'filters': {
            'severity': severity, 'agent': agent,
            'date_from': date_from, 'date_to': date_to,
            'search': search, 'sort': sort,
        },
    }
    return render(request, 'alerts/list.html', context)


@login_required
@require_POST
def fetch_wazuh(request):
    """AJAX endpoint — trigger a Wazuh fetch and return stats as JSON."""
    from datetime import datetime, timezone as dt_timezone
    try:
        min_level = int(request.POST.get('min_level', 3))
        date_from_str = request.POST.get('date_from', '').strip()
        if date_from_str:
            # Custom date_from provided — convert to hours from now
            date_from = datetime.fromisoformat(date_from_str).replace(tzinfo=dt_timezone.utc)
            delta = datetime.now(dt_timezone.utc) - date_from
            hours = max(1, int(delta.total_seconds() / 3600) + 1)
        else:
            hours = int(request.POST.get('hours', 1))
        # Auto-scale limit based on hours (roughly 500 alerts/hour worst case)
        limit = min(10000, max(500, hours * 200))
    except (ValueError, TypeError):
        return JsonResponse({'ok': False, 'error': 'Invalid parameters'}, status=400)

    from .wazuh_fetcher import fetch_and_save
    stats = fetch_and_save(hours=hours, min_level=min_level, limit=limit)

    if stats.get('busy'):
        return JsonResponse({'ok': False, 'busy': True, 'error': stats['error_msg']})

    if stats['error_msg']:
        return JsonResponse({'ok': False, 'error': stats['error_msg']})

    return JsonResponse({
        'ok': True,
        'fetched': stats['fetched'],
        'created': stats['created'],
        'skipped': stats['skipped'],
        'errors':  stats['errors'],
    })


@login_required
@require_POST
def analyze_alert_view(request, pk):
    """Queue Ollama analysis in background — returns immediately."""
    from .models import AIAnalysis
    from .wazuh_fetcher import _analyze_in_thread
    alert = get_object_or_404(Alert, pk=pk)
    if AIAnalysis.objects.filter(alert=alert).exists():
        return JsonResponse({'ok': False, 'error': 'Already analyzed'})
    _analyze_in_thread(alert)
    return JsonResponse({'ok': True, 'queued': True})


@login_required
@require_POST
def reanalyze_alert_view(request, pk):
    """Delete existing analysis and queue re-analysis in background."""
    from .models import AIAnalysis
    from .wazuh_fetcher import _analyze_in_thread
    alert = get_object_or_404(Alert, pk=pk)
    AIAnalysis.objects.filter(alert=alert).delete()
    _analyze_in_thread(alert)
    return JsonResponse({'ok': True, 'queued': True})


@login_required
@require_POST
def analyze_chat_view(request, pk):
    """Queue Chat AI analysis in background — returns immediately."""
    import threading
    from .models import AIAnalysisChat
    alert = get_object_or_404(Alert, pk=pk)
    AIAnalysisChat.objects.filter(alert=alert).delete()

    def _run(a):
        from .chat_analyzer import analyze_alert_chat
        try:
            analyze_alert_chat(a)
        finally:
            try:
                from django.db import connection as _db_conn
                _db_conn.close()
            except Exception:
                pass

    threading.Thread(target=_run, args=(alert,), daemon=True).start()
    return JsonResponse({'ok': True, 'queued': True})


@login_required
def ai_status_view(request, pk):
    """Polling endpoint — returns whether AI / Chat AI analysis is ready."""
    from .models import AIAnalysis, AIAnalysisChat
    alert = get_object_or_404(Alert, pk=pk)
    return JsonResponse({
        'has_ai':   AIAnalysis.objects.filter(alert=alert).exists(),
        'has_chat': AIAnalysisChat.objects.filter(alert=alert).exists(),
    })


@login_required
def alert_detail(request, pk):
    import json as _json
    from .chat_analyzer import _build_event_json
    alert = get_object_or_404(
        Alert.objects.select_related('ai_analysis', 'ai_analysis_chat')
                     .prefetch_related('incidents', 'notifications'),
        pk=pk
    )
    event_json_str = _json.dumps(_build_event_json(alert), ensure_ascii=False, indent=2)
    return render(request, 'alerts/detail.html', {
        'alert': alert,
        'event_json': event_json_str,
    })


@login_required
def alert_raw_data(request, pk):
    alert = get_object_or_404(Alert, pk=pk)
    return JsonResponse(alert.raw_data)


@login_required
@require_POST
def push_to_thehive(request, pk):
    import urllib.request as _req
    import urllib.error as _uerr
    import json as _json
    from apps.config.models import IntegrationConfig
    from apps.incidents.models import Incident

    alert = get_object_or_404(Alert, pk=pk)

    if alert.incidents.exists():
        inc = alert.incidents.first()
        return JsonResponse({'ok': False, 'error': f'Already pushed — Case {inc.thehive_case_id}'})

    configs = {c.key: c.value for c in IntegrationConfig.objects.filter(
        key__in=['THEHIVE_URL', 'THEHIVE_API_KEY']
    )}
    thehive_url = configs.get('THEHIVE_URL', '').rstrip('/')
    api_key = configs.get('THEHIVE_API_KEY', '')

    if not thehive_url or not api_key:
        return JsonResponse({'ok': False, 'error': 'TheHive URL or API Key not set in Settings'})

    sev_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 1}
    tags = list(set(list(alert.rule_groups or []) + [alert.severity, 'wazuh']))
    if alert.mitre_id:
        tags.append(alert.mitre_id)

    ai = getattr(alert, 'ai_analysis', None)
    description = (
        f"## Alert Details\n"
        f"| Field | Value |\n|---|---|\n"
        f"| Rule | {alert.rule_description} |\n"
        f"| Rule ID | {alert.rule_id} (Level {alert.rule_level}) |\n"
        f"| Agent | {alert.agent_name} ({alert.agent_ip or 'N/A'}) |\n"
        f"| Source IP | {alert.src_ip or 'N/A'} |\n"
        f"| MITRE ATT&CK | {alert.mitre_id or 'N/A'} |\n"
        f"| Timestamp | {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} |\n"
        f"| Wazuh ID | {alert.wazuh_id} |\n"
    )
    if ai:
        description += (
            f"\n## AI Analysis\n"
            f"- **Attack Type**: {ai.attack_type}\n"
            f"- **Summary**: {ai.summary}\n"
            f"- **Impact**: {ai.impact}\n"
            f"- **Recommendations**: {ai.recommendations}\n"
            f"- **False Positive**: {ai.false_positive_pct}%\n"
        )

    case_payload = {
        'title': f'[{alert.severity}] {alert.rule_description[:120]}',
        'description': description,
        'severity': sev_map.get(alert.severity, 2),
        'tags': tags,
        'status': 'New',
        'source': 'SOC Dashboard',
        'sourceRef': str(alert.wazuh_id)[:100],
    }

    try:
        http_req = _req.Request(
            f'{thehive_url}/api/case',
            data=_json.dumps(case_payload).encode(),
            headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
            method='POST',
        )
        with _req.urlopen(http_req, timeout=15) as resp:
            result = _json.loads(resp.read())
    except _uerr.HTTPError as e:
        return JsonResponse({'ok': False, 'error': f'TheHive HTTP {e.code}: {e.read().decode()[:200]}'})
    except _uerr.URLError as e:
        return JsonResponse({'ok': False, 'error': f'Cannot connect to TheHive: {e.reason}'})
    except Exception as e:
        return JsonResponse({'ok': False, 'error': str(e)})

    case_id = result.get('_id') or result.get('id', '')
    case_number = result.get('caseId') or result.get('number', '')
    case_url = f'{thehive_url}/cases/{case_id}/details'

    try:
        incident = Incident.objects.create(
            alert=alert,
            thehive_case_id=f'#{case_number}' if case_number else case_id,
            title=case_payload['title'],
            status='New',
            severity=alert.severity,
            thehive_url=case_url,
        )
    except Exception as e:
        return JsonResponse({'ok': False, 'error': f'Case created in TheHive but DB error: {e}'})

    return JsonResponse({
        'ok': True,
        'case_number': case_number,
        'case_url': case_url,
        'incident_id': incident.pk,
    })


@login_required
@require_POST
def bulk_dismiss(request):
    import json as _json
    from django.utils import timezone
    data = _json.loads(request.body)
    ids = [int(i) for i in data.get('ids', []) if str(i).isdigit()]
    count = Alert.objects.filter(pk__in=ids).update(
        dismissed=True, dismissed_at=timezone.now()
    )
    try:
        from apps.core.audit import audit
        audit(request, 'alert_dismiss', 'Alert', ','.join(map(str, ids)),
              f'Dismissed {count} alert(s): {ids[:5]}')
    except Exception:
        pass
    return JsonResponse({'ok': True, 'dismissed': count})


@login_required
@require_POST
def bulk_undismiss(request):
    import json as _json
    data = _json.loads(request.body)
    ids = [int(i) for i in data.get('ids', []) if str(i).isdigit()]
    count = Alert.objects.filter(pk__in=ids).update(dismissed=False, dismissed_at=None)
    try:
        from apps.core.audit import audit
        audit(request, 'alert_undismiss', 'Alert', ','.join(map(str, ids)),
              f'Undismissed {count} alert(s)')
    except Exception:
        pass
    return JsonResponse({'ok': True, 'restored': count})


@login_required
def export_alerts_csv(request):
    import csv
    from django.http import HttpResponse
    severity  = request.GET.get('severity', '')
    agent     = request.GET.get('agent', '')
    date_from = request.GET.get('date_from', '')
    date_to   = request.GET.get('date_to', '')
    search    = request.GET.get('search', '')

    qs = Alert.objects.filter(dismissed=False).select_related('ai_analysis')
    if severity:  qs = qs.filter(severity=severity)
    if agent:     qs = qs.filter(agent_name__icontains=agent)
    if date_from: qs = qs.filter(timestamp__date__gte=date_from)
    if date_to:   qs = qs.filter(timestamp__date__lte=date_to)
    if search:    qs = qs.filter(rule_description__icontains=search)
    qs = qs.order_by('-timestamp')[:5000]

    response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
    response['Content-Disposition'] = 'attachment; filename="alerts.csv"'
    w = csv.writer(response)
    w.writerow(['ID','Timestamp','Severity','Agent','Agent IP','Source IP',
                'Rule Description','Rule Level','MITRE','Groups',
                'AI Severity','AI Attack Type'])
    for a in qs:
        ai = getattr(a, 'ai_analysis', None)
        w.writerow([
            a.id, a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            a.severity, a.agent_name, a.agent_ip or '', a.src_ip or '',
            a.rule_description, a.rule_level, a.mitre_id or '',
            ','.join(a.rule_groups or []),
            ai.severity_assessment if ai else '',
            ai.attack_type_en or ai.attack_type if ai else '',
        ])
    return response


# ─── Alert Suppress Rules ────────────────────────────────────────────────────

@login_required
def suppress_rule_list(request):
    from .models import AlertSuppressRule
    rules = AlertSuppressRule.objects.all()
    return render(request, 'alerts/suppress_list.html', {'rules': rules})


@login_required
@require_POST
def suppress_rule_add(request):
    from .models import AlertSuppressRule
    from django.http import JsonResponse
    rule_id  = request.POST.get('rule_id', '').strip()
    agent_ip = request.POST.get('agent_ip', '').strip() or None
    reason   = request.POST.get('reason', '').strip()

    if not rule_id:
        return JsonResponse({'ok': False, 'error': 'rule_id is required'})

    obj, created = AlertSuppressRule.objects.get_or_create(
        rule_id=rule_id,
        agent_ip=agent_ip,
        defaults={'reason': reason, 'is_active': True},
    )
    if not created:
        obj.reason    = reason
        obj.is_active = True
        obj.save(update_fields=['reason', 'is_active', 'updated_at'])

    return JsonResponse({
        'ok': True,
        'id': obj.pk,
        'rule_id': obj.rule_id,
        'agent_ip': obj.agent_ip or '',
        'reason': obj.reason,
        'is_active': obj.is_active,
        'created': created,
    })


@login_required
@require_POST
def suppress_rule_toggle(request, pk):
    from .models import AlertSuppressRule
    from django.http import JsonResponse
    try:
        rule = AlertSuppressRule.objects.get(pk=pk)
    except AlertSuppressRule.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'Not found'})
    rule.is_active = not rule.is_active
    rule.save(update_fields=['is_active', 'updated_at'])
    return JsonResponse({'ok': True, 'is_active': rule.is_active})


@login_required
@require_POST
def suppress_rule_delete(request, pk):
    from .models import AlertSuppressRule
    from django.http import JsonResponse
    AlertSuppressRule.objects.filter(pk=pk).delete()
    return JsonResponse({'ok': True})


# ─── Threat Intelligence ──────────────────────────────────────────────────────

@login_required
def threat_intel_lookup(request, pk):
    """AJAX — check src_ip of alert against threat intel providers."""
    from .threat_intel import lookup_ip
    alert = get_object_or_404(Alert, pk=pk)
    ip = alert.src_ip or alert.agent_ip
    if not ip:
        return JsonResponse({'ok': False, 'error': 'No IP address on this alert'})
    force = request.GET.get('force') == '1'
    results = lookup_ip(ip, force=force)
    data = []
    for r in results:
        data.append({
            'provider': r.provider,
            'is_malicious': r.is_malicious,
            'score': r.score,
            'country': r.country,
            'isp': r.isp,
            'domain': r.domain,
            'checked_at': r.checked_at.strftime('%Y-%m-%d %H:%M'),
        })
    return JsonResponse({'ok': True, 'ip': ip, 'results': data})


# ── Playbook views ────────────────────────────────────────────────

@login_required
def playbook_list(request):
    from .models import Playbook, PlaybookRun
    from django.db.models import Count

    playbooks = list(
        Playbook.objects.annotate(runs_count=Count('runs', distinct=True)).order_by('name')
    )

    # Pre-process fields and compute completion stats
    for pb in playbooks:
        pb.rule_ids_list    = [r.strip() for r in pb.rule_ids.split(',')       if r.strip()]
        pb.rule_groups_list = [g.strip() for g in pb.rule_groups.split(',')    if g.strip()]
        pb.severity_list    = [s.strip() for s in pb.severity_filter.split(',') if s.strip()]
        if pb.runs_count > 0 and pb.steps:
            runs        = list(PlaybookRun.objects.filter(playbook=pb))
            n_steps     = len(pb.steps)
            pb.completed_runs = sum(1 for r in runs if len(r.completed_steps) >= n_steps)
            pb.avg_pct        = round(
                sum(min(len(r.completed_steps), n_steps) / n_steps * 100 for r in runs)
                / pb.runs_count
            )
        else:
            pb.completed_runs = 0
            pb.avg_pct        = 0

    return render(request, 'alerts/playbook_list.html', {'playbooks': playbooks})


@login_required
@require_POST
def playbook_save(request):
    """Create or update a playbook via AJAX (JSON body)."""
    import json as json_mod
    from .models import Playbook
    try:
        data = json_mod.loads(request.body)
    except Exception:
        return JsonResponse({'ok': False, 'error': 'Invalid JSON'}, status=400)

    pk = data.get('id')
    if pk:
        pb = get_object_or_404(Playbook, pk=pk)
    else:
        pb = Playbook()

    pb.name            = (data.get('name') or '').strip()
    pb.description     = (data.get('description') or '').strip()
    pb.rule_ids        = (data.get('rule_ids') or '').strip()
    pb.rule_groups     = (data.get('rule_groups') or '').strip()
    pb.severity_filter = (data.get('severity_filter') or '').strip()
    pb.is_active       = bool(data.get('is_active', True))
    # steps: accept list or newline-separated string
    steps_raw = data.get('steps', [])
    if isinstance(steps_raw, str):
        pb.steps = [s.strip() for s in steps_raw.splitlines() if s.strip()]
    else:
        pb.steps = [str(s).strip() for s in steps_raw if str(s).strip()]

    if not pb.name:
        return JsonResponse({'ok': False, 'error': 'Name is required'}, status=400)
    pb.save()
    return JsonResponse({'ok': True, 'id': pb.pk, 'name': pb.name})


@login_required
@require_POST
def playbook_delete(request, pk):
    from .models import Playbook
    pb = get_object_or_404(Playbook, pk=pk)
    pb.delete()
    return JsonResponse({'ok': True})


@login_required
def playbook_get(request, pk):
    from .models import Playbook
    pb = get_object_or_404(Playbook, pk=pk)
    return JsonResponse({
        'ok': True, 'id': pb.pk,
        'name': pb.name, 'description': pb.description,
        'rule_ids': pb.rule_ids, 'rule_groups': pb.rule_groups,
        'severity_filter': pb.severity_filter, 'is_active': pb.is_active,
        'steps': pb.steps,
    })


@login_required
def alert_playbooks(request, pk):
    """Return matching playbooks + run status for an alert."""
    from .models import Playbook, PlaybookRun
    alert = get_object_or_404(Alert, pk=pk)
    active_pbs = Playbook.objects.filter(is_active=True)
    matching = [pb for pb in active_pbs if pb.matches_alert(alert)]
    result = []
    for pb in matching:
        try:
            run = PlaybookRun.objects.get(alert=alert, playbook=pb)
            completed = run.completed_steps
            notes = run.notes
            run_id = run.pk
        except PlaybookRun.DoesNotExist:
            completed = []
            notes = ''
            run_id = None
        result.append({
            'id': pb.pk, 'name': pb.name,
            'description': pb.description,
            'steps': pb.steps,
            'run_id': run_id,
            'completed_steps': completed,
            'notes': notes,
        })
    return JsonResponse({'ok': True, 'playbooks': result})


@login_required
@require_POST
def playbook_update_run(request, alert_pk, pb_pk):
    """Toggle step completion and save notes."""
    import json as json_mod
    from .models import Playbook, PlaybookRun
    alert    = get_object_or_404(Alert, pk=alert_pk)
    playbook = get_object_or_404(Playbook, pk=pb_pk)
    try:
        data = json_mod.loads(request.body)
    except Exception:
        return JsonResponse({'ok': False, 'error': 'Invalid JSON'}, status=400)

    run, _ = PlaybookRun.objects.get_or_create(
        alert=alert, playbook=playbook,
        defaults={'completed_by': request.user}
    )
    run.completed_steps = data.get('completed_steps', run.completed_steps)
    run.notes           = data.get('notes', run.notes)
    run.completed_by    = request.user
    run.save()
    total = len(playbook.steps)
    done  = len(run.completed_steps)
    return JsonResponse({'ok': True, 'done': done, 'total': total})


@login_required
def threat_intel_ip(request):
    """AJAX — check arbitrary IP (from asset detail or manual lookup)."""
    from .threat_intel import lookup_ip
    ip = request.GET.get('ip', '').strip()
    if not ip:
        return JsonResponse({'ok': False, 'error': 'ip required'})
    force = request.GET.get('force') == '1'
    results = lookup_ip(ip, force=force)
    data = []
    for r in results:
        data.append({
            'provider': r.provider,
            'is_malicious': r.is_malicious,
            'score': r.score,
            'country': r.country,
            'isp': r.isp,
            'domain': r.domain,
            'checked_at': r.checked_at.strftime('%Y-%m-%d %H:%M'),
        })
    return JsonResponse({'ok': True, 'ip': ip, 'results': data})
