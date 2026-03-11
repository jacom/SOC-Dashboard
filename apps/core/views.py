import json
import subprocess
import threading
import urllib.request

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_POST
from datetime import timedelta
from apps.alerts.models import Alert


@login_required
def dashboard(request):
    from django.db.models import Count, Q
    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    last_24h  = now - timedelta(hours=24)
    last_7d   = now - timedelta(days=7)
    last_14d  = now - timedelta(days=14)

    # ── Summary counts today ────────────────────────────────────
    alerts_today = Alert.objects.filter(timestamp__gte=today_start)
    critical_count = alerts_today.filter(severity='CRITICAL').count()
    high_count     = alerts_today.filter(severity='HIGH').count()
    medium_count   = alerts_today.filter(severity='MEDIUM').count()
    total_count    = alerts_today.count()

    # ── Week comparison ─────────────────────────────────────────
    week_start      = now - timedelta(days=7)
    prev_week_start = now - timedelta(days=14)
    this_week_total = Alert.objects.filter(timestamp__gte=week_start).count()
    prev_week_total = Alert.objects.filter(timestamp__gte=prev_week_start, timestamp__lt=week_start).count()
    week_change_pct = 0
    if prev_week_total > 0:
        week_change_pct = round((this_week_total - prev_week_total) / prev_week_total * 100)

    # ── Open incidents ──────────────────────────────────────────
    from apps.incidents.models import Incident
    open_incidents = Incident.objects.exclude(status__in=['Resolved', 'Closed'])
    open_incident_count = open_incidents.count()
    new_incident_count  = open_incidents.filter(status='New').count()
    inprogress_count    = open_incidents.filter(status='InProgress').count()

    # ── AI Coverage (CRITICAL+HIGH+MEDIUM) ─────────────────────
    from apps.alerts.models import AIAnalysis
    coverage_qs  = Alert.objects.filter(severity__in=['CRITICAL', 'HIGH', 'MEDIUM'])
    coverage_total    = coverage_qs.count()
    coverage_analyzed = AIAnalysis.objects.filter(alert__severity__in=['CRITICAL', 'HIGH', 'MEDIUM']).count()
    coverage_pct = round(coverage_analyzed / coverage_total * 100) if coverage_total else 0

    # ── Hourly timeline last 24h ────────────────────────────────
    recent_alerts = Alert.objects.filter(timestamp__gte=last_24h).order_by('timestamp')
    hourly_labels   = []
    hourly_critical = []
    hourly_high     = []
    hourly_medium   = []
    hourly_low      = []
    for i in range(24):
        bucket_start = last_24h + timedelta(hours=i)
        bucket_end   = bucket_start + timedelta(hours=1)
        hourly_labels.append(timezone.localtime(bucket_start).strftime('%H:00'))
        bqs = recent_alerts.filter(timestamp__gte=bucket_start, timestamp__lt=bucket_end)
        hourly_critical.append(bqs.filter(severity='CRITICAL').count())
        hourly_high.append(bqs.filter(severity='HIGH').count())
        hourly_medium.append(bqs.filter(severity='MEDIUM').count())
        hourly_low.append(bqs.filter(severity='LOW').count())

    # ── Daily trend last 7 days (stacked bar) ──────────────────
    daily_labels   = []
    daily_critical = []
    daily_high     = []
    daily_medium   = []
    daily_low      = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).date()
        day_start = timezone.make_aware(timezone.datetime(day.year, day.month, day.day))
        day_end   = day_start + timedelta(days=1)
        daily_labels.append(day.strftime('%d %b'))
        dqs = Alert.objects.filter(timestamp__gte=day_start, timestamp__lt=day_end)
        daily_critical.append(dqs.filter(severity='CRITICAL').count())
        daily_high.append(dqs.filter(severity='HIGH').count())
        daily_medium.append(dqs.filter(severity='MEDIUM').count())
        daily_low.append(dqs.filter(severity='LOW').count())

    # ── Severity donut (7 days) ─────────────────────────────────
    sev_qs = Alert.objects.filter(timestamp__gte=last_7d)
    donut_data = [
        sev_qs.filter(severity='CRITICAL').count(),
        sev_qs.filter(severity='HIGH').count(),
        sev_qs.filter(severity='MEDIUM').count(),
        sev_qs.filter(severity='LOW').count(),
        sev_qs.filter(severity='INFO').count(),
    ]

    # ── Top Attacked Agents (7 days, CRITICAL+HIGH) ─────────────
    top_agents = (
        Alert.objects.filter(timestamp__gte=last_7d, severity__in=['CRITICAL', 'HIGH'])
        .values('agent_name', 'agent_ip')
        .annotate(count=Count('id'))
        .order_by('-count')[:8]
    )

    # ── Top Rules (7 days) ──────────────────────────────────────
    top_rules = (
        Alert.objects.filter(timestamp__gte=last_7d)
        .values('rule_id', 'rule_description')
        .annotate(count=Count('id'))
        .order_by('-count')[:8]
    )

    # ── MITRE ATT&CK Tactics (7 days) ──────────────────────────
    mitre_raw = (
        Alert.objects.filter(timestamp__gte=last_7d, mitre_id__isnull=False)
        .exclude(mitre_id='')
        .values('mitre_id')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )
    mitre_data = list(mitre_raw)

    # ── Recent open incidents ───────────────────────────────────
    recent_incidents = (
        Incident.objects.select_related('alert')
        .exclude(status__in=['Resolved', 'Closed'])
        .order_by('-created_at')[:6]
    )

    # ── Recent critical/high alerts (24h) ──────────────────────
    recent_critical = Alert.objects.filter(
        severity__in=['CRITICAL', 'HIGH'],
        timestamp__gte=last_24h,
    ).select_related('ai_analysis').order_by('-timestamp')[:10]

    # ── SLA Summary ─────────────────────────────────────────────
    from apps.sla.models import SLAPolicy
    from apps.vulnerabilities.models import Vulnerability
    sla_breach_inc  = 0
    sla_breach_vuln = 0
    sla_breached_list = []
    try:
        policies = {p.severity: p for p in SLAPolicy.objects.filter(is_active=True)}
        today = now.date()
        for sev, policy in policies.items():
            threshold_inc  = timedelta(hours=policy.resolve_hours)
            threshold_days = policy.resolve_hours / 24.0
            sla_breach_inc += Incident.objects.filter(
                severity=sev, status__in=['New', 'InProgress'],
                created_at__lt=now - threshold_inc,
            ).count()
            breach_date = today - timedelta(days=threshold_days)
            sla_breach_vuln += Vulnerability.objects.filter(
                severity=sev, status__in=['open', 'in_progress'],
                discovered_at__lt=breach_date,
            ).count()
        # Top 5 most overdue incidents for mini-table
        for sev, policy in policies.items():
            threshold_inc = timedelta(hours=policy.resolve_hours)
            qs = Incident.objects.filter(
                severity=sev, status__in=['New', 'InProgress'],
                created_at__lt=now - threshold_inc,
            ).order_by('created_at')[:5]
            for inc in qs:
                overdue_h = round((now - inc.created_at).total_seconds() / 3600 - policy.resolve_hours, 1)
                sla_breached_list.append({'inc': inc, 'overdue_h': overdue_h})
        sla_breached_list.sort(key=lambda x: x['inc'].created_at)
        sla_breached_list = sla_breached_list[:5]
    except Exception:
        pass

    context = {
        # KPI cards
        'critical_count':      critical_count,
        'high_count':          high_count,
        'medium_count':        medium_count,
        'total_count':         total_count,
        'open_incident_count': open_incident_count,
        'new_incident_count':  new_incident_count,
        'inprogress_count':    inprogress_count,
        'coverage_pct':        coverage_pct,
        'coverage_analyzed':   coverage_analyzed,
        'coverage_total':      coverage_total,
        'this_week_total':     this_week_total,
        'prev_week_total':     prev_week_total,
        'week_change_pct':     week_change_pct,
        # Charts
        'hourly_labels':   json.dumps(hourly_labels),
        'hourly_critical': json.dumps(hourly_critical),
        'hourly_high':     json.dumps(hourly_high),
        'hourly_medium':   json.dumps(hourly_medium),
        'hourly_low':      json.dumps(hourly_low),
        'daily_labels':    json.dumps(daily_labels),
        'daily_critical':  json.dumps(daily_critical),
        'daily_high':      json.dumps(daily_high),
        'daily_medium':    json.dumps(daily_medium),
        'daily_low':       json.dumps(daily_low),
        'donut_data':      json.dumps(donut_data),
        'top_rules':       json.dumps(list(top_rules)),
        'top_agents':      json.dumps(list(top_agents)),
        'mitre_data':      json.dumps(mitre_data),
        # Tables
        'recent_critical':  recent_critical,
        'recent_incidents': recent_incidents,
        # SLA
        'sla_breach_inc':   sla_breach_inc,
        'sla_breach_vuln':  sla_breach_vuln,
        'sla_breached_list': sla_breached_list,
    }
    return render(request, 'core/dashboard.html', context)


def _version_gt(a, b):
    """Return True if version a > version b (semver)."""
    try:
        return tuple(int(x) for x in a.split('.')) > tuple(int(x) for x in b.split('.'))
    except Exception:
        return False


@login_required
def check_update(request):
    """AJAX — ตรวจ version ใหม่จาก GitHub, cache 1 ชม."""
    from django.core.cache import cache
    CACHE_KEY = 'soc_latest_version'

    cached = cache.get(CACHE_KEY)
    if cached:
        return JsonResponse(cached)

    current = settings.APP_VERSION
    try:
        req = urllib.request.Request(
            'https://api.github.com/repos/jacom/SOC-Dashboard/releases/latest',
            headers={'User-Agent': 'SOC-Dashboard', 'Accept': 'application/vnd.github+json'},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        latest = data.get('tag_name', '').lstrip('v')
        result = {
            'ok': True,
            'current': current,
            'latest': latest,
            'has_update': _version_gt(latest, current),
            'release_url': data.get('html_url', ''),
            'release_name': data.get('name', f'v{latest}'),
        }
    except Exception as e:
        result = {'ok': False, 'current': current, 'latest': current, 'has_update': False}

    cache.set(CACHE_KEY, result, 3600)
    return JsonResponse(result)


@login_required
@require_POST
def do_update(request):
    """รัน update script แล้ว restart service."""
    from django.core.cache import cache

    script = settings.BASE_DIR / 'scripts' / 'update.sh'

    try:
        result = subprocess.run(
            ['bash', str(script)],
            capture_output=True, text=True, timeout=300,
            cwd=str(settings.BASE_DIR),
        )
        if result.returncode != 0:
            return JsonResponse({'ok': False, 'error': result.stderr[-1000:] or result.stdout[-500:]})
        output = result.stdout
    except subprocess.TimeoutExpired:
        return JsonResponse({'ok': False, 'error': 'Update timed out (5 min)'})
    except Exception as e:
        return JsonResponse({'ok': False, 'error': str(e)})

    # ล้าง version cache เพื่อให้เช็คใหม่หลัง restart
    cache.delete('soc_latest_version')

    # Restart ใน background thread (หลังส่ง response)
    def _restart():
        import time
        time.sleep(1)
        subprocess.run(
            ['sudo', 'systemctl', 'restart', 'soc-dashboard', 'soc-fetcher', 'soc-bot'],
            timeout=30,
        )

    threading.Thread(target=_restart, daemon=True).start()

    return JsonResponse({'ok': True, 'output': output})
