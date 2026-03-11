import json
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.http import require_POST, require_http_methods
from .models import Asset


@login_required
def asset_list(request):
    q = request.GET.get('q', '').strip()
    assets = Asset.objects.all()
    if q:
        assets = assets.filter(agent_ip__icontains=q) | \
                 Asset.objects.filter(agent_name__icontains=q) | \
                 Asset.objects.filter(hostname__icontains=q) | \
                 Asset.objects.filter(owner__icontains=q) | \
                 Asset.objects.filter(department__icontains=q)
        assets = assets.distinct()
    return render(request, 'assets/list.html', {'assets': assets, 'q': q})


@login_required
def asset_detail(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    from apps.alerts.models import Alert
    from django.db.models import Count
    recent_alerts = Alert.objects.filter(agent_ip=asset.agent_ip).order_by('-timestamp')[:20]
    sev_counts = Alert.objects.filter(agent_ip=asset.agent_ip).values('severity').annotate(n=Count('id'))
    counts = {s['severity']: s['n'] for s in sev_counts}
    return render(request, 'assets/detail.html', {
        'asset': asset,
        'recent_alerts': recent_alerts,
        'count_critical': counts.get('CRITICAL', 0),
        'count_high':     counts.get('HIGH', 0),
        'count_medium':   counts.get('MEDIUM', 0),
        'count_low':      counts.get('LOW', 0),
    })


@login_required
@require_POST
def asset_add(request):
    # รองรับทั้ง multipart/form-data (มีรูป) และ JSON
    if request.content_type and 'multipart' in request.content_type:
        data = request.POST
        image_file = request.FILES.get('image')
    else:
        try:
            data = json.loads(request.body)
        except Exception:
            data = request.POST
        image_file = None

    agent_ip = (data.get('agent_ip') or '').strip()
    if not agent_ip:
        return JsonResponse({'ok': False, 'error': 'agent_ip is required'}, status=400)

    defaults = {
        'agent_name':   (data.get('agent_name') or '').strip(),
        'hostname':     (data.get('hostname') or '').strip(),
        'owner':        (data.get('owner') or '').strip(),
        'owner_email':  (data.get('owner_email') or '').strip(),
        'department':   (data.get('department') or '').strip(),
        'asset_type':   data.get('asset_type') or 'workstation',
        'machine_type': data.get('machine_type') or 'physical',
        'criticality':  data.get('criticality') or 'MEDIUM',
        'location':     (data.get('location') or '').strip(),
        'notes':        (data.get('notes') or '').strip(),
    }
    asset, created = Asset.objects.update_or_create(agent_ip=agent_ip, defaults=defaults)
    if image_file:
        asset.image = image_file
        asset.save(update_fields=['image'])

    return JsonResponse({
        'ok': True, 'created': created,
        'id': asset.pk, 'agent_ip': asset.agent_ip,
        'agent_name': asset.agent_name, 'owner': asset.owner,
        'department': asset.department, 'criticality': asset.criticality,
        'asset_type': asset.asset_type, 'machine_type': asset.machine_type,
    })


@login_required
def asset_edit(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    if request.method == 'GET':
        return JsonResponse({
            'ok': True,
            'id': asset.pk,
            'agent_ip': asset.agent_ip,
            'agent_name': asset.agent_name,
            'hostname': asset.hostname,
            'owner': asset.owner,
            'owner_email': asset.owner_email,
            'department': asset.department,
            'asset_type': asset.asset_type,
            'machine_type': asset.machine_type,
            'criticality': asset.criticality,
            'location': asset.location,
            'notes': asset.notes,
            'image_url': asset.image.url if asset.image else '',
        })
    # POST — update (multipart for image, JSON otherwise)
    if request.content_type and 'multipart' in request.content_type:
        data = request.POST
        image_file = request.FILES.get('image')
    else:
        try:
            data = json.loads(request.body)
        except Exception:
            data = request.POST
        image_file = None

    asset.agent_name   = (data.get('agent_name') or '').strip()
    asset.hostname     = (data.get('hostname') or '').strip()
    asset.owner        = (data.get('owner') or '').strip()
    asset.owner_email  = (data.get('owner_email') or '').strip()
    asset.department   = (data.get('department') or '').strip()
    asset.asset_type   = data.get('asset_type') or asset.asset_type
    asset.machine_type = data.get('machine_type') or asset.machine_type
    asset.criticality  = data.get('criticality') or asset.criticality
    asset.location     = (data.get('location') or '').strip()
    asset.notes        = (data.get('notes') or '').strip()
    if image_file:
        asset.image = image_file
    asset.save()
    return JsonResponse({'ok': True, 'id': asset.pk})


@login_required
@require_POST
def asset_delete(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    asset.delete()
    return JsonResponse({'ok': True})


@login_required
def agent_choices(request):
    """Return distinct agent_ip+agent_name from Alert table, excluding already-registered IPs."""
    from apps.alerts.models import Alert
    registered_ips = set(Asset.objects.values_list('agent_ip', flat=True))
    agents = (
        Alert.objects
        .exclude(agent_ip__isnull=True)
        .values('agent_ip', 'agent_name')
        .distinct()
        .order_by('agent_ip')
    )
    # deduplicate by IP, keep latest agent_name
    seen = {}
    for a in agents:
        ip = a['agent_ip']
        if ip and ip not in seen:
            seen[ip] = a['agent_name'] or ''
    result = [
        {'ip': ip, 'name': name, 'registered': ip in registered_ips}
        for ip, name in seen.items()
    ]
    return JsonResponse({'ok': True, 'agents': result})


@login_required
def asset_lookup(request):
    """Quick lookup by IP — used by alert detail page."""
    ip = request.GET.get('ip', '').strip()
    if not ip:
        return JsonResponse({'found': False})
    try:
        asset = Asset.objects.get(agent_ip=ip)
        return JsonResponse({
            'found': True,
            'id': asset.pk,
            'agent_name': asset.agent_name,
            'hostname': asset.hostname,
            'owner': asset.owner,
            'department': asset.department,
            'asset_type': asset.asset_type,
            'criticality': asset.criticality,
            'criticality_color': asset.criticality_color(),
            'location': asset.location,
            'notes': asset.notes,
        })
    except Asset.DoesNotExist:
        return JsonResponse({'found': False})
