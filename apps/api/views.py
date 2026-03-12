from datetime import date, timedelta

from django.db.models import Count, Q
from django.utils import timezone
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response

from apps.alerts.models import Alert
from apps.incidents.models import Incident
from apps.vulnerabilities.models import Vulnerability
from apps.sla.models import SLAPolicy
from .authentication import MISApiKeyAuthentication
from .permissions import HasMISApiKey

_auth    = [MISApiKeyAuthentication]
_perm    = [HasMISApiKey]


# ── /api/v1/mis/summary/ ──────────────────────────────────────────────────────
@api_view(['GET'])
@authentication_classes(_auth)
@permission_classes(_perm)
def summary(request):
    today    = date.today()
    last_24h = timezone.now() - timedelta(hours=24)
    last_7d  = timezone.now() - timedelta(days=7)

    alert_counts = Alert.objects.aggregate(
        total     = Count('id'),
        critical  = Count('id', filter=Q(severity='CRITICAL')),
        high      = Count('id', filter=Q(severity='HIGH')),
        medium    = Count('id', filter=Q(severity='MEDIUM')),
        low       = Count('id', filter=Q(severity='LOW')),
        last_24h  = Count('id', filter=Q(timestamp__gte=last_24h)),
        last_7d   = Count('id', filter=Q(timestamp__gte=last_7d)),
    )

    incident_counts = Incident.objects.aggregate(
        total       = Count('id'),
        open        = Count('id', filter=Q(status='New')),
        in_progress = Count('id', filter=Q(status='InProgress')),
        resolved    = Count('id', filter=Q(status='Resolved')),
        closed      = Count('id', filter=Q(status='Closed')),
    )

    vuln_counts = Vulnerability.objects.aggregate(
        total     = Count('id'),
        critical  = Count('id', filter=Q(severity='CRITICAL')),
        high      = Count('id', filter=Q(severity='HIGH')),
        open      = Count('id', filter=Q(status='open')),
        resolved  = Count('id', filter=Q(status='resolved')),
    )

    return Response({
        'generated_at': timezone.now().isoformat(),
        'alerts':       alert_counts,
        'incidents':    incident_counts,
        'vulnerabilities': vuln_counts,
    })


# ── /api/v1/mis/alerts/ ───────────────────────────────────────────────────────
@api_view(['GET'])
@authentication_classes(_auth)
@permission_classes(_perm)
def alert_list(request):
    limit    = min(int(request.GET.get('limit', 50)), 200)
    severity = request.GET.get('severity')

    qs = Alert.objects.order_by('-timestamp')
    if severity:
        qs = qs.filter(severity=severity.upper())

    alerts = qs[:limit].values(
        'id', 'wazuh_id', 'timestamp', 'agent_name', 'agent_ip',
        'rule_id', 'rule_level', 'rule_description', 'mitre_id',
        'severity', 'dismissed',
    )
    return Response({'count': len(alerts), 'results': list(alerts)})


# ── /api/v1/mis/incidents/ ────────────────────────────────────────────────────
@api_view(['GET'])
@authentication_classes(_auth)
@permission_classes(_perm)
def incident_list(request):
    limit  = min(int(request.GET.get('limit', 50)), 200)
    status = request.GET.get('status')

    qs = Incident.objects.order_by('-created_at')
    if status:
        qs = qs.filter(status=status)

    incidents = qs[:limit].values(
        'id', 'thehive_case_id', 'title', 'status',
        'severity', 'created_at', 'updated_at',
    )
    return Response({'count': len(incidents), 'results': list(incidents)})


# ── /api/v1/mis/vulnerabilities/ ─────────────────────────────────────────────
@api_view(['GET'])
@authentication_classes(_auth)
@permission_classes(_perm)
def vulnerability_list(request):
    limit    = min(int(request.GET.get('limit', 50)), 200)
    severity = request.GET.get('severity')
    status   = request.GET.get('status')

    qs = Vulnerability.objects.order_by('-discovered_at')
    if severity:
        qs = qs.filter(severity=severity.upper())
    if status:
        qs = qs.filter(status=status)

    vulns = qs[:limit].values(
        'id', 'title', 'cve_id', 'severity', 'status',
        'agent_ip', 'discovered_at', 'due_date',
    )
    return Response({'count': len(vulns), 'results': list(vulns)})
