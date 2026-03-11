import json
import requests
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.db.models import Q, Count
from django.views.decorators.http import require_http_methods

from .models import Vulnerability, VulnerabilityAIAnalysis


def _opensearch_request(method, path, body=None):
    url  = settings.WAZUH_INDEXER_URL.rstrip('/') + path
    auth = (settings.WAZUH_INDEXER_USERNAME, settings.WAZUH_INDEXER_PASSWORD)
    kwargs = dict(auth=auth, verify=False, timeout=15)
    if body:
        kwargs['json'] = body
    resp = getattr(requests, method)(url, **kwargs)
    resp.raise_for_status()
    return resp.json()


@login_required
def vuln_wazuh(request):
    """Live vulnerability data from Wazuh Indexer (OpenSearch)."""
    index   = settings.WAZUH_VULN_INDEX
    page    = max(1, int(request.GET.get('page', 1)))
    size    = 50
    from_   = (page - 1) * size
    severity_filter = request.GET.get('severity', '')
    agent_filter    = request.GET.get('agent', '')
    q               = request.GET.get('q', '').strip()

    # Build query
    must = []
    if severity_filter:
        must.append({'match': {'vulnerability.severity': severity_filter}})
    if agent_filter:
        must.append({'match': {'agent.name': agent_filter}})
    if q:
        must.append({'multi_match': {'query': q, 'fields': ['vulnerability.id', 'vulnerability.description', 'package.name']}})

    base_query = {'bool': {'must': must}} if must else {'match_all': {}}

    # Build agent_name → IP lookup from local Asset + Alert tables
    from apps.assets.models import Asset
    from apps.alerts.models import Alert as AlertModel
    agent_ip_lookup = {}
    for row in AlertModel.objects.exclude(agent_ip=None).values('agent_name', 'agent_ip').distinct():
        if row['agent_name'] and row['agent_ip']:
            agent_ip_lookup[row['agent_name']] = str(row['agent_ip'])
    for asset in Asset.objects.exclude(agent_name='').exclude(agent_ip=None):
        agent_ip_lookup[asset.agent_name] = str(asset.agent_ip)

    try:
        # Aggregations for summary
        agg_body = {
            'size': 0,
            'query': base_query,
            'aggs': {
                'by_severity': {'terms': {'field': 'vulnerability.severity', 'size': 10}},
                'by_agent':    {'terms': {'field': 'agent.name', 'size': 50}},
            }
        }
        agg_resp = _opensearch_request('post', f'/{index}/_search', agg_body)
        sev_buckets   = agg_resp['aggregations']['by_severity']['buckets']
        agent_buckets = agg_resp['aggregations']['by_agent']['buckets']
        sev_counts    = {b['key']: b['doc_count'] for b in sev_buckets}
        agent_list    = [b['key'] for b in agent_buckets]

        # Main search — sort Critical→High→Medium→Low via script
        search_body = {
            'from': from_, 'size': size,
            'query': base_query,
            'sort': [
                {
                    '_script': {
                        'type': 'number',
                        'script': {
                            'lang': 'painless',
                            'source': (
                                "Map order = ['Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3];"
                                "String sev = doc.containsKey('vulnerability.severity') && !doc['vulnerability.severity'].empty ? doc['vulnerability.severity'].value : '-';"
                                "return order.containsKey(sev) ? order.get(sev) : 4;"
                            ),
                        },
                        'order': 'asc',
                    }
                },
                {'vulnerability.detected_at': {'order': 'desc'}},
            ],
            '_source': [
                'vulnerability.id', 'vulnerability.severity', 'vulnerability.score.base',
                'vulnerability.score.version', 'vulnerability.description',
                'vulnerability.detected_at', 'vulnerability.published_at',
                'vulnerability.reference', 'vulnerability.category',
                'vulnerability.scanner.source', 'vulnerability.scanner.condition',
                'vulnerability.under_evaluation',
                'agent.name', 'agent.id',
                'package.name', 'package.version', 'package.architecture',
                'package.type', 'package.description', 'package.installed',
                'host.os.full', 'host.os.kernel', 'host.os.platform',
            ]
        }
        search_resp = _opensearch_request('post', f'/{index}/_search', search_body)
        total_hits  = search_resp['hits']['total']['value']
        hits        = search_resp['hits']['hits']

        vulns = []
        sev_color = {'Critical': 'danger', 'High': 'warning', 'Medium': 'info', 'Low': 'secondary'}
        for h in hits:
            s = h['_source']
            vuln_data  = s.get('vulnerability', {})
            sev        = vuln_data.get('severity', '-')
            pkg_name   = s.get('package', {}).get('name', '')
            pkg_ver    = s.get('package', {}).get('version', '')
            cve_id     = vuln_data.get('id', '')
            agent_name  = s.get('agent', {}).get('name', '')
            agent_ip    = agent_ip_lookup.get(agent_name, '')
            pkg         = s.get('package', {})
            os_data     = s.get('host', {}).get('os', {})
            scanner     = vuln_data.get('scanner', {})
            desc_full   = (vuln_data.get('description', '') or '')
            vulns.append({
                'cve_id':           cve_id,
                'severity':         sev,
                'sev_upper':        sev.upper(),
                'sev_color':        sev_color.get(sev, 'secondary'),
                'score':            vuln_data.get('score', {}).get('base', ''),
                'score_ver':        vuln_data.get('score', {}).get('version', ''),
                'description':      desc_full[:120],
                'description_full': desc_full[:2000],
                'detected_at':      (vuln_data.get('detected_at', '') or '')[:10],
                'published_at':     (vuln_data.get('published_at', '') or '')[:10],
                'reference':        vuln_data.get('reference', ''),
                'category':         vuln_data.get('category', ''),
                'scanner_source':   scanner.get('source', ''),
                'scanner_cond':     scanner.get('condition', ''),
                'agent_name':       agent_name,
                'agent_ip':         agent_ip,
                'package':          f"{pkg_name} {pkg_ver}".strip(),
                'pkg_name':         pkg_name,
                'pkg_ver':          pkg_ver,
                'pkg_arch':         pkg.get('architecture', ''),
                'pkg_type':         pkg.get('type', ''),
                'pkg_installed':    (pkg.get('installed', '') or '')[:10],
                'os':               os_data.get('full', ''),
                'os_kernel':        os_data.get('kernel', ''),
                'title':            f"{cve_id} — {pkg_name}".strip(' —') if cve_id or pkg_name else 'Vulnerability',
                'imported_key':     f"{cve_id}|{agent_ip}",
            })

        total_pages = (total_hits + size - 1) // size
        error = None
    except Exception as e:
        vulns = []; total_hits = 0; total_pages = 0; page = 1
        sev_counts = {}; agent_list = []
        error = str(e)

    # Import status: check CVE + agent_ip combo so same CVE on different agents shows correctly
    imported_pairs = set(
        f"{cve}|{ip or ''}"
        for cve, ip in Vulnerability.objects.exclude(cve_id='').values_list('cve_id', 'agent_ip')
    )

    # Build compact page range: show first, last, current±2, use -1 as ellipsis
    def build_page_range(current, total):
        pages, seen = [], set()
        for p in ([1, 2] + list(range(current-2, current+3)) + [total-1, total]):
            if 1 <= p <= total:
                pages.append(p); seen.add(p)
        pages = sorted(set(pages))
        result = []
        prev = None
        for p in pages:
            if prev and p - prev > 1:
                result.append(-1)
            result.append(p)
            prev = p
        return result

    return render(request, 'vulnerabilities/wazuh.html', {
        'vulns':           vulns,
        'total_hits':      total_hits,
        'page':            page,
        'total_pages':     total_pages,
        'page_range':      build_page_range(page, total_pages),
        'severity_filter': severity_filter,
        'agent_filter':    agent_filter,
        'q':               q,
        'sev_counts':      sev_counts,
        'agent_list':      agent_list,
        'imported_pairs':  imported_pairs,
        'error':           error,
    })


@login_required
def vuln_list(request):
    from django.db.models import Count
    qs = Vulnerability.objects.select_related('asset', 'created_by').prefetch_related('ai_analysis').annotate(
        incident_count=Count('incidents', distinct=True)
    )

    severity_filter = request.GET.get('severity', '')
    status_filter = request.GET.get('status', '')
    q = request.GET.get('q', '').strip()

    if severity_filter:
        qs = qs.filter(severity=severity_filter)
    if status_filter:
        qs = qs.filter(status=status_filter)
    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(cve_id__icontains=q))

    # Summary counts
    all_vulns = Vulnerability.objects.all()
    severity_counts = {
        'CRITICAL': all_vulns.filter(severity='CRITICAL').count(),
        'HIGH': all_vulns.filter(severity='HIGH').count(),
        'MEDIUM': all_vulns.filter(severity='MEDIUM').count(),
        'LOW': all_vulns.filter(severity='LOW').count(),
    }
    status_counts = {
        'open': all_vulns.filter(status='open').count(),
        'in_progress': all_vulns.filter(status='in_progress').count(),
        'mitigated': all_vulns.filter(status='mitigated').count(),
        'resolved': all_vulns.filter(status='resolved').count(),
        'accepted': all_vulns.filter(status='accepted').count(),
    }

    context = {
        'vulns': qs,
        'severity_filter': severity_filter,
        'status_filter': status_filter,
        'q': q,
        'severity_counts': severity_counts,
        'status_counts': status_counts,
        'severity_choices': Vulnerability.SEVERITY_CHOICES,
        'status_choices': Vulnerability.STATUS_CHOICES,
    }
    return render(request, 'vulnerabilities/list.html', context)


@login_required
@require_http_methods(['POST'])
def vuln_add(request):
    try:
        data = json.loads(request.body)
        vuln = Vulnerability(
            title=data.get('title', '').strip(),
            cve_id=data.get('cve_id', '').strip(),
            agent_ip=data.get('agent_ip') or None,
            severity=data.get('severity', 'MEDIUM'),
            status=data.get('status', 'open'),
            description=data.get('description', ''),
            remediation=data.get('remediation', ''),
            discovered_at=data.get('discovered_at'),
            due_date=data.get('due_date') or None,
            resolved_at=data.get('resolved_at') or None,
            created_by=request.user,
        )
        vuln.full_clean()
        vuln.save()
        # Auto-link Asset by agent_ip
        if vuln.agent_ip:
            from apps.assets.models import Asset
            try:
                vuln.asset = Asset.objects.get(agent_ip=str(vuln.agent_ip))
                vuln.save(update_fields=['asset'])
            except Asset.DoesNotExist:
                pass
        # Notify LINE when saved from Wazuh Live (fire-and-forget)
        try:
            from .notifier import notify_vuln_registered
            notify_vuln_registered(vuln)
        except Exception:
            pass
        try:
            from apps.core.audit import audit
            audit(request, 'vuln_add', 'Vulnerability', vuln.pk,
                  f'{vuln.cve_id or vuln.title} [{vuln.severity}] {vuln.agent_ip or ""}')
        except Exception:
            pass
        return JsonResponse({'ok': True, 'id': vuln.pk})
    except Exception as e:
        return JsonResponse({'ok': False, 'error': str(e)}, status=400)


@login_required
@require_http_methods(['GET'])
def vuln_get(request, pk):
    vuln = get_object_or_404(
        Vulnerability.objects.select_related('asset', 'created_by', 'ai_analysis')
                             .prefetch_related('incidents'),
        pk=pk,
    )
    # AJAX / API call → JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
       request.GET.get('format') == 'json':
        return JsonResponse({
            'id': vuln.pk,
            'title': vuln.title,
            'cve_id': vuln.cve_id,
            'agent_ip': vuln.agent_ip or '',
            'severity': vuln.severity,
            'status': vuln.status,
            'description': vuln.description,
            'remediation': vuln.remediation,
            'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else '',
            'due_date': vuln.due_date.isoformat() if vuln.due_date else '',
            'resolved_at': vuln.resolved_at.isoformat() if vuln.resolved_at else '',
        })
    # Browser → HTML detail page
    linked_incidents = vuln.incidents.select_related('alert').order_by('-created_at')
    return render(request, 'vulnerabilities/detail.html', {
        'vuln': vuln,
        'linked_incidents': linked_incidents,
    })


@login_required
def vuln_edit(request, pk):
    vuln = get_object_or_404(Vulnerability, pk=pk)
    if request.method == 'GET':
        return JsonResponse({
            'id': vuln.pk,
            'title': vuln.title,
            'cve_id': vuln.cve_id,
            'agent_ip': vuln.agent_ip or '',
            'severity': vuln.severity,
            'status': vuln.status,
            'description': vuln.description,
            'remediation': vuln.remediation,
            'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else '',
            'due_date': vuln.due_date.isoformat() if vuln.due_date else '',
            'resolved_at': vuln.resolved_at.isoformat() if vuln.resolved_at else '',
        })
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            vuln.title = data.get('title', vuln.title).strip()
            vuln.cve_id = data.get('cve_id', vuln.cve_id).strip()
            vuln.agent_ip = data.get('agent_ip') or None
            vuln.severity = data.get('severity', vuln.severity)
            vuln.status = data.get('status', vuln.status)
            vuln.description = data.get('description', vuln.description)
            vuln.remediation = data.get('remediation', vuln.remediation)
            vuln.discovered_at = data.get('discovered_at', vuln.discovered_at)
            vuln.due_date = data.get('due_date') or None
            vuln.resolved_at = data.get('resolved_at') or None
            vuln.full_clean()
            vuln.save()
            return JsonResponse({'ok': True})
        except Exception as e:
            return JsonResponse({'ok': False, 'error': str(e)}, status=400)
    return JsonResponse({'ok': False, 'error': 'Method not allowed'}, status=405)


@login_required
@require_http_methods(['POST'])
def vuln_delete(request, pk):
    vuln = get_object_or_404(Vulnerability, pk=pk)
    label = f'{vuln.cve_id or vuln.title} [{vuln.severity}]'
    vuln.delete()
    try:
        from apps.core.audit import audit
        audit(request, 'vuln_delete', 'Vulnerability', pk, f'Deleted {label}')
    except Exception:
        pass
    return JsonResponse({'ok': True})


@login_required
@require_http_methods(['GET'])
def vuln_analysis_get(request, pk):
    """Return saved AI analysis for a vulnerability."""
    vuln = get_object_or_404(Vulnerability, pk=pk)
    try:
        a = vuln.ai_analysis
        return JsonResponse({
            'ok': True,
            'analysis': {
                'risk_level':     a.risk_level,
                'exploitability': a.exploitability,
                'urgency':        a.urgency,
                'urgency_reason': a.urgency_reason,
                'impact':         a.impact,
                'remediation':    a.remediation,
                'remediation_th': a.remediation_th,
                'summary_th':     a.summary_th,
            },
            'model': a.model_used,
            'analyzed_at': a.analyzed_at.strftime('%Y-%m-%d %H:%M'),
        })
    except VulnerabilityAIAnalysis.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'No saved analysis'}, status=404)


@login_required
@require_http_methods(['POST'])
def vuln_ai_analyze(request):
    """Send vulnerability data to AI for analysis. Saves result to DB if vuln_id provided."""
    import re
    import urllib.request
    import urllib.error

    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({'ok': False, 'error': 'Invalid JSON'}, status=400)

    # Load from DB if vuln_id provided
    vuln_id = data.get('vuln_id')
    vuln_obj = None
    if vuln_id:
        try:
            vuln_obj = Vulnerability.objects.get(pk=vuln_id)
        except Vulnerability.DoesNotExist:
            return JsonResponse({'ok': False, 'error': 'Vulnerability not found'}, status=404)

    # ── Get AI config ──
    from apps.config.models import IntegrationConfig
    configs = {c.key: c.value for c in IntegrationConfig.objects.filter(
        key__in=['OPENAI_URL', 'OPENAI_MODEL', 'OPENAI_API_KEY',
                 'OLLAMA_URL', 'OLLAMA_MODEL', 'NOTIFY_AI_SOURCE',
                 'OPENAI_ENABLED', 'OLLAMA_ENABLED']
    )}

    ai_source      = configs.get('NOTIFY_AI_SOURCE', 'both').lower()
    openai_enabled = configs.get('OPENAI_ENABLED', 'true').lower() != 'false'
    ollama_enabled = configs.get('OLLAMA_ENABLED', 'true').lower() != 'false'

    # Decide which API to call
    if ai_source == 'chatgpt' and openai_enabled:
        api_url = configs.get('OPENAI_URL', '').rstrip('/')
        model   = configs.get('OPENAI_MODEL', 'gpt-4o-mini')
        api_key = configs.get('OPENAI_API_KEY', '')
    elif ollama_enabled:
        api_url = configs.get('OLLAMA_URL', 'http://localhost:11434').rstrip('/')
        model   = configs.get('OLLAMA_MODEL', 'openchat:latest')
        api_key = ''
    elif openai_enabled:
        api_url = configs.get('OPENAI_URL', '').rstrip('/')
        model   = configs.get('OPENAI_MODEL', 'gpt-4o-mini')
        api_key = configs.get('OPENAI_API_KEY', '')
    else:
        return JsonResponse({'ok': False, 'error': 'ไม่มี AI service ที่ใช้งานได้ (Ollama/OpenAI ถูกปิด)'}, status=503)

    if not api_url:
        return JsonResponse({'ok': False, 'error': 'ไม่ได้ตั้งค่า AI URL'}, status=503)

    # ── Build prompt ── (prefer DB data when vuln_obj available)
    if vuln_obj:
        cve_id      = vuln_obj.cve_id
        severity    = vuln_obj.severity
        description = vuln_obj.description
        agent_ip    = str(vuln_obj.agent_ip) if vuln_obj.agent_ip else ''
        agent_name  = vuln_obj.asset.agent_name if vuln_obj.asset else ''
        discovered  = vuln_obj.discovered_at.isoformat() if vuln_obj.discovered_at else ''
    else:
        cve_id      = data.get('cve_id', '')
        severity    = data.get('severity', '')
        description = data.get('description_full', '') or data.get('description', '')
        agent_ip    = data.get('agent_ip', '')
        agent_name  = data.get('agent_name', '')
        discovered  = data.get('detected_at', '')
    score        = data.get('score', '')
    score_ver    = data.get('score_ver', '')
    published    = data.get('published_at', '')
    detected     = discovered if vuln_obj else data.get('detected_at', '')
    scanner_src  = data.get('scanner_source', '')
    scanner_cond = data.get('scanner_cond', '')
    os_full      = data.get('os', '')
    os_kernel    = data.get('os_kernel', '')
    pkg_name     = data.get('pkg_name', '')
    pkg_ver      = data.get('pkg_ver', '')
    pkg_arch     = data.get('pkg_arch', '')
    pkg_type     = data.get('pkg_type', '')
    pkg_installed= data.get('pkg_installed', '')

    context_block = f"""CVE ID: {cve_id}
Severity: {severity} | CVSS Score: {score} (v{score_ver})
Published: {published} | Detected by Wazuh: {detected}
Scanner Source: {scanner_src}
Scanner Condition: {scanner_cond}

Affected System:
  Agent Name: {agent_name}
  Agent IP: {agent_ip or 'N/A'}
  OS: {os_full}
  Kernel: {os_kernel or 'N/A'}

Affected Package:
  Name: {pkg_name}
  Version: {pkg_ver}
  Architecture: {pkg_arch}
  Package Type: {pkg_type}
  Installed Date: {pkg_installed or 'N/A'}

CVE Description:
{description}"""

    system_prompt = (
        "You are a SOC security analyst specializing in vulnerability management. "
        "Analyze the given CVE and affected system, then respond ONLY with valid JSON. "
        "No markdown, no extra text, no code blocks."
    )

    user_prompt = f"""\
Analyze this vulnerability and respond with JSON only.

{context_block}

Respond with this exact JSON format (remediation and impact in English, _th fields in Thai):
{{
  "risk_level": "Critical|High|Medium|Low",
  "exploitability": "Brief assessment of how easily this can be exploited",
  "urgency": "Critical|High|Medium|Low",
  "urgency_reason": "Why this urgency level (1-2 sentences)",
  "impact": "Potential impact if exploited (English)",
  "remediation": "Specific remediation steps (English)",
  "remediation_th": "ขั้นตอนการแก้ไขเป็นภาษาไทย",
  "summary_th": "สรุปช่องโหว่นี้เป็นภาษาไทย 2-3 ประโยค"
}}"""

    payload = json.dumps({
        'model': model,
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user',   'content': user_prompt},
        ],
        'temperature': 0.2,
        'stream': False,
    }).encode()

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}' if api_key else 'Bearer ollama',
    }

    try:
        req = urllib.request.Request(
            f'{api_url}/v1/chat/completions',
            data=payload, headers=headers, method='POST',
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
        raw_text = result['choices'][0]['message']['content']
    except urllib.error.URLError as e:
        return JsonResponse({'ok': False, 'error': f'AI connection error: {e.reason}'}, status=503)
    except Exception as e:
        return JsonResponse({'ok': False, 'error': str(e)}, status=503)

    # Parse JSON from response
    match = re.search(r'\{.*\}', raw_text, re.DOTALL)
    if not match:
        return JsonResponse({'ok': False, 'error': 'AI returned unreadable response', 'raw': raw_text[:300]}, status=500)
    try:
        analysis = json.loads(match.group())
    except json.JSONDecodeError:
        cleaned = re.sub(r'(?<=": ")([^"]*?)(?=")',
                         lambda m: m.group(0).replace('\n', ' '), match.group())
        try:
            analysis = json.loads(cleaned)
        except Exception:
            return JsonResponse({'ok': False, 'error': 'Could not parse AI JSON', 'raw': raw_text[:300]}, status=500)

    # Save to DB if we have a vulnerability object
    if vuln_obj:
        VulnerabilityAIAnalysis.objects.update_or_create(
            vulnerability=vuln_obj,
            defaults={
                'risk_level':     analysis.get('risk_level', ''),
                'exploitability': analysis.get('exploitability', ''),
                'urgency':        analysis.get('urgency', ''),
                'urgency_reason': analysis.get('urgency_reason', ''),
                'impact':         analysis.get('impact', ''),
                'remediation':    analysis.get('remediation', ''),
                'remediation_th': analysis.get('remediation_th', ''),
                'summary_th':     analysis.get('summary_th', ''),
                'model_used':     model,
            }
        )
        # Notify email + LINE after AI analysis (fire-and-forget)
        try:
            from .notifier import notify_ai_complete
            notify_ai_complete(vuln_obj, analysis)
        except Exception:
            pass

    return JsonResponse({'ok': True, 'analysis': analysis, 'model': model})
