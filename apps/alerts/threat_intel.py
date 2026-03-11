import logging
import requests
from django.utils import timezone

logger = logging.getLogger(__name__)
CACHE_HOURS = 24  # re-check after 24h


def _get_api_key(key_name):
    from apps.config.models import IntegrationConfig
    try:
        return IntegrationConfig.objects.get(key=key_name).value or ''
    except Exception:
        return ''


def check_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB. Returns dict with is_malicious, score, country, isp, domain, raw."""
    api_key = _get_api_key('ABUSEIPDB_API_KEY')
    if not api_key:
        return {'error': 'No API key'}
    try:
        resp = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            headers={'Key': api_key, 'Accept': 'application/json'},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get('data', {})
        score = data.get('abuseConfidenceScore', 0)
        return {
            'is_malicious': score >= 25,
            'score': score,
            'country': data.get('countryCode', ''),
            'isp': data.get('isp', ''),
            'domain': data.get('domain', ''),
            'raw': data,
        }
    except Exception as e:
        logger.error(f'AbuseIPDB check {ip}: {e}')
        return {'error': str(e)}


def check_virustotal(ip: str) -> dict:
    """Query VirusTotal IP report. Returns dict with is_malicious, score, country, raw."""
    api_key = _get_api_key('VIRUSTOTAL_API_KEY')
    if not api_key:
        return {'error': 'No API key'}
    try:
        resp = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers={'x-apikey': api_key},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get('data', {}).get('attributes', {})
        stats = data.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        score = malicious + suspicious
        return {
            'is_malicious': malicious >= 1,
            'score': score,
            'country': data.get('country', ''),
            'isp': data.get('as_owner', ''),
            'domain': '',
            'raw': data,
        }
    except Exception as e:
        logger.error(f'VirusTotal check {ip}: {e}')
        return {'error': str(e)}


def lookup_ip(ip: str, force: bool = False) -> list:
    """
    Run both providers. Cache results for CACHE_HOURS.
    Returns list of ThreatIntelResult objects.
    """
    from .models import ThreatIntelResult
    results = []
    cutoff = timezone.now() - timezone.timedelta(hours=CACHE_HOURS)

    for provider, fn in [('abuseipdb', check_abuseipdb), ('virustotal', check_virustotal)]:
        obj, created = ThreatIntelResult.objects.get_or_create(
            ip_address=ip, provider=provider,
            defaults={'raw_data': {}}
        )
        # use cache unless forced or too old
        if not force and not created and obj.checked_at >= cutoff:
            results.append(obj)
            continue
        data = fn(ip)
        if 'error' not in data:
            obj.is_malicious = data['is_malicious']
            obj.score        = data['score']
            obj.country      = data.get('country', '')
            obj.isp          = data.get('isp', '')
            obj.domain       = data.get('domain', '')
            obj.raw_data     = data.get('raw', {})
            obj.save()
        results.append(obj)
    return results
