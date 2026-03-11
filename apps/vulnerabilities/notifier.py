"""
Vulnerability notification helpers.
- notify_vuln_registered: LINE (MOPH) when a vuln is saved from Wazuh Live
- notify_ai_complete: email to asset owner + LINE (MOPH) after AI analysis
"""
import json
import logging
import smtplib
import urllib.request
import urllib.error
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

SEV_BG   = {'CRITICAL': '#FFD5D5', 'HIGH': '#FFF3CD', 'MEDIUM': '#D5E8FF', 'LOW': '#D5FFE0'}
SEV_TEXT = {'CRITICAL': '#CC0000', 'HIGH': '#8B6914', 'MEDIUM': '#1A5FBF', 'LOW': '#1A7A2F'}


def _get_configs():
    from apps.config.models import IntegrationConfig
    keys = [
        'MOPH_NOTIFY_URL', 'MOPH_NOTIFY_CLIENT_KEY', 'MOPH_NOTIFY_SECRET_KEY',
        'MOPH_IMG_CRITICAL', 'MOPH_IMG_HIGH', 'MOPH_IMG_MEDIUM', 'MOPH_IMG_LOW', 'MOPH_IMG_INFO',
        'SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM', 'SMTP_TLS',
    ]
    return {c.key: c.value for c in IntegrationConfig.objects.filter(key__in=keys)}


def _header_img(configs, severity):
    return (
        configs.get(f'MOPH_IMG_{severity}', '')
        or configs.get('MOPH_IMG_MEDIUM', '')
    )


def _detail_row(label, value):
    return {
        'type': 'box', 'layout': 'horizontal',
        'contents': [
            {'type': 'text', 'text': label, 'flex': 0, 'size': 'sm',
             'color': '#888888', 'gravity': 'center'},
            {'type': 'text', 'text': str(value) if value else '—',
             'size': 'sm', 'margin': 'md', 'weight': 'bold',
             'wrap': True, 'color': '#333333', 'gravity': 'center'},
        ],
    }


def _build_vuln_flex(vuln, title_text, rows, configs):
    sev       = vuln.severity or 'MEDIUM'
    bg        = SEV_BG.get(sev, '#E8E8E8')
    tc        = SEV_TEXT.get(sev, '#333333')
    img_url   = _header_img(configs, sev)

    header = {
        'type': 'box', 'layout': 'vertical',
        'paddingTop': '20px', 'paddingBottom': '0px',
        'paddingStart': '0px', 'paddingEnd': '0px',
        'contents': [{
            'type': 'image', 'url': img_url,
            'size': 'full', 'aspectRatio': '3120:885', 'aspectMode': 'cover',
        }],
    } if img_url else None

    body_contents = [
        {
            'type': 'box', 'layout': 'vertical',
            'backgroundColor': bg, 'cornerRadius': '15px',
            'paddingTop': 'lg', 'paddingBottom': 'lg',
            'paddingStart': '8px', 'paddingEnd': '8px',
            'contents': [{
                'type': 'text', 'text': f'[{sev}] {title_text}',
                'size': 'lg', 'weight': 'bold', 'color': tc,
                'align': 'center', 'adjustMode': 'shrink-to-fit',
            }],
        },
        {'type': 'separator', 'margin': '18px'},
        {
            'type': 'box', 'layout': 'vertical',
            'margin': '13px', 'spacing': 'sm',
            'contents': rows,
        },
    ]

    bubble = {
        'type': 'bubble', 'size': 'mega',
        'body': {'type': 'box', 'layout': 'vertical', 'contents': body_contents},
    }
    if header:
        bubble['header'] = header

    alt = f'[{sev}] {title_text} — {vuln.cve_id or ""}'
    return {'messages': [{'type': 'flex', 'altText': alt[:100], 'contents': bubble}]}


def _send_moph(payload, configs):
    base_url   = configs.get('MOPH_NOTIFY_URL', '').rstrip('/')
    client_key = configs.get('MOPH_NOTIFY_CLIENT_KEY', '')
    secret_key = configs.get('MOPH_NOTIFY_SECRET_KEY', '')
    if not base_url or not client_key or not secret_key:
        logger.warning('MOPH Notify ยังไม่ได้ตั้งค่า')
        return False
    try:
        data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        req  = urllib.request.Request(
            f'{base_url}/api/notify/send',
            data=data,
            headers={
                'Content-Type': 'application/json',
                'client-key':   client_key,
                'secret-key':   secret_key,
            },
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            logger.info(f'MOPH vuln notify sent: {resp.status}')
            return True
    except Exception as e:
        logger.warning(f'MOPH vuln notify failed: {e}')
        return False


# ─── Email ────────────────────────────────────────────────────────────────────

def _send_email(to, subject, html_body, configs):
    host      = configs.get('SMTP_HOST', '').strip()
    user      = configs.get('SMTP_USER', '').strip()
    password  = configs.get('SMTP_PASSWORD', '').strip()
    from_addr = configs.get('SMTP_FROM', user).strip() or user
    if not host or not user or not to:
        return False
    try:
        port    = int(configs.get('SMTP_PORT', '587') or '587')
        use_tls = configs.get('SMTP_TLS', 'true').strip().lower() != 'false'

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = from_addr
        msg['To']      = to
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        server = smtplib.SMTP(host, port, timeout=15) if use_tls else smtplib.SMTP_SSL(host, port, timeout=15)
        if use_tls:
            server.starttls()
        server.login(user, password)
        server.sendmail(from_addr, [to], msg.as_string())
        server.quit()
        logger.info(f'Email sent to {to}: {subject}')
        return True
    except Exception as e:
        logger.warning(f'Email send failed to {to}: {e}')
        return False


# ─── Public API ──────────────────────────────────────────────────────────────

def notify_vuln_registered(vuln) -> None:
    """LINE via MOPH when a vulnerability is saved from Wazuh Live."""
    configs    = _get_configs()
    owner_name = vuln.asset.owner if vuln.asset else ''
    hostname   = vuln.asset.hostname if vuln.asset else ''

    rows = [
        _detail_row('CVE ID',    vuln.cve_id or '—'),
        {'type': 'separator', 'margin': 'sm'},
        _detail_row('Title',     (vuln.title or vuln.cve_id or '—')[:80]),
        {'type': 'separator', 'margin': 'sm'},
        _detail_row('Agent IP',  str(vuln.agent_ip) if vuln.agent_ip else '—'),
    ]
    if hostname:
        rows += [{'type': 'separator', 'margin': 'sm'}, _detail_row('Host', hostname)]
    if owner_name:
        rows += [{'type': 'separator', 'margin': 'sm'}, _detail_row('เจ้าของ', owner_name)]
    rows += [
        {'type': 'separator', 'margin': 'sm'},
        _detail_row('Status', vuln.status or '—'),
    ]

    payload = _build_vuln_flex(vuln, 'Vulnerability Registered', rows, configs)
    _send_moph(payload, configs)


def notify_ai_complete(vuln, analysis: dict) -> None:
    """LINE via MOPH + email to asset owner after AI analysis."""
    configs    = _get_configs()
    cve_id     = vuln.cve_id or 'N/A'
    sev        = vuln.severity or 'UNKNOWN'
    risk       = analysis.get('risk_level', sev)
    urgency    = analysis.get('urgency', '—')
    summary_th = analysis.get('summary_th', '')
    owner_name = vuln.asset.owner if vuln.asset else ''
    hostname   = vuln.asset.hostname if vuln.asset else ''

    # ── LINE via MOPH ──
    rows = [
        _detail_row('CVE ID',   cve_id),
        {'type': 'separator', 'margin': 'sm'},
        _detail_row('Title',    (vuln.title or cve_id)[:80]),
        {'type': 'separator', 'margin': 'sm'},
        _detail_row('Agent IP', str(vuln.agent_ip) if vuln.agent_ip else '—'),
    ]
    if hostname:
        rows += [{'type': 'separator', 'margin': 'sm'}, _detail_row('Host', hostname)]
    if owner_name:
        rows += [{'type': 'separator', 'margin': 'sm'}, _detail_row('เจ้าของ', owner_name)]
    rows += [
        {'type': 'separator', 'margin': 'sm'},
        _detail_row('Risk',    risk),
        {'type': 'separator', 'margin': 'sm'},
        _detail_row('Urgency', urgency),
    ]
    if summary_th:
        rows += [
            {'type': 'separator', 'margin': 'sm'},
            {'type': 'text', 'text': summary_th[:200], 'size': 'sm',
             'wrap': True, 'color': '#555555', 'margin': 'sm'},
        ]

    payload = _build_vuln_flex(vuln, 'AI Analysis Complete', rows, configs)
    _send_moph(payload, configs)

    # ── Email ──
    if not vuln.asset:
        return
    owner_email = (vuln.asset.owner_email or '').strip()
    if not owner_email:
        return

    sev_colors = {'CRITICAL': '#f85149', 'HIGH': '#f85149', 'HIGH': '#e3b341'}
    risk_color = '#f85149' if risk.upper() in ('CRITICAL', 'HIGH') else '#e3b341'
    sev_emoji  = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(sev, '⚪')

    subject = f'[SOC Alert] AI Analysis: {cve_id} — {sev}'
    html = f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;">
  <div style="max-width:640px;margin:auto;background:#161b22;border-radius:8px;padding:24px;border:1px solid #30363d;">
    <h2 style="color:#58a6ff;margin-top:0;">🤖 AI Vulnerability Analysis</h2>
    <table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
      <tr><td style="color:#8b949e;padding:4px 0;width:130px;">CVE ID</td>
          <td style="color:#79c0ff;font-weight:bold;">{cve_id}</td></tr>
      <tr><td style="color:#8b949e;padding:4px 0;">Title</td>
          <td>{vuln.title or cve_id}</td></tr>
      <tr><td style="color:#8b949e;padding:4px 0;">Severity</td>
          <td>{sev_emoji} <strong>{sev}</strong></td></tr>
      <tr><td style="color:#8b949e;padding:4px 0;">Risk Level</td>
          <td><strong style="color:{risk_color};">{risk}</strong></td></tr>
      <tr><td style="color:#8b949e;padding:4px 0;">Urgency</td>
          <td>{urgency}</td></tr>
      {'<tr><td style="color:#8b949e;padding:4px 0;">Agent IP</td><td>' + str(vuln.agent_ip) + '</td></tr>' if vuln.agent_ip else ''}
      {'<tr><td style="color:#8b949e;padding:4px 0;">Host</td><td>' + hostname + '</td></tr>' if hostname else ''}
      {'<tr><td style="color:#8b949e;padding:4px 0;">เจ้าของ</td><td>' + owner_name + '</td></tr>' if owner_name else ''}
    </table>
    <hr style="border-color:#30363d;margin:16px 0;">
    <h3 style="color:#58a6ff;font-size:1rem;">สรุปช่องโหว่</h3>
    <p style="line-height:1.6;">{summary_th or '—'}</p>
    <h3 style="color:#58a6ff;font-size:1rem;">ผลกระทบ (Impact)</h3>
    <p style="line-height:1.6;">{analysis.get('impact', '—')}</p>
    <h3 style="color:#58a6ff;font-size:1rem;">ขั้นตอนการแก้ไข (Thai)</h3>
    <p style="line-height:1.6;">{analysis.get('remediation_th', '—')}</p>
    <h3 style="color:#58a6ff;font-size:1rem;">Remediation (English)</h3>
    <p style="line-height:1.6;">{analysis.get('remediation', '—')}</p>
    <hr style="border-color:#30363d;margin:16px 0;">
    <p style="font-size:0.8rem;color:#8b949e;">
      Urgency Reason: {analysis.get('urgency_reason', '—')}<br>
      Exploitability: {analysis.get('exploitability', '—')}
    </p>
    <p style="font-size:0.75rem;color:#484f58;margin-top:16px;">Automated notification from SOC Dashboard.</p>
  </div>
</body>
</html>"""

    _send_email(owner_email, subject, html, configs)
