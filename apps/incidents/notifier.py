"""
Incident notification helpers.
notify_incident_inprogress: email to asset owner when incident moves to InProgress
"""
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

SEV_EMOJI  = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': '⚪'}
SEV_COLOR  = {'CRITICAL': '#f85149', 'HIGH': '#e3b341', 'MEDIUM': '#58a6ff', 'LOW': '#3fb950'}


def _smtp_configs():
    from apps.config.models import IntegrationConfig
    keys = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM', 'SMTP_TLS']
    return {c.key: c.value for c in IntegrationConfig.objects.filter(key__in=keys)}


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
        server  = smtplib.SMTP(host, port, timeout=15) if use_tls else smtplib.SMTP_SSL(host, port, timeout=15)
        if use_tls:
            server.starttls()
        server.login(user, password)
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = from_addr
        msg['To']      = to
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        server.sendmail(from_addr, [to], msg.as_string())
        server.quit()
        logger.info(f'Incident email sent to {to}: {subject}')
        return True
    except Exception as e:
        logger.warning(f'Incident email failed to {to}: {e}')
        return False


def notify_incident_inprogress(incident) -> None:
    """Send email to asset owner when incident status changes to InProgress."""
    from apps.assets.models import Asset

    # Resolve asset via alert agent_ip
    alert = incident.alert
    owner_email = ''
    owner_name  = ''
    hostname    = ''
    agent_ip    = str(alert.agent_ip) if alert.agent_ip else ''
    agent_name  = alert.agent_name or ''

    if agent_ip:
        try:
            asset = Asset.objects.get(agent_ip=agent_ip)
            owner_email = (asset.owner_email or '').strip()
            owner_name  = asset.owner or ''
            hostname    = asset.hostname or ''
        except Asset.DoesNotExist:
            pass

    if not owner_email:
        logger.info(f'Incident #{incident.pk}: no owner_email found, skip email')
        return

    sev        = (incident.severity or 'UNKNOWN').upper()
    emoji      = SEV_EMOJI.get(sev, '⚪')
    sev_color  = SEV_COLOR.get(sev, '#8b949e')
    case_id    = incident.thehive_case_id or f'#{incident.pk}'
    title      = incident.title
    thehive_url = incident.thehive_url or ''

    configs = _smtp_configs()
    subject = f'[SOC Incident] {case_id} กำลังดำเนินการ — {sev}'
    html = f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;">
  <div style="max-width:640px;margin:auto;background:#161b22;border-radius:8px;
              padding:24px;border:1px solid #30363d;">

    <h2 style="color:#58a6ff;margin-top:0;">
      🚨 Incident กำลังดำเนินการ (In Progress)
    </h2>

    <table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
      <tr>
        <td style="color:#8b949e;padding:5px 0;width:140px;">Case ID</td>
        <td style="color:#79c0ff;font-weight:bold;">{case_id}</td>
      </tr>
      <tr>
        <td style="color:#8b949e;padding:5px 0;">Title</td>
        <td><strong>{title}</strong></td>
      </tr>
      <tr>
        <td style="color:#8b949e;padding:5px 0;">Severity</td>
        <td><strong style="color:{sev_color};">{emoji} {sev}</strong></td>
      </tr>
      <tr>
        <td style="color:#8b949e;padding:5px 0;">Status</td>
        <td><span style="background:#e3b341;color:#000;padding:2px 10px;border-radius:4px;
                         font-size:0.85rem;font-weight:bold;">🔄 In Progress</span></td>
      </tr>
      {'<tr><td style="color:#8b949e;padding:5px 0;">Agent IP</td><td>' + agent_ip + '</td></tr>' if agent_ip else ''}
      {'<tr><td style="color:#8b949e;padding:5px 0;">Agent Name</td><td>' + agent_name + '</td></tr>' if agent_name else ''}
      {'<tr><td style="color:#8b949e;padding:5px 0;">Host</td><td>' + hostname + '</td></tr>' if hostname else ''}
      {'<tr><td style="color:#8b949e;padding:5px 0;">เจ้าของ</td><td>' + owner_name + '</td></tr>' if owner_name else ''}
    </table>

    <hr style="border-color:#30363d;margin:16px 0;">

    <p style="line-height:1.6;color:#8b949e;font-size:0.9rem;">
      ทีม SOC กำลังดำเนินการตรวจสอบ Incident นี้อยู่
      กรุณาอย่าปิด session หรือเปลี่ยนแปลงระบบที่เกี่ยวข้องโดยไม่แจ้งทีมก่อน
    </p>

    {'<p><a href="' + thehive_url + '" style="color:#58a6ff;">ดู Case ใน TheHive →</a></p>' if thehive_url else ''}

    <p style="font-size:0.75rem;color:#484f58;margin-top:16px;">
      Automated notification from SOC Dashboard.
    </p>
  </div>
</body>
</html>"""

    _send_email(owner_email, subject, html, configs)
