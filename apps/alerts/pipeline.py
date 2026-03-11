"""
Auto alert pipeline with sequential queue.

Queue guarantees:
  - Only ONE alert is analyzed at a time (no concurrent Ollama/MOPH calls)
  - Wazuh fetch is skipped if queue is not idle (worker busy or items pending)
  - MOPH retry logic is in moph_notifier.py

AI source is controlled by IntegrationConfig key NOTIFY_AI_SOURCE:
  ollama   → Ollama only
             severity_assessment = CRITICAL/HIGH → MOPH Notify + TheHive
             severity_assessment = MEDIUM        → TheHive only
             severity_assessment = LOW/INFO      → stop

  chatgpt  → Chat AI only
             risk_level = Critical/High → MOPH Notify + TheHive
             risk_level other           → stop

  both     → Ollama first, then Chat AI (default — original behaviour)
             severity_assessment = CRITICAL/HIGH → Chat AI gate
               risk_level = Critical/High → MOPH Notify + TheHive
             severity_assessment = MEDIUM → TheHive only
             severity_assessment = LOW/INFO → stop

  Step 3  MOPH Notify (LINE Flex Message)
  Step 4  TheHive incident (auto create)
"""
import json
import logging
import queue
import threading
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

# ── Queue & worker state ───────────────────────────────────────
_pipeline_queue = queue.Queue()
_worker_thread: threading.Thread | None = None
_worker_lock = threading.Lock()
_is_processing = False   # True while worker is actively running run_pipeline


def is_busy() -> bool:
    """True if worker is processing or queue has pending alerts."""
    return _is_processing or not _pipeline_queue.empty()


def queue_depth() -> int:
    return _pipeline_queue.qsize()


# ── Worker ─────────────────────────────────────────────────────

def _worker_loop():
    global _is_processing
    logger.info('Pipeline: worker thread started')
    while True:
        try:
            alert_id = _pipeline_queue.get(timeout=120)
        except queue.Empty:
            continue

        _is_processing = True
        try:
            from .models import Alert
            try:
                alert = Alert.objects.get(pk=alert_id)
            except Alert.DoesNotExist:
                logger.warning(f'Pipeline: alert_id={alert_id} not found in DB')
                continue
            run_pipeline(alert)
        except Exception as e:
            logger.error(f'Pipeline: worker error for alert_id={alert_id}: {e}')
        finally:
            _is_processing = False
            _pipeline_queue.task_done()
            # Close DB connection after each task to prevent idle connection accumulation
            try:
                from django.db import connection as _db_conn
                _db_conn.close()
            except Exception:
                pass


def _ensure_worker():
    global _worker_thread
    with _worker_lock:
        if _worker_thread is None or not _worker_thread.is_alive():
            _worker_thread = threading.Thread(target=_worker_loop, daemon=True, name='pipeline-worker')
            _worker_thread.start()


def enqueue_pipeline(alert):
    """Add alert to sequential pipeline queue (replaces run_pipeline_in_thread)."""
    _ensure_worker()
    _pipeline_queue.put(alert.id)
    logger.info(
        f'Pipeline: alert {alert.id} [{alert.severity}] enqueued '
        f'(queue depth={_pipeline_queue.qsize()})'
    )


# ── TheHive: standalone push ───────────────────────────────────

def _push_to_thehive_auto(alert) -> tuple[bool, str]:
    """Create a TheHive case and save Incident to DB. Returns (ok, error_msg)."""
    from apps.config.models import IntegrationConfig
    from apps.incidents.models import Incident

    if alert.incidents.exists():
        return False, 'Already has incident'

    # ถ้ามี incident InProgress สำหรับ rule_id + agent_ip เดียวกันอยู่แล้ว → ไม่สร้างซ้ำ
    if alert.agent_ip and alert.rule_id:
        dup_incident = Incident.objects.filter(
            alert__rule_id=alert.rule_id,
            alert__agent_ip=alert.agent_ip,
            status='InProgress',
        ).exclude(alert=alert).first()
        if dup_incident:
            logger.info(
                f'Pipeline: skip TheHive for alert {alert.id} '
                f'— incident {dup_incident.thehive_case_id} (InProgress) มีอยู่แล้ว '
                f'สำหรับ rule_id={alert.rule_id} agent_ip={alert.agent_ip}'
            )
            return False, f'Duplicate InProgress incident exists: {dup_incident.thehive_case_id}'

    configs = {c.key: c.value for c in IntegrationConfig.objects.filter(
        key__in=['THEHIVE_URL', 'THEHIVE_API_KEY']
    )}
    thehive_url = configs.get('THEHIVE_URL', '').rstrip('/')
    api_key = configs.get('THEHIVE_API_KEY', '')

    if not thehive_url or not api_key:
        return False, 'TheHive URL or API Key not set'

    sev_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 1}
    tags = list(set(list(alert.rule_groups or []) + [alert.severity, 'wazuh', 'auto']))
    if alert.mitre_id:
        tags.append(alert.mitre_id)

    ai   = getattr(alert, 'ai_analysis', None)
    chat = getattr(alert, 'ai_analysis_chat', None)

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
            f"\n## AI Analysis (Ollama)\n"
            f"- **Attack Type**: {ai.attack_type}\n"
            f"- **Severity Assessment**: {ai.severity_assessment}\n"
            f"- **Summary**: {ai.summary}\n"
            f"- **Impact**: {ai.impact}\n"
            f"- **Recommendations**: {ai.recommendations}\n"
            f"- **False Positive**: {ai.false_positive_pct}%\n"
        )
    if chat:
        description += (
            f"\n## Chat AI Analysis\n"
            f"- **Risk Level**: {chat.risk_level}\n"
            f"- **Classification**: {chat.is_malicious}\n"
            f"- **Root Cause**: {chat.root_cause}\n"
            f"- **Recommended Action**: {chat.recommended_action}\n"
        )

    case_payload = {
        'title':       f'[{alert.severity}] {alert.rule_description[:120]}',
        'description': description,
        'severity':    sev_map.get(alert.severity, 2),
        'tags':        tags,
        'status':      'New',
        'source':      'SOC Dashboard',
        'sourceRef':   str(alert.wazuh_id)[:100],
    }

    try:
        req = urllib.request.Request(
            f'{thehive_url}/api/case',
            data=json.dumps(case_payload).encode(),
            headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return False, f'TheHive HTTP {e.code}: {e.read().decode()[:200]}'
    except Exception as e:
        return False, str(e)

    case_id     = result.get('_id') or result.get('id', '')
    case_number = result.get('caseId') or result.get('number', '')
    case_url    = f'{thehive_url}/cases/{case_id}/details'

    try:
        Incident.objects.create(
            alert=alert,
            thehive_case_id=f'#{case_number}' if case_number else case_id,
            title=case_payload['title'],
            status='New',
            severity=alert.severity,
            thehive_url=case_url,
        )
        logger.info(f'Pipeline: TheHive case #{case_number} created for alert {alert.id}')
        return True, ''
    except Exception as e:
        return False, f'Case created in TheHive but DB error: {e}'


# ── Helpers ────────────────────────────────────────────────────

def _reuse_analysis_if_duplicate(alert) -> tuple[bool, str]:
    """
    ตรวจสอบว่ามี alert อื่นที่มี rule_id + agent_ip เดียวกัน
    และมี incident ที่ status = InProgress อยู่แล้วหรือไม่

    ถ้าพบ → copy AI analysis จาก alert นั้นมาใช้กับ alert ปัจจุบัน
             แล้ว return (True, 'reused')
    ถ้าไม่พบ → return (False, '')
    """
    from .models import Alert, AIAnalysis, AIAnalysisChat
    from apps.incidents.models import Incident

    if not alert.agent_ip or not alert.rule_id:
        return False, ''

    ai_source = _get_ai_source()

    # กำหนด filter ตาม ai_source ปัจจุบัน
    # reuse เฉพาะเมื่อ dup_alert มี analysis ที่ตรงกับ source ที่ใช้อยู่
    if ai_source == 'chatgpt':
        dup_filter = {'ai_analysis_chat__isnull': False}
    elif ai_source == 'ollama':
        dup_filter = {'ai_analysis__isnull': False}
    else:  # both
        dup_filter = {'ai_analysis__isnull': False, 'ai_analysis_chat__isnull': False}

    # หา alert อื่นที่มี rule_id + agent_ip + rule_level เดียวกัน และมี AI analysis แล้ว
    dup_alert = (
        Alert.objects
        .filter(
            rule_id=alert.rule_id,
            agent_ip=alert.agent_ip,
            rule_level=alert.rule_level,
            **dup_filter,
        )
        .exclude(pk=alert.pk)
        .select_related('ai_analysis', 'ai_analysis_chat')
        .order_by('-timestamp')
        .first()
    )

    if dup_alert is None:
        return False, ''

    logger.info(
        f'Pipeline: alert {alert.id} มี rule_id={alert.rule_id} agent_ip={alert.agent_ip} '
        f'ซ้ำกับ alert {dup_alert.id} → reuse AI analysis'
    )

    reused_note = f'[Reused from Alert #{dup_alert.id}]'

    # Copy AIAnalysis (Ollama)
    src_ai = getattr(dup_alert, 'ai_analysis', None)
    if src_ai and not AIAnalysis.objects.filter(alert=alert).exists():
        AIAnalysis.objects.create(
            alert=alert,
            attack_type=src_ai.attack_type,
            attack_type_en=src_ai.attack_type_en,
            summary=src_ai.summary,
            summary_en=src_ai.summary_en,
            impact=src_ai.impact,
            impact_en=src_ai.impact_en,
            recommendations=src_ai.recommendations,
            recommendations_en=src_ai.recommendations_en,
            remediation_steps=src_ai.remediation_steps,
            remediation_steps_en=src_ai.remediation_steps_en,
            mitre_technique=src_ai.mitre_technique,
            severity_assessment=src_ai.severity_assessment,
            false_positive_pct=src_ai.false_positive_pct,
            raw_response=reused_note,
        )

    # Copy AIAnalysisChat (OpenAI)
    src_chat = getattr(dup_alert, 'ai_analysis_chat', None)
    if src_chat and not AIAnalysisChat.objects.filter(alert=alert).exists():
        AIAnalysisChat.objects.create(
            alert=alert,
            model_used=src_chat.model_used,
            risk_level=src_chat.risk_level,
            is_malicious=src_chat.is_malicious,
            root_cause=src_chat.root_cause,
            root_cause_th=src_chat.root_cause_th,
            recommended_action=src_chat.recommended_action,
            recommended_action_th=src_chat.recommended_action_th,
            should_create_incident=src_chat.should_create_incident,
            raw_response=reused_note,
        )

    return True, f'Alert #{dup_alert.id}'


def _get_ai_source() -> str:
    """Return NOTIFY_AI_SOURCE config value (default 'both')."""
    from apps.config.models import IntegrationConfig
    try:
        cfg = IntegrationConfig.objects.get(key='NOTIFY_AI_SOURCE')
        return cfg.value.strip().lower() or 'both'
    except Exception:
        return 'both'


def _is_service_enabled(key: str) -> bool:
    """Return True if OLLAMA_ENABLED or OPENAI_ENABLED is 'true' (default True)."""
    from apps.config.models import IntegrationConfig
    try:
        cfg = IntegrationConfig.objects.get(key=key)
        return cfg.value.strip().lower() != 'false'
    except Exception:
        return True


def _is_suppressed(alert) -> tuple[bool, str]:
    """ตรวจสอบว่า alert ตรงกับ AlertSuppressRule ที่ active อยู่หรือไม่"""
    from .models import AlertSuppressRule
    # ตรวจทั้ง rule_id เฉพาะ + rule_id+agent_ip
    qs = AlertSuppressRule.objects.filter(
        rule_id=alert.rule_id,
        is_active=True,
    )
    for rule in qs:
        if rule.agent_ip is None or rule.agent_ip == alert.agent_ip:
            reason = rule.reason or 'ไม่ระบุ'
            return True, reason
    return False, ''


def _is_rate_limited(alert, cooldown_minutes: int = 60) -> bool:
    """
    ตรวจสอบว่า rule_id+agent_ip เพิ่งถูก notify ไปแล้วภายใน cooldown_minutes นาที
    ถ้าใช่ → True (ข้าม notify) ถ้าไม่ใช่ → False (notify ได้)
    """
    from django.utils import timezone
    from apps.notifications.models import NotificationLog
    if not alert.rule_id or not alert.agent_ip:
        return False
    cutoff = timezone.now() - timezone.timedelta(minutes=cooldown_minutes)
    return NotificationLog.objects.filter(
        alert__rule_id=alert.rule_id,
        alert__agent_ip=alert.agent_ip,
        channel='MOPH',
        status='sent',
        sent_at__gte=cutoff,
    ).exists()


def _send_notify_and_thehive(alert):
    """Send MOPH Notify and push to TheHive. Used by all pipeline branches."""
    from apps.notifications.moph_notifier import send_moph_notify
    from apps.notifications.models import NotificationLog

    # ── Suppress check ─────────────────────────────────────────
    suppressed, reason = _is_suppressed(alert)
    if suppressed:
        logger.info(
            f'Pipeline: alert {alert.id} suppressed '
            f'(rule_id={alert.rule_id}, agent_ip={alert.agent_ip}) — {reason}'
        )
        return

    # ── Rate limit: notify ชั่วโมงละครั้งต่อ rule_id+agent_ip ──
    if _is_rate_limited(alert, cooldown_minutes=60):
        logger.info(
            f'Pipeline: alert {alert.id} rate-limited '
            f'(rule_id={alert.rule_id}, agent_ip={alert.agent_ip}) — skip notify'
        )
        return

    ok, err = send_moph_notify(alert)
    NotificationLog.objects.create(
        alert=alert,
        channel='MOPH',
        status='sent' if ok else 'failed',
        message_preview=f'[{alert.severity}] {alert.rule_description[:100]}',
        error_message=err if not ok else '',
    )
    if ok:
        logger.info(f'Pipeline: MOPH Notify sent for alert {alert.id}')
    else:
        logger.warning(f'Pipeline: MOPH Notify failed for alert {alert.id}: {err}')

    ok2, err2 = _push_to_thehive_auto(alert)
    if not ok2:
        logger.warning(f'Pipeline: TheHive failed for alert {alert.id}: {err2}')


# ── Pipeline logic ─────────────────────────────────────────────

def run_pipeline(alert):
    """
    Sequential pipeline — called by worker thread only (never call directly from web request).
    Branching is controlled by IntegrationConfig NOTIFY_AI_SOURCE.
    """
    from .ai_analyzer import analyze_alert
    from .chat_analyzer import analyze_alert_chat
    from .models import AIAnalysis, AIAnalysisChat

    # ── Pipeline enabled check ─────────────────────────────────
    if not _is_service_enabled('PIPELINE_ENABLED'):
        logger.info(f'Pipeline: alert {alert.id} — pipeline disabled → save to DB only')
        return

    # ── Suppress check: ถ้า suppress อยู่ → ข้าม AI ทั้งหมด ──
    suppressed, suppress_reason = _is_suppressed(alert)
    if suppressed:
        logger.info(
            f'Pipeline: alert {alert.id} suppressed (rule_id={alert.rule_id}, '
            f'agent_ip={alert.agent_ip}) — skip AI + notify [{suppress_reason}]'
        )
        return

    ai_source      = _get_ai_source()
    ollama_enabled = _is_service_enabled('OLLAMA_ENABLED')
    openai_enabled = _is_service_enabled('OPENAI_ENABLED')
    logger.info(
        f'Pipeline: start alert {alert.id} [{alert.severity}] '
        f'ai_source={ai_source} ollama={ollama_enabled} openai={openai_enabled}'
    )

    # ── Fallback: ทั้ง Ollama และ Chat AI ถูกปิด → ใช้ severity ของ alert โดยตรง ──
    if not ollama_enabled and not openai_enabled:
        if alert.severity in ('CRITICAL', 'HIGH'):
            logger.info(
                f'Pipeline: alert {alert.id} — AI disabled (both), '
                f'severity={alert.severity} → Notify + TheHive (direct)'
            )
            _send_notify_and_thehive(alert)
        else:
            logger.info(
                f'Pipeline: alert {alert.id} — AI disabled (both), '
                f'severity={alert.severity} → stop (ไม่ถึง CRITICAL/HIGH)'
            )
        return

    # ── Duplicate check: reuse analysis จาก incident ที่ InProgress ──────
    reused, reused_from = _reuse_analysis_if_duplicate(alert)
    if reused:
        # มี analysis พร้อมแล้ว (copied) — รัน pipeline ต่อโดยใช้ข้อมูลที่ copy มา
        # ไม่ต้องเรียก AI ใหม่ แต่ยังต้องตัดสินใจว่าจะ notify หรือไม่
        from .models import AIAnalysis, AIAnalysisChat
        ai_obj   = AIAnalysis.objects.filter(alert=alert).first()
        chat_obj = AIAnalysisChat.objects.filter(alert=alert).first()

        should_notify = False
        if ai_source == 'chatgpt':
            should_notify = chat_obj and chat_obj.risk_level in ('Critical', 'High')
        elif ai_source == 'ollama':
            should_notify = ai_obj and ai_obj.severity_assessment in ('CRITICAL', 'HIGH')
        else:  # both
            should_notify = (
                ai_obj and ai_obj.severity_assessment in ('CRITICAL', 'HIGH') and
                chat_obj and chat_obj.risk_level in ('Critical', 'High')
            )

        if should_notify:
            logger.info(f'Pipeline: alert {alert.id} reused from {reused_from} → Notify + TheHive')
            _send_notify_and_thehive(alert)
        else:
            logger.info(f'Pipeline: alert {alert.id} reused from {reused_from} → no notify (severity ไม่ถึง)')
        return

    # ── chatgpt-only branch ────────────────────────────────────
    if ai_source == 'chatgpt':
        if not openai_enabled:
            logger.info(f'Pipeline: alert {alert.id} Chat AI disabled → stop')
            return
        ok = analyze_alert_chat(alert)
        if not ok:
            logger.warning(f'Pipeline: Chat AI failed for alert {alert.id} — stop')
            return
        try:
            chat = AIAnalysisChat.objects.get(alert=alert)
        except AIAnalysisChat.DoesNotExist:
            logger.warning(f'Pipeline: AIAnalysisChat missing for alert {alert.id} — stop')
            return
        if chat.risk_level in ('Critical', 'High'):
            logger.info(f'Pipeline: alert {alert.id} Chat={chat.risk_level} → Notify + TheHive')
            _send_notify_and_thehive(alert)
        else:
            logger.info(f'Pipeline: alert {alert.id} Chat={chat.risk_level} → stop')
        return

    # ── ollama-only or both: run Ollama first (if enabled) ─────
    if ollama_enabled:
        ok = analyze_alert(alert)
        if not ok:
            logger.warning(f'Pipeline: Ollama analysis failed for alert {alert.id} — stop')
            return
        try:
            ai = AIAnalysis.objects.get(alert=alert)
        except AIAnalysis.DoesNotExist:
            logger.warning(f'Pipeline: AIAnalysis missing for alert {alert.id} — stop')
            return

        # MEDIUM path: TheHive only
        if ai.severity_assessment == 'MEDIUM':
            logger.info(f'Pipeline: alert {alert.id} Ollama=MEDIUM → TheHive only')
            ok, err = _push_to_thehive_auto(alert)
            if not ok:
                logger.warning(f'Pipeline: TheHive failed for alert {alert.id}: {err}')
            return

        if ai.severity_assessment not in ('CRITICAL', 'HIGH'):
            logger.info(f'Pipeline: alert {alert.id} Ollama={ai.severity_assessment} → stop')
            return

        # ollama-only branch: notify immediately
        if ai_source == 'ollama':
            logger.info(f'Pipeline: alert {alert.id} Ollama={ai.severity_assessment} → Notify + TheHive')
            _send_notify_and_thehive(alert)
            return

        # both: Ollama passed → fall through to Chat AI gate
        ollama_verdict = ai.severity_assessment
    else:
        # Ollama disabled in "both" mode → skip Ollama gate
        logger.info(f'Pipeline: alert {alert.id} Ollama disabled — skip Ollama gate')
        ollama_verdict = 'SKIPPED'

    # ── both branch: Chat AI gate ─────────────────────────────
    if not openai_enabled:
        # Chat AI disabled — if Ollama already passed, notify directly
        if ollama_verdict in ('CRITICAL', 'HIGH'):
            logger.info(f'Pipeline: alert {alert.id} Chat AI disabled, Ollama={ollama_verdict} → Notify + TheHive')
            _send_notify_and_thehive(alert)
        else:
            logger.info(f'Pipeline: alert {alert.id} Chat AI disabled, Ollama={ollama_verdict} → stop')
        return

    ok = analyze_alert_chat(alert)
    if not ok:
        logger.warning(f'Pipeline: Chat AI failed for alert {alert.id} — stop')
        return

    try:
        chat = AIAnalysisChat.objects.get(alert=alert)
    except AIAnalysisChat.DoesNotExist:
        logger.warning(f'Pipeline: AIAnalysisChat missing for alert {alert.id} — stop')
        return

    if chat.risk_level not in ('Critical', 'High'):
        logger.info(f'Pipeline: alert {alert.id} Chat={chat.risk_level} → stop')
        return

    logger.info(
        f'Pipeline: alert {alert.id} Ollama={ollama_verdict} Chat={chat.risk_level} → Notify + TheHive'
    )
    _send_notify_and_thehive(alert)
