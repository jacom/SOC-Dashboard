from django.db import models


class Alert(models.Model):
    SEVERITY = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
        ('INFO', 'Info'),
    ]

    wazuh_id = models.CharField(max_length=100, unique=True)
    timestamp = models.DateTimeField()
    agent_name = models.CharField(max_length=200)
    agent_ip = models.GenericIPAddressField(null=True, blank=True)
    rule_id = models.CharField(max_length=20)
    rule_level = models.IntegerField()
    rule_description = models.TextField()
    rule_groups = models.JSONField(default=list)
    mitre_id = models.CharField(max_length=50, blank=True)
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    severity = models.CharField(max_length=10, choices=SEVERITY)
    raw_data = models.JSONField()
    dismissed = models.BooleanField(default=False)
    dismissed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['severity']),
            models.Index(fields=['agent_name']),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.rule_description[:60]} - {self.agent_name}"

    @property
    def severity_color(self):
        colors = {
            'CRITICAL': 'danger',
            'HIGH': 'warning',
            'MEDIUM': 'info',
            'LOW': 'secondary',
            'INFO': 'light',
        }
        return colors.get(self.severity, 'secondary')


class AIAnalysisChat(models.Model):
    """Second AI analysis using OpenAI chat-completions format."""
    RISK_LEVELS = [('Low','Low'),('Medium','Medium'),('High','High'),('Critical','Critical')]

    alert = models.OneToOneField('Alert', on_delete=models.CASCADE, related_name='ai_analysis_chat')
    model_used = models.CharField(max_length=100, blank=True)
    risk_level = models.CharField(max_length=20, blank=True)
    is_malicious = models.CharField(max_length=50, blank=True)   # malicious / misconfiguration / benign
    root_cause = models.TextField(blank=True)
    root_cause_th = models.TextField(blank=True)
    recommended_action = models.TextField(blank=True)
    recommended_action_th = models.TextField(blank=True)
    should_create_incident = models.BooleanField(default=False)
    raw_response = models.TextField(blank=True)
    analyzed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ChatAnalysis for Alert #{self.alert_id}: {self.risk_level}"


class AIAnalysis(models.Model):
    alert = models.OneToOneField(Alert, on_delete=models.CASCADE, related_name='ai_analysis')
    # Thai fields (original)
    attack_type = models.CharField(max_length=200)
    summary = models.TextField(blank=True)
    impact = models.TextField()
    recommendations = models.TextField()
    remediation_steps = models.TextField(blank=True, default='')
    # English fields (bilingual support)
    attack_type_en = models.CharField(max_length=200, blank=True, default='')
    summary_en = models.TextField(blank=True, default='')
    impact_en = models.TextField(blank=True, default='')
    recommendations_en = models.TextField(blank=True, default='')
    remediation_steps_en = models.TextField(blank=True, default='')
    # Common fields
    mitre_technique = models.CharField(max_length=50, blank=True)
    severity_assessment = models.CharField(max_length=20)
    false_positive_pct = models.IntegerField(default=0)
    raw_response = models.TextField()
    analyzed_at = models.DateTimeField(auto_now_add=True)

    @property
    def remediation_steps_list(self):
        return [s.strip() for s in self.remediation_steps.split('|') if s.strip()]

    @property
    def remediation_steps_en_list(self):
        return [s.strip() for s in self.remediation_steps_en.split('|') if s.strip()]

    def __str__(self):
        return f"AI Analysis for Alert #{self.alert_id}: {self.attack_type}"


class ThreatIntelResult(models.Model):
    PROVIDER_CHOICES = [('abuseipdb', 'AbuseIPDB'), ('virustotal', 'VirusTotal')]
    ip_address  = models.GenericIPAddressField(db_index=True)
    provider    = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
    is_malicious = models.BooleanField(default=False)
    score       = models.IntegerField(default=0, help_text='AbuseIPDB: abuse confidence %, VT: malicious vote count')
    country     = models.CharField(max_length=10, blank=True)
    isp         = models.CharField(max_length=200, blank=True)
    domain      = models.CharField(max_length=200, blank=True)
    raw_data    = models.JSONField(default=dict)
    checked_at  = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [('ip_address', 'provider')]
        ordering = ['-checked_at']


class AlertSuppressRule(models.Model):
    """
    ปิดการแจ้งเตือนสำหรับ rule_id + agent_ip ที่ระบุ
    agent_ip = None หมายถึง suppress ทุก agent สำหรับ rule_id นี้
    """
    rule_id    = models.CharField(max_length=50, db_index=True)
    agent_ip   = models.GenericIPAddressField(null=True, blank=True,
                     help_text='เว้นว่างเพื่อ suppress ทุก agent')
    reason     = models.TextField(blank=True, help_text='เหตุผลที่ suppress')
    is_active  = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        unique_together = [('rule_id', 'agent_ip')]

    def __str__(self):
        target = self.agent_ip or 'ALL agents'
        return f'Suppress rule_id={self.rule_id} / {target}'


class Playbook(models.Model):
    """Response checklist template for a rule type."""
    name        = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    rule_ids    = models.TextField(blank=True, help_text='Comma-separated rule IDs, e.g. 92058,92059')
    rule_groups = models.TextField(blank=True, help_text='Comma-separated rule groups, e.g. authentication_failed,web')
    severity_filter = models.CharField(
        max_length=50, blank=True,
        help_text='Only apply to these severities, comma-separated. Empty = all.'
    )
    steps       = models.JSONField(default=list, help_text='List of step strings')
    is_active   = models.BooleanField(default=True)
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    def matches_alert(self, alert) -> bool:
        """Check if this playbook applies to the given alert."""
        # Severity filter
        if self.severity_filter:
            allowed = [s.strip().upper() for s in self.severity_filter.split(',') if s.strip()]
            if alert.severity not in allowed:
                return False
        # Match by rule_id
        if self.rule_ids:
            ids = [r.strip() for r in self.rule_ids.split(',') if r.strip()]
            if str(alert.rule_id) in ids:
                return True
        # Match by rule_group
        if self.rule_groups:
            groups = [g.strip().lower() for g in self.rule_groups.split(',') if g.strip()]
            alert_groups = [g.lower() for g in (alert.rule_groups or [])]
            if any(g in alert_groups for g in groups):
                return True
        return False


class PlaybookRun(models.Model):
    """Tracks which steps have been completed for an alert."""
    alert      = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='playbook_runs')
    playbook   = models.ForeignKey(Playbook, on_delete=models.CASCADE, related_name='runs')
    completed_steps = models.JSONField(default=list, help_text='List of completed step indices')
    notes      = models.TextField(blank=True)
    started_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_by = models.ForeignKey(
        'auth.User', on_delete=models.SET_NULL, null=True, blank=True
    )

    class Meta:
        unique_together = [('alert', 'playbook')]
        ordering = ['-updated_at']
