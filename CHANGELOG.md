# Changelog

All notable changes to SOC Dashboard will be documented here.
Format: [Semantic Versioning](https://semver.org/) — `MAJOR.MINOR.PATCH`

---

## [1.1.0] - 2026-03-11

### Added
- **2FA / TOTP** — ระบบ Two-Factor Authentication แบบ opt-in, QR code setup, middleware enforcement
- **Incident ↔ Vulnerability linking** — ManyToMany ระหว่าง Incident กับ Vulnerability, AJAX search/link/unlink UI
- **Vulnerability Detail page** — หน้า `/vulnerabilities/<pk>/` แสดง CVE, AI analysis, linked incidents
- **SLA Dashboard** — tracking MTTR, Incident SLA compliance, Vulnerability SLA compliance, breached item list
- **Dashboard SLA KPI cards** — breached incidents/vulns, alert trend %, total alerts today
- **Docker Compose** — `docker-compose.yml` + `Dockerfile` สำหรับ deploy ด้วย container
- **License Key system** — HMAC-SHA256 offline validation, grace period 30 วัน, หน้า `/license/`
- **Admin registration** — เพิ่ม admin.py ครบทุก app (assets, core, sla, vulnerabilities)
- **`scripts/gen_license.py`** — vendor tool สำหรับออก license key ให้ลูกค้า
- **`scripts/update.sh`** — รองรับ `--docker` flag สำหรับ Docker Compose update

### Fixed
- SLA dashboard 500 error — Django template ห้ามใช้ underscore-prefix variables (`_overdue_h`, `_overdue_days`)
- 2FA middleware ล็อคผู้ใช้ที่ยังไม่มี TOTP device — แก้เป็น opt-in เฉพาะผู้ที่ enroll แล้ว
- Vulnerability list แสดง JSON แทน HTML — เพิ่ม content negotiation (browser → HTML, AJAX → JSON)
- Vulnerability link ใน SLA — เปลี่ยนจาก `?q=` query string เป็น `/vulnerabilities/<pk>/`

### Changed
- `requirements.txt` — เพิ่ม `django-otp>=1.0`
- `.env.example` — เพิ่ม `LICENSE_VENDOR_SECRET`, `LICENSE_GRACE_DAYS`, `DASHBOARD_PORT`
- `update.sh` — รองรับทั้ง Docker และ non-Docker (HUP signal / systemctl)

---

## [1.0.0] - 2026-03-02

### Added
- Authentication system — login_required ทุก view, dark-theme login page
- Incident `approved_by` — บันทึกว่าใคร approve incident
- Universal install script (`scripts/install.sh`) รองรับ Ubuntu 22/24 และ AlmaLinux 9
- AI analysis ด้วย Ollama (background thread)
- Chat AI analysis ด้วย OpenAI-compatible API
- TheHive integration — push alert เป็น case
- LINE Notify & MOPH Notify alerts
- Wazuh webhook receiver (`/api/alerts/wazuh-webhook/`)
- Version display ใน sidebar

### Core Features
- Dashboard พร้อม hourly timeline chart, top rules, recent critical alerts
- Alert list พร้อม filter, sort, pagination
- Incident management (New / InProgress / Resolved / Closed)
- Notification log (LINE, MOPH)
- Integration Settings UI (Wazuh, Ollama, TheHive, LINE, MOPH)
