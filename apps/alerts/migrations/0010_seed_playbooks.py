from django.db import migrations

PLAYBOOKS = [
    {
        'name': 'Brute Force Login Response',
        'description': 'ขั้นตอนรับมือเมื่อตรวจพบการ brute force login',
        'rule_ids': '',
        'rule_groups': 'authentication_failed,authentication_failures',
        'severity_filter': 'CRITICAL,HIGH',
        'steps': [
            'ตรวจสอบ src_ip ว่ามาจากภายในหรือภายนอกองค์กร',
            'ดู frequency — กี่ครั้งใน 5 นาที (ดูใน Wazuh)',
            'ตรวจสอบ username ที่ถูก brute force — มีอยู่จริงหรือไม่',
            'Block src_ip ที่ Firewall / IPS ชั่วคราว',
            'แจ้ง admin เจ้าของ account ให้ตรวจสอบ',
            'ตรวจสอบ log ว่ามี login สำเร็จก่อนหรือหลัง alert หรือไม่',
            'ถ้า login สำเร็จ — reset password ทันที และ revoke session',
            'บันทึก incident และ timeline ใน TheHive',
        ],
    },
    {
        'name': 'Malware / Suspicious Process',
        'description': 'ขั้นตอนรับมือเมื่อตรวจพบ process หรือ file ต้องสงสัย',
        'rule_ids': '',
        'rule_groups': 'malware,virus,trojan,ransomware',
        'severity_filter': 'CRITICAL,HIGH',
        'steps': [
            'Isolate เครื่อง — ตัด network connection ทันที (ถ้าทำได้)',
            'ระบุ process name, PID, path ของไฟล์ต้องสงสัย',
            'Hash ไฟล์และ check กับ VirusTotal',
            'ตรวจสอบ persistence — startup, registry, scheduled task',
            'ตรวจสอบ lateral movement — มีการเชื่อมต่อออกไปเครื่องอื่นไหม',
            'Collect memory dump (ถ้าจำเป็น)',
            'Reimaging เครื่อง หรือ clean malware ตาม playbook ของ AV',
            'สแกนเครื่องอื่นในวง subnet เดียวกัน',
            'บันทึก IOC ทั้งหมด (hash, IP, domain)',
        ],
    },
    {
        'name': 'Privilege Escalation',
        'description': 'ขั้นตอนรับมือเมื่อตรวจพบการ escalate privilege',
        'rule_ids': '',
        'rule_groups': 'privilege_escalation,sudo',
        'severity_filter': 'CRITICAL,HIGH',
        'steps': [
            'ระบุ user ที่ทำการ escalate และ account ที่ถูก escalate ไป',
            'ตรวจสอบว่าเป็นการกระทำที่ authorized หรือไม่ (ถามเจ้าของ account)',
            'ตรวจสอบ command ที่รันหลังจาก escalate',
            'ตรวจสอบ sudo log / audit log ย้อนหลัง 24 ชั่วโมง',
            'ถ้าไม่ authorized — kill session ทันที',
            'Reset credential ของ account ที่ affected',
            'ตรวจสอบว่ามีไฟล์ถูกแก้ไขหลัง escalation หรือไม่',
            'สร้าง incident ใน TheHive',
        ],
    },
    {
        'name': 'Suspicious Network Connection',
        'description': 'ขั้นตอนรับมือเมื่อตรวจพบการเชื่อมต่อเครือข่ายผิดปกติ',
        'rule_ids': '',
        'rule_groups': 'network,firewall,ids',
        'severity_filter': 'CRITICAL,HIGH,MEDIUM',
        'steps': [
            'ระบุ src_ip, dst_ip, port, protocol',
            'Check src_ip กับ Threat Intel (AbuseIPDB, VirusTotal)',
            'ตรวจสอบว่า port/service ที่เชื่อมต่อควรเปิดใช้งานหรือไม่',
            'ตรวจสอบ traffic volume — มีปริมาณผิดปกติหรือไม่',
            'ดู process ที่ initiate connection บนเครื่อง agent',
            'Block IP/Port ที่ Firewall ถ้าเป็น external และต้องสงสัย',
            'ตรวจสอบเครื่องอื่นในเครือข่ายที่ติดต่อกับ IP เดียวกัน',
        ],
    },
]


def seed(apps, schema_editor):
    Playbook = apps.get_model('alerts', 'Playbook')
    for pb_data in PLAYBOOKS:
        Playbook.objects.get_or_create(
            name=pb_data['name'],
            defaults=pb_data,
        )


class Migration(migrations.Migration):
    dependencies = [('alerts', '0009_playbook')]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
