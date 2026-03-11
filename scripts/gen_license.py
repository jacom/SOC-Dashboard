#!/usr/bin/env python3
"""
SOC Dashboard — License Key Generator (Vendor Tool)
====================================================
รันบนเครื่อง vendor เท่านั้น — ห้าม distribute ไปกับ source code

วิธีใช้:
    python3 scripts/gen_license.py

ต้องการ:
    LICENSE_VENDOR_SECRET ใน environment หรือ .env
    pip install python-dotenv
"""

import hmac
import hashlib
import os
import sys
from datetime import date, timedelta
from pathlib import Path

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / '.env')
except ImportError:
    pass

VENDOR_SECRET = os.environ.get('LICENSE_VENDOR_SECRET', '')

PLANS = ['TRIAL', 'PRO', 'ENT']
PLAN_DEFAULTS = {
    'TRIAL': 30,
    'PRO':   365,
    'ENT':   730,
}


def _sign(instance_id: str, plan: str, expiry: str) -> str:
    message = f'{instance_id}|{plan}|{expiry}'.encode()
    sig = hmac.new(VENDOR_SECRET.encode(), message, hashlib.sha256).hexdigest()
    return sig[:16].upper()


def generate(instance_id: str, plan: str, days: int) -> str:
    expiry = (date.today() + timedelta(days=days)).strftime('%Y%m%d')
    sig = _sign(instance_id.strip().lower(), plan, expiry)
    return f'SOC-{plan}-{expiry}-{sig}'


def main():
    if not VENDOR_SECRET:
        print('ERROR: LICENSE_VENDOR_SECRET ไม่ได้ตั้งค่า')
        print('ใส่ใน .env:  LICENSE_VENDOR_SECRET=<64-char hex>')
        sys.exit(1)

    print('=' * 55)
    print('  SOC Dashboard — License Key Generator')
    print('=' * 55)

    instance_id = input('Instance ID (UUID จากหน้า /license/): ').strip()
    if not instance_id:
        print('ERROR: ต้องระบุ Instance ID')
        sys.exit(1)

    print(f'\nแผน: {", ".join(PLANS)}')
    plan = input('เลือกแผน: ').strip().upper()
    if plan not in PLANS:
        print(f'ERROR: แผนต้องเป็น {PLANS}')
        sys.exit(1)

    default_days = PLAN_DEFAULTS[plan]
    days_input = input(f'จำนวนวัน (default {default_days}): ').strip()
    days = int(days_input) if days_input.isdigit() else default_days

    key = generate(instance_id, plan, days)
    expiry = (date.today() + timedelta(days=days)).strftime('%d %b %Y')

    print('\n' + '=' * 55)
    print(f'  License Key:')
    print(f'  {key}')
    print(f'  Plan: {plan} | Expires: {expiry} ({days} วัน)')
    print('=' * 55)
    print('\nส่ง key นี้ให้ลูกค้าใส่ที่ /license/activate/')


if __name__ == '__main__':
    main()
