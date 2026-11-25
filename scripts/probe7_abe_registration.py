#!/usr/bin/env python3
"""Phase 7: how is the elevation service actually registered?

Service-backed COM has no LocalServer32. The chain is CLSID -> AppID -> LocalService.
This resolves it properly, with case-insensitive matching.
"""
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CLSID_ROOT = r"HKLM\SOFTWARE\Classes\CLSID"
APPID_ROOT = r"HKLM\SOFTWARE\Classes\AppID"

OLD = {
    "Chrome (2024 blog)": "{708860E0-F641-4611-8895-7D867DD3675B}",
    "Edge (2024 blog)": "{1FCBE96C-1697-43AF-9140-29DB18F2E706}",
}


def reg(key):
    p = subprocess.run(["reg", "query", key], capture_output=True, text=True,
                       timeout=30, errors="replace")
    return p.stdout


def local_service(appid):
    out = reg(f"{APPID_ROOT}\\{appid}")
    m = re.search(r"LocalService\s+REG_SZ\s+(\S+)", out)
    return m.group(1) if m else None


print("=" * 70)
print(" PHASE 7 — elevation service registration chain")
print("=" * 70)

print("\n[A] ARE THE 2024 GUIDs CLSIDs, AppIDs, OR BOTH?")
for label, guid in OLD.items():
    as_clsid = "FOUND" if "HKEY_" in reg(f"{CLSID_ROOT}\\{guid}") else "absent"
    as_appid = "FOUND" if "HKEY_" in reg(f"{APPID_ROOT}\\{guid}") else "absent"
    svc = local_service(guid)
    print(f"  {label:22} {guid}")
    print(f"  {'':22} CLSID={as_clsid}  AppID={as_appid}  LocalService={svc}")

print("\n[B] EVERY AppID POINTING AT AN *Elevation* SERVICE")
p = subprocess.run(
    ["powershell", "-NoProfile", "-Command",
     "Get-ChildItem 'HKLM:\\SOFTWARE\\Classes\\AppID' -ErrorAction SilentlyContinue | "
     "ForEach-Object { $ls = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).LocalService; "
     "if ($ls -match 'Elevation') { \"$($_.PSChildName)|$ls\" } }"],
    capture_output=True, text=True, timeout=180, errors="replace")
appids = [l.strip() for l in p.stdout.splitlines() if "|" in l]
for a in appids:
    guid, svc = a.split("|", 1)
    print(f"  {guid}  ->  {svc}")

print("\n[C] WHICH CLSID MAPS TO EACH OF THOSE AppIDs?")
for a in appids:
    appid, _svc = a.split("|", 1)
    q = subprocess.run(
        ["reg", "query", CLSID_ROOT, "/s", "/f", appid, "/d", "/c"],
        capture_output=True, text=True, timeout=300, errors="replace")
    hits = []
    cur = None
    for line in q.stdout.splitlines():
        s = line.strip()
        if s.startswith("HKEY_"):
            cur = s
        elif appid.lower() in s.lower() and "AppID" in s and cur:
            hits.append(cur.split("CLSID\\")[-1])
            cur = None
    print(f"  AppID {appid}: {len(hits)} CLSID(s)")
    for h in hits[:5]:
        print(f"      CLSID {h}")

print("\n[D] SERVICE BINARIES")
p = subprocess.run(
    ["powershell", "-NoProfile", "-Command",
     "Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'Elevation' } | "
     "ForEach-Object { \"$($_.Name)|$($_.StartName)|$($_.PathName)\" }"],
    capture_output=True, text=True, timeout=90, errors="replace")
for line in p.stdout.splitlines():
    if line.strip():
        print(f"  {line.strip()[:150]}")

print("\n" + "=" * 70)
