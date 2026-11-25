#!/usr/bin/env python3
"""Phase 2 probe: does the DPAPI layer still open, and where does ABE actually register?

Reports success/failure and byte counts only. Never prints key material.
"""
import base64
import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LOCAL = os.environ["LOCALAPPDATA"]
ROAM = os.environ["APPDATA"]
PROGRAMDATA = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
PF = os.environ.get("ProgramFiles", r"C:\Program Files")
PF86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")

ROOTS = {
    "Chrome": f"{LOCAL}/Google/Chrome/User Data",
    "Edge":   f"{LOCAL}/Microsoft/Edge/User Data",
    "Brave":  f"{LOCAL}/BraveSoftware/Brave-Browser/User Data",
    "Opera":  f"{ROAM}/Opera Software/Opera Stable",
}
BINS = {
    "Chrome": f"{PF}/Google/Chrome/Application",
    "Brave":  f"{PF}/BraveSoftware/Brave-Browser/Application",
    "Edge":   f"{PF86}/Microsoft/EdgeCore",
}


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_unprotect(blob: bytes):
    """Returns bytes on success, None on failure. Caller decides what to print."""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(blob, len(blob))
    din = DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    dout = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(din), None, None, None, None, 0x1, ctypes.byref(dout)):
        return None
    try:
        return ctypes.string_at(dout.pbData, dout.cbData)
    finally:
        kernel32.LocalFree(dout.pbData)


print("=" * 70)
print(" PHASE 2 — DPAPI layer, ABE registration, Brave surface")
print("=" * 70)

print("\n[A] CAN THE DPAPI LAYER STILL BE OPENED IN THIS SESSION?")
for name, root in ROOTS.items():
    ls = Path(root) / "Local State"
    if not ls.is_file():
        continue
    try:
        j = json.loads(ls.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        print(f"  {name:8} Local State unreadable: {e}")
        continue
    oc = j.get("os_crypt", {}) or {}
    ek = oc.get("encrypted_key")
    if not isinstance(ek, str):
        print(f"  {name:8} no encrypted_key")
        continue
    raw = base64.b64decode(ek)
    prefix = raw[:5]
    body = raw[5:] if prefix == b"DPAPI" else raw
    out = dpapi_unprotect(body)
    if out is None:
        print(f"  {name:8} DPAPI unwrap FAILED  (prefix={prefix!r})")
    else:
        print(f"  {name:8} DPAPI unwrap OK      (prefix={prefix!r} -> {len(out)} bytes)")

    abe = oc.get("app_bound_encrypted_key")
    if isinstance(abe, str):
        araw = base64.b64decode(abe)
        head = araw[:8]
        payload = araw[8:] if head == b"APPB\x01\x00\x00\x00" else araw
        d1 = dpapi_unprotect(payload)
        if d1 is None:
            print(f"  {'':8} ABE outer DPAPI FAILED  (raw={len(araw)})")
        else:
            d2 = dpapi_unprotect(d1)
            if d2 is None:
                print(f"  {'':8} ABE layer1 OK ({len(d1)}B), layer2 FAILED -> CNG/SYSTEM wall")
            else:
                printable = re.sub(rb"[^\x20-\x7e]", b".", d2[:60])
                print(f"  {'':8} ABE layer2 OK ({len(d2)}B) head={printable!r}")

print("\n[B] BRAVE COOKIE DB — CAN IT BE READ AT ALL?")
db = Path(ROOTS["Brave"]) / "Default" / "Network" / "Cookies"
print(f"  exists={db.is_file()}")
if db.is_file():
    tmp = Path(tempfile.mkdtemp(prefix="brave_"))
    for attempt in ("copy2", "raw", "vss"):
        dst = tmp / "Cookies"
        try:
            if attempt == "copy2":
                shutil.copy2(db, dst)
            elif attempt == "raw":
                with open(db, "rb") as f, open(dst, "wb") as o:
                    while True:
                        chunk = f.read(1 << 20)
                        if not chunk:
                            break
                        o.write(chunk)
            else:
                src = Path(f"{db}-wal")
                if src.is_file():
                    with open(src, "rb") as f, open(tmp / "Cookies-wal", "wb") as o:
                        o.write(f.read())
                continue
            con = sqlite3.connect(dst.as_posix(), timeout=3)
            meta = con.execute("SELECT value FROM meta WHERE key='version'").fetchone()
            rows = con.execute("SELECT COUNT(*) FROM cookies").fetchone()[0]
            pref = con.execute(
                "SELECT substr(encrypted_value,1,3), COUNT(*) FROM cookies "
                "WHERE length(encrypted_value)>3 GROUP BY 1 ORDER BY 2 DESC").fetchall()
            print(f"  read OK via {attempt}: meta={meta[0] if meta else '?'} rows={rows} {pref}")
            con.close()
            break
        except Exception as e:
            print(f"  {attempt}: {type(e).__name__}: {e}")

print("\n[C] WHAT CLSIDs DOES THE ELEVATION SERVICE ACTUALLY USE?")
GUID = re.compile(rb"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
for name, base in BINS.items():
    d = Path(base)
    if not d.is_dir():
        continue
    vers = sorted([x for x in d.iterdir() if x.is_dir() and x.name[0].isdigit()],
                  key=lambda p: [int(n) for n in re.findall(r"\d+", p.name.split(".")[0]) or [0]])
    if not vers:
        continue
    exe = vers[-1] / "elevation_service.exe"
    if not exe.is_file():
        continue
    data = exe.read_bytes()
    ascii_hits = {m.group().decode().lower() for m in GUID.finditer(data)}
    wide = data.decode("utf-16-le", "ignore").encode("ascii", "ignore")
    wide_hits = {m.group().decode().lower() for m in GUID.finditer(wide)}
    hits = ascii_hits | wide_hits
    print(f"  {name:8} {exe.parent.name}  {len(hits)} GUID(s) in binary")
    for h in sorted(hits)[:12]:
        print(f"      {h}")

print("\n[D] REGISTRY: WHERE IS THE COM SERVER?")
probes = [
    ("HKLM CLSID (64)", r"HKLM\SOFTWARE\Classes\CLSID"),
    ("HKLM CLSID (WOW)", r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID"),
    ("HKCU CLSID", r"HKCU\Software\Classes\CLSID"),
]
for label, root in probes:
    try:
        out = subprocess.run(["reg", "query", root, "/s", "/f", "elevation_service", "/d"],
                             capture_output=True, text=True, timeout=180, errors="replace")
        lines = [l.strip() for l in out.stdout.splitlines() if "elevation_service" in l.lower()]
        print(f"  {label:18} {len(lines)} hit(s)")
        seen = set()
        for l in lines[:10]:
            v = l.split("REG_")[-1].strip()
            if v not in seen:
                seen.add(v)
                print(f"      {v}")
    except Exception as e:
        print(f"  {label:18} error: {e}")

print("\n[E] SYSTEM PROFILE KEY STORE (where a SYSTEM-scoped CNG key would live)")
syskeys = Path(r"C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Crypto\Keys")
try:
    if syskeys.is_dir():
        print(f"  {syskeys}: {len(list(syskeys.iterdir()))} entr(ies)")
    else:
        print("  not present")
except PermissionError:
    print("  ACCESS DENIED -> key is SYSTEM-scoped, elevation required to even list")

print("\n[F] ELEVATION SERVICE SIGNER")
for name, base in BINS.items():
    d = Path(base)
    if not d.is_dir():
        continue
    vers = sorted([x for x in d.iterdir() if x.is_dir() and x.name[0].isdigit()])
    if not vers:
        continue
    exe = vers[-1] / "elevation_service.exe"
    if not exe.is_file():
        continue
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-AuthenticodeSignature '{exe}').SignerCertificate.Subject"],
            capture_output=True, text=True, timeout=30, errors="replace")
        print(f"  {name:8} {out.stdout.strip()[:90]}")
    except Exception as e:
        print(f"  {name:8} error: {e}")

print("\n" + "=" * 70)
