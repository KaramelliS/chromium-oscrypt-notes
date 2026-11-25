#!/usr/bin/env python3
"""Structural recon for Chromium-family browser stores.

Reads only structure: key names, lengths, prefixes, counts, versions.
Never decrypts a single value and never prints one.
"""
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LOCAL = os.environ.get("LOCALAPPDATA", "")
ROAM = os.environ.get("APPDATA", "")
PROGRAMDATA = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
PF = os.environ.get("ProgramFiles", r"C:\Program Files")
PF86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")

ROOTS = {
    "Chrome":    f"{LOCAL}/Google/Chrome/User Data",
    "Chrome Beta": f"{LOCAL}/Google/Chrome Beta/User Data",
    "Edge":      f"{LOCAL}/Microsoft/Edge/User Data",
    "Brave":     f"{LOCAL}/BraveSoftware/Brave-Browser/User Data",
    "Vivaldi":   f"{LOCAL}/Vivaldi/User Data",
    "Opera":     f"{ROAM}/Opera Software/Opera Stable",
    "Opera GX":  f"{ROAM}/Opera Software/Opera GX Stable",
    "Chromium":  f"{LOCAL}/Chromium/User Data",
}

SKIP_PROFILE = {"System Profile", "Guest Profile", "Snapshot", "Crashpad"}


def sqlite_ro(path: Path):
    for uri in (
        f"file:{path.as_posix()}?mode=ro",
        f"file:{path.as_posix()}?mode=ro&immutable=1",
    ):
        try:
            con = sqlite3.connect(uri, uri=True, timeout=2)
            con.execute("SELECT 1 FROM sqlite_master LIMIT 1")
            return con
        except Exception:
            continue
    return _sqlite_from_copy(path)


def _sqlite_from_copy(path: Path):
    """Live browsers hold locks. Copy the db plus its WAL sidecars, then read."""
    import shutil
    import tempfile

    try:
        tmp = Path(tempfile.mkdtemp(prefix="recon_"))
        dst = tmp / path.name
        shutil.copy2(path, dst)
        for side in (f"{path}-wal", f"{path}-shm"):
            s = Path(side)
            if s.is_file():
                shutil.copy2(s, tmp / s.name)
        con = sqlite3.connect(dst.as_posix(), timeout=3)
        con.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        return con
    except Exception:
        return None


def q1(con, sql, default=None):
    try:
        r = con.execute(sql).fetchone()
        return r[0] if r else default
    except Exception:
        return default


def note_ls(profile_root: Path):
    ls = profile_root / "Local State"
    if not ls.is_file():
        return None
    try:
        j = json.loads(ls.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        return {"error": str(e)}
    oc = j.get("os_crypt", {}) or {}
    out = {"os_crypt_keys": sorted(oc.keys())}
    ek = oc.get("encrypted_key")
    if isinstance(ek, str):
        import base64
        try:
            raw = base64.b64decode(ek)
            out["encrypted_key_prefix"] = raw[:5].decode("ascii", "replace")
            out["encrypted_key_len"] = len(raw)
        except Exception:
            pass
    ab = oc.get("app_bound_encrypted_key")
    if isinstance(ab, str):
        import base64
        try:
            raw = base64.b64decode(ab)
            out["abe_present"] = True
            out["abe_raw_len"] = len(raw)
            out["abe_prefix"] = raw[:8].hex()
        except Exception:
            out["abe_present"] = True
    else:
        out["abe_present"] = False
    return out


def note_cookies(p: Path):
    db = p / "Network" / "Cookies"
    if not db.is_file():
        db = p / "Cookies"
    if not db.is_file():
        return None
    con = sqlite_ro(db)
    if not con:
        return {"error": "locked or unreadable", "path": str(db)}
    try:
        meta = q1(con, "SELECT value FROM meta WHERE key='version'")
        total = q1(con, "SELECT COUNT(*) FROM cookies", 0)
        prefixes = con.execute(
            "SELECT substr(encrypted_value,1,3) AS p, COUNT(*) "
            "FROM cookies WHERE length(encrypted_value) > 3 GROUP BY p ORDER BY 2 DESC"
        ).fetchall()
        return {"meta_version": meta, "rows": total,
                "prefixes": {str(k): v for k, v in prefixes}}
    finally:
        con.close()


def note_logins(p: Path):
    db = p / "Login Data"
    if not db.is_file():
        return None
    con = sqlite_ro(db)
    if not con:
        return {"error": "locked"}
    try:
        total = q1(con, "SELECT COUNT(*) FROM logins", 0)
        prefixes = con.execute(
            "SELECT substr(password_value,1,3) AS p, COUNT(*) FROM logins "
            "WHERE length(password_value) > 3 GROUP BY p ORDER BY 2 DESC"
        ).fetchall()
        return {"rows": total, "prefixes": {str(k): v for k, v in prefixes}}
    finally:
        con.close()


def exe_version(path: Path):
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-Item '{path}').VersionInfo.ProductVersion"],
            capture_output=True, text=True, timeout=20,
        )
        return out.stdout.strip() or None
    except Exception:
        return None


def writable(path: Path):
    if not path.is_dir():
        return None
    probe = path / ".write_probe_tmp"
    try:
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
        return True
    except Exception:
        return False


print("=" * 66)
print(" CHROMIUM STORE RECON — structure only, zero decryption")
print("=" * 66)

print("\n[1] BROWSERS FOUND")
found = {}
for name, root in ROOTS.items():
    r = Path(root)
    if not r.is_dir():
        continue
    profiles = [d.name for d in r.iterdir()
                if d.is_dir() and d.name not in SKIP_PROFILE
                and ((d / "Network" / "Cookies").is_file() or (d / "Cookies").is_file()
                     or (d / "Login Data").is_file())]
    if not profiles:
        continue
    found[name] = (r, profiles)
    print(f"  {name:12} {len(profiles)} profile(s): {', '.join(profiles[:6])}")

if not found:
    print("  none")

print("\n[2] KEY WRAPPING (Local State)")
for name, (r, _) in found.items():
    info = note_ls(r)
    if not info:
        print(f"  {name:12} no Local State")
        continue
    if "error" in info:
        print(f"  {name:12} parse error: {info['error']}")
        continue
    abe = "ABE v20" if info.get("abe_present") else "no ABE (v10/v11 only)"
    print(f"  {name:12} {abe:24} keys={info['os_crypt_keys']}")
    if info.get("abe_present"):
        print(f"  {'':12} abe_raw_len={info['abe_raw_len']} prefix={info['abe_prefix']}")

print("\n[3] COOKIE / LOGIN STORES")
for name, (r, profiles) in found.items():
    for prof in profiles:
        p = r / prof
        c = note_cookies(p)
        l = note_logins(p)
        bits = []
        if c:
            if "error" in c:
                bits.append(f"cookies={c['error']}")
            else:
                bits.append(f"cookies={c['rows']} meta={c['meta_version']} {c['prefixes']}")
        if l:
            if "error" in l:
                bits.append(f"logins={l['error']}")
            else:
                bits.append(f"logins={l['rows']} {l['prefixes']}")
        if bits:
            print(f"  {name}/{prof}")
            for b in bits:
                print(f"      {b}")

print("\n[4] INSTALL PATHS AND WRITABILITY")
bins = {
    "Chrome":  [f"{PF}/Google/Chrome/Application/chrome.exe",
                f"{LOCAL}/Google/Chrome/Application/chrome.exe"],
    "Edge":    [f"{PF86}/Microsoft/Edge/Application/msedge.exe",
                f"{PF}/Microsoft/Edge/Application/msedge.exe"],
    "Brave":   [f"{LOCAL}/BraveSoftware/Brave-Browser/Application/brave.exe",
                f"{PF}/BraveSoftware/Brave-Browser/Application/brave.exe"],
    "Vivaldi": [f"{LOCAL}/Vivaldi/Application/vivaldi.exe",
                f"{PF}/Vivaldi/Application/vivaldi.exe"],
}
for name, candidates in bins.items():
    for c in candidates:
        p = Path(c)
        if p.is_file():
            print(f"  {name:8} {p}")
            print(f"  {'':8} version={exe_version(p)}")
            print(f"  {'':8} dir_writable_by_current_user={writable(p.parent)}")
            break

print("\n[5] ELEVATION SERVICES")
for pat in ("*/elevation_service.exe", "*/Brave-Browser/*/elevation_service.exe",
            "*/Application/*/elevation_service.exe"):
    for base in (PF, PF86, LOCAL):
        for hit in Path(base).glob(f"**/{Path(pat).name}") if base else []:
            print(f"  {hit}")

print("\n[6] ABE COM REGISTRATION")
KNOWN = {
    "Chrome": "{708860E0-F641-4611-8895-7D867DD3675B}",
    "Edge":   "{1FCBE96C-1697-43AF-9140-29DB18F2E706}",
    "Brave":  "{576B31AF-6369-4BA6-8566-2CEAB14C3BA6}",
}
for name, clsid in KNOWN.items():
    try:
        out = subprocess.run(
            ["reg", "query", rf"HKLM\SOFTWARE\Classes\CLSID\{clsid}\LocalServer32", "/ve"],
            capture_output=True, text=True, timeout=15,
        )
        val = [l.strip() for l in out.stdout.splitlines() if "REG_" in l]
        print(f"  {name:8} {clsid} -> {val[0].split('REG_')[-1].strip() if val else 'NOT REGISTERED'}")
    except Exception as e:
        print(f"  {name:8} error: {e}")

print("\n[6b] CLSID SCAN FOR elevation_service (reg.exe /s)")
try:
    out = subprocess.run(
        ["reg", "query", r"HKLM\SOFTWARE\Classes\CLSID", "/s", "/f", "elevation_service", "/d"],
        capture_output=True, text=True, timeout=120,
    )
    cur = None
    for line in out.stdout.splitlines():
        s = line.strip()
        if s.startswith("HKEY_"):
            cur = s
        elif "elevation_service" in s.lower() and cur:
            key = cur.split("CLSID\\")[-1].split("\\")[0]
            print(f"  {key}  {s.split('REG_')[-1].strip()}")
            cur = None
except Exception as e:
    print(f"  error: {e}")

print("\n[7] TPM")
try:
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "try { $t = Get-CimInstance -Namespace root/cimv2/security/microsofttpm "
         "-Class Win32_Tpm -ErrorAction Stop; "
         "\"present=$($t.IsEnabled_InitialValue) activated=$($t.IsActivated_InitialValue) "
         "spec=$($t.SpecVersion)\" } catch { 'no TPM WMI class' }"],
        capture_output=True, text=True, timeout=40,
    )
    print(f"  {out.stdout.strip() or out.stderr.strip() or 'unknown'}")
except Exception as e:
    print(f"  error: {e}")

print("\n[8] CNG KEY STORES ON DISK")
for base in (f"{PROGRAMDATA}/Microsoft/Crypto/Keys",
             f"{PROGRAMDATA}/Microsoft/Crypto/SystemKeys",
             f"{PROGRAMDATA}/Microsoft/Crypto/PCPKSP",
             f"{PROGRAMDATA}/Microsoft/Crypto/RSA",
             r"C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Crypto\Keys",
             f"{ROAM}/Microsoft/Crypto/Keys",
             f"{LOCAL}/Microsoft/Crypto/Keys"):
    d = Path(base)
    if not d.is_dir():
        continue
    try:
        entries = list(d.iterdir())
    except PermissionError:
        print(f"  {base}\n      ACCESS DENIED (needs elevation)")
        continue
    files = [e for e in entries if e.is_file()]
    dirs = [e for e in entries if e.is_dir()]
    print(f"  {base}")
    print(f"      files={len(files)} dirs={len(dirs)}")
    for sub in dirs[:5]:
        try:
            n = len(list(sub.iterdir()))
        except PermissionError:
            n = "denied"
        print(f"      dir {sub.name}: {n} entr(ies)")

print("\n[8b] CHROME/EDGE/BRAVE KEY NAMES VIA CNG")
for provider in ("Microsoft Software Key Storage Provider",
                 "Microsoft Platform Crypto Provider"):
    try:
        out = subprocess.run(
            ["certutil", "-csp", provider, "-key"],
            capture_output=True, text=True, timeout=30,
        )
        hits = [l.strip() for l in out.stdout.splitlines()
                if re.search(r"chromekey|brave|elevation", l, re.I)]
        print(f"  {provider}: {len(hits)} match(es)")
        for h in hits[:10]:
            print(f"      {h}")
    except Exception as e:
        print(f"  {provider}: error {e}")

print("\n[9] ABE POLICY OVERRIDE")
for name, rel in (
    ("Chrome", r"SOFTWARE\Policies\Google\Chrome"),
    ("Edge", r"SOFTWARE\Policies\Microsoft\Edge"),
    ("Brave", r"SOFTWARE\Policies\BraveSoftware\Brave"),
):
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"$p = 'HKLM:\\{rel}'; if (Test-Path $p) {{ "
             f"(Get-ItemProperty $p).ApplicationBoundEncryptionEnabled }} else {{ 'no policy key' }}"],
            capture_output=True, text=True, timeout=25,
        )
        print(f"  {name:8} ApplicationBoundEncryptionEnabled={out.stdout.strip() or 'unset'}")
    except Exception as e:
        print(f"  {name:8} error: {e}")

print("\n" + "=" * 66)
