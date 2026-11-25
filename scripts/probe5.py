#!/usr/bin/env python3
"""Phase 5: whose DPAPI master key protects the ABE blob?

Parses the master key GUID out of the blob and looks for it in the user's
Protect store. Reports GUIDs and flags only; no secret material.
"""
import base64
import json
import os
import sys
import uuid
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LOCAL = os.getenv("LOCALAPPDATA", "")
ROAM = os.getenv("APPDATA", "")

ROOTS = {
    "Chrome": f"{LOCAL}/Google/Chrome/User Data",
    "Edge": f"{LOCAL}/Microsoft/Edge/User Data",
    "Brave": f"{LOCAL}/BraveSoftware/Brave-Browser/User Data",
}


def user_master_keys():
    keys = set()
    base = Path(ROAM) / "Microsoft" / "Protect"
    if base.is_dir():
        for d in base.iterdir():
            if d.is_dir():
                try:
                    for f in d.iterdir():
                        keys.add(f.name.upper())
                except PermissionError:
                    pass
    return keys


def parse_dpapi(body: bytes):
    if len(body) < 44:
        return None
    version = int.from_bytes(body[0:4], "little")
    provider = str(uuid.UUID(bytes_le=body[4:20])).upper()
    mk_version = int.from_bytes(body[20:24], "little")
    master = str(uuid.UUID(bytes_le=body[24:40])).upper()
    flags = int.from_bytes(body[40:44], "little")
    return {
        "version": version,
        "provider": provider,
        "mk_version": mk_version,
        "master": master,
        "flags": flags,
    }


user_keys = user_master_keys()
print("=" * 70)
print(" PHASE 5 — ABE blob master key ownership")
print("=" * 70)
print(f"\n  user master key files found: {len(user_keys)}")

for name, root in ROOTS.items():
    ls = Path(root) / "Local State"
    if not ls.is_file():
        continue
    try:
        j = json.loads(ls.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        continue
    oc = j.get("os_crypt") or {}
    print(f"\n  {name}")
    for key, prefix_len in (("encrypted_key", 5), ("app_bound_encrypted_key", 4)):
        v = oc.get(key)
        if not isinstance(v, str):
            continue
        raw = base64.b64decode(v)
        info = parse_dpapi(raw[prefix_len:])
        if not info:
            print(f"      {key:26} too short")
            continue
        owner = "USER" if info["master"] in user_keys else "NOT in user store"
        print(f"      {key:26} master={info['master']}  {owner}")
        print(f"      {'':26} provider={info['provider']} flags=0x{info['flags']:x} ver={info['version']}")

print("\n" + "=" * 70)
