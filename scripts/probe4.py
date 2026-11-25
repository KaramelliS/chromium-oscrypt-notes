#!/usr/bin/env python3
"""Phase 4: is the ABE blob just a DPAPI blob behind a 4-byte marker?

Tries every plausible offset and reports success plus nothing else.
"""
import base64
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LOCAL = os.environ["LOCALAPPDATA"]
ROOTS = {
    "Chrome": f"{LOCAL}/Google/Chrome/User Data",
    "Edge":   f"{LOCAL}/Microsoft/Edge/User Data",
    "Brave":  f"{LOCAL}/BraveSoftware/Brave-Browser/User Data",
}

crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32
RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def unprotect(blob: bytes, entropy: bytes = None, flags: int = 0):
    buf = ctypes.create_string_buffer(blob, len(blob))
    din = DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    dout = DATA_BLOB()
    ent = None
    if entropy:
        ebuf = ctypes.create_string_buffer(entropy, len(entropy))
        ent = DATA_BLOB(len(entropy), ctypes.cast(ebuf, ctypes.POINTER(ctypes.c_char)))
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(din), None,
        ctypes.byref(ent) if ent else None,
        None, None, flags, ctypes.byref(dout))
    if not ok:
        return None
    try:
        return ctypes.string_at(dout.pbData, dout.cbData)
    finally:
        kernel32.LocalFree(dout.pbData)


def show(label, out):
    if out is None:
        print(f"      {label:28} FAIL")
    else:
        print(f"      {label:28} OK -> {len(out)} bytes, head={out[:16].hex()}")


print("=" * 70)
print(" PHASE 4 — ABE blob vs DPAPI, offset sweep")
print("=" * 70)

for name, root in ROOTS.items():
    ls = Path(root) / "Local State"
    if not ls.is_file():
        continue
    j = json.loads(ls.read_text(encoding="utf-8", errors="replace"))
    abe = (j.get("os_crypt") or {}).get("app_bound_encrypted_key")
    if not isinstance(abe, str):
        continue
    raw = base64.b64decode(abe)
    print(f"\n  {name}  (total {len(raw)} bytes)")
    print(f"      raw[0:12] = {raw[0:12].hex()}  ascii={raw[0:4]!r}")
    for off in (0, 4, 8, 12, 16):
        if len(raw) - off < 40:
            continue
        show(f"offset {off}", unprotect(raw[off:]))
    # if the blob is DPAPI, the provider GUID should sit at blob offset 4
    guid = raw[8:24] if len(raw) > 24 else b""
    print(f"      provider-ish guid = {guid.hex()}")

print("\n[?] WHO AM I")
try:
    out = subprocess.run(["whoami", "/groups"], capture_output=True, text=True,
                         timeout=30, errors="replace")
    admin = "S-1-5-32-544" in out.stdout and "Enabled" in out.stdout
    integ = [l for l in out.stdout.splitlines() if "Mandatory Label" in l]
    print(f"      admin group present+enabled: {admin}")
    for l in integ:
        print(f"      {l.strip()[:100]}")
except Exception as e:
    print(f"      error: {e}")

print("\n" + "=" * 70)
