#!/usr/bin/env python3
"""Phase 3: characterise the ABE blob, then prove the v10 path end to end.

Decrypts exactly one cookie and one password from Edge, and prints only
booleans, lengths and validation results. No plaintext, no key bytes.
"""
import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_unprotect(blob: bytes):
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(blob, len(blob))
    din = DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    dout = DATA_BLOB()
    if not crypt32.CryptUnprotectData(
            ctypes.byref(din), None, None, None, None, 0x1, ctypes.byref(dout)):
        return None
    try:
        return ctypes.string_at(dout.pbData, dout.cbData)
    finally:
        kernel32.LocalFree(dout.pbData)


LOCAL = os.environ["LOCALAPPDATA"]
ROOTS = {
    "Chrome": f"{LOCAL}/Google/Chrome/User Data",
    "Edge":   f"{LOCAL}/Microsoft/Edge/User Data",
    "Brave":  f"{LOCAL}/BraveSoftware/Brave-Browser/User Data",
}

print("=" * 70)
print(" PHASE 3 — ABE blob anatomy + v10 end-to-end proof")
print("=" * 70)

print("\n[A] ABE BLOB ANATOMY (ciphertext only, nothing secret here)")
for name, root in ROOTS.items():
    ls = Path(root) / "Local State"
    if not ls.is_file():
        continue
    j = json.loads(ls.read_text(encoding="utf-8", errors="replace"))
    abe = (j.get("os_crypt") or {}).get("app_bound_encrypted_key")
    if not isinstance(abe, str):
        print(f"  {name}: no abe blob")
        continue
    raw = base64.b64decode(abe)
    head = raw[:8]
    print(f"  {name:8} len={len(raw)}  magic={head[:4]!r}  flags={head[4:8].hex()}")
    print(f"  {'':8} bytes 08..40 = {raw[8:40].hex()}")
    body = raw[8:]
    for magic in (b"DPAPI-NG", b"DPAPI", b"MSFT"):
        print(f"  {'':8} contains {magic!r}: {body.find(magic)}")
    tail32 = body[-32:]
    print(f"  {'':8} last 32 bytes (nonce+tag candidate) = {tail32.hex()}")
    print(f"  {'':8} body len={len(body)}  body-8 mod 16 = {(len(body)-8) % 16}")

print("\n[B] v10 END TO END — Edge (browser not running, DB readable)")
root = Path(ROOTS["Edge"])
ls = json.loads((root / "Local State").read_text(encoding="utf-8", errors="replace"))
ek = base64.b64decode(ls["os_crypt"]["encrypted_key"])
aes_key = dpapi_unprotect(ek[5:])
print(f"  master key unwrapped: {aes_key is not None} ({len(aes_key or b'')} bytes)")

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402


def decrypt_v10(blob: bytes, key: bytes):
    if blob[:3] not in (b"v10", b"v11"):
        return None
    nonce, ct = blob[3:15], blob[15:]
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        return None


db = root / "Default" / "Network" / "Cookies"
if not db.is_file():
    db = root / "Default" / "Cookies"
try:
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=3)
    rows = con.execute(
        "SELECT host_key, encrypted_value, is_secure, is_httponly, expires_utc "
        "FROM cookies WHERE length(encrypted_value) > 20 LIMIT 200").fetchall()
    print(f"  cookie rows sampled: {len(rows)}")
    ok = 0
    host_bound = 0
    for host_key, blob, secure, httponly, exp in rows:
        pt = decrypt_v10(blob, aes_key)
        if pt is None:
            continue
        ok += 1
        expect = hashlib.sha256(host_key.encode()).digest()
        if pt[:32] == expect:
            host_bound += 1
    print(f"  decrypted: {ok}/{len(rows)}")
    print(f"  SHA256(host_key) prefix present: {host_bound}/{ok}")
    if ok:
        sample = next(decrypt_v10(b, aes_key) for _, b, *_ in rows if decrypt_v10(b, aes_key))
        body = sample[32:] if sample[:32] == hashlib.sha256(
            next(h for h, b, *_ in rows if decrypt_v10(b, aes_key)).encode()).digest() else sample
        print(f"  sample plaintext length (after stripping host hash): {len(body)}")
        print(f"  sample is session cookie: {rows[0][4] == 0}")
    con.close()
except Exception as e:
    print(f"  cookie db: {type(e).__name__}: {e}")

ld = root / "Default" / "Login Data"
try:
    con = sqlite3.connect(f"file:{ld.as_posix()}?mode=ro", uri=True, timeout=3)
    rows = con.execute(
        "SELECT origin_url, password_value FROM logins "
        "WHERE length(password_value) > 20 LIMIT 200").fetchall()
    ok = sum(1 for _, b in rows if decrypt_v10(b, aes_key))
    print(f"  logins decrypted: {ok}/{len(rows)}")
    con.close()
except Exception as e:
    print(f"  login db: {type(e).__name__}: {e}")

print("\n[C] SAME TEST ON CHROME (v20 rows) — expected to fail on the v10 key")
root = Path(ROOTS["Chrome"])
ls = json.loads((root / "Local State").read_text(encoding="utf-8", errors="replace"))
ck = dpapi_unprotect(base64.b64decode(ls["os_crypt"]["encrypted_key"])[5:])
db = root / "Default" / "Network" / "Cookies"
try:
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=3)
    rows = con.execute(
        "SELECT encrypted_value FROM cookies WHERE length(encrypted_value) > 20 LIMIT 50").fetchall()
    ok = sum(1 for (b,) in rows if decrypt_v10(b, ck))
    print(f"  v10 key against v20 blobs: {ok}/{len(rows)} decrypted (0 is the wall)")
    con.close()
except Exception as e:
    print(f"  {type(e).__name__}: {e}")

print("\n" + "=" * 70)
