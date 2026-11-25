# Windows DPAPI — Isolated Reference

Scope: DPAPI on Windows 10/11 — on-disk structures, key hierarchy, offline decryption chain.
**VERIFIED** = reproduced on the reference machine (Windows 11, Chrome 158, no TPM) by
parsing real files. **COMMUNITY** = from a public reimplementation (mimikatz, Impacket) that
agrees with observation but is not Microsoft-documented. **UNVERIFIED** = not confirmed.

## Ozet (TR)

DPAPI, kullanıcı parolasından türetilen bir master key ile veriyi şifreleyen ve Windows 2000'den beri
gelen sistem içi kasadır; blob formatı Microsoft tarafından dokümante edilmemiştir, yalnızca topluluk
çalışmalarıyla çözülmüştür. Master key'ler `%APPDATA%\Microsoft\Protect\<SID>\` altında 128 baytlık
başlıklı dosyalarda durur ve PBKDF2-HMAC ile parolanın SHA1 (yerel) veya MD4/NTLM (domain) özetinden
açılır. Makine kapsamlı veriler `…\System32\Microsoft\Protect\S-1-5-18\` altında, paroladan değil
`DPAPI_SYSTEM` LSA sırrından türeyen anahtarlarla korunur. Chromium'un ABE blobu (`APPB` + normal DPAPI
blobu) tam olarak bu kapsamdadır: anahtarı kayıp değil, `S-1-5-18\User` altında duruyor; orta
bütünlükte `NTE_BAD_KEY_STATE` almamızın sebebi bu. Duvar kriptografik değil, ayrıcalık duvarıdır.

## 1. What DPAPI actually is

`CryptProtectData` / `CryptUnprotectData` are thin RPC wrappers over code inside `lsass.exe`; the
calling process never holds the master key. Crypt32.dll forwards to LSA over a local RPC channel,
the context switches to SYSTEM, encryption happens there, only the blob comes back. [passcape]

- The blob is **self-describing**: master key GUID, algorithm IDs, salt and MAC travel with
  the ciphertext, so decryption needs no metadata beyond the master key file — and the master
  key is not in the blob, nor in the SQLite/JSON file next to it, and is itself encrypted.
- DPAPI is a *session* primitive — "DPAPI works exclusively online, only after the user has
  logged on", because the password hash is cached in LSA. Every offline tool simulates LSA.
- Three APIs get conflated: `CryptProtectData` (persistent, master-key-backed);
  `CryptProtectMemory` (session key in LSA, `_SAME_PROCESS`/`_CROSS_PROCESS`/`_SAME_LOGON`,
  **lost on reboot by design**); `NCryptProtectSecret` (DPAPI-NG, section 6, different
  container).

The `dwFlags` inside a blob are prompt/audit bits, not the API flags: the 0x10 in Chrome's
blob is `CRYPTPROTECT_AUDIT`. Microsoft documents AUDIT / LOCAL_MACHINE / UI_FORBIDDEN as
`CryptProtectData` parameters; the stored field is a different one with overlapping values
and the bit naming is mimikatz's, not Microsoft's. [ms-cryptprotectdata] [mimikatz-kull_m_dpapi.c]

## 2. Blob byte layout

Little-endian throughout; GUIDs in mixed-endian form. All `Len` fields are **bytes** except
`dwAlgCryptLen` / `dwAlgHashLen`, which are **bits**. This is `KULL_M_DPAPI_BLOB`
(`#pragma pack(4)`) walked field by field, and it consumes a real Chrome blob exactly.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `dwVersion` | `1` in every blob measured |
| 4 | 16 | `guidProvider` | `DF9D8CD0-1501-11D1-8C7A-00C04FC297EB` = standard provider (`psbase.dll`) |
| 20 | 4 | `dwMasterKeyVersion` | matches the master key file version (2) |
| 24 | 16 | `guidMasterKey` | which master key file opens this blob |
| 40 | 4 | `dwFlags` | 0x10 = audit in every Chrome blob measured |
| 44 | 4 | `dwDescriptionLen` | UTF-16LE **including** the terminating NUL |
| 48 | n | `szDescription` | `"Google Chrome\0"` = 28 bytes |
| 48+n | 4 | `algCrypt` | `0x6610` CALG_AES_256, `0x6603` CALG_3DES |
| 52+n | 4 | `dwAlgCryptLen` | 256, 192 |
| 56+n | 4 | `dwSaltLen` | 32 on AES-256 blobs |
| 60+n | s | `pbSalt` | per-blob random; this is what makes each session key unique |
| … | 4 | `dwHmacKeyLen` | **0** on every modern blob measured (its `pbHmacKey` follows, empty) |
| … | 4 | `algHash` | `0x800E` CALG_SHA_512, `0x8004` CALG_SHA1 |
| … | 4 | `dwAlgHashLen` | 512, 160 |
| … | 4 | `dwHmac2KeyLen` | 32 on AES/SHA-512 blobs |
| … | k | `pbHmac2Key` | nonzero; role unexplained, see open questions |
| … | 4 | `dwDataLen` | ciphertext length, multiple of block size |
| … | d | `pbData` | AES-CBC ciphertext, PKCS#7 padded |
| … | 4 | `dwSignLen` | 64 (SHA-512) |
| … | g | `pbSign` | MAC over the blob, section 5 |

`os_crypt.encrypted_key` after its 5-byte `DPAPI` prefix — 288 bytes total:

```
0000  01 00 00 00 d0 8c 9d df 01 15 d1 11 8c 7a 00 c0   .............z..
0010  4f c2 97 eb 01 00 00 00 42 e0 12 33 c5 65 5a 4d   O.......B..3.eZM
0020  ac 08 e3 bd 99 ac da 1e 10 00 00 00 1c 00 00 00   ................
0030  47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 43 00   G.o.o.g.l.e. .C.
0040  68 00 72 00 6f 00 6d 00 65 00 00 00 10 66 00 00   h.r.o.m.e....f..
0050  00 01 00 00 20 00 00 00 ff 22 66 d4 49 a2 67 9e   .... ...."f.I.g.
```

Version 1, provider `df9d8cd0-…`, master key version 1, master key
`3312e042-65c5-4d5a-ac08-e3bd99acda1e`, flags 0x10, descLen 0x1c = 28, `"Google Chrome\0"`,
`algCrypt` 0x6610 with 0x100 = 256 bits, saltLen 32 — and the salt starts at offset 88, exactly
where the field walk predicts. All 288 bytes consumed. That is the layout proof.

Sizing rule: salt starts at **60 + descLen**; everything after it costs
**24 + hmacKeyLen + hmac2KeyLen + signLen** bytes of length fields and MACs, plus salt and
ciphertext. Chrome-style `88 + 32 + 4 + 0 + 12 + 32 + 4 + 4 + 64 = 240` header, so a 32-byte
secret pads to 48 bytes and the blob totals 288. [VERIFIED]

## 3. Master key hierarchy

```
password (UTF-16LE, no NUL)
  ├─ local account  → SHA1(password)          ─┐
  └─ domain account → MD4(password) = NTLM    ─┤ PassHash
  PassHash ── HMAC-SHA1(PassHash, SID + NUL) ──► derivedKey (20 bytes)
  PBKDF2-HMAC-<algHash>(derivedKey, salt16, rounds, keyLen + blockLen)
  key = out[0:keyLen], iv = out[keyLen:];  AES-256-CBC (or 3DES) decrypt slot payload
  payload = [16-byte prefix][MAC hashLen][master key keyLen][padding]
```

Which hash applies is decided by the master key file's `dwPolicy`: `& 0x4` → SHA1 (local
account), otherwise MD4 (domain). mimikatz: `PassAlg = (flags & 4) ? CALG_SHA1 : CALG_MD4;`.
Passcape calls it "bit 3", the same bit from 1. [mimikatz-kull_m_dpapi.c] [mimikatz-wiki] [passcape]

The SID is hashed as the **string** `S-1-5-21-…-1001` in UTF-16LE **with** its NUL
(`(lstrlen(sid)+1) * sizeof(wchar_t)`); get the NUL wrong and the MAC check fails silently.

### 3.1 Master key file

One file per key, named `<GUID>` with braces stripped, `Hidden|System`, under
`%APPDATA%\Microsoft\Protect\<SID>\`. Header is 128 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `dwVersion` — 1 on Windows 2000, 2 on everything since |
| 4 / 8 | 4 / 4 | reserved |
| 12 | 72 | `szGuid[36]` — UTF-16LE, no NUL, matches the filename |
| 84 / 88 | 4 / 4 | unused |
| 92 | 4 | `dwPolicy` — `& 0x4` SHA1 password hash, `& 0x2` machine-secret-protected, `& 0x1` backup key needs `DPAPI_SYSTEM` |
| 96 | 8 | `dwMasterKeyLen` |
| 104 | 8 | `dwBackupKeyLen` |
| 112 | 8 | `dwCredHistLen` |
| 120 | 8 | `dwDomainKeyLen` |
| 128 | … | slots in that order |

The four length fields are **8 bytes each**. A DWORD version puts the first slot at 108; reading
`rounds` at 128+20 on a 468-byte file yields 8000 — plausible only if the slot starts at 128.
Passcape's struct shows `DWORD` and is wrong here; mimikatz uses `DWORD64`.
[VERIFIED] [passcape] [mimikatz-kull_m_dpapi.h] The slot is a 32-byte header plus payload:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `dwVersion` — 2 |
| 4 | 16 | `salt` |
| 20 | 4 | `rounds` — **8000** on Windows 11 24H2+, 4000 XP, 5600 Win7 default |
| 24 | 4 | `algHash` — `0x800E` SHA-512 |
| 28 | 4 | `algCrypt` — `0x6610` AES-256 |
| 32 | … | payload: 16-byte prefix ‖ MAC ‖ master key ‖ padding |

Measured slot: 176 = 32 + 16 + 64 (SHA-512 MAC) + 64 (AES-256 key). Read `rounds` and the
algorithm IDs from the file; hardcoding 4000 or 3DES breaks on any modern profile.

### 3.2 The Protect directory

```
%APPDATA%\Microsoft\Protect\
├── CREDHIST                       24-byte header + chained entries
└── S-1-5-21-…-1001\
    ├── Preferred                  24 bytes: GUID(16) + FILETIME(8)
    └── 3312e042-…, d3528bbc-…     master key files (468 bytes here)
```

`Preferred` is **binary**, not a UTF-16 GUID string — the common "text GUID" claim is wrong on
this build. Measured: 24 bytes; the first 16 decode as `d3528bbc-6507-47cd-8b68-f5d7caed717d`,
a real key file in the same directory. The trailing FILETIME is the key file's mtime **+ 90
days** (2026-10-04 09:43 local → 2027-01-02 06:43 UTC), so it behaves as an expiry, not the
creation time Passcape's struct name implies. [VERIFIED, one data point] [passcape]

`CREDHIST` is a 24-byte header (`dwVersion=1`, GUID, `dwNextLen=0`) when the password was never
changed; later entries are links each encrypted with the previous link's hash, so a chain of old
passwords unwinds from the newest password alone. [passcape] [VERIFIED size]

## 4. Scope: user / machine / SYSTEM

| Scope | Flag at protect time | Master key store | Unlocked by |
|---|---|---|---|
| Current user | `0` | `%APPDATA%\Microsoft\Protect\<SID>\` | password hash + SID |
| Any user on box | `CRYPTPROTECT_LOCAL_MACHINE` 0x4 | `%WINDIR%\System32\Microsoft\Protect\S-1-5-18\` | `DPAPI_SYSTEM` machine secret |
| System only | `CRYPTPROTECT_SYSTEM` 0x20000000 | `%WINDIR%\System32\Microsoft\Protect\S-1-5-18\User\` | `DPAPI_SYSTEM` (which half unconfirmed) |
| SYSTEM profile | — | `…\config\systemprofile\AppData\Roaming\Microsoft\Protect\` | SYSTEM's own password |

Measured: `…\Protect\S-1-5-18\` holds 3 master keys + `Preferred` + a `User` subdirectory and is
readable without elevation. `…\Protect\S-1-5-18\User\` holds 3 master keys + `Preferred` +
`Diagnostic.log` — **Chrome's and Edge's ABE master keys live here.**
`…\config\systemprofile\AppData\Roaming\Microsoft\Protect\` is **absent** here; it is created
lazily the first time something protects data in the SYSTEM profile, so never assume it exists.

`DPAPI_SYSTEM` is an LSA secret: 4-byte version, 20-byte machine key, 20-byte user key.
Impacket models exactly that (`DPAPI_SYSTEM{Version, MachineKey[20], UserKey[20]}`); mimikatz
accepts `2*20+4` bytes with a DWORD offset and tries machine half then user half. Reading it
needs `SECURITY` (plus `SYSTEM` for the boot key) or `lsass` — which is the point.
[impacket-dpapi.py] [mimikatz-kull_m_dpapi.c] [passcape]

`CRYPTPROTECT_SYSTEM` is protect-time only: passing it to `CryptUnprotectData` returns
`ERROR_INVALID_PARAMETER` (87) — measured on all three browsers. `CRYPTPROTECT_LOCAL_MACHINE` at
unprotect is harmless and unnecessary; unprotect searches both stores, so `flags=0` already finds
user-scope blobs and `LOCAL_MACHINE` still succeeds on them. [VERIFIED]

## 5. Offline decryption chain

Given a master key file, a blob, and either a password, a hash, or `DPAPI_SYSTEM`.

**1 — password to derived key.**

```
PassHash   = SHA1(pw.encode("utf-16le"))  if dwPolicy & 0x4     # local account
           = MD4(pw.encode("utf-16le"))   otherwise            # domain account
derivedKey = HMAC-SHA1(PassHash, (sid + "\0").encode("utf-16le"))
```

Protected users (Windows Hello / Protected Users group) use neither: mimikatz substitutes
`PBKDF2-SHA256(ntlm, sid, 10000)` then `PBKDF2-SHA256(that, sid, 1)`. The wiki is explicit —
"it's NOT the NTLM hash of the password, but another derived hash from it".

**2 — derived key to master key.**

```
key||iv = PBKDF2-HMAC-<algHash>(derivedKey, slot.salt, slot.rounds, keyLen + blockLen)
plain   = AES-256-CBC-decrypt(slot.payload, key, iv)        # no padding removal
check   : HMAC-<algHash>(derivedKey, plain[0:16]) == plain[16:16+hashLen]
masterkey = plain[-keyLen:]
```

The 16-byte prefix is a per-slot salt; the MAC is keyed by the HMAC of that salt, not by the
derived key directly. 3DES slots carry 4 extra padding bytes to subtract from the tail.

**3 — master key to blob plaintext.**

```
keyHash    = masterkey if len(masterkey) == 20 else SHA1(masterkey)
sessionKey = HMAC-<algHash>(keyHash, salt || entropy [|| SHA(password)])
derivedKey = sessionKey, ipad/opad-extended if shorter than keyLen
plain      = AES-CBC-decrypt(blob.pbData, derivedKey[0:keyLen], IV = 0x00…) → PKCS#7 unpad
```

IV is **all zeros**; uniqueness comes from the per-blob salt inside the session key. mimikatz
and Impacket agree.

**4 — integrity.** Impacket verifies `pbSign` as a MAC over `blob[20:]` (from `guidMasterKey` to
the end of `pbData`), keyed from `keyHash` and `pbHmac2Key`. mimikatz does **not** verify at all —
it decrypts and returns whatever falls out, so a wrong master key yields plausible garbage there
while Impacket returns `None`. [COMMUNITY]

### 5.1 mimikatz

```
sekurlsa::dpapi                       # decrypted master keys out of lsass
dpapi::cache                          # what is cached: SID;GUID;MD4;SHA1

dpapi::masterkey /in:"%APPDATA%\Microsoft\Protect\S-1-5-21-…-1001\3312e042-…" ^
                 /sid:S-1-5-21-…-1001 /password:<pw>
#   /hash:<sha1|ntlm hex>   /protected   /system:<DPAPI_SYSTEM hex> with /sid:S-1-5-18
dpapi::blob /in:blob.bin /masterkey:<hex> [/entropy:<hex>]
```

`/hash` takes 20 bytes (SHA-1) or 16 (NTLM) and picks the algorithm from the length; `/protected`
applies the PBKDF2 transform; `/system` takes the `DPAPI_SYSTEM` secret and tries machine half then
user half. `lsadump::secrets` produces that hex from `SECURITY`. [mimikatz-wiki] [mimikatz-kuhl_m_dpapi.c]

### 5.2 Impacket, as a second implementation

`impacket/dpapi.py` exposes `MasterKeyFile`, `MasterKey.decrypt(key)`,
`DPAPI_BLOB.decrypt(key, entropy)` and `deriveKeysFromUser(sid, password)`, which returns
**three** candidate keys — SHA1, MD4, and the protected-user PBKDF2 variant — so trying all
three sidesteps the "which hash" question. Its path is PBKDF2 → CBC → MAC check and returns
`None` on MAC failure, a better oracle than mimikatz when inputs are uncertain. [impacket-dpapi.py]

### 5.3 Failure modes

| Symptom | Meaning |
|---|---|
| `NTE_BAD_KEY_STATE` `0x8009000B` | the named master key exists but this logon may not use it — wrong scope, not a corrupt blob |
| decrypt OK, MAC fails | wrong password/hash, or MD4 used where policy says SHA1 |
| `ERROR_INVALID_PARAMETER` 87 | a protect-only flag (`CRYPTPROTECT_SYSTEM`) passed to unprotect |

## 6. DPAPI-NG and CNG

DPAPI-NG exists because DPAPI is single-machine by construction. Microsoft: "Cloud computing,
however, often requires that content encrypted on one computer be decrypted on another …
DPAPI-NG enables you to securely share secrets … by protecting them to a set of principals".
[ms-cng-dpapi]

| | DPAPI (v1) | DPAPI-NG |
|---|---|---|
| API | `CryptProtectData` / `CryptUnprotectData` | `NCryptProtectSecret` / `NCryptUnprotectSecret` |
| Container | blob of section 2 (`01 00 00 00` + provider GUID) | "Protected Data Format"; not parseable as a v1 blob |
| Scope | user / machine flags | a **protection descriptor string** |
| Key holder | local master key file | a CNG key protection provider (AD group key, web credentials, certificate) |
| Cross-machine | no (roaming profile excepted) | yes, by design |

Descriptor grammar: `Descriptor = Protector-or *("OR" Protector-or)`,
`Protector-or = Protector-and *("AND" Protector-and)`, `Protector-and = providerName "="
providerAttribute`. The left side must be `SID`, `SDDL`, `LOCAL`, `WEBCREDENTIALS` or
`CERTIFICATE`, case-insensitive. Documented examples:

```
SID=S-1-5-21-4392301 AND SID=S-1-5-21-3101812
LOCAL=user            LOCAL=machine
WEBCREDENTIALS=MyPasswordName,myweb.com
CERTIFICATE=HashID:sha1_hash_of_certificate
```

`SID` / `SDDL` / `LOCAL` route to the Microsoft Key Protection provider (AD group keys),
`WEBCREDENTIALS` to the Client Key Protection provider; custom providers are not allowed.
`LOCAL=user` and `LOCAL=machine` are the NG spellings of DPAPI's two scopes.
[ms-protection-descriptors] [ms-protection-providers]

Choose NG when the secret must open on another machine or for a group; plain DPAPI when it only
needs to open for this user on this box. A blob whose provider GUID is
`DF9D8CD0-1501-11D1-8C7A-00C04FC297EB` is **plain DPAPI** — a CNG key name existing somewhere in
the product does not make the blob DPAPI-NG. That GUID is the fastest discriminator.

## 7. Implications for Chromium OSCrypt

Chrome 158 / Edge 158 / Brave 158.1, no TPM, medium integrity:

| Item | Value |
|---|---|
| `os_crypt.encrypted_key` | `"DPAPI"` + 288-byte blob, master key `3312e042-…` (user store), desc `"Google Chrome"`, AES-256/SHA-512, 8000 rounds |
| `CryptUnprotectData` on it, as user | OK, 32 bytes |
| `os_crypt.app_bound_encrypted_key` | `"APPB"` + **640-byte blob**, master key `df9a3e03-…` (Chrome) / `bfb9d720-…` (Edge, Brave) |
| Where that master key is | `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\` — **present**, `dwPolicy = 0x6` |
| `CryptUnprotectData` on the ABE blob, as user | fails `0x8009000B` `NTE_BAD_KEY_STATE` |

Three corrections this reference forces on the article:

1. **`APPB` is followed by the DPAPI version DWORD, not an ABE version.** The bytes after the
   4-byte magic are `01 00 00 00` — `dwVersion` of an ordinary blob. The blob starts at offset 4,
   so the provider GUID sits at offset 8. Parsing from offset 8 shifts every field and yields a
   7 MB "description length"; that symptom identifies this exact bug.
2. **The ABE master key is not missing, it is scoped.** Absent from
   `%APPDATA%\Microsoft\Protect\<SID>` — true, and what the article reports — but present in the
   machine store under `S-1-5-18\User`, beside the keys that `CRYPTPROTECT_LOCAL_MACHINE` data
   uses. `NTE_BAD_KEY_STATE` means "key exists, you may not use it", not "not found".
3. **So the wall is privilege, not cryptography and not TPM.** A TPM-less machine produces the
   identical structure. Anything running as SYSTEM — service, scheduled task, `psexec -s` —
   reaches that store, and anything holding `DPAPI_SYSTEM` (SYSTEM + SECURITY hives, or `lsass`)
   can do it offline. That is a much narrower claim than "no cryptographic route".

What does not change: the v20 payload still embeds the install path and the service still
validates the caller, so scope bypass and caller validation are two separate problems. A
successful unwrap yields a ~384-byte payload (400 bytes of ciphertext, AES padding), not a
cookie — the AES-GCM layer and the path check are still ahead. And the offline route costs
PBKDF2 with 8000 rounds of HMAC-SHA-512 per guess per key; Passcape measured ~10 guesses/second
at 5600 rounds on Win7. Password cracking is not the attack; scope is.

## 8. Open questions

- Which half of `DPAPI_SYSTEM` unlocks the `S-1-5-18\User` store? mimikatz tries machine then
  user and prints which worked, implying it is not fixed. Not tested here (needs SYSTEM).
- `pbHmac2Key` (32 nonzero bytes) has no public explanation. Impacket uses it in the signature
  construction; mimikatz ignores it.
- Whether the ABE blob was created with `CRYPTPROTECT_SYSTEM`: the store location suggests it,
  the blob does not record it, and it is not recoverable from the bytes. [UNVERIFIED]
- Whether the ABE blob uses optional entropy. Wrong entropy would fail with a decrypt/MAC error
  rather than `NTE_BAD_KEY_STATE`, so our error is consistent with empty entropy but proves
  nothing.
- `Preferred` FILETIME = mtime + 90 days is one observation on one machine; Passcape calls the
  field a creation time. Two readings, one data point.
- `dwPolicy` bits beyond `0x4` (SHA1) are inferred from mimikatz branch conditions, not
  documentation. Whether Windows 11 25H2 changed `rounds` again is also open; 8000 is this build.

## 9. Sources

| URL | What it establishes |
|---|---|
| https://raw.githubusercontent.com/gentilkiwi/mimikatz/master/modules/kull_m_dpapi.h | blob / masterkey struct definitions, `pack(4)`, `CRYPTPROTECT_SYSTEM 0x20000000` |
| https://raw.githubusercontent.com/gentilkiwi/mimikatz/master/modules/kull_m_dpapi.c | field-by-field blob parse; `sessionkey`; PBKDF2→CBC→MAC sequence; `flags & 4 → SHA1`; `DPAPI_SYSTEM` machine-then-user order; `getProtected` chain |
| https://raw.githubusercontent.com/gentilkiwi/mimikatz/master/mimikatz/modules/dpapi/kuhl_m_dpapi.c | `/masterkey /hash /system /password /protected` semantics; `NTE_BAD_KEY_STATE` handling; blob flag names |
| https://raw.githubusercontent.com/wiki/gentilkiwi/mimikatz/module-~-dpapi.md | scope→secret mapping in prose; protected users; command syntax; `dpapi::cache` shape |
| https://raw.githubusercontent.com/fortra/impacket/master/impacket/dpapi.py | independent structs; zero IV; three candidate user keys; signature over `blob[20:]` |
| https://www.passcape.com/index.php?section=docsys&cmd=details&id=28 | master key header/slot structs; `Preferred`; 90-day rotation; `DPAPI_SYSTEM` unlocks machine keys; per-OS algorithm table; CryptProtectData→LSA RPC flow |
| https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata | LOCAL_MACHINE / UI_FORBIDDEN / AUDIT; session key + MAC statement; same-computer constraint |
| https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory | memory protection is session-scoped, lost on reboot |
| https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptprotectsecret | DPAPI-NG entry point, `NCRYPT_SILENT_FLAG` |
| https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi | DPAPI-NG rationale, principal types, function list |
| https://learn.microsoft.com/en-us/windows/win32/seccng/protection-descriptors | descriptor ABNF, allowed prefixes, example strings |
| https://learn.microsoft.com/en-us/windows/win32/seccng/protection-providers | provider selection per descriptor prefix; no custom providers |

Local measurements came from read-only temp-dir scripts: blob field walk, master key header walk,
`CryptUnprotectData` per-flag success/failure, `Preferred` FILETIME decode. No key material,
password or cookie value was printed.

## Confidence

**VERIFIED (measured, reproducible)**
- Blob field order, offsets, widths; 288-byte Chrome blob consumed exactly. `dwVersion = 1`,
  `guidProvider = DF9D8CD0-1501-11D1-8C7A-00C04FC297EB`, `dwFlags = 0x10`,
  `desc = "Google Chrome\0"` (28 bytes), `algCrypt = 0x6610`, `algHash = 0x800E`.
- Master key file: 128-byte header, 8-byte length fields, `dwPolicy = 0x5` (user) / `0x6`
  (machine), slot at 128 with `rounds = 8000`, `algHash = 0x800E`, `algCrypt = 0x6610`.
- `Preferred` = 24 bytes, binary GUID + FILETIME = key mtime + 90 days.
- ABE blob is `"APPB"` + a standard 640-byte DPAPI blob whose `dwVersion` is the DWORD at
  offset 4; its master keys `df9a3e03-…` (Chrome) and `bfb9d720-…` (Edge/Brave) exist at
  `…\Protect\S-1-5-18\User\` with `dwPolicy = 0x6`.
- `CryptUnprotectData`: v10 blob OK (32 bytes) with `flags=0` and `LOCAL_MACHINE`; ABE blob
  `0x8009000B`; `CRYPTPROTECT_SYSTEM` on unprotect → 87.
- `…\config\systemprofile\…\Protect` absent on this machine.

**COMMUNITY (reimplementation agrees, undocumented)**
- The PBKDF2/HMAC sequence and the exact strings hashed (password UTF-16LE, SID+NUL); slot MAC
  keyed by `HMAC(derivedKey, 16-byte prefix)`; blob signature over `blob[20:]` via `pbHmac2Key`.
- `dwFlags` bit names inside the blob; `dwPolicy` bit meanings; 90-day rotation as policy.

**UNVERIFIED (hypothesis only)**
- Which `DPAPI_SYSTEM` half unlocks the `S-1-5-18\User` store.
- That `elevation_service.exe` protects the ABE key with `CRYPTPROTECT_SYSTEM`.
- That the ABE blob has no optional entropy; any behaviour on other Windows builds.
