# Chromium's Encrypted Vault

## OSCrypt, App-Bound Encryption, and the Lie of "Works on Every Machine"

> This is format documentation. It describes what happens at the byte level, why it happens, and where it breaks.

---

## 1. Summary

Chromium-based browsers (Chrome, Edge, Brave, Opera, Vivaldi) store saved passwords and cookies on disk with a **two-layer** scheme. The outer layer is the operating system's key vault (DPAPI on Windows, Keychain on macOS, keyring on Linux). The inner layer is the browser's own AES key. The SQLite file is actually open — only a single column is encrypted.

In 2024, Chrome 127 added a third layer to this model: **App-Bound Encryption (ABE)**. ABE binds the key to the machine and to an install path, wrapping it through a TPM-backed, non-exportable CNG key. The consequence in one sentence: **decryption is no longer portable.** Run on the same machine, as the same user, and it opens. Copy the `Local State` file to another machine and it does not.

The central claim of this article: a tool that "works on every machine" is not possible as of 2026. What is possible is a library that honestly declares its coverage. The rest of this piece shows why, byte by byte.

---

## 2. What Chromium writes to disk

Relevant files inside a profile directory (`%LOCALAPPDATA%\Google\Chrome\User Data\Default`, `~/Library/Application Support/Google/Chrome/Default` on macOS, `~/.config/google-chrome/Default` on Linux):

| File | Content | Critical column |
|---|---|---|
| `Login Data` | Saved passwords | `logins.password_value` |
| `Network/Cookies` | Cookies | `cookies.encrypted_value` |
| `Web Data` | Autofill, card data | `credit_cards` |
| `History` | Browsing history | `urls` |
| `Local State` (root dir, not profile) | Key wrapping | `os_crypt.encrypted_key` |

Since Chrome 96 the cookie database moved from the profile root into `Network/`. Most older tools still look in the root and silently return nothing — the number one cause of "it doesn't work" reports.

Two more practical traps:

**WAL mode.** SQLite databases operate with `-wal` and `-shm` sidecar files. Copy only the `Cookies` file and you lose the most recent session's cookies, because they have not been written to the main file yet. The correct approach is the SQLite backup API or a VSS snapshot.

**Locking.** The file may be locked while the browser is running. On Windows, opening with `FILE_SHARE_READ` is usually enough, but for a consistent copy prefer a snapshot.

---

## 3. Two-layer encryption

```
┌──────────────────────────────────────────┐
│  SQLite file (plain on disk)             │
│  ┌────────────────────────────────────┐  │
│  │ password_value / encrypted_value   │  │
│  │  = "v10" + AES-256-GCM(data)       │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
                    ▲
                    │ 32-byte AES key
                    │
┌──────────────────────────────────────────┐
│  Local State → os_crypt.encrypted_key    │
│  = base64( "DPAPI" + DPAPI(aes_key) )    │
└──────────────────────────────────────────┘
                    ▲
                    │ DPAPI / Keychain / libsecret
                    │
┌──────────────────────────────────────────┐
│  OS key vault (bound to user session)    │
└──────────────────────────────────────────┘
```

The design rationale is simple: anyone who can read the SQLite file sees the data structure, but without the key all they see is ciphertext. The key in turn is bound to the user session. So the threat model is "someone who copies the file" — that person cannot copy the key either, because the key is not in the file, it is in the OS vault.

This model held together until 2024. The assumption ABE broke is exactly this one: *the key travels with the user session.*

---

## 4. Blob formats

### 4.1 Windows — `v10` / `v11` (AES-256-GCM)

```
offset  0 .. 2    "v10"  or  "v11"         (3 bytes, ASCII)
offset  3 .. 14   nonce                    (12 bytes)
offset 15 .. n-16 ciphertext               (n-31 bytes)
offset n-16 .. n  authentication tag       (16 bytes)
```

Total overhead is 31 bytes. `v11` is the same structure, differing only at the application level (Chromium's code handles both identically). The AES key comes from `Local State`.

### 4.2 macOS / Linux — `v10` (AES-128-CBC)

```
offset  0 .. 2    "v10"                       (3 bytes)
offset  3 .. 18   IV = 0x20 × 16              (16 space characters)
offset 19 .. n    AES-128-CBC ciphertext      (PKCS#7 padded)
```

No GCM, no tag, no nonce. The IV is fixed and is literally sixteen spaces. This is not a cryptographic weakness in context (IV reuse under the same key leaks information in CBC, but here the key is per-user and there is a single writer), but it shows how hand-rolled the format is.

Key derivation:

```python
# macOS
key = PBKDF2_HMAC_SHA1(password_from_keychain, b"saltysalt", 1003, 16)

# Linux, basic store
key = PBKDF2_HMAC_SHA1(b"peanuts", b"saltysalt", 1, 16)
```

On macOS, `password_from_keychain` is the `"Chrome Safe Storage"` entry in Keychain. The 1003 iteration count has not changed since 2013.

### 4.3 Host binding — a silent format change

Around Chrome 130 the cookie database's `meta` version rose to 24 and `SHA256(host_key)` was prepended to the decrypted plaintext:

```
plaintext = SHA256(host_key)[0..32] || actual_cookie_value
```

A tool unaware of this writes 32 bytes of garbage at the head of the cookie and the site rejects it. The same change produced a side effect: since the hash binds to the host rather than the cookie value, two cookies belonging to the same host become interchangeable. That is a useful looseness for session fixation.

### 4.4 Timestamps

Chromium uses `base::Time`: **microseconds since 1601-01-01 UTC.** To convert:

```python
unix_seconds = chromium_ts / 1_000_000 - 11644473600
```

`expires_utc = 0` means it is a session cookie.

---

## 5. App-Bound Encryption — why it appeared

In 2024 a known family of infostealers spread on Windows. Their common denominator: **they ran as the user.** Running as the user, they opened the DPAPI key without friction. So Chromium's entire layered encryption meant **nothing** against malware running in the same user context. The layers protected against a file thief, not against a process thief.

Google's answer was ABE: separate the key from the user, bind it to the machine, and open it only through a signed Chrome binary calling a service.

### 5.1 Mechanism

```
Chrome  ──COM──▶  elevation_service.exe  ──▶  CNG machine key (TPM)
                         │
                         └─ validates who the caller is:
                            • process path
                            • signature
                            • command line
```

The critical point: validation looks at the **identity of the calling process.** That is why most community solutions follow a "get inside Chrome" logic:

- Reflective process hollowing (`xaitax/Chrome-App-Bound-Encryption-Decryption`)
- Transacted hollowing + named pipe (`internetangel/ZeroCrumb`)
- Injection into the COM server (`teng-lin/rookie-cookies`)

All of them solve the same problem: make the code execute from inside the Chrome process so it passes validation.

### 5.2 COM interface and the real registration chain

Service-backed COM has no `LocalServer32` subkey. The chain is:

```
CLSID {…}  →  AppID {…}  →  LocalService  →  elevation_service.exe (LocalSystem)
```

Measured on this machine:

| Vendor | CLSID = AppID | LocalService | Runs as |
|---|---|---|---|
| Chrome | `{708860E0-F641-4611-8895-7D867DD3675B}` | `GoogleChromeElevationService` | **LocalSystem** |
| Brave | `{576B31AF-6369-4B6B-8560-E4B203A97A8B}` | `BraveElevationService` | **LocalSystem** |
| Edge | `{CD489BAC-BF1F-4F4B-9DB9-39B823919EAC}` | `MicrosoftCopilotElevationService` | **LocalSystem** |

Chrome's GUID from 2024 is still valid. Edge's is dead: Edge moved to the "Copilot" application in 2026 and uses a new one. So "the CLSID is version-dependent" is true for Edge and false for Chrome.

The last column is the important one: **all three services run as `LocalSystem`.** That is the answer to the master key puzzle in the next section.

A probe that looks for `LocalServer32` concludes "the CLSID is not registered." That was the mistake in the first version of this article.

### 5.3 Inside the v20 key wrap

This section is measurement, not speculation. On Chrome 158, Edge 158 and Brave 158.1 at the end of 2026, `os_crypt.app_bound_encrypted_key` has this byte layout:

```
4150504201000000...     "APPB" + 0x00000001
d08c9ddf0115d1118c7a00c04fc297eb...   ← DPAPI provider GUID
```

`DF9D8CD0-1501-11D1-8C7A-00C04FC297EB` is Windows' standard DPAPI provider. So the wrap is **an ordinary DPAPI blob** with a 4-byte `APPB` marker in front. No CNG, no TPM, no ChaCha — at least on this machine.

Parsing the master key GUID inside the blob gives this:

| Browser | master key | In the user's Protect store |
|---|---|---|
| Chrome | `DF9A3E03-…-ACE50E51608E` | **no** |
| Edge | `BFB9D720-…-CB821EF2222C` | **no** |
| Brave | `BFB9D720-…-CB821EF2222C` | **no** |

For comparison, the legacy `encrypted_key` in the same `Local State` uses `3312E042-…` and that one **is** in the user's store. That is the difference: the v10 wrap is sealed to the user account, the v20 wrap is sealed to a different account context (the elevation service).

That account's store was located as well:

```
C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\
├── df9a3e03-044f-4442-b5f1-ace50e51608e   ← Chrome ABE master key
├── bfb9d720-c655-4be8-9abc-cb821ef2222c   ← Edge/Brave ABE master key
└── Preferred
```

`S-1-5-18` is LocalSystem's SID. The files are **readable** — you can list them. Their contents are encrypted with the `DPAPI_SYSTEM` LSA secret, and unlocking that secret requires SYSTEM. The master key is not missing, it is inaccessible.

The consequence: `CryptUnprotectData` returns `NTE_BAD_KEY_STATE` (`0x8009000B`) at medium integrity. That does not mean "no key", it means "the key exists and you may not use it." ABE's wall is a **privilege boundary**, not cryptography.

Once the wrap opens, the remaining payload has this structure:

```
[len]            install path: "C:\Program Files\Google\Chrome"
0x01             version/flags byte
[12]             nonce
[32]             ciphertext  → the 32-byte AES key
[16]             GCM tag
```

The presence of the path inside the encrypted payload is no accident — the service compares the caller's path against this value. The path is part of authentication.

### 5.4 Version treadmill

ABE's evolution over two years:

| Version | Change |
|---|---|
| 127 | `v20` lands for cookies. The key is no longer opened with the user's DPAPI. |
| 133 | ChaCha20-Poly1305 inside `elevation_service.exe` |
| 137 | Back to AES-256-GCM, key after the `\x03` byte |
| 157 | New CNG key name `Google Chromekey2`, new XOR key |

Considering a major release arrives roughly every four weeks, this table says one clear thing: **write an offset-based parser and it breaks every month.** The breakage is silent — not an exception, just wrong garbage data.

The right approach is to bind to a function rather than an offset:

```javascript
// Frida — version independent
Interceptor.attach(Module.findExportByName("bcrypt.dll", "BCryptDecrypt"), {
  onEnter(args) {
    // args[0] = hKey, args[2] = pbInput (ciphertext), args[3] = cbInput
    this.input = args[2];
    this.len = args[3].toInt32();
  },
  onLeave(retval) {
    if (retval.toInt32() === 0 && this.len === 32) {
      send({ kind: "aes_key", bytes: hexdump(this.input, { length: 32 }) });
    }
  }
});
```

The key size (32 bytes) and call shape are a far more stable anchor. The internals can change; the signature of `BCryptDecrypt` does not.

---

## 6. Coverage matrix

Every row here is an honest answer to "does it work":

| Situation | Windows | macOS | Linux | Confidence |
|---|---|---|---|---|
| Same machine, same user session, Chrome < 127 | ✅ | ✅ | ✅ | High |
| Same machine, same user, Chrome 127+ (ABE) | ⚠️ | ✅ | ✅ | Conditional |
| Same machine, SYSTEM/root, no user session | ⚠️ impersonation required | ⚠️ keychain locked | ⚠️ no D-Bus | Fragile |
| Different machine, Chrome < 127 | ✅ | ✅ | ✅ | High |
| Different machine, Chrome 127+ | ❌ | ✅ | ✅ | Impossible |
| Firefox / Safari | ❌ | ❌ | ❌ | Out of scope |

The ✅ marks on the macOS rows are not an oversight but an observation: ABE has not spread to macOS. Keychain `"Chrome Safe Storage"` is still PBKDF2 and there is no TPM. Today it is the highest-yield platform.

---

## 7. Where it dies

### 7.1 The death of the cross-host scenario

The `dumpkeys` / `archive` / `restore` model of tools like `moonD4rk/HackBrowserData` was this: extract the key on machine A, decrypt the database on machine B. In the v10/v11 world this was entirely valid, because the key was just an AES key and it could be carried as a file.

ABE killed that model. But not for the reason usually assumed — it is not TPM. It fails on a machine with no TPM at all. The real reason: the v20 wrap's DPAPI master key is not in the user's Protect store, it lives in another account's context. Copy `Local State` to another machine and both the master key and the account context are missing. The error surface is narrow, so you cannot even see which stage died.

So the technical life of "pull it from every machine" ended in 2024. What remains is "on every machine, in that machine's own context" — a different claim.

### 7.2 Working ≠ surviving

There are three distinct things here, routinely confused:

1. **Producing a correct result.** Format knowledge + key = works.
2. **Not being detected.** Reflective hollowing, COM injection, named pipes — all generate AV/EDR signatures. `rookie-cookies` says so plainly in its own README.
3. **Staying clean.** Talking over COM within the same user session is technically the cleanest path, and also the narrowest in coverage.

Collapse these into a single "success" flag and a library lies to its user.

### 7.3 Linux is more fragile than you think

The basic store key (`peanuts`) always works. But most modern distributions use gnome-keyring or kwallet, and those depend on the session D-Bus. Run with `sudo` and root's keyring is empty — no key, decryption fails. This is where the "Linux is easy" assumption most often collapses.

### 7.4 Keychain lock on macOS

An enabled FileVault is not the problem — the disk is already mounted. The problem is a locked login keychain. If locked, `"Chrome Safe Storage"` cannot be read and a password is prompted. Within the same user session it is usually unlocked.

### 7.5 Version drift

Look at the table above: 127, 133, 137, 157. Four changes in two years. Can a library sustain this? Yes, but only if CI runs against real Chrome binaries. Otherwise every release brings an issue flood.

---

## 8. Design consequence: capability tiers

Instead of selling "works everywhere," let the library **declare what it encountered**:

```rust
pub enum Capability {
    /// v10/v11 — anywhere, anytime.
    Plain,
    /// v20, same user session, COM path — clean.
    AbeSameUser,
    /// v20, in-process hook — works, carries AV risk.
    AbeInjected,
    /// Only possible in Plain mode.
    CrossHost,
}

pub struct Decrypted {
    pub value: Vec<u8>,
    pub capability: Capability,
}
```

Returning `(data, capability)` instead of `Result<Vec<u8>>` lets the caller answer "what do I have." The difference between telling a library user "success" and "success, via injection" is the difference between an incident and no incident in production.

And an honest table in the README. An inflated promise collapses in the first issue; a measured promise makes the project trustworthy.

---

## 9. Measurements — late 2026, one real machine

The table below was taken on a Windows 11 machine with no TPM, in a normal medium-integrity user session. Installed versions: Chrome `158.0.8127.36`, Edge `158.0.4370.33`, Brave `158.1.100.59`, Opera (no ABE).

| Measurement | Result |
|---|---|
| TPM | none (`Win32_Tpm` class absent) |
| Chrome cookies | 200 rows, **all `v20`**, meta 24 |
| Edge cookies | 197 rows, **all `v10`**, meta 24 |
| Edge cookie decryption | **197/197 succeeded**, 197/197 host hash prefixes correct |
| Edge passwords | 245 rows, 183 `v10` → **183/183 decrypted** |
| Brave passwords | 23 rows, **all `v20`** |
| Opera cookies | 14 rows, all `v10` |
| Chrome v10 key against v20 blobs | **0/40** — the wall |
| Brave `Network/Cookies` | WinError 32, file locked (19 processes running) |
| Brave install dir user-writable | **yes** |
| Chrome install dir user-writable | no |
| 2024 CLSIDs | Chrome ✓ still valid, Edge ✗ (moved to Copilot) |
| Elevation services run as | **LocalSystem**, all three |
| Where the ABE master key lives | `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\` (readable, sealed by `DPAPI_SYSTEM`) |
| `elevation_service.exe` signers | Google LLC / Brave Software, Inc. / Microsoft Corporation |

Three conclusions follow.

**1. ABE rollout is uneven.** Edge at version 158 carries an `app_bound_encrypted_key` field but still writes its cookies and passwords with `v10`. So Edge has ABE but it is not engaged. Today 183 passwords and 197 cookies open with plain DPAPI, no bypass at all. In practice the softest target is not Chrome, it is Edge.

**2. The lock lives in the file handle.** While Brave runs, `Network/Cookies` is opened with share mode 0. Copying it, opening it with `mode=ro`, reading the `-wal` — none of it works. That is the real obstacle to "copy the profile, open it elsewhere." The fix is either closing the browser or a VSS snapshot, and the latter requires administrator.

**3. ABE's wall is account scope.** This machine has no TPM, no CNG key, no ChaCha. Just a DPAPI blob sealed to another account. So there are two ways past ABE: run in that account's context (elevation), or put code inside that account's process (injection). There is no third, cryptographic route.

---

## 10. Verifying it yourself

```bash
# Windows: inspect the key wrap without printing the value
python -c "
import base64, json, pathlib
ls = json.loads(pathlib.Path(r'%LOCALAPPDATA%/Google/Chrome/User Data/Local State').read_text())
raw = base64.b64decode(ls['os_crypt']['encrypted_key'])
print('prefix:', raw[:5], 'length:', len(raw))
print('abe present:', 'app_bound_encrypted_key' in ls['os_crypt'])
"

# Cookie database meta version
sqlite3 "Network/Cookies" "SELECT value FROM meta WHERE key='version';"

# Prefix of a cookie row on Windows
sqlite3 "Network/Cookies" "SELECT substr(encrypted_value,1,3), length(encrypted_value) FROM cookies LIMIT 5;"
```

If `meta` is 24 or higher, the plaintext begins with `SHA256(host_key)`. That single line answers most "why is my cookie garbage" questions.

---

## 11. References

| Project | What to look at it for |
|---|---|
| `moonD4rk/HackBrowserData` | Go, cross-platform, `dumpkeys` / `archive` / `restore` — the cross-host model of the v10 era |
| `xaitax/Chrome-App-Bound-Encryption-Decryption` | ABE bypass via reflective process hollowing |
| `runassu/chrome_v20_decryption` | The best documentation of v20 structure and version changes |
| `internetangel/ZeroCrumb` | Unprivileged ABE, transacted hollowing + named pipe |
| `norahc-x/Margaret-Stealer` | In-memory `CookieMonster` discovery, never touches disk |
| `teng-lin/rookie-cookies` | Rust core + Python/Node bindings, MIT — a template for library architecture |
| `mendacus/chrome-abe-decryption-bof` | Cobalt Strike BOF implementation |
| `AlessandroZ/LaZagne` | Classic cross-platform credential extraction |
| `djhohnstein/SharpChrome` | The .NET side |

---

## 12. Verification note

Version numbers and structural details in this article rest on community observations as of late 2026. ABE internals change every few releases and the changes are not announced backwards. Do not carry this into production code without verifying in your own environment.

Check these three things on your own machine in particular:

1. Is there an `app_bound_encrypted_key` under `os_crypt`
2. What is the cookie `meta` version
3. Is the `encrypted_value` prefix `v10` or `v20`

These three values fully determine which code path will work.

---

*License: CC BY 4.0 — use, translate, redistribute freely with attribution.*
