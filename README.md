# Chromium's Encrypted Vault

**OSCrypt, App-Bound Encryption, and the Lie of "Works on Every Machine"**

Format documentation on how Chromium-based browsers store credentials and cookies, why Chrome 127 changed the model, and where every "extract from any machine" claim actually dies.

[![License: CC BY 4.0](https://img.shields.io/badge/license-CC%20BY%204.0-lightgrey.svg)](LICENSE)
[![Chromium](https://img.shields.io/badge/Chromium-127%20%E2%86%92%20157-blue)](article/en.md#54-version-treadmill)

---

## Read

| | |
|---|---|
| **Türkçe** | [`article/tr.md`](article/tr.md) |
| **English** | [`article/en.md`](article/en.md) |

---

## What's inside

- The two-layer OSCrypt design: SQLite on disk, AES key in `Local State`, that key wrapped by DPAPI / Keychain / keyring
- Byte-level layouts for `v10` / `v11` / `v20`, Windows epoch-1601 timestamps
- The silent host-binding change (cookie `meta` version 24, `SHA256(host_key)` prefix)
- App-Bound Encryption: the COM elevation service, caller validation, the 32-byte key wrap with the install path baked in
- ABE timeline across releases 127 → 133 → 137 → 157 and why offset-based parsers break every month
- A coverage matrix that answers "does it work" honestly, per OS and per Chrome version
- Why cross-host extraction died in 2024, and what a capability-tier API looks like instead

---

## The short version

> A tool that works on every machine is not possible in 2026. What is possible is a library that declares its coverage.

| Situation | Windows | macOS | Linux |
|---|---|---|---|
| Same user session, Chrome < 127 | ✅ | ✅ | ✅ |
| Same user session, Chrome 127+ | ⚠️ | ✅ | ✅ |
| Cross-host, Chrome < 127 | ✅ | ✅ | ✅ |
| Cross-host, Chrome 127+ | ❌ | ✅ | ✅ |

### Measured on Chrome/Edge/Brave 158, no TPM

| Finding | Evidence |
|---|---|
| ABE wrap is a plain DPAPI blob behind a 4-byte `APPB` marker — no CNG, no TPM | provider GUID `DF9D8CD0-…` at blob offset 4 |
| Its master key is **not** in the user's Protect store | `DF9A3E03-…` (Chrome), `BFB9D720-…` (Edge/Brave) absent from `%APPDATA%\Microsoft\Protect` |
| Edge ships an ABE key but still writes `v10` | 197/197 cookies and 183/183 passwords decrypted with plain DPAPI |
| Chrome has fully migrated | 0/40 `v20` blobs open with the v10 key |
| A running browser locks its cookie DB (share mode 0) | `WinError 32` on copy, even with the WAL present |
| The 2024 CLSIDs no longer resolve | not registered in HKLM/WOW6432Node/HKCU on 158 |

ABE's wall is **account scope**, not cryptography.

---

## Scripts

Read-only structural reconnaissance. None of them print a decrypted value, a cookie, a password or a key.

| Script | Purpose |
|---|---|
| `scripts/inspect.py` | Profiles, key fields, blob prefixes, cookie `meta` version, install paths, writability, TPM, COM registration |
| `scripts/probe2.py` | Which DPAPI layers open in your session; where ABE registers; Brave DB lock behaviour |
| `scripts/probe3.py` | ABE blob anatomy plus an end-to-end v10 decryption proof (reports match counts only) |
| `scripts/probe4.py` | Offset sweep of the ABE blob against `CryptUnprotectData` |
| `scripts/probe5.py` | Parses the master key GUID and looks for it in your Protect store |
| `scripts/probe6_system_test.py` | Run elevated/as SYSTEM to test the account-scope hypothesis |

```bash
python scripts/inspect.py
python scripts/probe3.py
```

---

## Scope

This is format documentation and reference material. The verification snippets are meant for your own machine and test environments.

---

## Contributing

ABE internals move. If a version number, structure, or CLSID in this repo is stale, open an issue with the Chrome version you observed and the three values from section 11 of the article — `app_bound_encrypted_key` present or not, cookie `meta` version, and the `v10`/`v20` prefix. That is enough to pin down which code path is live.

---

## License

Text is licensed under [CC BY 4.0](LICENSE). Attribute and reuse freely.
