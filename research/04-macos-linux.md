# macOS and Linux Key Stores — Isolated Reference

Scope: how Chromium obtains, stores and derives the OSCrypt key on macOS and Linux.

**Nothing here was measured on macOS or Linux hardware.** Unlike `01-dpapi.md` there is no reference
machine, so every claim is tagged: **SOURCE** (read from the Chromium tree, path given), **LOCAL**
(recomputed on this Windows box), **DOC** (vendor/spec), **COMMUNITY** (reported, matches code, not
reproduced), **UNVERIFIED** (inference with a gap).

Snapshot: `chromium/src` at `refs/heads/main`, Nov 2026, plus M130 (`branch-heads/6723`), M133
(`6943`) and M134 (`6998`) for dating. `components/os_crypt/sync/` **no longer exists on main** — the
async README says it outright: *"It has replaced the legacy synchronous OSCrypt implementation which
has now been removed."* Grepping for `os_crypt_linux.cc` on current main finds nothing.

## Ozet (TR)

macOS'ta anahtar, login keychain'de `Chrome Safe Storage` / hesap `Chrome` generic password öğesidir;
içeriği 16 rastgele baytın base64'ü, türetimi PBKDF2-HMAC-SHA1(`saltysalt`, **1003** tur, 16 bayt) →
AES-128-CBC, sabit IV 16 boşluk, önek `v10`; sabitler M130'dan bugüne değişmedi, ama **varsayılan
olmayan `--user-data-dir`** artık `v11` + `pepper` tuzuyla ayrı anahtar yazıyor ve `v10`'ı kasıtlı
olarak kullanılamaz işaretliyor. Linux'ta depo `--password-store` ile seçilir: `basic` (sabit
`peanuts`, `v10`), `gnome-libsecret`/`kwallet*` (`v11`), sandbox'ta portal (`v12`, AES-256-GCM);
hepsinde tuz `saltysalt`, tur **1**, anahtar 16 bayt. `sudo` ile D-Bus oturumu kaybolur, geriye
yalnızca `peanuts` kalır ve `v11`/`v12` okunamaz. macOS'ta ABE **yok** — sağlayıcı kaynakta yalnızca
Windows için derleniyor; ama "sertleştirme yok" da yanlış, profil bazlı `v11` var.

## 1. macOS

### 1.1 Keychain item and lifecycle

Generic password in the user's default (login) keychain; not localized, because the strings are
*"used to access the encryption keyword"* and a translated Chrome would lose every cookie on a locale
change. Constants, `components/os_crypt/common/keychain_password_mac.mm:34-40`:

| Field | Chrome | Chromium |
|---|---|---|
| `kSecAttrService` | `Chrome Safe Storage` | `Chromium Safe Storage` |
| `kSecAttrAccount` | `Chrome` | `Chromium` |
| `kSecClass` | `kSecClassGenericPassword` | same |

**Creation** (`:91-117`): `SecItemCopyMatching`; on `errSecItemNotFound`,
`AddRandomPasswordToKeychain` does `Base64Encode(RandBytesAsVector(128/8))` — **16 random bytes → 24
ASCII chars**, per install, on first use, derived from nothing about the machine or the user. That
decides the access matrix: the secret is not reproducible, so nothing depending on it is portable. Any
process running as the user can create the item first and Chrome adopts it, since lookup matches only
service+account. The write path is the modern Security framework (`keychain_v2.mm` wraps
`SecItemAdd`/`SecItemCopyMatching`), not the deprecated Keychain Services calls.

**Failure does not rotate the key.** An empty password (denied, unreadable) yields
`KeyError::kTemporarilyUnavailable` (`keychain_key_provider.mm:60-64`), leaving the tag in the key
ring with a null key — decryption reports "try later", not "wrong key". Only `errSecItemNotFound`
creates.

### 1.2 Key derivation

`keychain_key_provider.mm:32-37,66-71`, verbatim: tag `"v10"`, key size `16`, salt
`{'s','a','l','t','y','s','a','l','t'}`, `kIterations = 1003`, `Pbkdf2HmacSha1(...)` →
`Algorithm::kAES128CBC`.

So `key = PBKDF2-HMAC-SHA1(keychain_secret, "saltysalt", 1003, 16)` → AES-128-CBC; the blob is `"v10"`
+ CBC ciphertext, fixed IV of sixteen spaces (`encryptor.cc:39-42`), PKCS#7. The article's numbers are
correct. At M130 (Oct 2024) the sync backend already carried the same three constants, so they are
stable M130 → main; "unchanged since 2013" is older than I could verify (**UNVERIFIED**).

**Non-default data dir — new, and it breaks "one key per user"** (`browser_process_impl.cc:1697-1716`):
when `kKeychainKeyProviderUserDataDirProtection` is on and the profile is not the default data
directory, the code registers `UnavailableKeyProvider("v10")` at precedence 10 plus
`KeychainKeyProvider("v11", salt="pepper")` at 15. Both features are `FEATURE_ENABLED_BY_DEFAULT`
(`chrome/common/chrome_features.cc:60-66`).

| User data dir | Tag | Salt | Iter | `v10` readable |
|---|---|---|---|---|
| default | `v10` | `saltysalt` | 1003 | yes |
| custom `--user-data-dir` | `v11` | `pepper` | 1003 | **no, deliberately** |

A profile moved between default and custom stops decrypting, because the *same* keychain secret now
feeds a different salt; a tool assuming `v10` returns nothing for every custom-dir install.
`UnavailableKeyProvider` always answers `kTemporarilyUnavailable` (`:325-336`), matching the feature
comment: *"marks the default ("v10") key as temporarily unavailable."*

### 1.3 Lock states and access

**Locked login keychain.** `SecItemCopyMatching` returns an error that is not `errSecItemNotFound`;
Chromium logs `OSCrypt.Mac.FindGenericPasswordError`, returns empty, and the provider reports
`kTemporarilyUnavailable`. It does **not** create a second item and does **not** rotate the key —
unlock and it works again. Not about FileVault: the disk is already mounted by the time Chrome runs,
the failure is keychain lock. The article's §7.4 is right. Creation sets
`kSecAttrAccessibleWhenUnlocked` (`keychain_util.mm`, non-iOS branch), largely a data-protection
concept on macOS; whether it affects file-based login keychain items is **UNVERIFIED**.

**ACL, and why a third-party tool prompts.** A generic password carries an ACL of trusted
applications. The creating binary is trusted; a different signed binary reading the same
service/account triggers "…wants to access key *Chrome Safe Storage* in your keychain" with Deny /
Allow / Always Allow — interactive the first time, silent afterwards if the user clicked Always Allow.
`security find-generic-password -s "Chrome Safe Storage" -w` goes through the same machinery.
**COMMUNITY**, consistent with the ACL model. Keychain generic passwords are not TCC-gated: the prompt
is the item ACL, a different mechanism with a different bypass story.

**Sandbox / root.** Chrome is not on the Mac App Store, so there is no MAS build to compare;
`ExecutableHasKeychainAccessGroupEntitlement()` in `keychain_util.mm` checks the
`keychain-access-groups` entitlement — without it a sandboxed build cannot read an item created by the
unsandboxed browser, even as the same user. As root there is no silent path either: root gets
ciphertext, and `security unlock-keychain` against another user's keychain needs that password.
Contrast Windows, where SYSTEM reaches a machine-scoped store.

### 1.4 ABE on macOS — status

`chrome/browser/os_crypt/` contains exactly `app_bound_encryption_provider_win.{cc,h}`,
`app_bound_encryption_win.{cc,h}`, `app_bound_encryption_test_main.cc` — no `_mac`, no `_linux`, no
cross-platform ABE interface. The only `AppBoundEncryptionProviderWin` registration sits inside
`#if BUILDFLAG(IS_WIN)` (`browser_process_impl.cc:1651-1667`, precedence 15 over DPAPI's 10), with no
`#if BUILDFLAG(IS_MAC)` counterpart. **SOURCE.** So as of main / Nov 2026: **no App-Bound Encryption
on macOS** — no caller validation, no service process, no machine-bound wrap, no Secure Enclave, no
`v20`. The article is right about that.

**But "unchanged since 2013" is no longer true.** The macOS hardening that did happen is
profile-scoped, not machine-scoped (§1.2): a separate `v11` key for non-default data dirs plus a
deliberate refusal to decrypt `v10` there. It separates one profile from another code path, not from
malware running as the user.

**Consequence for the article's §6.** The macOS `✅` on "Different machine, Chrome 127+" is wrong, and
was wrong before any of this: the keychain secret is per-install random, so copying `Local State` and
the profile to a second Mac does not copy it. macOS is as non-portable as Windows post-ABE, for a
simpler reason — the key never lived in a file. Same for the Linux keyring rows; only `peanuts` is
portable. See §3.

## 2. Linux

### 2.1 Password store backends

`components/password_manager/core/browser/password_manager_switches.cc` documents the switch:
*"Possible values are kwallet, kwallet5, kwallet6, gnome-libsecret, basic. Any other value will lead
to Chrome detecting the best backend automatically."* Registration is
`browser_process_impl.cc:1669-1695`; highest precedence that succeeds wins *for encryption*, while
every successful provider stays in the key ring *for decryption*:

| Prec. | Provider | Tag | Condition |
|---|---|---|---|
| 5 | `PosixKeyProvider` | `v10` | always on POSIX except macOS |
| 10 | `FreedesktopSecretKeyProvider` | `v11` | always on Linux; internally picks libsecret/KWallet/basic |
| 15 | `SecretPortalKeyProvider` | `v12` | `--password-store` != `basic` and `kDbusSecretPortal` on |

`PosixKeyProvider` is registered on Linux **even when a keyring is in use** — that is why old `v10`
blobs still open. macOS gets none (`#if BUILDFLAG(IS_POSIX) && !BUILDFLAG(IS_MAC)`), which is why
`v10` there depends entirely on the keychain.

Auto-detection (`key_storage_util_linux.cc` at M133; the async provider keeps the same desktop-env
logic): KDE4/5/6 → `kwallet`/`kwallet5`/`kwallet6`; GNOME, Cinnamon, Deepin, Pantheon, UKUI, Unity,
XFCE → `gnome-libsecret`; KDE3, LXQT and unknown → `basic`. KDE3 is excluded because *"KDE3 didn't use
DBus, which our KWallet store uses."* LXQT falling to `basic` is the most common "why is this box on
peanuts" answer that isn't an explicit flag. A file named `Disable Local Encryption` in the user data
dir also forces `basic` — *"The presense of this file in the file system means that the backend should
be ignored"* (`:13-24`); it is how the old "use basic password store" setting persisted.

### 2.2 libsecret / gnome-keyring

The async provider speaks Secret Service over D-Bus directly, with no libsecret linkage
(`freedesktop_secret_key_provider.h:74-96`): service `org.freedesktop.secrets`, path
`/org/freedesktop/secrets`, interfaces `.Service`/`.Collection`/`.Session`/`.Prompt`. Sequence:
`CheckForServiceAndStart` → `ReadAlias("default")` → if the alias is `/`, `CreateCollection` labelled
`Default Keyring` → `Unlock` via the Prompt interface (no timeout: the user may take forever) →
`OpenSession("plain")` → `SearchItems({application})` → `GetSecrets`.

Item attributes and label (`:777-801`, `.h:113-121,142-150`): `application` = `chrome`/`chromium`,
`xdg:schema` = `chrome_libsecret_os_crypt_password_v2`, `Label` = `Chrome Safe Storage`, MIME
`text/plain`. Search uses **only** `application`, not the schema — deliberate compatibility with the
old sync backend, which wrote the same schema (`kKeystoreSchemaV2`, `key_storage_libsecret.cc:17-23`
at M133). An item created in 2019 is still found in 2026 and still yields the key that opens 2019
`v11` data; change that attribute and every existing profile dies.

**Secret and KDF** (`:814-824`): `Base64Encode(RandBytesAsVector(16))` — 24 chars, unrelated to the
macOS value — then `Pbkdf2HmacSha1({.iterations = 1}, secret, "saltysalt", 16 bytes)` → AES-128-CBC,
tag `v11`. **One iteration**, because the input is already 128 bits of entropy; do not read "1 vs
1003" as Linux being weaker. `kMethodCallTimeout = 3s` per call, so a slower daemon is
`kTemporarilyUnavailable`; `Unlock` goes through the Prompt interface with no timeout, so a locked
keyring on a headless box hangs rather than failing — **COMMUNITY** for the hang.

### 2.3 KWallet

Same provider, native KDE interface instead of Secret Service (`:545-775`, `.h:98-140`):
`org.kde.kwalletd` at `/modules/kwalletd` (KDE3/4), `org.kde.kwalletd5` at `/modules/kwalletd5`
(KDE5), `org.kde.kwalletd6` at `/modules/kwalletd6` (KDE6). Call chain: `isEnabled` →
`networkWallet` → `openAsync(wallet, 0, app, handleSession=true)` → `walletAsyncOpened(txn, handle)` →
`hasFolder`/`createFolder` → `hasEntry` → `readPassword`/`writePassword`. Layout matches the old sync
backend (`key_storage_linux.cc:28-34`): folder `Chrome Keys` (Chromium: `Chromium Keys`), entry
`Chrome Safe Storage`, app `chrome`.

Differences that matter:

- KWallet is **not** a Secret Service implementation for the parts used here, so
  `org.freedesktop.secrets` may not exist on a KDE box; a tool that only speaks Secret Service finds
  nothing.
- `isEnabled == false` (user disabled the wallet) fails **permanently**, not temporarily — same
  visible symptom as a locked wallet, different retry behaviour.
- `handleSession = true` keeps the wallet open for the app's lifetime; an **empty** password entry
  means "generate a new one" (`:735-741`), and a cancelled dialog gives handle `-1` →
  `FinalizeFailure`.

D-Bus is mandatory on both paths: `GetSharedSessionBus()` builds a `dbus::Bus::SESSION` connection
(`dbus_thread_linux.cc:31,58-68`), i.e. libdbus reads `DBUS_SESSION_BUS_ADDRESS`. No bus, no key.

### 2.4 basic store

`components/os_crypt/async/browser/posix_key_provider.cc:16-33`: tag `v10`, and the key as a literal
commented `// PBKDF2-HMAC-SHA1(1 iteration, key = "peanuts", salt = "saltysalt")` =
`fd 62 1f e5 a2 b4 02 53 9d fa 14 7c a9 27 27 78`. **LOCAL check:**

```
PBKDF2-HMAC-SHA1("peanuts", "saltysalt", 1, 16) = fd621fe5a2b402539dfa147ca9272778
PBKDF2-HMAC-SHA1("",        "saltysalt", 1, 16) = d0d0ec9c7d77d43ac54187fa4818d17f
```

Both match the tree — the first in `posix_key_provider.cc`, the second as `kEmptyKey`
(`encryptor.cc:186-188`). The article's `PBKDF2("peanuts","saltysalt",1,16)` is correct, and the key
is a literal, not a computation: one constant shared by every Linux install on earth.

**When basic is active:** (1) `--password-store=basic`; (2) KDE3/LXQT/unknown desktop; (3) the
`Disable Local Encryption` marker; (4) build without `USE_LIBSECRET`/`USE_KWALLET`; (5) the selected
backend failed to initialise; (6) **always**, as a decryption fallback. Case 6 is the asymmetry —
`v10` is always decryptable on Linux because `PosixKeyProvider` never fails. Case 5 is why "it worked
yesterday" happens: a daemon crash flips new writes to `v10` and the profile ends up with mixed tags.

**Empty-key fallback** (`encryptor.cc:177-191`): on CBC failure Chromium retries with `kEmptyKey`,
citing `crbug.com/40055416` — data written when the keyring password was empty, which a tool that
tries `peanuts` and stops will miss. **Plaintext passthrough:** at M133 (`os_crypt_linux.cc:191-196`)
a value with no `v10`/`v11` prefix is legacy cleartext returned as-is.

### 2.5 Why sudo breaks it

1. `sudo` strips the environment → no `DBUS_SESSION_BUS_ADDRESS` → `dbus::Bus::SESSION` has nothing to
   connect to.
2. Even with `sudo -E`, the socket lives in `XDG_RUNTIME_DIR` (`/run/user/1000`, mode `0700`). Root
   bypasses the bits, but the daemon sees a different uid on the peer credentials.
3. `gnome-keyring-daemon` / `kwalletd` are per-session services holding an unlocked collection for one
   uid; a uid-0 client is rejected or finds a locked collection.
4. Provider fails → `PosixKeyProvider` at precedence 5 takes over → only `v10` is producible.
5. Net effect: as root, `v11`/`v12` are unreadable and `v10` is readable. The symptom is a decrypt
   failure that looks like a corrupt database, not a permission error.

Step 3 is the unproven link — whether gnome-keyring rejects on peer uid or just returns a locked
collection, and whether `sudo -E` ever works, is **UNVERIFIED**; steps 1, 2 and 4 are **SOURCE**.
Practical inversion: on Linux root is *weaker* than the user, so the correct model is "run as the
user, inside the user's session".

### 2.6 Sandboxed installs

Flatpak and snap cannot reach `org.freedesktop.secrets`; the portal is the only exposed route —
*"This is the only interface exposed from sandboxed environments like Flatpak."*

| Item | Value |
|---|---|
| Service / path | `org.freedesktop.portal.Desktop` / `/org/freedesktop/portal/desktop` |
| Interface / method | `org.freedesktop.portal.Secret` / `RetrieveSecret` (returns a pipe fd) |
| Tag | `v12` |
| KDF | HKDF-SHA-256, salt `fdo_portal_secret_salt`, info `HKDF-SHA-256 AES-256-GCM` |
| Cipher | AES-256-GCM, 12-byte nonce prepended, 16-byte tag |

The secret arrives over a pipe, hence the async fd watch — the write may not land until the keyring is
unlocked. A `token` is persisted as `os_crypt.portal.token`, though xdg-desktop-portal does not
implement returning it yet, so the secret is re-derived each launch. `v12` is **AES-256-GCM with a
random nonce**, the Windows-shaped layout, not CBC.

| Packaging | Profile root |
|---|---|
| distro package | `~/.config/google-chrome` |
| Flatpak | `~/.var/app/com.google.Chrome/config/google-chrome` |
| snap | `~/snap/chromium/common/chromium` |

**COMMUNITY** for the paths, **SOURCE** for the portal mechanism. If the portal is unavailable and
`--password-store` isn't `basic`, `FreedesktopSecretKeyProvider` runs underneath — which in a Flatpak
also fails, leaving `v10`: a silent downgrade inside a sandbox.

## 3. Access matrix

| Platform | Store / tag | Same session, same user | root / sudo | Cross-host | Basis |
|---|---|---|---|---|---|
| macOS | login keychain, `v10` | yes, silent if ACL allows | no — needs account password | **no** | SOURCE + COMMUNITY |
| macOS | login keychain, `v11` + `pepper` | yes | no | **no** | SOURCE |
| macOS | keychain locked | no (`kTemporarilyUnavailable`) | no | — | SOURCE |
| macOS | `v20` / ABE | does not exist | — | — | SOURCE |
| Linux | gnome-libsecret, `v11` | yes, keyring unlocked | no | no | SOURCE |
| Linux | KWallet 5/6, `v11` | yes, wallet open | no | no | SOURCE |
| Linux | basic, `v10` (`peanuts`) | yes | **yes** | **yes** | LOCAL + SOURCE |
| Linux | portal, `v12` | yes, inside sandbox | no | no | SOURCE |
| Linux | any store, read as root | `v10` only | — | — | SOURCE |

Only the `peanuts` row is green everywhere — not a gap in the table but the design: a hardcoded key
cannot be protected by anything.
**Corrections this forces on `article/en.md`:**

1. §4.2 says "macOS / Linux — `v10` (AES-128-CBC)". Linux is `v10`, `v11` **or** `v12`, and `v12` is
   AES-256-GCM; the KDF line under it holds for `basic` only.
2. §4.2 implies one macOS key per user. Current builds write `v11` + `pepper` for non-default
   `--user-data-dir` and refuse `v10` there.
3. §6 marks macOS and Linux `✅` for "Different machine". Both are `❌` unless the store is `peanuts`,
   and the Linux "SYSTEM/root" row's outcome is a silent downgrade, not a visible error.
4. §7.3 says the `peanuts` key "always works". Stronger than stated: any machine, any user, offline.

## 4. What is guaranteed vs what is not

**macOS — guaranteed.** `Chrome Safe Storage` / `Chrome` (branded), `Chromium Safe Storage` /
`Chromium` otherwise, across M130 → main; `v10` = PBKDF2-HMAC-SHA1(secret, `saltysalt`, 1003, 16) →
AES-128-CBC with the fixed 16-space IV; given the item exists, the keychain is unlocked and the ACL
permits the reading binary, decryption is local, offline and deterministic; no ABE, no TPM/Secure
Enclave dependency, no machine binding, no caller validation; a failed read never rotates the key.

**macOS — not guaranteed.** Reading the item from a binary that did not create it; reading anything
while the login keychain is locked; any custom `--user-data-dir` install (tag `v11`, salt `pepper`,
`v10` unavailable by design); any cross-machine scenario; any effect of the Accessibility attribute.

**Linux — guaranteed.** `v10` decrypts on any machine, for any user including root, offline, with
`fd621fe5a2b402539dfa147ca9272778`; the `v10`/`v11` layout is prefix + AES-128-CBC, 16-space IV,
PKCS#7; `v10`, `v11` and `v12` are identifiable by their 3-byte prefix before any key is involved;
unprefixed values are legacy cleartext; the `v11` KDF is one HMAC-SHA1 iteration with `saltysalt`.

**Linux — not guaranteed.** That a machine uses a keyring at all (LXQT, KDE3, unknown DE, no
`USE_LIBSECRET`, marker file); that the keyring is reachable (D-Bus address, `XDG_RUNTIME_DIR`,
unlocked collection, daemon answering within 3 s); that root can read `v11`/`v12` — it cannot, and it
looks like corruption; that a profile uses one tag, since mixed `v10`/`v11` after a daemon crash is
normal; that the secret survives a keyring reinstall, since deleting `~/.local/share/keyrings`
destroys every `v11` blob; that Flatpak/snap Chrome writes CBC at all — it writes `v12`/GCM.

## 5. Open questions

- **When did macOS start writing `v11` + `pepper`?** Both features are default-on at main, but tags
  below M130 would not resolve and gitiles log needs auth (`403: Please sign in to view the history
  pages`). If it is recent, most field data predates it.
- **When did the async Linux provider take over the cookie path?** It exists at M134, not M133;
  whether M134 used it for cookies or only built it is invisible from files alone.
- **Does `kSecAttrAccessibleWhenUnlocked` do anything on macOS?** Set unconditionally at creation, but
  legacy keychain items are not data-protection items.
- **gnome-keyring: reject uid 0, or return a locked collection?** Decides whether `sudo -E` is ever
  useful. Same code path either way, different error surface.
- **Default of `kDbusSecretPortal`?** Referenced in `browser_process_impl.cc` but not defined in
  `chrome/common/chrome_features.cc`, and I did not locate it — so "Flatpak Chrome uses `v12`" is a
  should, not a does. Likewise **KWallet6 headless behaviour** when the wallet is closed is untested.
- **Do distro builds ship `USE_LIBSECRET`?** Debian/Ubuntu/Fedora do; a from-source build without it
  silently produces `peanuts` profiles that break if the user later switches to a packaged build.

## 6. Sources

| URL / path | Establishes |
|---|---|
| `components/os_crypt/common/keychain_password_mac.mm`, `crypto/apple/keychain_v2.mm`, `keychain_util.mm` | service/account, 128-bit base64 secret, `errSecItemNotFound` → create, `SecItemAdd`/`SecItemCopyMatching`, `kSecAttrAccessibleWhenUnlocked`, access groups |
| `components/os_crypt/async/browser/keychain_key_provider.mm` | `v10`, `saltysalt`, 1003, 16 bytes, AES-128-CBC, `kTemporarilyUnavailable` |
| `chrome/browser/browser_process_impl.cc` (325-336, 1669-1695, 1697-1716) | macOS `v11`/`pepper`, Linux precedence, `UnavailableKeyProvider` |
| `chrome/common/chrome_features.cc` (60-66) | both macOS keychain features default-on |
| `components/os_crypt/async/browser/posix_key_provider.cc` | `v10`, `peanuts` literal |
| `.../freedesktop_secret_key_provider.{cc,h}` | `v11`, 1 iteration, schema/attributes, KWallet names, 3 s timeout |
| `.../secret_portal_key_provider.{cc,h}` | `v12`, HKDF-SHA-256 → AES-256-GCM, portal names |
| `components/os_crypt/async/common/encryptor.cc` | fixed 16-space IV, empty-key fallback, prefix dispatch |
| `components/password_manager/core/browser/password_manager_switches.cc` | `--password-store` and its five values |
| `components/dbus/thread_linux/dbus_thread_linux.cc` | session bus is `dbus::Bus::SESSION` |
| M133 `components/os_crypt/sync/os_crypt_linux.cc` | `v10` hardcoded vs `v11` keyring, empty-key fallback, unprefixed = cleartext |
| M133 `.../key_storage_util_linux.cc`, `key_storage_libsecret.cc`, `key_storage_linux.cc` | desktop-env detection, `Disable Local Encryption`, schema v2 + `application`, KWallet names |
| M130 `.../sync/os_crypt_mac.mm` | 1003 / `saltysalt` / `v10` already present Oct 2024 |
| https://specifications.freedesktop.org/secret-service-spec/latest/ | collections, items, prompts, sessions |

Local work: one `python -c` recomputation of the two PBKDF2 constants. No key material, keychain value
or cookie value was read or printed.

## Confidence

**SOURCE** — macOS: `Chrome Safe Storage`/`Chrome`, generic password, 16 random bytes base64, created
on `errSecItemNotFound`, `v10` + `saltysalt` + 1003 + 16 bytes + AES-128-CBC; `v11` + `pepper` for
non-default data dirs with `v10` unavailable, both features default-on; no ABE, the only ABE provider
being `_win` inside `#if BUILDFLAG(IS_WIN)`. Linux: `--password-store` values, precedence 5/10/15,
`v11` for libsecret/KWallet, `v12` for the portal, `saltysalt` + 1 iteration + 16 bytes; libsecret
schema/attributes, KWallet names, 3 s timeout, desktop-env detection, marker file (M133 tree).
`components/os_crypt/sync/` is gone from main.

**LOCAL** — `PBKDF2-HMAC-SHA1("peanuts","saltysalt",1,16)` = `fd621fe5a2b402539dfa147ca9272778`;
`PBKDF2-HMAC-SHA1("","saltysalt",1,16)` = `d0d0ec9c7d77d43ac54187fa4818d17f`.

**COMMUNITY** — keychain ACL prompting and "Always Allow"; `security find-generic-password -w` through
the same ACL; keychain not being TCC-gated; Flatpak/snap paths; the headless keyring hang.

**UNVERIFIED** — the 2013 origin of 1003 (only M130 → main confirmed); any effect of
`kSecAttrAccessibleWhenUnlocked` on legacy keychain items; whether uid 0 is rejected by gnome-keyring
or handed a locked collection, and whether `sudo -E` ever works; the default of `kDbusSecretPortal`,
hence whether `v12` is live for Flatpak; which release first wrote `v11`/`pepper` on macOS and which
first used the async Linux provider for cookies.
