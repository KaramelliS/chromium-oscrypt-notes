# Chromium Credential and Cookie Storage — Isolated Reference

Scope: what a Chromium-family browser writes to disk, at which offset, and how the format evolved.
Evidence tags: **[SRC]** read from `chromium/src` (gitiles, `main` or a release tag); **[DISK]**
measured on the reference machine (Windows 11, Chrome 158.0.8127.36, Edge 158.0.4370.33,
Brave 158.1.100.59, Opera, no TPM) by querying real files read-only; **[ART]** prior measurement
from `article/en.md`; **[UNVERIFIED]** hypothesis, do not build on it.

## Ozet (TR)
Chromium'un disk üzerindeki kimlik verisi tek bir SQLite dosyası ve içindeki tek bir sütundur;
şifreleme dosya seviyesinde değil, `password_value` / `encrypted_value` sütunu seviyesindedir.
Çerez şeması `meta.version` ile sürümlenir ve bu çalışma anında 24'tür; sürüm 24, 2024-08-15'te
`SHA256(host_key)` önekini şifreli metnin başına ekledi ve tüm eski çerez okuyucularını sessizce
bozdu. `Login Data` 43. sürümdedir, `logins` tablosu 32 sütundur; `form_data` ve
`possible_username_pairs` şifreli değil, Pickle blob'larıdır. Windows'ta blob `v10` + 12 bayt nonce +
AES-256-GCM + 16 bayt tag (31 bayt ek yük), macOS/Linux'ta `v10` + 16 boşluk sabit IV + AES-128-CBC.
Ölçülen profillerde `Cookies` **WAL değil**, TRUNCATE rollback journal kullanır: `-journal` vardır,
`-wal` yoktur.

## 1. Files and where they live
`Local State` sits at the **user-data root**, one level above the profile. Everything else sits
inside the profile. This one fact causes most "the key is missing" bugs.

| File | Scope | Content | Critical column / key |
|---|---|---|---|
| `Local State` | root | Key wrapping | `os_crypt.encrypted_key`, `os_crypt.app_bound_encrypted_key` |
| `Network/Cookies` | profile | Cookies | `cookies.encrypted_value` |
| `Login Data` / `Login Data For Account` | profile | Passwords (user / account store) | `logins.password_value` |
| `Web Data` | profile | Autofill, cards, IBANs | `credit_cards.card_number_encrypted` |
| `History` | profile | URLs, visits, downloads | `urls`, `visits` |
| `Bookmarks` | profile | Bookmark tree (JSON, created lazily) | — |
| `Preferences` / `Secure Preferences` | profile | Settings (JSON, second one MAC'd) | `protection.macs` |

| Platform | User-data root | Profile |
|---|---|---|
| Windows Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data` | `Default`, `Profile 1`… |
| Windows Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data` | `Default` |
| Windows Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data` | `Default` |
| Windows Opera | `%APPDATA%\Opera Software\Opera Stable` | `Default` (root *is* the profile) |
| Windows Vivaldi | `%LOCALAPPDATA%\Vivaldi\User Data` | `Default` |
| macOS | `~/Library/Application Support/Google/Chrome` | `Default` |
| Linux | `~/.config/google-chrome` | `Default` |

[DISK] Opera lives under **`%APPDATA%` (Roaming)**, not `%LOCALAPPDATA%` — routinely missed.
[SRC] `chrome/common/chrome_constants.h`: `kInitialProfile="Default"`,
`kMultiProfileDirPrefix="Profile "`, `kLocalStateFilename="Local State"`, `kCookieFilename="Cookies"`.
Since Chrome 96 the cookie DB moved into `Network/`; [DISK] Chrome 158 has `Default/Network/Cookies`
and no `Default/Cookies`.

## 2. Cookie database schema
Two tables only: `meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)` and
`cookies`. [DISK] `sqlite_master` on Chrome 158 matches [SRC] `CreateV24Schema`
(`sqlite_persistent_cookie_store.cc:670`) byte for byte, including the unique index
`cookies_unique_index ON cookies(host_key, top_frame_site_key, has_cross_site_ancestor, name,
path, source_scheme, source_port)`. All 20 columns, ordinal order:

| # | Column | Type | Meaning |
|---|---|---|---|
| 0 | `creation_utc` | INTEGER | `base::Time`, µs since 1601 (§6) |
| 1 | `host_key` | TEXT | Domain, leading `.` for domain cookies; input to the v24 hash |
| 2 | `top_frame_site_key` | TEXT | CHIPS partition key; empty = unpartitioned |
| 3 | `name` | TEXT | Cookie name |
| 4 | `value` | TEXT | Plaintext. **Empty** when `encrypted_value` is set |
| 5 | `encrypted_value` | BLOB | `v10`/`v20` blob (§5); takes precedence over `value` |
| 6 | `path` | TEXT | Cookie path |
| 7 | `expires_utc` | INTEGER | `0` = session cookie |
| 8 / 9 | `is_secure`, `is_httponly` | INTEGER | 0/1 each |
| 10 | `last_access_utc` | INTEGER | `base::Time` |
| 11 / 12 | `has_expires`, `is_persistent` | INTEGER | 0/1, "an expiry was supplied" / survives restart |
| 13 | `priority` | INTEGER | `0` low, `1` medium (default), `2` high |
| 14 | `samesite` | INTEGER | `-1` unspecified, `0` none, `1` lax, `2` strict |
| 15 | `source_scheme` | INTEGER | `0` unset, `1` non-secure, `2` secure |
| 16 | `source_port` | INTEGER | Port; `-1` unspecified |
| 17 | `last_update_utc` | INTEGER | `base::Time`; 400-day cap input |
| 18 | `source_type` | INTEGER | `1` HTTP header, `2` `document.cookie`, `3` other |
| 19 | `has_cross_site_ancestor` | INTEGER | 0/1, part of partition key |

Enums [SRC] `net/cookies/cookie_constants.h`: `CookiePriority` `LOW=0, MEDIUM=1, HIGH=2`;
`CookieSameSite` `UNSPECIFIED=-1, NO_RESTRICTION=0, LAX_MODE=1, STRICT_MODE=2`; `CookieSourceScheme`
`kUnset=0, kNonSecure=1, kSecure=2`; `CookieSourceType` `kHTTP=1, kScript=2, kOther=3`. `samesite`
is **signed** — reading it unsigned turns `-1` into `255`.

[DISK] `meta` on Chrome 158: `('mmap_status','-1')`, `('version','24')`,
`('last_compatible_version','24')`. `mmap_status` is crash-recovery bookkeeping: after an unclean
shutdown Chromium disables mmap and records it [SRC] `sql/meta_table.cc`.## 3. meta.version history and the host binding change
[SRC] `kCurrentVersionNumber = 24`, `kCompatibleVersionNumber = 24`
(`sqlite_persistent_cookie_store.cc:320`). Changelog from the comment block in that file:

| v | Date | Change |
|---|---|---|
| 4 / 5 | 2009-09 / 2011-12 | Time epoch migration; `has_expires`, `is_persistent` |
| 6 / 7 | 2013-04 / 2013-12 | Priority; **encrypted values** |
| 8 – 11 | 2015-02 → 2019-04 | First-party-only, partial index, drop uniqueness on creation time, `firstpartyonly` → `samesite` |
| 12 / 13 | 2019-11 / 2020-10 | `source_scheme`; `source_port` |
| 14 / 15 | 2021-02 / 2021-07 | Read+rewrite all encrypted cookies; `top_frame_site_key` (CHIPS) |
| 16 – 19 | 2021-09 → 2023-09 | Unique-constraint reorder, v16 fix, `last_update_utc`, **cap `expires_utc` at 400 days** |
| 20 / 21 | 2023-11 | Unique gains `source_scheme`+`source_port`; drop `is_same_party` |
| 22 / 23 | 2024-03 / 2024-04 | `source_type`; `has_cross_site_ancestor` |
| **24** | **2024-08-15** | **`SHA256(host_key)` prefixed to plaintext** |

v24 is `crrev.com/c/5792044`. `DoMigrateDatabaseSchema` (line 1139) runs one transaction that, per
row, decrypts, prepends `crypto::SHA256HashString(host_key)`, re-encrypts, and **blanks `value`**.
The read path enforces it (line 1057):

```cpp
std::string correct_hash = crypto::SHA256HashString(domain);
if (!base::StartsWith(value, correct_hash, base::CompareCase::SENSITIVE)) {
  RecordCookieLoadProblem(CookieLoadProblem::kHashFailed);  // row dropped
  continue;
}
value = value.substr(correct_hash.length());
```

1. **The hash covers `host_key`, not the cookie name.** Stripping 32 bytes blindly works;
   validating the hash against the *URL host* fails on every domain cookie, because `host_key` is
   `.example.com` and the URL host is not.
2. On mismatch **Chromium deletes the row at load time**. A cookie written with the wrong hash is
   destroyed on next start — that is the mechanism behind "my injected cookie vanished", and it is
   not a parser quirk.

`last_compatible_version = 24` means a v23 binary refuses the DB rather than downgrading it.

## 4. Login Data schema
[DISK] Chrome 158: `meta.version = 43`, `last_compatible_version = 40`. [SRC]
`components/password_manager/core/browser/password_store/login_database.cc`:
`kCurrentVersionNumber = 43`, `kCompatibleVersionNumber = 40`. 32 columns:

| Column | Type | Meaning |
|---|---|---|
| `origin_url` | VARCHAR NOT NULL | Form origin (UNIQUE key) |
| `action_url` | VARCHAR | Form action |
| `username_element` | VARCHAR | DOM element name (UNIQUE key) |
| `username_value` | VARCHAR | Username, **plaintext** |
| `password_element` | VARCHAR | DOM element name (UNIQUE key) |
| `password_value` | BLOB | **Encrypted blob** (§5); NULL for blacklist rows |
| `submit_element` | VARCHAR | Submit button name |
| `signon_realm` | VARCHAR NOT NULL | `https://example.com/`, or bare host for basic auth |
| `date_created` | INTEGER NOT NULL | `base::Time` |
| `blacklisted_by_user` | INTEGER NOT NULL | 1 = "never save here", not a credential |
| `scheme` | INTEGER NOT NULL | `0` HTML, `1` basic, `2` digest, `3` other, `4` username-only |
| `password_type` | INTEGER | `0` unknown, `1` plaintext, `2`/`3` 0-/1-SHA1, `4`/`5` 0-/1-SHA256 |
| `times_used` | INTEGER | Legacy counter |
| `form_data` | BLOB | **`autofill::FormData` Pickle** — see below |
| `display_name`, `icon_url`, `federation_url` | VARCHAR | Display name, avatar URL, OIDC issuer |
| `skip_zero_click`, `generation_upload_status` | INTEGER | Legacy auto-sign-in; password-generation bookkeeping |
| `possible_username_pairs` | BLOB | Pickle of `(element, value)` pairs |
| `id` | INTEGER PK AUTOINCREMENT | Stable row id (AUTOINCREMENT since v26) |
| `date_last_used` | INTEGER DEFAULT 0 | Replaced `preferred` in v25 |
| `moving_blocked_for` | BLOB | Serialized GAIA-id hash list (v27) |
| `date_password_modified` | INTEGER DEFAULT 0 | v30 |
| `sender_email`, `sender_name`, `date_received` | VARCHAR, VARCHAR, INTEGER | v37, received-share metadata |
| `sharing_notification_displayed` | INTEGER DEFAULT 0 | v37 |
| `keychain_identifier` | BLOB | v39, iOS credential provider |
| `sender_profile_image_url` | VARCHAR | v41 |
| `date_last_filled` | INTEGER DEFAULT 0 | v42 |
| `actor_login_approved` | INTEGER DEFAULT 0 | v43 |

`UNIQUE (origin_url, username_element, username_value, password_element, signon_realm)`.

Two columns look like ciphertext but are not: **`form_data`** is a `base::Pickle` from
`autofill::SerializeFormData` (`BindBlob`) holding field names, types and submitted values — in
some captures including the password field. It is **never encrypted**; reading it means walking the
Pickle format (4-byte payload length, then length-prefixed elements), not decrypting.
`possible_username_pairs` uses the same container. `blacklisted_by_user = 1` rows have
`password_value` NULL: [DISK] Edge 158 has 245 rows, 183 `v10` and **62 NULL**, so "245 saved
passwords" overstates by a third. Edge also adds fork tables (`meta` carries
`edge_breached_table_version = 5`, `logins_edge_extended_table_version = 4`). Related tables:
`insecure_credentials` (v29, FK to `logins.id`), `password_notes` (v33, OSCrypt since v40).

## 5. Blob formats
### 5.1 Windows `v10` / `v11` — AES-256-GCM
[SRC] `components/os_crypt/sync/os_crypt_win.cc` @ tag `131.0.6778.85`:

```cpp
constexpr size_t kKeyLength = 256 / 8;      // 32
constexpr size_t kNonceLength = 96 / 8;     // 12
constexpr char kEncryptionVersionPrefix[] = "v10";
crypto::Aead aead(crypto::Aead::AES_256_GCM);
aead.Seal(plaintext, nonce, std::string(), ciphertext);   // empty AD
ciphertext->insert(0, nonce);                             // then the prefix
```

```
offset  0 ..  2   "v10"                    3 bytes ASCII
offset  3 .. 14   nonce                   12 bytes, random per write
offset 15 .. n-16 ciphertext + GCM tag     n-31 bytes
offset n-16 .. n  authentication tag      16 bytes
```

Overhead **31 bytes**, empty associated data — the host binding is a plaintext prefix (§5.3), not
an AEAD AD. The 32-byte key comes from `Local State` → base64 → strip 5-byte `"DPAPI"` →
`CryptUnprotectData`.

**On `v11`:** Chromium does not emit it. `os_crypt_win.cc` at tags 79, 80, 96 and 131 contains
exactly one prefix constant, `"v10"`; the Chrome 80 DPAPI fallback wrote a **bare DPAPI blob with no
prefix**, and `DecryptString` routes anything not starting with `"v10"` into
`DecryptStringWithDPAPI`. Third-party parsers accept `v11` as a synonym for `v10` — a harmless
superset, but that is their convention, not Chromium's behaviour. See §11.

### 5.2 macOS / Linux `v10` — AES-128-CBC, fixed IV
[SRC] `os_crypt_mac.mm`, `os_crypt_posix.cc`: `kSalt = "saltysalt"`, 128-bit key, 1003 iterations on
macOS (1 on the Linux basic store), and `const std::string iv(kCCBlockSizeAES128, ' ')`.

```
offset  0 ..  2   "v10"                     3 bytes
offset  3 .. 18   IV = 0x20 × 16            16 bytes, constant
offset 19 .. n    AES-128-CBC ciphertext    PKCS#7 padded
```

No nonce, no tag, no length field. Key derivation: macOS uses
`PBKDF2_HMAC_SHA1(keychain_password, b"saltysalt", 1003, 16)` where the password comes from the
Keychain entry `"Chrome Safe Storage"`; the Linux basic store uses
`PBKDF2_HMAC_SHA1(b"peanuts", b"saltysalt", 1, 16)`.

[SRC] `os_crypt_posix.cc`: when the keyring is unavailable the code falls back to `"peanuts"`, and
POSIX `DecryptString` returns input unchanged when the prefix is not `"v10"` — legacy plaintext
passes through silently. "It returned something, so it worked" is not a valid Linux test.

### 5.3 `v20` — App-Bound Encryption
Two different objects carry a `v20`/`APPB` marker. Do not conflate them.

**(a) The cookie/password blob.** [SRC] `components/os_crypt/async/common/encryptor.cc`: the
version prefix is now the **key-provider tag**, prepended generically
(`ciphertext.insert(ciphertext.begin(), provider.cbegin(), provider.cend())`). DPAPI tag `"v10"`
[SRC] `dpapi_key_provider.cc:32`; ABE tag `"v20"` [SRC] `app_bound_encryption_provider_win.h:50`.
The payload is the §5.1 layout verbatim — `"v20"` + 12-byte nonce + ciphertext + 16-byte tag — so
`v20` and `v10` are **byte-identical containers**. Only the key differs, and therefore whether a
medium-integrity user process can obtain it.

**(b) The key wrap in `Local State`.** [SRC] `chrome/elevation_service/elevator.cc::EncryptData`
is the authority, and it is a **double DPAPI**, not an AEAD: `GenerateValidationData()` collects the
caller's identity including the install path, `AppendStringWithLength()` writes each field as a
uint32 length followed by the bytes, then `CryptProtectData` seals the whole thing **to the user**
and the result is sealed again **to SYSTEM**.

```
00 41 50 50 42              "APPB"                      4 bytes, fixed marker
04 d0 8c 9d df 01 15 d1 11  DPAPI blob header           16-byte provider GUID
   8c 7a 00 c0 4f c2 97 eb  = DF9D8CD0-1501-11D1-...
   ...                      DPAPI(SYSTEM, DPAPI(user, payload))

payload after both layers:
uint32_le  len(validation_data)
byte[len]  validation_data
             ├ byte 0     protection level (2 or 3)
             ├ byte 1     isolated flag, only when level == 3
             └ bytes 2..  "C:\Program Files\Google\Chrome"   UTF-8, no NUL
uint32_le  len(inner)
byte[len]  inner         32-byte AES key, possibly itself wrapped
```

`GenerateValidationData` [SRC] `caller_validation.cc:183` returns `[ProtectionLevel] (+ [isolated]
if level 3) || UTF-8 install directory`, the directory being the process path with `.exe`, `Temp`,
`Application`, version segment and `Program Files (x86)` normalised away. `ProtectionLevel` [SRC]
`elevation_service_idl.idl`: `NONE=0, PATH_VALIDATION_OLD=1, PATH_VALIDATION=2,
PATH_VALIDATION_WITH_ISOLATION=3, MAX=4`.

The article's §5.3 reading — `[len] path`, `0x01` flags byte, `[12] nonce`, `[32] ciphertext`,
`[16] tag` — fits this if `0x01` is the head of the *second* length-prefixed field and the 12/32/16
split is a `PreProcessData` envelope (Google-branding only, called before the seal). `PreProcessData`
is referenced at `elevator.cc:94` but its body was not located, so the inner envelope is
**[UNVERIFIED]**. Verified is the outer shape: two nested `CryptProtectData` calls with user context
inside SYSTEM context, install path inside the payload. That is why the article's finding holds —
the outer master key belongs to `S-1-5-18`, so `CryptUnprotectData` from a normal user process fails
on account scope, not on cryptography.

COM identity [SRC] `elevation_service_idl.idl` @ `main`: `IElevator`
`{A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}`, `IElevator2` `{8F7B6792-784D-4047-845D-1782EFBEF205}`,
`IElevator2Chrome` `{1BF5208B-295F-4992-B5F4-3A9BB6494838}`, `IElevatorChrome`
`{463ABECF-410D-407F-8AF5-0DF35A005CC8}`. The 2024-era `{708860E0-…}` (Chrome) and `{1FCBE96C-…}`
(Edge) appear nowhere in this list, and per-brand IIDs mean a hardcoded GUID is wrong for every
brand but the one it was copied from.

## 6. Timestamps
`base::Time` is **microseconds since 1601-01-01 00:00:00 UTC** (FILETIME epoch). [SRC]
`base/time/time.h:551`: `kWindowsEpochDeltaMicroseconds = INT64_C(11644473600000000)`.

```python
unix_seconds = chromium_ts / 1_000_000 - 11_644_473_600
chromium_ts  = int((unix_seconds + 11_644_473_600) * 1_000_000)
```

| Value | Meaning |
|---|---|
| `expires_utc = 0` | **Session cookie** — dies with the session |
| `has_expires = 0` / `is_persistent = 0` | No expiry supplied / must not be restored across restart |
| `date_created = 0` in `logins` | Never set; some migrations leave 0 |
| `date_last_used = 0`, `date_last_filled = 0` | Column added after the row was written |
| `source_port = -1` | Port unknown |

Since v19 (2023-09-22) Chromium caps `expires_utc` at **400 days** from `last_update_utc` on
migration, so a far-future expiry is pre-v19 data or third-party-written. `base::Time` is signed
64-bit; `0x7FFF…` is `Time::Max()`, negatives are pre-1601 and should be rejected, not wrapped.
`Cookies` timestamps are the same encoding as `logins.date_created`, `urls.last_visit_time` and
`visits.visit_time` — one converter covers every table.

## 7. Other profile artefacts
**`Web Data`** [DISK] `meta.version = 161`, `last_compatible_version = 160`:

```sql
CREATE TABLE credit_cards (guid VARCHAR PRIMARY KEY, name_on_card VARCHAR,
  expiration_month INTEGER, expiration_year INTEGER, card_number_encrypted BLOB,
  date_modified INTEGER NOT NULL DEFAULT 0, use_count INTEGER NOT NULL DEFAULT 0,
  use_date INTEGER NOT NULL DEFAULT 0, billing_address_id VARCHAR, nickname VARCHAR,
  is_user_confirmed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE autofill (name VARCHAR, value VARCHAR, value_lower VARCHAR,
  date_created INTEGER DEFAULT 0, date_last_used INTEGER DEFAULT 0,
  count INTEGER DEFAULT 1, PRIMARY KEY (name, value));
CREATE TABLE local_ibans (guid VARCHAR PRIMARY KEY, use_count INTEGER, use_date INTEGER,
  value_encrypted VARCHAR, nickname VARCHAR);
```

`card_number_encrypted` and `local_ibans.value_encrypted` are the same `v10`/`v20` blobs as
everywhere else. `masked_credit_cards` holds no PAN and is not encrypted. `autofill` values are
**plaintext by design** — the table people forget when they say "only passwords and cookies matter".

**`History`** [DISK] `meta.version = 70`, `last_compatible_version = 16`. `urls(id, url, title,
visit_count, typed_count, last_visit_time, hidden)` and `visits(id, url, visit_time, from_visit,
external_referrer_url, transition, segment_id, visit_duration, …)`, both `INTEGER PRIMARY KEY
AUTOINCREMENT` on `id`. `transition` low byte: 0 link, 1 typed, 2 auto-bookmark, 3 auto-subframe,
4 manual subframe, 5 generated, 6 start page, 7 form submit, 8 reload, 9 keyword, 10
keyword-generated; high bits are qualifiers (`0x01` client redirect, `0x02` server redirect,
`0x04` forward/back, `0x08` address bar, `0x10` home page, `0x20` API, `0x40` chain start,
`0x80` chain end, each in the top byte).

**`Bookmarks` / `Preferences`** — JSON. `Bookmarks` is created **lazily**: [DISK] on a profile with
no bookmarks the file does not exist. Shape: `{"checksum": "<md5>", "roots": {"bookmark_bar",
"other", "synced"}, "version": 1}`; each node `{"date_added": "<µs since 1601 as string>", "guid",
"id", "name", "type": "url"|"folder", "url"}` — note `date_added` is a **string**. `Preferences`
[DISK] has top-level keys `autofill`, `bookmark`, `browser`, `download`, `extensions`, `profile`,
`signin`, `sync`; `Secure Preferences` adds `protection.macs`, an HMAC over selected prefs with a
machine+user-bound key, so editing a protected pref invalidates the MAC and Chromium resets it.
Plain `Preferences` has no such guard.

**`Local State`** — root-level JSON. [DISK] `os_crypt` holds exactly three keys on Chrome 158 and
Edge 158: `encrypted_key` (legacy `DPAPI`-prefixed v10 key, base64), `app_bound_encrypted_key` (the
`APPB` wrap, base64), `audit_enabled` (bool). Presence of `app_bound_encrypted_key` does **not**
mean `v20` is in use: Edge 158 has the field and writes `v10` for all 197 cookies and 183
passwords. It is a capability flag, not a state flag.

## 8. SQLite behaviour: WAL, locks, backup
**Journal mode is per-database and is not WAL by default.** [SRC] `sql/database.cc:2325`: if
`UseWALMode()` then `PRAGMA journal_mode=WAL`, else `PRAGMA journal_mode=TRUNCATE`. Chromium
switched PERSIST → TRUNCATE in 2015 so sensitive content is removed from the journal
(crbug.com/493008).

[DISK] sidecars on Chrome 158 `Default/`:

| Database | `-wal` | `-journal` | Mode |
|---|---|---|---|
| `Network/Cookies` | no | yes (0 bytes) | rollback (TRUNCATE) |
| `Login Data`, `Web Data`, `History` | no | yes | rollback (TRUNCATE) |
| `DIPS` | **yes** | — | WAL |

The article's §2 "WAL mode" warning is **only true for some databases**. A zero-length `-journal`
means the last transaction committed cleanly, so copying `.db` alone is consistent. A **non-zero**
`-journal` means a transaction is in flight or a crash left a hot journal: copying `.db` alone gives
SQLite a file it will roll back on open, and without the journal you get a silently older snapshot,
not an error. A `-wal` means the newest committed pages live **only** in the WAL — copy `.db`
without `-wal` and you lose them, which is the `DIPS` case.

**Locking.** [SRC] `sql/database.cc:2157`: `enable_exclusive_access` opens with
`file:...?exclusive=true`, i.e. SQLite `EXCLUSIVE` mode, a mandatory file lock on Windows. [DISK]
while Brave runs, `Network/Cookies` fails with `WinError 32` even read-only, and the WAL is
unreadable; Chrome and Edge were readable read-only while running on the same machine. That is a
per-brand/per-flag difference, not a universal property.

**`immutable=1`.** `file:path?immutable=1` declares the file unchanging: SQLite skips all locking
and **ignores `-wal` and `-journal` entirely**. It is the only way to open a locked DB without a
copy, and that is exactly its risk — it can silently omit WAL-committed transactions and can return
a torn page set mid-commit. `PRAGMA journal_mode` under `immutable=1` always reports `delete`
regardless of the real mode, so check the sidecar files instead.

**Consistent copy**, best first: (a) close the browser; (b) SQLite backup API
(`sqlite3_backup_init`/`_step`), which reads under a shared lock and includes WAL content; (c) VSS
snapshot (`vssadmin create shadow`) — administrator, but the only consistent non-intrusive option
on a live system; (d) copy `.db` + `-wal` + `-journal` together; (e) copy `.db` alone — correct
only when no sidecar has content.

## 9. Profile discovery
A profile is a directory directly under the user-data root containing `Preferences`. Enumerating by
name is unreliable: `Profile 3` may not exist, and `Crashpad`, `ShaderCache`, `BrowserMetrics` sit
in the same root. [SRC] `chrome_constants.h`: `kInitialProfile="Default"`,
`kMultiProfileDirPrefix="Profile "` (trailing space), `kGuestProfileDir="Guest Profile"`,
`kSystemProfileDir="System Profile"`.

[DISK] Chrome 158 root held `Default`, `Profile 1`, `System Profile` and **no** `Guest Profile` —
that directory is created on demand and removed after, so discovery that requires it reports a
false negative. [SRC] `profile_manager.cc`: `Default` loads first, then `Profile N` numerically;
guest and system are excluded from the "last used" list. `Local State → profile.last_used` and
`profile.info_cache` map directory → display name — the only reliable way to know which `Profile 1`
is whose. Override paths: `--user-data-dir=<path>` replaces the whole root (and `Local State` moves
with it, shifting everything in §1); `--profile-directory=<name>` selects inside the root; portable
installs put the root next to the executable (e.g. `...\Chrome\Data\profile`) with no registry
pointer; `%LOCALAPPDATA%` itself is redirectable by policy. Minimum viable discovery: read
`ClientState\UserDataDir` (or the portable marker), fall back to the per-brand default, treat every
subdirectory containing `Preferences` as a candidate, and read `Local State` from the **root**.

## 10. Version matrix
| OS | Chrome | `meta.version` | Prefix | What opens it |
|---|---|---|---|---|
| Windows | ≤ 79 | ≤ 10 | none (bare DPAPI) | `CryptUnprotectData` directly |
| Windows | 80 – 126 | 11 – 23 | `v10` | AES-256-GCM, `DPAPI`-wrapped key from `Local State` |
| Windows | 127 – 129 | 24 | `v10` or `v20` | `v10`: user DPAPI key; `v20`: ABE |
| Windows | 130+ | 24 | `v10` or `v20` | as above **plus** `SHA256(host_key)` on cookies |
| macOS | any | 24 | `v10` | AES-128-CBC, PBKDF2-SHA1(Keychain, `saltysalt`, 1003) |
| Linux | any | 24 | `v10` | AES-128-CBC, keyring or `peanuts` |

Measured [DISK], consistent with the article's §9: Chrome 158 `Default` holds 40 cookies, all `v20`,
`meta` 24/24; Edge 158 holds 197, all `v10`, `meta` 24/24, plus 245 login rows of which 183 are
`v10` and 62 NULL; Opera holds 14, all `v10`, `meta` 24/24; Brave's cookie DB is unreadable while
running but its 23 password rows are all `v20` [ART]. `Login Data` is at **43/40** on both Chrome
and Edge — an independent counter from the cookie DB, so reading one and assuming the other is
wrong.

The decisive check, in order: (1) `app_bound_encrypted_key` present? → ABE exists on this install;
(2) `meta.version ≥ 24`? → strip 32 bytes of `SHA256(host_key)` after decrypt; (3) per-row prefix
`v10`/`v20`. (1) and (3) are independent — Edge answers yes to (1) and `v10` to (3).

## 11. Open questions
1. **`v11` has no producer in Chromium** (tags 79/80/96/131 contain only `"v10"`; pre-80 wrote an
   unprefixed DPAPI blob). Where wild `v11` blobs come from is **[UNVERIFIED]**.
2. **`PreProcessData`** (`elevator.cc:94`, Google-branding only) was not located. It is the likely
   explanation for the article's `0x01 + nonce + 32 + tag` inner reading; the outer double-DPAPI
   shape is confirmed, the inner envelope is not.
3. **`host_key` hashing for `__Host-` and IDN cookies.** The source hashes `host_key` verbatim;
   whether punycode-normalised and `__Host-` cookies always store the hashed form was not tested —
   a mismatch silently drops rows, since Chromium deletes on hash failure.
4. **Edge's `logins_edge_extended_table_version`** implies fork columns not enumerated here.
5. **Whether Chrome 158 writes `v20` for `card_number_encrypted`** was not measured; the container
   is shared so it should follow, but "should" is not a measurement.
6. **Brave's `v20` passwords with an unreadable cookie DB** suggests a per-file, not per-profile,
   lock; the exact flag combination was not isolated.

## 12. Sources
All source reads are `chromium/src` via gitiles (`?format=TEXT`, base64), fetched 2026-11-25.

| Ref | Path / tag | Used for |
|---|---|---|
| [SRC] | `net/extras/sqlite/sqlite_persistent_cookie_store.cc` @ `main` | cookie DDL, v24 migration, hash check, DML |
| [SRC] | `components/os_crypt/sync/{os_crypt_win.cc,os_crypt_posix.cc,os_crypt_mac.mm}` @ `131.0.6778.85` | `v10` constants, GCM layout, `saltysalt`, 1003/1, IV |
| [SRC] | `components/os_crypt/async/common/encryptor.cc`, `.../browser/dpapi_key_provider.cc` @ `main` | provider-tag prefixing, payload order, `kKeyTag="v10"` |
| [SRC] | `chrome/browser/os_crypt/app_bound_encryption_provider_win.h`, `chrome/elevation_service/*` @ `main` | `APPB`, `"v20"`, double DPAPI, length prefix, `ProtectionLevel`, IIDs |
| [SRC] | `components/password_manager/core/browser/password_store/login_database.cc` @ `main` | `logins` columns, v0→v43, 43/40 |
| [SRC] | `sql/database.cc`, `sql/meta_table.cc`, `base/time/time.h`, `chrome/common/chrome_constants.h`, `net/cookies/cookie_constants.h` @ `main` | journal mode, mmap, epoch, profile dirs, enums |
| [DISK] / [ART] | Chrome / Edge / Opera profiles on Windows 11; `article/en.md` §2, §4, §5.3, §9 | `sqlite_master`, meta rows, prefixes, sidecars; prior measurements and the Brave numbers |

## Confidence
| Area | Confidence | Basis |
|---|---|---|
| `cookies` DDL, 20 column meanings, `meta.version = 24`, hash change | **High** | Source + exact `sqlite_master` match |
| `Login Data` 32 columns, 43/40 | **High** | Source builder + on-disk DDL |
| Windows `v10` (3+12+ct+16) and POSIX `v10` (fixed 16-space IV) | **High** | Source literals, 31-byte arithmetic |
| `v20` container == `v10` container | **High** | Prefix is the provider tag |
| ABE = DPAPI(user) inside DPAPI(SYSTEM) | **High** | Source `EncryptData` |
| Journal mode per DB (Cookies = rollback, not WAL), `immutable=1` | **High** | Sidecars on disk + source pragma branch |
| ABE inner payload field order | **Medium** | Length-prefix helper confirmed; `PreProcessData` not read |
| `v11` not emitted by Chromium | **Medium-High** | Four tags grepped; absence of evidence |
| Bookmark / Preferences JSON shapes | **Medium** | `Preferences` observed; `Bookmarks` absent |
| Edge extension tables | **Low** | Names observed, contents not read |

Anything marked **[UNVERIFIED]** is a hypothesis with a test attached, not documentation.

*License: CC BY 4.0.*
