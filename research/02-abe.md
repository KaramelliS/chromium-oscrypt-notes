# App-Bound Encryption — Isolated Reference

Scope: Chromium's App-Bound Encryption (ABE) on Windows, as it stands at the end of 2026.
**VERIFIED** = reproduced on the reference machine (Windows 11, no TPM, Chrome `158.0.8127.36`,
Edge/Copilot `158.0.4370.33`, Brave `158.1.100.59`) or read out of current Chromium source.
**UNVERIFIED** = stated by a third party or inferred, not reproduced here. All local checks were
read-only and printed no decrypted value, cookie, password or key.

## Ozet (TR)

ABE, anahtarı kullanıcı DPAPI'sinden alıp SYSTEM kapsamlı bir DPAPI katmanının arkasına koyar; açma
işi LocalSystem çalışan `elevation_service.exe` üzerinden, çağıranın **yolunu** doğrulayarak yapılır.
TPM yoktur, çağrı anında imza doğrulaması yoktur. Referans makinede anahtar `S-1-5-18\User` deposunda
(`df9a3e03…` Chrome, `bfb9d720…` Edge profili/Brave) ve `DPAPI_SYSTEM` ile korunuyor — duvar
kriptografik değil, **hesap kapsamı** duvarı. 2024 CLSID'leri hâlâ kayıtlı (AppID → LocalService),
ölen şey **IID**; makalenin "CLSID öldü" iddiası yanlış. Edge 2026'da "Copilot" uygulamasına taşındı,
yeni CLSID kullanıyor; makaledeki 197/197 v10 ölçümü artık yazılmayan eski profilden geldiği için
"Edge hâlâ v10 yazıyor" sonucu kanıtlanmış değil.

---

## 1. What ABE protects and why it exists

Before 2024 the Chromium model on Windows was one layer: a random 32-byte AES key in `Local State`,
wrapped with `CryptProtectData` and bound to the logged-in user's DPAPI master key. That defends
against a stolen disk and against other users on the box. It does **not** defend against a process
running as the same user, because DPAPI is deliberately permissive inside a logon session. The 2024
infostealer wave was exactly that shape — user-mode code, no privilege escalation, reading
`Local State` and the SQLite databases. Layering more encryption on top changed nothing, because the
innermost key was still reachable by any same-user process. [01-dpapi]

ABE's answer is to move the unwrap step out of the user's reach:

- the key wrap is additionally encrypted in the **SYSTEM** DPAPI context, which a medium-integrity
  user process cannot open;
- the only sanctioned way to unwrap is a COM call into `elevation_service.exe`, which runs as
  `LocalSystem` and refuses to decrypt for callers whose executable path does not match the path
  recorded at encryption time.

Stated non-goals, from Google's own design notes as summarised by xaitax: ABE does not stop
Administrator/SYSTEM, kernel code, or code injected into the browser. The design document explicitly
names injection into Chrome as a known bypass. [xaitax-research]

Consequence: every public bypass is either "become SYSTEM" or "put code inside a process that
already passes path validation". There is no cryptographic shortcut, and there is no third route.

Data actually covered today is uneven. Cookies moved to `v20` first. Passwords were still `v10` in
2025 per ZeroCrumb's README ("passwords aren't encrypted using the app bound key (yet)")
[zerocrumb]; on the reference machine Edge passwords are `v10` while Chrome cookies are `v20`.

---

## 2. The elevation service

One service per browser product, `WIN32_OWN_PROCESS`, `DEMAND_START`, `LocalSystem`. Measured on the
reference machine:

| Product | Service | Binary |
|---|---|---|
| Chrome | `GoogleChromeElevationService` | `…\Google\Chrome\Application\158.0.8127.36\elevation_service.exe` |
| Brave | `BraveElevationService` | `…\BraveSoftware\Brave-Browser\Application\158.1.100.59\elevation_service.exe` |
| Edge (now Copilot) | `MicrosoftCopilotElevationService` | `…\Microsoft\Copilot\Application\158.0.4370.33\elevation_service.exe` |

All three are registered the same way: a `CLSID` key that holds **only an `AppID` value**, plus an
`AppID` key whose `LocalService` names the service. There is no `InprocServer32` and no `LocalServer32`
subkey anywhere — measured: all three CLSID keys have zero subkeys. That single fact explains the most
common wrong claim in circulation (including in this repo's own article): a probe that looks for
`InprocServer32` concludes "the CLSID is not registered". It is registered; it is a service-backed
class.

### 2.1 API surface

Authoritative source is the IDL in Chromium. [chromium-idl]

```
IElevator   {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}
  RunRecoveryCRXElevated(crx_path, appid, version, session_id, caller_pid) -> proc_handle
  EncryptData(ProtectionLevel level, BSTR plaintext) -> BSTR ciphertext, DWORD last_error
  DecryptData(BSTR ciphertext) -> BSTR plaintext, DWORD last_error

IElevator2  {8F7B6792-784D-4047-845D-1782EFBEF205} : IElevator
  RunIsolatedChrome(flags, command_line) -> log, proc_handle
  AcceptInvitation(server_name)
```

There is **no** `IElevator2::DecryptDataWithKey` and no key parameter anywhere in the IDL — the
interface carries no caller-supplied key material at all. Any write-up that describes passing a key
into the service is describing something that does not exist in the public interface.

The service binary registers the same methods under per-flavour IIDs so several Chrome channels can
coexist: `IElevatorChromium` `B88C45B9-8825-4629-B83E-77CC67D9CEED`, `IElevatorChrome`
`463ABECF-410D-407F-8AF5-0DF35A005CC8`, `IElevator2Chromium` `BB19A0E5-00C6-4966-94B2-5AFEC6FED93A`,
`IElevator2Chrome` `1BF5208B-295F-4992-B5F4-3A9BB6494838`. Beta / Dev / Canary have their own in the
same IDL; they are omitted here because nothing below depends on them.

The CLSID is not in that list because the CLSID is not in the IDL — it is a per-install-mode
constant (`elevator_clsid` in `chrome/install_static/google_chrome_install_modes.h`). For the stable
Google Chrome mode it is `{708860E0-F641-4611-8895-7D867DD3675B}`, and `elevator_iid` is
`{1BF5208B-295F-4992-B5F4-3A9BB6494838}` (IElevator2Chrome). [chromium-install-modes]

Binary scan of the shipped services (VERIFIED, exact little-endian GUID byte search):

| GUID | Chrome 158 | Brave 158.1 | Edge/Copilot 158 |
|---|---|---|---|
| CLSID `708860E0-…` | present | absent | absent |
| CLSID `CD489BAC-BF1F-4F4B-9DB9-39B823919EAC` | absent | absent | present |
| AppID `576B31AF-6369-4B6B-8560-E4B203A97A8B` | absent | present | absent |
| `IElevator` `A949CB4E-…-B213-…` | present | **absent** | present |
| `IElevator2` `8F7B6792-…` | present | present | present |
| `IElevatorChrome` `463ABECF-…` | present | absent | absent |
| `IElevator2Chrome` `1BF5208B-…` | present | present | absent |

Two things follow. Brave's build only ships the `IElevator2` family, not base `IElevator`; and the
"2024 CLSID" for Edge (`{1FCBE96C-1697-43AF-9140-29DB18F2E706}`) is gone from the 158 binary, replaced
by `{CD489BAC-…}`.

The IID quoted in 2024-era write-ups, `{A949CB4E-C4F9-44C4-B113-378C4FE16981}` [UNVERIFIED as a
historical value, but measured absent from every 158 binary], is not what today's IDL declares. So
the correct statement is the opposite of the popular one: **the CLSID survived, the IID rotated.**
The rotation is a one-byte difference in the third group (`B113` vs `B213`), which is why nobody
noticed.

### 2.2 Caller validation

Validation lives in `chrome/elevation_service/caller_validation.cc`. [chromium-caller-validation]
There is no signature check there, no command-line check, and no allow-list of process names. The
mechanism is:

1. The service identifies the caller with `I_RpcOpenClientProcess(nullptr, access, &handle)` — an RPC
   call that returns a handle to the client process, falling back to the current process when there is
   no active call. [chromium-caller-validation]
2. It reads the caller's image path with `QueryFullProcessImageNameW`.
3. It normalises that path with `MaybeTrimProcessPath`: drop the final `.exe`, then drop a trailing
   `Temp`, `Application`, or version-number directory, and rewrite `Program Files (x86)` to
   `Program Files`. So `C:\Program Files (x86)\Blah\Application\1.2.3.4\app.exe` becomes
   `C:\Program Files\Blah`.
4. It compares the normalised path byte-for-byte against the path recorded in the blob at encryption.

`ProtectionLevel` decides how much is checked: `0` = `PROTECTION_NONE` (always validates), `1` =
`PROTECTION_PATH_VALIDATION_OLD` (unsupported, returns an error), `2` = `PROTECTION_PATH_VALIDATION`
(path comparison only), `3` = `PROTECTION_PATH_VALIDATION_WITH_ISOLATION` (path plus an isolation bit
from the caller's token).

Level 3 is the current default: `kEncryptWithIsolatedState` is `FEATURE_ENABLED_BY_DEFAULT`. The
"isolated" bit is the presence of a security attribute on the caller's process token
(`installer::GetIsolationAttributeName()`); a non-isolated caller cannot decrypt data written by an
isolated one, but the reverse is allowed and triggers a re-encrypt hint.

The practical weaknesses all follow directly from the code:

- **Path, not identity.** Any executable whose normalised path matches passes. Because version
  directories are trimmed, dropping a different `chrome.exe` into
  `C:\Program Files\Google\Chrome\Application\<anything>\` satisfies validation. On the reference
  machine Chrome's install directory is not user-writable; Brave's was reported user-writable.
- **`Temp` and `Application` are trimmed**, so a caller running out of `…\Blah\Temp\x.exe` validates
  against a blob written by `…\Blah\anything.exe`.
- **Injection wins outright.** Code executing inside `chrome.exe` inherits the path. Every serious
  public tool is built on this, and Google's design document concedes it. [xaitax-research]
- **`PROTECTION_NONE` exists.** A level-0 blob decrypts for anyone. No shipping browser uses it, but
  the branch is live in the service.
- The service runs as `LocalSystem`, which is what makes the SYSTEM DPAPI layer openable at all.

### 2.3 The APPB blob

`Local State → os_crypt.app_bound_encrypted_key` is base64 of the four ASCII bytes `APPB` (added
client-side, in `chrome.dll`) followed by one DPAPI blob. VERIFIED on all four profiles measured —
Chrome 644 bytes, Brave 596, Edge profile 582, Copilot 582. The inner blob's provider GUID is
`DF9D8CD0-1501-11D1-8C7A-00C04FC297EB`, the standard DPAPI provider, so there is no CNG/TPM envelope
at this layer — contrary to the "CNG machine key (TPM)" box in the article's mechanism diagram.

Master keys referenced by the inner blob (VERIFIED by parsing offset 24..40 of the DPAPI blob), and
none of them present in the user's `%APPDATA%\Microsoft\Protect\<SID>`:

| Profile | `guidMasterKey` |
|---|---|
| Chrome | `df9a3e03-044f-4442-b5f1-ace50e51608e` |
| Edge profile | `bfb9d720-c655-4be8-9abc-cb821ef2222c` |
| Brave | `bfb9d720-c655-4be8-9abc-cb821ef2222c` |
| Copilot | `df9a3e03-044f-4442-b5f1-ace50e51608e` |

All three keys exist under `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\` as 468-byte files
(`bfb9d720…`, `df9a3e03…`, and a third, `fd8aa86f-655d-4be2-a0b2-5d42cf7d99c6`, owned by nothing
measured here). `Preferred` in that directory contains `df9a3e03-…`, i.e. Chrome's ABE master key is
currently the machine-wide default. This is the decisive observation, and it corrects the article in
two ways:

1. The key is **not** "lost" or "in another account's profile". It is in the machine store, protected
   by the `DPAPI_SYSTEM` LSA secret, exactly like any other machine-scope DPAPI key. [01-dpapi]
2. The master key is **not per-browser**. Edge and Brave share `bfb9d720`, Chrome and Copilot share
   `df9a3e03`. The GUID is simply whichever machine key was current when the wrap was created — only
   possible if the wrap is a plain machine-scope `CryptProtectData` call, not a browser-specific CNG
   container.

A medium-integrity user process calling `CryptUnprotectData` on the blob fails with
`0x8009000B` (`NTE_BAD_KEY_STATE`) — VERIFIED, reproduced on Chrome and Edge blobs. The user context
cannot touch a SYSTEM-scope key, which is precisely the intended wall.

Inside the outer layer, per `Elevator::EncryptData` / `DecryptData` [chromium-elevator]:

```
CryptProtectData(                              ← SYSTEM context
    CryptProtectData(                          ← caller context (impersonated)
        [len][validation_data][len][plaintext]
    )
)
validation_data = [ProtectionLevel][normalised path bytes]
```

`DecryptData` peels SYSTEM first, then impersonates the caller and peels the user layer, then runs
`ValidateData` on the extracted `validation_data`, then returns the plaintext. Both layers are the
same `CryptProtectData` primitive; the difference is only *whose* key is used, which is why
impersonation (`ScopedClientImpersonation`) is load-bearing.

The plaintext is **not** the raw AES key for Chrome-branded builds. Under
`BUILDFLAG(GOOGLE_CHROME_BRANDING)` the service runs `PreProcessData`/`PostProcessData` around it,
and those live in `chrome/elevation_service/internal/…` which is **not** in the public tree (HTTP 404
from the source host, VERIFIED). So the last step is a closed-source transform, and its shape is
known only from reverse engineering:

```
[1 byte flag] [12 byte nonce] [32 byte ciphertext] [16 byte tag]
```

i.e. AES-256-GCM over the 32-byte key with a key that is either hardcoded in `elevation_service.exe`
or held in a CNG/KSP container, depending on version. [runassu]

Correction to the article's §5.3: the `[len] path` / `0x01` / nonce / ciphertext / tag layout is the
*payload* after both DPAPI layers, not the layer directly under `APPB`. The real inner plaintext has
two more fields the article omits — a protection-level byte and a second length prefix:

```
1f 00 00 00  | 02 | "C:\Program Files\Google\Chrome" | 3d 00 00 00 | 01 | IV12 | CT32 | TAG16
     ^len=31   ^level 2                                  ^len=61   ^flag
```

That dump is runassu's, and it parses exactly against the `EncryptData` code above. [runassu]

The wall is therefore two-sided: SYSTEM (or the service) peels the outer layer, the user's own logon
peels the inner one. That is why "run as SYSTEM" alone is not enough, and why the service impersonates
the caller rather than just using its own token.

---

## 3. Version timeline 127 → 158

Every row is a claim about behaviour, with the evidence that supports it. "Local" means measured on
the reference machine in this session.

| Version | Change | Evidence |
|---|---|---|
| 125 | Enterprise policy `ApplicationBoundEncryptionEnabled` exists (`supported_on: chrome.win:125-`), default `true` | [chromium-policy-yaml] |
| 127 | ABE ships; cookies start being written as `v20`; key unwrap moves behind the elevation service | [xaitax-research] [runassu] [article §5] |
| pre-133 | Inner payload protected with AES-256-GCM under a key hardcoded in `elevation_service.exe`; the Chrome 130-era Go PoC hardcodes that key as a base64 constant | [runassu] (implied by the 133 switch) [githubesson] |
| 133 | Inner payload switches to ChaCha20-Poly1305; key still hardcoded in the binary | [runassu] |
| 137 | Switches back to AES-256-GCM; the key moves out of the binary into a CNG/KSP container; the plaintext key blob sits after a `\x03` flag byte | [runassu] |
| 144 | `IElevator2` in use; ChromElevator auto-selects `IElevator2` and falls back to `IElevator` for older builds; tested against Chrome 144.0.7559.133 / Edge 145 / Brave 1.86 | [xaitax-readme] |
| 157 | New CNG key name `Google Chromekey2` and a new XOR key | [runassu] |
| 158 | **Local:** Chrome's `elevation_service.exe` imports `NCryptOpenStorageProvider`, `NCryptCreatePersistedKey`, `NCryptOpenKey`, `NCryptEncrypt`, `NCryptDecrypt` — CNG is still in play. But the strings `Google Chromekey` / `Chromekey2` are **absent** from Chrome's binary (ASCII and UTF-16), while Edge/Copilot's binary contains UTF-16 `Google Chromekey1`. Neither `C:\ProgramData\Microsoft\Crypto\Keys` nor the user's `…\Crypto\Keys` holds a usable persisted key (`certutil -csp "Microsoft Software Key Storage Provider" -key` lists none). So on this machine the CNG stage either falls back or uses a name built at runtime. | local |

Two structural notes matter more than the crypto churn. First, the CLSID did **not** change for Chrome
between 2024 and 158 (`{708860E0-…}` is still registered and still points at
`GoogleChromeElevationService`); the IID did change, so tools that hardcode the IID break while tools
that hardcode the CLSID and ask for `IElevator2Chrome` keep working. Second, the article's claim that
"none of the three [CLSIDs] is registered" is **false on this machine** for Chrome and Brave, and only
true for the 2024 Edge CLSID — the likely cause is a probe that required an `InprocServer32` subkey.

---

## 4. Known bypass techniques

| Technique | What it defeats | Target | Detection risk | Source |
|---|---|---|---|---|
| Reflective process hollowing of a spawned browser + direct syscalls + in-memory DLL; COM call from inside | Path validation | Chrome 144 / Edge 145 / Brave 1.86 tested; user-mode, no admin | High — hollowing, `Nt*` syscalls, RDI, PE header wipe are all named EDR signatures; MIT | [xaitax-readme] |
| Transacted hollowing + named pipe to exfiltrate the key | Path validation | Chrome / Brave / Edge as of 2025-05; no privileges | High — transacted hollowing is a known primitive; MIT | [zerocrumb] |
| Suspend browser, inject DLL with `LoadLibraryA`, named pipe with deterministic name | Path validation | Chromium 144; no admin | Very high — plain `LoadLibraryA`, DLL on disk as base64, kills the browser; author says so explicitly; MIT | [majanito] |
| COM injection into a spawned browser process, exposed as a library API | Path validation | `IElevator2`, live CI against Chrome/Edge/Brave; MIT | Medium-high — author warns endpoint products can flag it; opt-out provided | [rookie-cookies] |
| Same as above, packaged as a Cobalt Strike BOF | Path validation | Chrome only, hardcoded profile path; MIT | Medium — runs in Beacon, no new process | [mendacus] |
| Impersonate `lsass.exe` token (admin) → SYSTEM DPAPI unwrap → user DPAPI unwrap → parse payload | The whole service; never talks to COM | Chrome 157+ per README; **requires admin** | Medium — `SeDebugPrivilege` + token theft from lsass is a textbook detection | [runassu] |
| Fully offline: SYSTEM DPAPI userkey → SYSTEM masterkey → KSP key blob → blob1 → blob2 → key derivation by flag byte | The whole service, no live process | Chrome, offline artefacts only | Low at runtime (nothing runs on the host), but needs the `DPAPI_SYSTEM` secret and the user's masterkey | [0rcruxe] |
| Extract the hardcoded AES key from `elevation_service.exe` and decrypt the payload without COM at all | Everything except the DPAPI layers | Chrome 130 era | Low, but obsolete — killed by 133 (ChaCha) and again by 137 (KSP) | [githubesson] |
| Write a binary into the browser's install directory so its normalised path matches | Path validation | Any build where the install dir is user-writable (Brave was reported writable) | Medium — needs a file write into the install dir, and a version-directory change may force a re-encrypt | [article §9] |

The pattern is unambiguous: nobody breaks the cryptography. They either borrow the browser's identity
or they borrow SYSTEM's. Every 2026 tool that works without admin is an injection tool; every tool
that works without injection needs admin. `runassu`'s variant is worth calling out on its own because
it is the only public one that matches what this repo measured: impersonate `lsass.exe`, unwrap
SYSTEM, revert to the user, unwrap the user layer, apply the binary-specific inner transform. It
requires administrator and says so in the first line of its README.

---

## 5. Vendor differences: Chrome vs Edge vs Brave

Measured on the reference machine:

| Property | Chrome 158.0.8127.36 | Edge/Copilot 158.0.4370.33 | Brave 158.1.100.59 |
|---|---|---|---|
| CLSID | `{708860E0-F641-4611-8895-7D867DD3675B}` | `{CD489BAC-BF1F-4F4B-9DB9-39B823919EAC}` | `{576B31AF-6369-4B6B-8560-E4B203A97A8B}` |
| AppID → LocalService | `GoogleChromeElevationService` | `MicrosoftCopilotElevationService` | `BraveElevationService` |
| Service account | `LocalSystem` | `LocalSystem` | `LocalSystem` |
| IIDs in binary | `IElevator`, `IElevator2`, Chrome/Chromium flavours | `IElevator`, `IElevator2` | `IElevator2` family only |
| `NCrypt*` imports | yes | yes | **no** |
| `CryptProtectData` / `CryptUnprotectData` | yes | yes | yes |
| ABE master key | `df9a3e03-…` | `df9a3e03-…` (Copilot profile) / `bfb9d720-…` (old Edge profile) | `bfb9d720-…` |
| `os_crypt` keys | `app_bound_encrypted_key`, `audit_enabled`, `encrypted_key` | same **plus** `aster_app_bound_encrypted_key` (Copilot profile) | same as Chrome |
| Cookie prefix, measured | 40/40 `v20` | 197/197 `v10` — **see caveat** | DB locked, not measured |
| ABE blob opens in user context | no (`NTE_BAD_KEY_STATE`) | no (`NTE_BAD_KEY_STATE`) | not tested |

**Brave is structurally the easiest target.** Its `elevation_service.exe` has no `NCrypt*` imports
at all, which means the `BUILDFLAG(GOOGLE_CHROME_BRANDING)`-only `PreProcessData`/`PostProcessData`
step is compiled out. After the two DPAPI layers, Brave hands back the raw 32-byte key — exactly what
runassu's README says ("In other brand browsers, we can directly get the 32-bytes AES key").
[runassu] The COM identity requirement is identical, but there is no third crypto stage to reverse.
Brave's ABE blob also shares `bfb9d720` with the Edge profile, which is only explicable if both are
plain machine-scope DPAPI.

**Edge has been renamed.** There is no `msedge.exe` and no `MicrosoftEdgeElevationService` here. The
browser is installed as `…\Microsoft\Copilot\Application\158.0.4370.33\` with the entry point
`copilotapp.exe` and 9 running `copilotapp` processes; the elevation service's version resource still
says `ProductName: Microsoft Edge`, `FileVersion 158.0.4370.33`. The old `…\Microsoft\Edge\User Data`
profile still exists but has not been written since 2026-10-30 — which forces a correction to the
article's strongest claim.

> Article §9: "Edge cookies: 197 rows, all `v10` … Edge has ABE but it is not engaged … the softest
> target is not Chrome, it is Edge."

The 197/197 measurement is real and I reproduced it independently: 197 rows, all `v10`, all 197
decrypt with the legacy DPAPI key, all 197 carry a correct `SHA256(host_key)` prefix. But it comes
from a profile that stopped being written a month ago, while the live profile
(`…\Microsoft\Copilot\User Data`) is locked with share mode 0 and cannot be sampled without closing
the browser. The honest statement is therefore: **an Edge-branded 158 profile was 100% `v10` at the
end of October 2026; whether the live Copilot profile still writes `v10` today is not established.**

Candidate explanations for Edge sitting on `v10` while carrying an ABE key, none of them verified:
ABE is staged per-channel or per-experiment and this install sits in the not-yet-enabled bucket (the
`app_bound_encrypted_key` is created by the key provider at startup regardless); Edge binds ABE to a
different data class first, which the Copilot-only `aster_app_bound_encrypted_key` would suggest; or
`os_crypt.audit_enabled: true`, present in every profile and unexamined here, gates an audit mode that
keeps writing `v10` while validating `v20`. [UNVERIFIED] Treat "Edge is the soft target" as a
hypothesis with one month of evidence behind it, not a fact.

---

## 6. Policy and opt-out

The enterprise control is a single boolean, and its text is worth quoting because it states the
threat model in Google's own words: [chromium-policy-yaml]

```yaml
name: ApplicationBoundEncryptionEnabled
default: true
desc: |-
  Setting the policy to Enabled or leaving it unset binds encryption keys used for local data
  storage to $1 whenever that is possible. Setting the policy to Disabled has a detrimental
  effect on $1's security as unknown and potentially hostile apps can retrieve encryption keys.
  Only turn off the policy if there are compatibility issues, such as other applications that
  need legitimate access, encrypted data must be portable between computers, or the integrity
  and location of $1's executables is not consistent.
supported_on: [chrome.win:125-]
features: { dynamic_refresh: false, per_profile: false }
```

Practical reading: `false` is the documented way to get `v10`-equivalent behaviour back, and the
description names the three legitimate reasons (third-party access, portability across machines,
unstable install path). `dynamic_refresh: false` means it is read at startup, not live — a change
needs a restart. `per_profile: false` means machine/user level, not per profile. The policy predates
the 127 rollout by two releases, which is why "ABE appeared in 125" shows up in policy lists and
"ABE appeared in 127" in write-ups; both are right about different things.

What the policy does on an existing profile is undocumented: it is [UNVERIFIED] whether flipping it to
`false` re-encrypts an existing `v20` key back to a user-scope wrap, or only stops new wraps from being
created. Given `DecryptData` returns `kSuccessShouldReencrypt` on a level mismatch, a re-encrypt path
exists in the service, but the policy plumbing to it was not traced.

Separately, `AppBoundPolicy::Disabled` is **not** a Chrome policy. It is `rookie-cookies`' own
library-level opt-out (Rust enum, `app_bound="disabled"` in Python, `appBound: "disabled"` in Node,
`--app-bound disabled` in the CLI) which makes the library omit `v20` rows and report them unavailable
instead of injecting into a browser process. [rookie-cookies] Both are called "policy"; only one is
enforced by the browser.

---

## 7. What is NOT known

Marked honestly, because most of these are where a confident blog post would invent something.

1. **The inner transform in 158.** `PreProcessData`/`PostProcessData` are closed source (404 in the
   public tree). runassu documents ChaCha20 at 133, AES-GCM at 137, and a new CNG key name plus XOR
   key at 157. Chrome 158's binary has no `Chromekey` string at all, and no persisted CNG key exists
   on this machine, yet ABE works. Whether 158 uses a runtime-built key name, a hardcoded fallback, or
   something else is unknown.
2. **Why no CNG key exists here.** `NCryptCreatePersistedKey` is imported but neither key store has a
   key. Either creation failed silently and a fallback path ran, or the key is created per-boot in a
   volatile provider. Not determined.
3. **Whether the live Copilot profile writes `v10` or `v20`.** Blocked by the share-mode-0 lock on
   `Network\Cookies`; resolving it requires closing the browser or a VSS snapshot. **What
   `aster_app_bound_encrypted_key` is** (Copilot-only, no public documentation) is equally open, as is
   **who owns `fd8aa86f-655d-4be2-a0b2-5d42cf7d99c6`** in the `S-1-5-18\User` store — a third key,
   unclaimed by any of the four profiles measured.
4. **Whether the 2024 IID `{A949CB4E-C4F9-44C4-B113-378C4FE16981}` was ever real.** It is absent from
   every 158 binary; the current IDL declares `…-B213-…`. Could be a transcription error in 2024
   write-ups rather than a rotation.
5. **Signature validation.** `caller_validation.cc` has none. Whether the installer or the service
   registration path validates the binary's Authenticode signature before creating the service was
   not traced.
6. **TPM behaviour.** The reference machine has no TPM, so nothing here says what a TPM-equipped
   machine does. The ABE blob has no CNG envelope, but the inner transform's key container could be
   platform-bound on such a machine. **Policy → re-encrypt plumbing** is equally untraced (§6).

---

## 8. Sources

| Ref | What it is |
|---|---|
| [chromium-idl] | `chrome/elevation_service/elevation_service_idl.idl` — https://chromium.googlesource.com/chromium/src/+/main/chrome/elevation_service/elevation_service_idl.idl |
| [chromium-elevator] | `chrome/elevation_service/elevator.cc` — EncryptData/DecryptData, two DPAPI layers, impersonation |
| [chromium-caller-validation] | `chrome/elevation_service/caller_validation.cc`, `chrome/windows_services/service_program/get_calling_process.cc` — path trim, protection levels, `I_RpcOpenClientProcess` |
| [chromium-install-modes] | `chrome/install_static/google_chrome_install_modes.h` — `elevator_clsid`, `elevator_iid` per install mode |
| [chromium-policy-yaml] | `components/policy/resources/templates/policy_definitions/Miscellaneous/ApplicationBoundEncryptionEnabled.yaml` |
| [chromium-abe-client] | `chrome/browser/os_crypt/app_bound_encryption_provider_win.cc` — `kEncryptWithIsolatedState`, `NTE_BAD_KEY_STATE` handling |
| [xaitax-research] | https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/blob/main/docs/RESEARCH.md |
| [xaitax-readme] | https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption — MIT, last commit 2026-02-09, tested Chrome 144.0.7559.133 |
| [runassu] | https://github.com/runassu/chrome_v20_decryption — no LICENSE file, last commit 2026-11-12, admin-only PoC |
| [zerocrumb] | https://github.com/internetangel/ZeroCrumb — MIT, last commit 2025-05-28 |
| [rookie-cookies] | https://github.com/teng-lin/rookie-cookies — MIT, last commit 2026-10-30, `IElevator2`, `AppBoundPolicy::Disabled` |
| [mendacus] | https://github.com/mendacus/chrome-abe-decryption-bof — MIT, last commit 2025-07-14 |
| [majanito] | https://github.com/Majanito/ABE-Decryption — MIT, last commit 2026-02-02, tested Chromium 144 |
| [0rcruxe] | https://github.com/0rcruxe/chrome-abe-offline-decrypt — no LICENSE file, last commit 2026-09-28 |
| [githubesson] | https://github.com/githubesson/chrome_abe_poc — no LICENSE file, last commit 2024-11-04, Chrome 130 |
| [01-dpapi] | `research/01-dpapi.md` in this repo — DPAPI hierarchy, `S-1-5-18` store, `DPAPI_SYSTEM` |
| [article §5] | `article/en.md` §5 — the narrative this document checks against |

---

## Confidence

| Claim | Confidence | Basis |
|---|---|---|
| ABE blob = `APPB` + one SYSTEM-scope DPAPI blob, no CNG/TPM envelope | High | parsed on 4 profiles; source matches |
| Master keys live in `S-1-5-18\User`, protected by `DPAPI_SYSTEM` | High | files present, `Preferred` mapping, source model |
| A user process cannot open the blob (`NTE_BAD_KEY_STATE`) | High | reproduced twice |
| Validation is path-based, not signature-based; no `DecryptDataWithKey` exists | High | `caller_validation.cc` + full IDL read |
| Chrome's CLSID is still registered in 158 | High | registry + binary + service path all agree |
| The 2024 CLSIDs are "dead" (article claim) | **Refuted** | measured: Chrome and Brave registered; only the old Edge CLSID is gone |
| Edge 158 still writes `v10` | Medium | 197/197 measured, but from a profile last written 2026-10-30 |
| Brave returns the raw key after two DPAPI layers | Medium-high | no `NCrypt*` imports + brand-gated pre/post-process in source + runassu |
| Chrome 158's inner transform uses `Google Chromekey2` | **Unverified** | string absent from the 158 binary |
| Version changes at 127/133/137/157 | Medium | single upstream source (runassu), consistent with tool breakage reports |
| Policy `false` re-encrypts existing `v20` keys | Unverified | not traced |
