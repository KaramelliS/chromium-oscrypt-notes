# Existing Tooling — Isolated Reference

Scope: the eleven projects in `article/en.md` §11, read at source level and compared as architecture.
Purpose is the input for a library (Rust core + Python/Node bindings) that this corpus will be followed by.

**SOURCE** = read from the project's README, source or licence file at `HEAD`. **COMMUNITY** = a claim
another project makes about this one, quoted as such. **INFERRED** = my reading of source behaviour.
**UNVERIFIED** = could not confirm. Stars and commit dates read 2026-11-25.

## Ozet (TR)

Ekosistemde iki ayrı şey aynı isimle anılıyor: *format bilgisi* (v10/v20 byte düzeni) ve *anahtar elde
etme* (DPAPI, COM, injection). Hiçbir proje bu ikisini ayrı, sürümlenmiş bir sözleşme olarak yayınlamıyor
— `HackBrowserData` bunu kendi içinde `masterkey`/`browser`/`crypto` paketleriyle en temiz şekilde
ayırıyor ve `dumpkeys`/`archive`/`restore` üçlüsüyle taşınabilir hale getiriyor. `rookie-cookies` ise tek
Rust çekirdeği + PyO3 + napi-rs ile kütüphane şablonunu veriyor: tipli hata kodu taksonomisi,
`declared`/`available` yetenek bildirimi, ve ABE injection'ın AV tarafından karantinaya alındığını kendi
README'sinde yazan tek proje. Doğru karar ikisinin sentezi: HBD'nin `keyRetriever` trait'i ve
snapshot-first boru hattı, rookie'nin binding katmanı ve hata disiplini, üstüne bu korpustaki
`Capability` modeli. Lisans tarafı temiz: MIT dışında yalnızca LaZagne var (LGPL-3.0); dört projede hiç
lisans dosyası yok.

## 1. Comparison table

| Project | Lang | Platform | Licence | ABE approach | Cross-host | Binding | Last commit | Stars |
|---|---|---|---|---|---|---|---|---|
| `moonD4rk/HackBrowserData` | Go 1.20+ (+C payload via `zig cc`) | Win/mac/Linux | MIT | embedded C payload, reflective injection; needs `make build-windows` | **yes** — `dumpkeys`/`archive`/`restore` | none (CLI) | 2026-11-22 | ~14.7k |
| `teng-lin/rookie-cookies` | Rust + PyO3 + napi-rs | Win/mac/Linux | MIT | unprivileged reflective COM injection into a spawned browser, **on by default**; elevated DPAPI/CNG fallback for 133+ | no | **Rust, Python, Node, CLI** | 2026-10-30 | ~20 |
| `xaitax/Chrome-App-Bound-Encryption-Decryption` | C++ / x64 ASM | Win x64+ARM64 | MIT | direct-syscall reflective hollowing of a suspended browser, in-target COM | no | none | 2026-02-09 | ~1.9k |
| `runassu/chrome_v20_decryption` | Python | Windows (admin) | none declared | **no injection** — double DPAPI (SYSTEM→user) + hardcoded `elevation_service.exe` key | effectively yes (key portable) | none | 2026-11-12 | ~275 |
| `internetangel/ZeroCrumb` | C++ | Windows | MIT | transacted hollowing + named pipe, no admin | no | none (DLL sketch) | 2025-05-28 | ~171 |
| `norahc-x/Margaret-Stealer` | C + ASM (MinGW) | Win11 24H2 x64 | none declared | **none** — walks live `CookieMonster` in the network utility, no key at all | no | none | 2026-11-24 | ~13 |
| `mendacus/chrome-abe-decryption-bof` | C++ | Windows (Cobalt Strike) | MIT | in-memory BOF into parent `chrome.exe`, calls the elevator | partial (`decryptor.exe --key`) | none | 2025-07-14 | ~20 |
| `AlessandroZ/LaZagne` | Python | Win/mac/Linux | **LGPL-3.0** | none documented for v20 | no | none | 2025-09-18 | ~11.1k |
| `djhohnstein/SharpChrome` | C# (.NET 4.0+) | Windows | none declared | none (pre-ABE, v80 BCrypt) | no | none (.NET asm) | 2020-10-23 | ~765 |
| `0rcruxe/chrome-abe-offline-decrypt` | Python 3.10+ | Windows (offline) | none declared | **offline** — SYSTEM userkey→masterkey→KSP blob→`blob1`→`blob2`→content flag | yes, with origin DPAPI material | none | 2026-09-28 | ~9 |
| `Majanito/ABE-Decryption` | Python + C++ DLL | Windows x64 | MIT | spawns suspended, `LoadLibraryA`, COM via pipe | no | none | 2026-02-02 | ~22 |

Two rows the table flattens. `runassu` is the only project reaching v20 **without** code in a browser
process; its README documents the drift as a sequence: 133+ ChaCha20-Poly1305 with a key hardcoded in
`elevation_service.exe`, 137+ back to AES-256-GCM with the key in the DPAPI blob after flag `\x03`
(CNG/KSP), 157+ a new CNG key name `Google Chromekey2` and a new XOR key. `Margaret-Stealer` does not
attack at-rest encryption at all.

## 2. Per-project notes

### moonD4rk/HackBrowserData
Go, MIT, 20 browsers, three OSes plus Safari. Split into `internal/{abe, app, atomicfile, browser,
category, crypto, export, golden, keychain, log, masterkey, record, snapshot, sqlitex, timeconv, winapi,
zipfile}` with an RFC set `rfcs/000-goals.md`…`007-quality.md` written as decisions, not as docs. Three
stated boundaries map onto our problem: **secret retrieval** is one layer that talks to OS stores and
knows nothing about browsers or records; **cryptography** is pure functions over bytes with no OS calls,
testable with fixed vectors; **blob formats** belong to each browser base, which decides which key
decrypts what. `rfcs/004` adds **snapshot-first**: no parser reads a live profile — capture copies to a
temp root, every parser reads the copy, the copy is removed on success, on error and on Ctrl-C, so
locked-file handling exists in one place. Cross-host is first-class: `restore` "never consults the
analyst's local browser table". Output `csv`/`json`/`cookie-editor`. No embedding surface; `rookie-cookies`
calls it "not designed for embedding".

### teng-lin/rookie-cookies
Rust core at `rookie-rs/`, PyO3, napi-rs, `clap` CLI over one shared core; 25 browsers; MIT, continuing
`thewh1teagle/rookie`. Closest thing to what we intend to write.
**API surface.** Recommended job `read` (returns `ReadResult` with warnings, partitions, container
identity); `jar` is warning-discarding projection sugar; `ReadRequest` builder; `SendContext` for header
projection. Legacy per-browser helpers (`chrome()`, `firefox()`, `load()`) are a compatibility bridge
explicitly scheduled to break in 0.7. Named helpers cover 15 of 25 browsers; the rest are job-API only.
**Capability is two levels, not one.** Registry level: each `RegisteredBrowser` carries a
`BrowserCapabilityDescriptor` with *declared* and *available* formats, roles and decryption tiers; the
public DTO is `BrowserCapabilitiesDescriptor`. Run level: `ExtractionReport` carries provenance, per-source
failure and a typed issue taxonomy. "What should be possible" and "what happened" are separate objects.
**Error taxonomy.** Typed `Error` hierarchy; the CLI writes runtime failures to stderr as one JSON object
with exactly `code` and `message`, and says to branch on `code` because `message` may change.
**Pipeline.** Compiler-enforced stage types: discovery → `SourceCandidate`, reading → `Source`,
`Outcome::finalize` → shared result, then projections. Verbs: resolve, discover, select, lookup, acquire,
decode, unseal, finalize, project. Deliberately **no engine-plugin trait** — four `match` arms on
`RegisteredBrowser.engine` (ADR 0005).
**Registry.** One hand-maintained `browser_registry.json`; `CONFIG` is a read-only projection. ADR 0002
exists because two discovery stacks had diverged.
**Public API snapshots.** `rookie-rs/public-api/` holds checked text snapshots per OS per feature set
(`windows-all-features.txt`, `linux-no-default-features.txt`, …) plus `deprecated-items.json`. API drift
fails CI.
**AV status, documented.** README §Security: the unprivileged `v20` path "reflectively injects into a
spawned browser process — the same shape real infostealers use"; engines have flagged the native module
(`Trojan:Win64/InfoStealer!AMTB`), silently deleting `rookie_cookies.pyd` / `rookie-cookies.node`.
`docs/troubleshooting.md` gains a `Get-MpThreatDetection` diagnostic. Opt-out exists:
`AppBoundPolicy::Disabled`, `app_bound="disabled"`, `--app-bound disabled`. Note the default: injection is
**on**. **Testing.** 34 real-browser CI combinations, 3 fuzz targets, scheduled OSV scans, a live Windows
ABE canary against Chrome/Edge/Brave; deadline- and cancellation-supervised key retrieval on every platform.

### xaitax/Chrome-App-Bound-Encryption-Decryption (ChromElevator)
C++ with x86-64 asm, MIT, Win x64/ARM64. The reference injection implementation and the source of most
shared field knowledge. Technique: direct syscalls resolved at runtime by Hell's Gate with DJB2 hash
matching (no plaintext `Nt*` names); `CREATE_SUSPENDED` host; `NtAllocateVirtualMemory` /
`NtWriteVirtualMemory` / `NtProtectVirtualMemory` / `NtCreateThreadEx`; ChaCha20-encrypted payload DLL
embedded at compile time; reflective loader that destroys PE headers; named-pipe IPC; payload then calls
`IElevator2`/`IElevator`/`IEdgeElevatorFinal`/`IAvastElevator` from inside the trusted process. The
original browser main thread is never resumed. Two things matter more than the evasion detail: it tracks
the COM interface per vendor and per version as a table (Chrome 144 `IElevator2` with `RunIsolatedChrome`
and `AcceptInvitation`; Avast `IElevatorChrome` with a 12-method vtable and `DecryptData` at offset 104),
and it ships `comrade_abe.py`, a dynamic COM analyser that enumerates registry services, loads the type
library, heuristically matches the ABE signature and emits C++ stubs — discovery instead of hardcoding.

### runassu/chrome_v20_decryption
Single Python script, no licence. The most informative README in the set: the only place the crypto drift
is written as a sequence with byte layouts — double DPAPI unwrap, then `path` + flag `0x01` + 12-byte IV +
32-byte ciphertext + 16-byte tag, the hardcoded AES-256-GCM key at `0x01455184`, and the resulting 32-byte
key that behaves exactly like a v10 `encrypted_key`. Requires administrator, no injection, no COM. This is
the second acquisition route, and the reason "v20" must not be modelled as synonymous with "injection".

### internetangel/ZeroCrumb
C++, MIT, Windows. Transacted hollowing (hasherezade's technique) so the elevator call comes from a
legitimate image; the decrypted key is handed back over a named pipe — deliberately process-external
transport, which is a cleaner boundary than most of the set. Ships `CookieReader`/`PasswordReader` over
sqlite3 + libsodium (Vcpkg). Its README is the most honest about detection: "by no means the most stealthy
implementation … can get detected by checking for specific strings, hooking APIs"; passed Defender at
writing time, no other engine tested. Known bug: debug builds emit the wrong key.

### norahc-x/Margaret-Stealer
C + asm, position-independent x64 shellcode, MinGW cross-built. Not an ABE project — it never touches
DPAPI or a key. It locates the `CookieMonster` vtable and Chrome's `crypto::ProcessBound<std::string>::value()`
de-obfuscator by two compiler invariants: the method-name string `CookieMonster::GetCookieListWithOptionsAsync`
(string → code reference → function → fixed vtable slot), and the canonical three-instruction value-read
shape with register wildcards. Then it calibrates every cookie field offset from live bytes by
cross-instance majority vote and fails closed with `UNSUPPORTED_BUILD`. The most transferable lesson is in
its tested-builds table: a `.57`→`.58` auto-update kept an identical image size and shifted code, so a
pinned RVA landed mid-instruction; per-build pinning was abandoned. Also accepts one leaked `std::string`
per long value and documents a deadlock risk when the hijacked thread holds the per-process key lock.

### mendacus/chrome-abe-decryption-bof
C++, MIT, Cobalt Strike. A thin packaging of xaitax's work into a BOF plus a standalone `decryptor.exe`
taking `--key <hex>` and SQLite paths, emitting CSV. Architecturally it is the cleanest statement of the
split the ecosystem keeps blurring: the BOF produces **a key**, the decryptor consumes **a key plus
files**, with a hex string between them. Chrome-only, profile-hardcoded, must target the parent `chrome.exe`.

### AlessandroZ/LaZagne
Python, LGPL-3.0, ~11.1k stars, widest credential surface here (browsers, chats, mail, sysadmin, wifi,
DPAPI vaults, LSA secrets). Browser coverage is a long table of Chromium forks plus Firefox on three OSes;
modules are per-software scripts under `lazagne/`; output txt/json/all with `-quiet`; also a pupy
post-exploitation module, so the Python runs in memory. No v20/ABE handling documented. Relevance is
structural: proof that a per-application module registry scales to hundreds of targets, and the reason to
keep our registry data-driven. The LGPL is the reason not to copy anything.

### djhohnstein/SharpChrome
C# .NET 4.0+, ~765 stars, no licence, last commit 2020 — pre-ABE, v80-era BCrypt via P/Invoke. Cookies as
JSON in Cookie-Editor import format, history with matching cookies, logins. Notable for the .NET side: it
embeds a managed SQLite parser (`plainprogrammer/csharp-sqlite`) instead of reflecting in a native DLL, and
documents its own bug — `System.Byte[]` columns cast to the literal string `"System.Byte[]"`, worked around
by base64-encoding every blob. Today a v10-era artefact.

### 0rcruxe/chrome-abe-offline-decrypt
Python 3.10+, no licence, one commit. Fully offline: no live Chrome, no COM, no injection. Walks SYSTEM
DPAPI userkey → SYSTEM masterkey → KSP key blob → `blob1` → `blob2` → derivation from the content flag
(1, 2 or 3), then decrypts `Login Data`, `Cookies`, `Web Data` (cards, CVC, IBANs). Has `--info`, a
read-only mode that reports which encryption version protects each entry without decrypting — the only
project treating "what protects this row" as a first-class query. README references
`THIRD_PARTY_LICENSES.txt` and says part of the C++ is adapted from xaitax (MIT), but that file 404s at
`HEAD` and no licence file exists. [UNVERIFIED]

### Majanito/ABE-Decryption
Python + C++ DLL compiled by `builder.py` and base64-embedded into `build/injector.py`; MIT. Flow: locate
install path, spawn suspended, deterministic pipe name, decode DLL to temp, `LoadLibraryA`, send the ABE
key in, receive the decrypted key, terminate the suspended process, copy cookie DBs, decrypt, write
Netscape-format `cookies/{BROWSER}_{PROFILE}_cookies.txt`. Tested on Chromium 144, Chrome/Brave/Edge, no
admin. README is the most explicit about what it is not: no EDR evasion, unencrypted DLL on disk,
high-level APIs only, and it kills the browser — "very obvious to the user what is happening".

## 3. The dumpkeys/archive model and why v20 kills it

**The model in its own terms** — three commands, two transportable artefacts: `dumpkeys` → `keys.json`,
`archive` → `browser-data.zip` (only the files a restore needs), `restore --keys --data-zip`. `keys.json`
is a real struct, not a bag:

```
KeyFile { version:"2", created_at, host{os,arch,hostname?,user?}, vaults:[Vault] }
Vault   { browser, id?, kind, user_data_dir, profiles[], keys: Set }
Set     = map["v10"|"v11"|"v12"|"v20"] -> bytes   (JSON object, base64 values)
```

Three decisions worth stealing outright. `Vault.Kind` names the **on-disk format**, so `restore` parses a
vault for a browser absent from the analyst host — the README makes this the headline (decrypt Sogou or QQ
data on macOS). `ReadKeyFile` **rejects** a version it cannot interpret, on the stated grounds that "a
silent misparse is worse than an error". `Vault.ID` appears only for a second user data dir, so the common
case stays a bare browser name.

Retrieval is `keyRetriever { Version(); Retrieve(ctx, Locator) ([]byte, error) }` collected by
`RetrieveAll`, which keeps the first key per version and **never discards a working version because another
failed**. `errNotApplicable` is a sentinel distinct from failure, so a Windows-only retriever does not
pollute the error list on Linux. `Retrieval{Keys, Err}` carries both; `buildKeyFile` logs `partial` vs
`failed` and omits a directory with no keys. `restore` maps `UserDataDirID → Set`; a directory the file
lacks gets no keys, so its encrypted values stay empty instead of erroring the run.

**What actually broke.** The model has two halves that failed differently.

*Transport still works.* A v20 blob is AES-256-GCM under a 32-byte key with a 32-byte nonce, and the
plaintext begins with `SHA256(host_key)`. Once the key is in hand, v20 rows open anywhere, in any
language. Nothing platform-bound is needed on the analyst side, and HBD's design reflects that correctly.

*Derivation broke.* In the v10/v11 world the key was a file operation: read `Local State`,
`CryptUnprotectData`, done — silent, same user, no code in another process. For v20 the wrap's DPAPI
master key is not in the user's Protect store (this corpus measured that ABE's wall is account scope, not
cryptography). No file operation yields the key. There are exactly two routes:

| Route | Cost | Projects |
|---|---|---|
| in-context COM (`IElevator` from a browser-identity process) | injection/hollowing; AV-shaped; needs a payload | xaitax, ZeroCrumb, Majanito, mendacus, HBD's `internal/abe` |
| offline double DPAPI + CNG/KSP | administrator/SYSTEM; needs the origin's DPAPI material | runassu, 0rcruxe |

So the accurate statement is **`dumpkeys` did not stop working, it stopped being passive.** On Chrome
127+ the origin step is an injection or an elevation. On a standard cross-platform build with no ABE
payload, `dumpkeys` emits v10/v11 entries and nothing for `v20`, and the archive's `v20` rows become
undecryptable on the analyst side — exactly what HBD's README footnote says: ABE cookie decryption on
Windows "requires the App-Bound Encryption payload built via `make build-windows`". `rookie-cookies`
independently calls HBD's ABE support "partial — reflective-injection route; 133+ flag-3 elevated fallback
unconfirmed", checked against source on 2026-08-22; HBD has since shipped `fix(abe): update Edge elevator
IIDs for Edge 157` (2026-11-17), so treat that as dated. [COMMUNITY]

Consequence for our README: "cross-host extraction died in 2024" is true of the *silent* variant and false
of the *key-file* variant. The precise claim is "cross-host without code execution in the origin account
died". That distinction belongs in the coverage matrix — it is the difference between telling a user
"impossible" and "possible, here is what it costs". Two more version facts a format doc should carry: `v12`
exists (Linux XDG-portal app-id keys, added 2026-11-20), and Edge 157 rotated its elevation COM interface
and deregistered the old IIDs, so `v20` failed with `E_NOINTERFACE` until `IElevator3Edge` was added and
tried newest-to-oldest. [SOURCE, commit log]

## 4. Architecture lessons for our library

**4.1 Return capability, not just `Result`.** `Result<Vec<u8>>` collapses three independent facts into one
bit: the value was produced, how, and whether the caller would want to know. Both mature projects refuse
that collapse — HBD with `Retrieval{Keys, Err}` plus `partial`/`failed`, rookie with `ExtractionReport` +
typed issues + `declared`/`available`. Take the article's `Decrypted` and add the second axis:

```rust
pub struct Opened { pub value: Vec<u8>, pub via: Route, pub ceiling: Ceiling }

pub enum Route {            // was code injected?
    Plain,                  // v10/v11: a file operation, no other process touched
    AbeOffline,             // v20 via SYSTEM+user DPAPI / CNG — admin on the origin
    AbeInContext,           // v20 via IElevator from a browser-identity process
    AbeInProcessMemory,     // no key at all; read from a live process (Margaret's shape)
}
pub enum Ceiling { CrossHost, ThisHost, ThisSession }   // does this value survive a copy?
```

`Route` answers "was code injected", the fact that turns an incident into a log line. `Ceiling` answers
"does this survive a copy", the fact a user needs before building a pipeline. They vary independently:
Edge 158 ships ABE and still writes `v10`, so `Route::Plain` coexists with `Ceiling::CrossHost` on a
machine that has ABE. Do **not** put the tier in a type parameter — every project using compile-time state
here (rookie's stage types) uses it for *internal* discipline and exposes plain structs at the edge. Copy
that: typestate inside, data outside.

**4.2 Error taxonomy with stable codes, not `Display` strings.** Adopt rookie's rule verbatim: one JSON
object with exactly `code` and `message`; branch on `code`; `message` may change. Codes this domain needs,
each a distinct caller decision: `NotPresent` (nothing to do, not an error), `Locked` (retry with the
browser closed or snapshot), `AccessDenied` (needs elevation), `KeyUnavailable` (the wrap exists, no route
opened it), `RouteUnavailable` (injection/elevation disabled by policy), `UnsupportedVersion` (format
moved, library stale), `DecryptFailed` (key present, bytes wrong — usually the wrong key for the row),
`BlockedByAv`, `Cancelled`, `Timeout`. `BlockedByAv` is not a joke: `rookie-cookies` documents Defender
deleting its native module and notes this "looks like v20 extraction failing rather than an AV issue". A
library that cannot say that will spend its issue tracker on it. `UnsupportedVersion` matters too —
Margaret's answer to an unrecognised build is `UNSUPPORTED_BUILD`, never a best-effort guess.

**4.3 The platform backend is a small trait with a "not applicable" sentinel.** HBD's shape, copied
conceptually: `KeySource { version(); retrieve(ctx, loc) -> Result<Vec<u8>, RetrieveError> }` with
`RetrieveError::NotApplicable | Failed`. Four rules fall out of it. `NotApplicable` is not a failure,
otherwise every Linux run reports Windows failures. One `Locator` struct carries every OS's fields, each
commented with which OS reads it — ugly and correct; an enum per OS multiplies the trait. Collect all
sources for a version, keep the first that works, join the errors of the rest. Fetch per **scope**, not
per record: per data directory for Chromium keys, per profile for Firefox, per run for the login keychain
— HBD states the tradeoff, that a run asking only for history must never prompt. Add deadline and
cancellation to every source on day one; every script in the set shells out to `security` / `secret-tool`
/ `kwallet-query` per lookup with no timeout.

**4.4 Snapshot-first, and the lock is the real enemy.** This corpus measured that a running Brave opens
`Network/Cookies` with share mode 0 — `WinError 32` on copy, even with the WAL, 19 processes running.
Every tool here either kills the browser (`Majanito`, `xaitax --kill`) or duplicates handles (`xaitax`
via syscalls; HBD's snapshot capture). Take HBD's rule: **no parser reads a live profile.** Copy to a
private temp root, parse the copy, delete on every exit path including Ctrl-C. Benefits beyond locking:
every parser becomes testable against a fixture instead of a browser, and "the file vanished since
planning" becomes `NotPresent` for the affected extractions only while the run continues. Document the
alternative we will not ship in v1: VSS needs administrator and changes the privilege story entirely.

**4.5 Registry as data, everything else derived.** `browser_registry.json` is the only hand-maintained
source; `CONFIG` is a projection. ADR 0002 exists because two discovery stacks diverged. For us: one table
of browser definitions (name, engine, install roots per OS, profile layout, key location, ABE dialect,
declared tiers) consumed by code, never duplicated. The per-vendor ABE dialect (`ChromeBase`/`Edge`/`Avast`)
is a field, not a branch in a function.

**4.6 Binding layer: one core, thin edges, checked API surface.** rookie's layering is the template — Rust
core owns discovery, acquisition, decryption, projection; PyO3 and napi-rs only translate types; one shared
test suite; the CLI is a third consumer; `public-api/*.txt` snapshots per OS per feature set checked in CI.
For us: keep `Result` at the Rust boundary, expose the structured report to Python/Node as a plain
object/dict because both will want to log it, and do not make a `jar`-style sugar projection the primary
API — rookie already regrets it and has scheduled the break.

**4.7 Policy knob for the invasive route, default off.** rookie defaults injection **on** with an opt-out.
For a library other applications embed, invert it: default `AbeInContext` to disabled, require explicit
`allow_injection(true)`, report `RouteUnavailable` instead of silently degrading. The capability value then
tells the truth without the caller reading a changelog.

**4.8 What to avoid.** *Pinned offsets* — Margaret's `.57`→`.58` shift landed an RVA mid-instruction; the
answer is `xaitax`'s: discover the interface (`comrade_abe.py`) instead of tabulating IIDs. *Per-build
tables* — same lesson. *A single success boolean* — see 4.1. *Hardcoded crypto keys* — `runassu` embeds the
`elevation_service.exe` AES key and the 133+ ChaCha20 key; correct for a script, unacceptable in a
redistributable library, because it goes stale silently and is a legal liability. Model it as a
version-keyed table that fails loudly. *CLI-shaped internals* — HBD is excellent at its job and unusable as
a dependency; our core must not know what a flag is. *Silent row drops* — rookie notes a competitor's
`cookies.py` "failed rows silently dropped", and HBD's own history has a commit fixing exactly that ("a row
that failed to scan was logged at debug and dropped, so it never counted toward partial"). Every dropped
row must reach a counter.

## 5. Licence compatibility

Verified by fetching each repository's licence file at `HEAD`.

| Project | Licence | Copy into an MIT/Apache Rust crate? |
|---|---|---|
| HackBrowserData | MIT (© 2020 moond4rk) | yes, with notice |
| rookie-cookies | MIT (© 2023-2024 thewh1teagle and others) | yes, with notice |
| ChromElevator | MIT | yes, with notice |
| ZeroCrumb | MIT (© 2025 dk0m) | yes, with notice |
| chrome-abe-decryption-bof | MIT | yes, with notice |
| Majanito/ABE-Decryption | MIT (© 2025 Majanito) | yes, with notice |
| LaZagne | **LGPL-3.0** | no |
| SharpChrome | none declared | no |
| Margaret-Stealer | none declared | no |
| chrome_v20_decryption | none declared | no |
| chrome-abe-offline-decrypt | none declared | no |

**GPL family:** LaZagne only, and it is LGPL-3.0, not GPL. LGPL permits linking but imposes relink and
notice obligations on the combined work — a poor fit for a Rust crate statically linked into Python and
Node extension modules. Do not copy from it. Reading it for module-registry structure is fine; structure
and ideas are not copyrightable, expression is.

**No licence declared** means all rights reserved by default: read for technique, copy nothing. That bites
in two places. `Margaret-Stealer` holds the in-memory `CookieMonster` route — if we implement it, it must
come from our own analysis of the binary. `chrome-abe-offline-decrypt` holds the clearest offline v20
chain, but the chain is also documented in Chromium's own `elevator.cc` and in xaitax's MIT notes, so the
*route* is reachable through permissive material while their code is not. `chrome_v20_decryption`'s README
is the only written record of the 133/137/157 drift — facts are not copyrightable, prose is; cite, do not
paste. That repo's referenced `THIRD_PARTY_LICENSES.txt` returns 404 at `HEAD`, so its derived portions
trace to xaitax's MIT while the repository itself declares nothing. [UNVERIFIED]
**Practical rule:** MIT for the crate, a `NOTICE` naming the six MIT projects whose *technique
descriptions* informed the design, and zero copied source in v1. Attribution costs nothing and this corpus
is CC BY 4.0 anyway.

## 6. What none of them do well

1. **Nobody publishes format knowledge separately from the acquirer.** HBD separates them internally and
   ships a CLI; `runassu` documents the drift and ships a script. No artefact says "here is v20's byte
   layout, here are its test vectors, here is what changed in 137 and 157" and can be depended on.
2. **Nobody returns per-value provenance.** rookie gets closest, at report level; no project says of a
   single row "this came from a v20 blob opened by an injected process".
3. **Nobody states the Edge state.** This corpus measured Edge 158 carrying `app_bound_encrypted_key` and
   still writing `v10` for 197/197 cookies and 183/183 passwords. HBD knows Edge has a different elevator
   dialect; no coverage matrix distinguishes "ABE present" from "ABE engaged".
4. **Nobody solves the live lock without privilege or killing the browser.** Handle duplication and VSS are
   the only two answers in the set, and only the first is implemented.
5. **Nobody treats the version treadmill as a published CI obligation.** rookie runs 34 real-browser
   combinations, the right shape; no project publishes "which Chrome version did we last verify, and when".
6. **Nobody offers a capability-query-only mode across the board.** `0rcruxe --info` and `rookie-cookies report` do it for their own scope; nothing answers "what can be opened on this machine right now, for every browser, without touching a value" as a first-class API.
7. **Nobody exposes an embedding contract.** One project of eleven has bindings. The rest are binaries or scripts, so every consumer reimplements the format layer — which is why the same `SHA256(host_key)` prefix bug keeps being rediscovered.

## 7. Open questions

- Does `dumpkeys` in a **release** build reach the ABE payload, or only a `make build-windows` build? The path is `machineKeys` → `chromium.KeyLocator` → `RetrieveAll`, with ABE retrievers in `internal/masterkey/abe_windows.go`, but whether the payload is embedded in the standard artefact is unconfirmed. [UNVERIFIED]
- Does the 133+ flag-3 elevated fallback work at medium integrity? rookie says "elevated", `runassu` says "run as administrator", `0rcruxe` needs SYSTEM DPAPI material — three sources, no shared measurement.
- What is Edge's `IElevator3Edge` rotation cadence? 157 deregistered the old IIDs; if that happens per major, a registry-driven dialect table needs a version range, not a constant.
- `v12` portal keys (Linux XDG portal app-id): does that change our Linux model, which assumes `peanuts` / libsecret / KWallet only?
- Does the in-memory `CookieMonster` route belong in a library's `Route` enum, or is it a separate product? It needs no key, survives DBSC, and carries the heaviest detection cost.
- Can any of the four unlicensed repos be asked for a licence? Worth one issue each before anyone reimplements their work from scratch.

## 8. Sources

`article/en.md` §6 (coverage matrix), §7 (where it dies), §8 (capability tiers), §11 (references); `README.md`
(measured table, scripts, scope); all eleven READMEs at `raw.githubusercontent.com/<owner>/<repo>/HEAD/README.md`.

Source files read — `moonD4rk/HackBrowserData`: `rfcs/003-secrets.md`, `rfcs/004-snapshots.md`,
`internal/masterkey/keyfile.go`, `internal/masterkey/masterkey.go`, `internal/app/dumpkeys.go`,
`internal/app/masterkeys.go`, `LICENSE`. `teng-lin/rookie-cookies`: `docs/architecture.md` (121 KB),
`LICENSE.md`, `docs/adr/0001`–`0005`, `rookie-rs/public-api/*` (listing). Licences:
`AlessandroZ/LaZagne/LICENSE`, `internetangel/ZeroCrumb/LICENSE`, `Majanito/ABE-Decryption/LICENSE`.
Commit feeds (`github.com/<repo>/commits/HEAD.atom`) for last-activity dates, read 2026-11-25.

## Confidence

| Claim | Basis |
|---|---|
| Licence of the 7 declared projects | **SOURCE** — licence file fetched |
| Absence of licence in 4 projects | **SOURCE** — `LICENSE`/`.md`/`.txt`/`COPYING` all 404; GitHub sidebar shows no licence |
| `keys.json` structure and `keyRetriever` trait | **SOURCE** — read `keyfile.go`, `masterkey.go` |
| dumpkeys/archive/restore split, snapshot-first rule | **SOURCE** — read `dumpkeys.go`, `rfcs/004` |
| rookie-cookies API surface, error codes, AV note | **SOURCE** — README + `docs/architecture.md` |
| HBD ABE support "partial", 133+ fallback unconfirmed | **COMMUNITY** — rookie's comparison table, dated 2026-08-22 |
| HBD's ABE payload absent from the standard build | **SOURCE** for the README footnote; **UNVERIFIED** for release artefacts |
| dumpkeys reaches ABE retrievers | **INFERRED** from `masterkeys.go` + `abe_windows.go` existing; not executed |
| "Cross-host died" needs the qualifier "without code execution" | **INFERRED** from §3 + this corpus §7.1 |
| Star counts and last-commit dates | **SOURCE** — repo pages and commit feeds, 2026-11-25 |
| Technique summaries for xaitax / ZeroCrumb / Margaret / Majanito | **SOURCE** — their READMEs; not verified against their source |
