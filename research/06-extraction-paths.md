# Extraction Without Decryption — Isolated Reference

Scope: obtaining cookie/state data from a Chromium-family browser **without** unwrapping a `v10`/`v20` blob.
Every route below leaves the ciphertext untouched and asks a different party for the plaintext. Tags:
**MEASURED** = reproduced on the reference machine (Windows 11, Brave 158 running, medium IL, admin group
enabled but not elevated). **DOCUMENTED** = vendor/protocol docs state it. **REASONED** = follows from
documented primitives, not observed here. **UNVERIFIED** = plausible, unconfirmed.

## Ozet (TR)

Şifre çözmeden veri almanın üç ailesi var: tarayıcıya sormak (CDP), kopyasını çalıştırıp sormak (profil
replay), dosyayı tarayıcıya dokunmadan almak (VSS, kapanmış profil). ABE yalnızca *anahtarın kimde durduğunu*
sınırlar; çalışan bir tarayıcıdan düz metni kimin okuyabileceğine dair hiçbir şey söylemez, bu yüzden CDP
bütün kripto katmanını atlar. Windows'ta asıl duvar kripto değil `CreateFile` paylaşım modudur: Brave açıkken
`Network/Cookies` share mode 0 ile tutuluyor ve hata 32'yi ne yönetici, ne `SeBackupPrivilege`, ne
`FILE_FLAG_BACKUP_SEMANTICS` aşar — ayrıcalık güvenlik denetimini atlar, paylaşım kuralını atlamaz. Chrome 136+
`--remote-debugging-port` için varsayılan olmayan bir `--user-data-dir` şart koştuğu, kopya da kilitliyken
alınamadığı için pratikte kalan yol: düzgün kapat → kopyala → kopyayı kendi `--user-data-dir`'inde aç →
`Storage.getCookies`.

## 1. The principle

The corpus so far treats the problem as "get the AES key, then decrypt". That framing is what ABE killed.
There is a second framing it never touched:

> The plaintext exists, in memory, inside a process the user already controls. Decryption is only one way
> to reach it, and it is the *hardest* one.

| Family | Who produces the plaintext | Touches `encrypted_value`? |
|---|---|---|
| Ask the browser (CDP) | the browser, on request | never |
| Run a copy of the browser (profile replay) | the copy, using the copied key material | never (the copy decrypts its own store) |
| Read the file (VSS, closed profile) | you, offline | yes — you still need the key |

Only the third family needs OSCrypt knowledge. The first two are *authorisation* problems, not cryptography
problems, which is why ABE's coverage matrix says nothing about whether a cookie can be extracted from a
live session. Two honest limits up front: **CDP does not expose saved passwords** (there is no
`Passwords.getLogins`; every credential in `Login Data` still needs the `v20` path — cookies, localStorage,
IndexedDB, service-worker state and response bodies are reachable, the password vault is not), and **a
cookie is not a session** (replay works only where the server binds the session to the cookie alone; TLS
fingerprint, IP, UA and CSRF tokens all sit outside this document).

## 2. Chrome DevTools Protocol

### 2.1 Endpoints

CDP is a JSON-RPC-over-WebSocket protocol. Two transports:

| Flag | Transport | Reachable from another process |
|---|---|---|
| `--remote-debugging-port=N` | TCP on `127.0.0.1:N` | yes — that is the point and the problem |
| `--remote-debugging-address=A` | bind address for the above | yes, including off-host if set to `0.0.0.0` |
| `--remote-debugging-pipe` | fd 3 (in) / 4 (out), NUL-delimited JSON | no — only the parent that owns the pipes |

HTTP discovery on the TCP transport (**DOCUMENTED**, shape stable for years):

```bash
curl -s http://127.0.0.1:9222/json/version   # Browser, Protocol-Version, User-Agent, V8/WebKit-Version,
                                             #   webSocketDebuggerUrl: ws://.../devtools/browser/<uuid>
curl -s http://127.0.0.1:9222/json/list      # [{id,type,title,url,webSocketDebuggerUrl,...}]
curl -s http://127.0.0.1:9222/json/protocol  # full schema == published browser_protocol.json
```

Also `PUT /json/new?url=...`, `GET /json/activate/<id>`, `GET /json/close/<id>`. Two consequences: the
**browser** endpoint (`/devtools/browser/<uuid>`) and the **page** endpoints are different sessions with
different domain availability, so store-wide cookie commands belong on the browser endpoint; and
`webSocketDebuggerUrl` is returned unauthenticated, so anything that can reach the port enumerates the whole
profile, including the origin of every open tab. **Port discovery without the port:** with port `0` the
browser picks an ephemeral one and writes `<user-data-dir>/DevToolsActivePort` (line 1 the port, line 2 the
browser WS path), which is how Puppeteer finds it. **MEASURED**: no such file in the live Brave profile — it
only exists for an instance launched with debugging on, which makes its absence a useful negative signal.

**`--remote-debugging-pipe` is not an extraction route.** Better for automation (no port, no origin checks, no
listening socket), useless here: the pipe handles are inherited by the child and nothing external can attach.
Documented so nobody spends an evening on it.

### 2.2 Cookie APIs

All names and parameters below are read from the published `browser_protocol.json`, not from memory.

| Command | Target | Parameters | Returns | Notes |
|---|---|---|---|---|
| `Network.getAllCookies` | page session (historically) | none | `cookies[]` | **deprecated** in the schema; "Use Storage.getCookies instead" |
| `Network.getCookies` | page session | `urls?: string[]` | `cookies[]` | scoped to URLs; defaults to the page and its subframes |
| `Storage.getCookies` | **browser** session | `browserContextId?: string` | `cookies[]` | whole cookie store; `browserContextId` "when called on the browser endpoint" |
| `Network.setCookie` | page session | `name, value, url?, domain?, path?, secure?, httpOnly?, sameSite?, expires?, priority?, sourceScheme?, sourcePort?, partitionKey?, partitionKeyOpaque?` | `success: bool` | one cookie; `success:false` is silent rejection |
| `Network.setCookies` | page session | `cookies: CookieParam[]` | — | batch |
| `Storage.setCookies` | **browser** session | `cookies: CookieParam[], browserContextId?` | — | batch, store-wide |

`Cookie` fields returned: `name, value, domain, path, expires, size, httpOnly, secure, session, sameSite?,
priority, sourceScheme, sourcePort, partitionKey?, partitionKeyOpaque?`. `expires` is epoch **seconds**,
`-1` when unset, `null` when ±Inf cannot be represented in JSON. `sameSite` is `Strict|Lax|None`.
`partitionKey` is `{topLevelSite, hasCrossSiteAncestor}` — present only for CHIPS-partitioned cookies.

**"Which domain permission is needed?" — none.** This is the whole answer and the whole problem. There is
no per-origin authorisation in CDP. `Storage.getCookies` has no `domain` parameter; it returns every cookie in
the profile, including `HttpOnly` ones that `document.cookie` can never see. The authorisation boundary is
"can you open a WebSocket to this port", not "which site are you". A page-context script therefore can never
do this (no `HttpOnly` access, no same-origin bypass), while any local process that reaches the port gets the
entire store on the first call. `Network.getCookies` is the only command with domain-ish scoping and it is a
*filter*, not a permission: you pass `urls` and it returns what would be sent to them — it narrows a query, it
cannot restrict what a client may ask for. Prefer `Storage.getCookies` on the browser endpoint;
`Network.getAllCookies` still works in many builds but is flagged deprecated and its page-session placement
has been inconsistent. **UNVERIFIED**: whether current Brave rejects it outright or only warns.

### 2.3 Launch flags and their restrictions

| Flag | Effect | Restriction |
|---|---|---|
| `--remote-debugging-port=N` | TCP endpoint | Chrome 136+: ignored for the default data dir |
| `--remote-debugging-pipe` | fd 3/4 endpoint | same restriction since 136 |
| `--user-data-dir=PATH` | profile root | now mandatory (non-default) whenever a debugging flag is used |
| `--remote-debugging-address=A` | bind address | default loopback; `0.0.0.0` exposes the store to the LAN |
| `--remote-allow-origins=...` | WebSocket `Origin` allowlist | introduced after the 2023 "web page drives your debug port" issues; native clients send no `Origin` and are unaffected |
| `--headless=new`, `--no-first-run`, `--no-default-browser-check` | no window, skip first-run UI | needed for a clean copied profile |

**The Chrome 136 change, verbatim from the source that matters** (Chrome security blog, Will Harris,
2025-03-17):

> "from Chrome 136 we're making changes to the behavior of `--remote-debugging-port` and
> `--remote-debugging-pipe`. These switches will no longer be respected if attempting to debug the default
> Chrome data directory. These switches must now be accompanied by the `--user-data-dir` switch to point to
> a non-standard directory. A non-standard data directory uses a different encryption key meaning Chrome's
> data is now protected from attackers."

Read carefully, the wording is easy to over-read. It does **not** remove the switch; it removes the ability
to point it at *the live default profile*. And "a non-standard data directory uses a different encryption key"
describes what happens when that directory is *empty* — fresh key material is generated there. A directory
that already contains a copied `Local State` keeps that file's key. The protection is therefore "you cannot
debug the live session", not "copied key material stops working". Both transports are covered, so
`--remote-debugging-pipe` buys nothing here.

Whether Brave and Edge inherited this verbatim: **UNVERIFIED** — Brave is a Chromium downstream and inherits
the patch series but ships its own profile defaults; Edge has its own policy surface and usually follows a
milestone later. Enterprise kill switch: a `RemoteDebuggingAllowed` policy (default true, version
**UNVERIFIED**) closes the whole CDP family by configuration if set false.

Detection surface: a new process with a debugging flag in its command line, a listening loopback socket, and
a non-default `--user-data-dir` on disk. All three are trivially visible to EDR and to any user-level
monitor. Highest-signal route in the table.

## 3. Profile replay

The chain, and where each link breaks.

```
[1] copy profile (Local State + Default/ + Network/*)
       └─ breaks: browser running, share mode 0 → WinError 32   ← MEASURED
[2] launch a second Chromium: --user-data-dir=<copy> --remote-debugging-port=0
       └─ breaks: stale SingletonLock in the copy (harmless, Chromium clears it)
       └─ 136+ needs a non-default dir → satisfied by definition
[3] read <copy>/DevToolsActivePort → port + browser ws path
[4] WebSocket to browser endpoint → Storage.getCookies
[5] Browser.close
```

**Step 1 is the only hard one.** What must travel:

| Path | Why |
|---|---|
| `Local State` | `os_crypt.encrypted_key`, `app_bound_encrypted_key`; without it the copy cannot read its own store |
| `Default/Network/Cookies` + `-wal`, `-shm`, `Cookies-journal` | the rows plus uncheckpointed state — omit the sidecars and the newest cookies are simply absent |
| `Default/Preferences`, `Secure Preferences` | profile identity, policy state, per-profile feature flags |
| `Default/Local Storage/leveldb`, `IndexedDB/` | not cookies, but most of the session state that survives |

Two facts make the replay work at all. **The ABE key is bound to the account and the install path, not to the
user-data dir**: same machine, same user, same browser binary directory → the `v20` unwrap still succeeds
inside the copy (**REASONED** from `01-dpapi.md`, not measured). And **cross-machine replay still dies**: the
`v20` wrap's DPAPI master key lives in another account's context, so copying `Local State` to a different host
reproduces §7.1 of the main article exactly.

**The ordering trap.** "Copy while it runs, then close it" captures a WAL mid-write: the `-wal` may hold a
half-applied transaction and the copy will fail or silently roll back on first open. Correct order is
close → wait for handle release → copy → launch.

## 4. File locking reality

### Windows

Sharing is enforced by the I/O manager at `CreateFile` time, independent of ACLs. From the `CreateFileW`
reference:

> `[in] dwShareMode` — "If this parameter is zero and **CreateFile** succeeds, the file or device cannot be
> shared and cannot be opened again until the handle to the file or device is closed." … zero "Prevents
> subsequent open operations on a file or device if they request delete, read, or write access."

The other three values are `FILE_SHARE_READ (0x1)`, `FILE_SHARE_WRITE (0x2)`, `FILE_SHARE_DELETE (0x4)`. A
share mode of 0 is the strictest possible posture: the holder has declared that *no* second handle may exist,
for any access, including delete and rename.

**MEASURED on the reference machine** (Brave 158 running, 19 processes):

| Attempt | Result |
|---|---|
| `shutil.copy2(Network/Cookies)` | `WinError 32` (ERROR_SHARING_VIOLATION) |
| plain `open(path, 'rb')` | `PermissionError` — errno 13, mapped from the same sharing violation |
| `sqlite3.connect('file:...?mode=ro')` | cannot open; the VFS open is the same `CreateFile` |
| reading `-wal` | fails identically |
| `os.path.getsize` / `stat` | **succeeds** — directory metadata is not the file handle |

That last row is the tell: attributes and size are visible, contents are not. Any tool that "found" the file
and then reported "0 cookies" was reading metadata and inventing the rest.

What does **not** help, and why: **`FILE_FLAG_BACKUP_SEMANTICS`** exists to let a privileged process
"override file security checks when the process has SE_BACKUP_NAME and SE_RESTORE_NAME privileges" — security
checks are the ACL, sharing is a separate gate (the flag is also mandatory for opening a *directory* handle,
which is why it appears in every backup script and gets misattributed); **`SeBackupPrivilege` / running as
admin** is the same confusion, buying ACL bypass but not a second handle on a share-mode-0 file (this machine
has the admin group enabled without elevation, and the failure mode would not change if it were elevated);
**`FILE_SHARE_*` on your side** is meaningless, since sharing is the intersection of what the opener allowed
and what you requested and cannot be granted retroactively on someone else's handle.

What does work, in increasing order of intrusiveness: (1) close the browser (§7); (2) VSS (§5);
(3) **handle duplication — REASONED, untested**; (4) open the volume (`\\.\C:`) and parse NTFS directly;
(5) a minifilter, which is out of scope and the point where "documentation" becomes "malware".

Handle duplication deserves its own paragraph because it is the only unprivileged answer that is not "give
up". The browser runs as the same user at the same integrity level, so `OpenProcess(PROCESS_DUP_HANDLE)`
followed by `DuplicateHandle` on the browser's own `Cookies` handle yields a readable handle **without a new
`CreateFile`** — share modes are never consulted, because no open happens. It needs handle enumeration
(`NtQuerySystemInformation(SystemHandleInformation)`, `NtQueryObject` for names), which is also why it is the
loudest option: handle enumeration is a textbook EDR signature.

### macOS / Linux

There is no mandatory share mode. `open()`/`read()` succeed on a file another process holds open; POSIX
record locks (`fcntl(F_SETLK)`) and `flock()` are **advisory** — they constrain cooperating processes, not the
kernel. That is the biggest platform asymmetry here, and why live-profile copying is ordinary on Unix and
impossible on Windows. The problem moves from *access* to *consistency*:

- `Network/Cookies` is WAL-mode. A byte copy without `-wal` yields a valid but stale database — everything
  written since the last checkpoint is missing. **DOCUMENTED**, and the trap the main article flags in §2.
- Opening a WAL database read-only normally needs write access to `-shm`, because the reader maintains the
  WAL index.
- `file:Cookies?mode=ro&immutable=1` sidesteps that: `immutable=1` "skips all file locking and change
  detection". It also skips the WAL, so you get a pre-checkpoint snapshot. Convenient, quiet, wrong.
- `nolock=1` disables `xLock`/`xUnlock` and is documented as risking corruption if anything else writes; on a
  copy it is redundant with `immutable=1`.

So on Unix the sequence is copy-all-three-files *then* open the copy; on Windows the same sequence, but the
copy is the step that fails.

## 5. VSS and snapshot routes

A volume snapshot is a block-level freeze. The browser's share-mode-0 handle exists on the *live* volume only;
inside the snapshot the file is an ordinary file with no holder. This is why VSS is the canonical answer to
section 4 and why it costs administrator.

```powershell
# elevated only
vssadmin create shadow /for=C:
#   Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7
cmd /c mklink /d C:\snap \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7\
# read C:\snap\Users\<u>\AppData\Local\BraveSoftware\...\Network\Cookies
vssadmin delete shadows /shadow=<id> /quiet
# COM equivalent, preferred in code: structured IDs instead of stdout to parse
Get-CimInstance -ClassName Win32_ShadowCopy -MethodName Create -ArgumentList 'C:\', 'ClientAccessible'
# ShadowID -> Win32_ShadowCopy.DeviceObject: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7
```

Why it needs admin: shadow creation is a privileged operation the VSS service performs for a caller holding
backup privileges. No unprivileged equivalent exists, and no way to snapshot a single file — it is volume
granularity, which is also why the output is gigabytes of NTFS metadata you do not want.

**`robocopy /b` is not a substitute.** `/b` means backup mode: `FILE_FLAG_BACKUP_SEMANTICS` plus
`SeBackupPrivilege` so ACLs are bypassed. Sharing is untouched, so it fails on the same
`ERROR_SHARING_VIOLATION`. This is the most common wrong answer to "the file is locked", and it is wrong for
exactly the reason §4 gives. Detection: VSS writes event-log records on creation and deletion, and shadow
creation by a non-backup-looking process is a well-known ransomware precursor signal.

## 6. SQLite backup semantics

The online backup API and `VACUUM INTO` solve **consistency**, not **access**. Both must open the source
first, which means the same `CreateFile`, which means the same sharing violation.

- `sqlite3_open()` on a share-mode-0 file fails as `SQLITE_CANTOPEN`, not `SQLITE_BUSY`. There is no
  busy-handler retry for that — it is not a lock, it is a refusal.
- `VACUUM INTO 'out.db'` runs inside the source connection and inherits the same failure.
- Where the API earns its place: once the file *is* readable (Windows after close, Unix always),
  `sqlite3_backup_step()` produces a snapshot "bit-wise identical … as it was when the copying commenced", in
  bounded chunks, without holding a read lock for the whole copy. That fixes "my copy is missing the last
  session"; it cannot fix "the file will not open".
- Each step takes a read lock on the source; a mid-transaction writer returns `SQLITE_BUSY`/`SQLITE_LOCKED`,
  which the documented recipe handles by sleeping 250 ms and retrying. Against a browser rather than another
  SQLite client, retries can starve — a browser is not obligated to yield.

Also: `-journal`/`-wal` presence changes recovery. A copy of a hot-journal database triggers rollback on
first open, which can *delete* the rows you wanted — looking like data loss, actually correct recovery.

## 7. Browser shutdown strategies

| Method | Mechanism | Cookie state after | Notes |
|---|---|---|---|
| `Browser.close` over CDP | graceful, in-protocol | flushed | cleanest; also closes the replay instance |
| `taskkill /IM brave.exe` (no `/F`) | `WM_CLOSE` to top-level windows | flushed | may hang on a confirm-exit dialog |
| `Stop-Process` / `TerminateProcess` / `taskkill /F` | immediate | last flush window lost, `-wal` left hot | next start runs WAL recovery |
| power loss | — | up to the last periodic flush | the realistic worst case |

Chromium flushes the cookie store periodically (tens of seconds) and on graceful shutdown. Session cookies are
memory-only and never hit disk, so a graceful close does not preserve them either — another reason the CDP
route differs in kind: it reads session cookies no copy will ever contain.

Ordering rules: **close then copy**, never the reverse (§3); **wait for handle release** (process exit and
handle close are not simultaneous — poll until the copy succeeds, do not sleep a fixed interval); **prefer a
copy over a second instance**, since pointing a new browser at the live `--user-data-dir` triggers
`ProcessSingleton` handoff and the new process simply exits; **weigh the cost honestly** — VSS costs admin and
noise, a graceful close costs the user their tabs.

## 8. Session replay

**Path A — CDP (the only clean one).** Open the target instance, then:

```json
{"id":1,"method":"Storage.setCookies","params":{"cookies":[
  {"name":"sid","value":"...","domain":".example.com","path":"/",
   "secure":true,"httpOnly":true,"sameSite":"Lax","expires":1790000000}]}}
```

Field-by-field, what breaks when omitted:

| Field | Failure if wrong |
|---|---|
| `domain` | cookie lands host-only on the wrong host, or is rejected as non-matching |
| `path` | cookie invisible to the request you care about, no error anywhere |
| `secure` | `sameSite:"None"` without `secure:true` is rejected outright |
| `httpOnly` | replayed cookie becomes readable by page JS — a detection surface, not a failure |
| `expires` | epoch **seconds**; omit and you create a session cookie that dies with the instance |
| `partitionKey` | CHIPS cookie replayed unpartitioned is a *different* cookie; the site sees a logged-out user |
| `sourceScheme` / `sourcePort` | affects `Secure` scoping and port-scoped legacy cookies; `Unset` is documented as a temporary emulation aid |

Verify with a navigation, then read back the non-`HttpOnly` subset via `document.cookie`. Do not trust
`setCookie`'s `success:true` alone — batch APIs return nothing at all.

**Path B — profile injection.** Writing rows directly into `Cookies` is the tempting one and it is a trap:
since `meta` version 24 every row's plaintext is prefixed with `SHA256(host_key)` and the value column must be
a valid `v10`/`v20` blob. Injecting means encrypting, which means holding the key — the exact problem this
document exists to avoid. SQLite injection is therefore *not* a decryption-free path, and any tool advertising
it is quietly doing the crypto anyway.

**Beyond cookies, and the limits of replay.** `localStorage`, `sessionStorage` and IndexedDB carry most modern
session state and live in LevelDB with their own OSCrypt-protected values; CDP reaches them directly
(`DOMStorage.getDOMStorageItems`, `Storage.getStorageKeyForFrame`, `IndexedDB.requestDatabaseNames`), so the CDP
family covers strictly more state than the file family, again without touching a blob. But a cookie alone
authenticates only cookie-only sessions: with device binding you also need the UA
(`Network.setUserAgentOverride`), the client hints, and ideally the same egress IP. That is the boundary between
"extraction" and "impersonation", and where most replay attempts fail — not in the crypto.

## 9. Route comparison table

| Route | Privilege required | Works while browser runs | Skips ABE | Detection risk | Platform |
|---|---|---|---|---|---|
| CDP on a **fresh** instance (`--user-data-dir` empty) | user | n/a (it is its own instance) | yes, but there is nothing to read | high: flags in cmdline, listening port | all |
| CDP on the **live default** profile | user | yes, pre-136 only | yes | high | all; **dead on Chrome 136+** |
| CDP on a **copied** profile | user | yes, if the copy succeeded | yes | medium: second process, new dir | all |
| Profile replay (close → copy → relaunch) | user | no (browser closed) | yes (copy decrypts itself) | medium: file copy, new process | all; cross-host still dead |
| Live file copy, Windows | user | **no** — share mode 0 | no | low, because it fails | Windows |
| Live file copy, macOS/Linux | user | yes, with WAL caveats | no — needs the key | low | Unix |
| Handle duplication | user (same user, same IL) | yes | yes | high: handle enumeration | Windows |
| VSS snapshot + offline read | **admin** | yes | no — needs the key | high: VSS events | Windows |
| `robocopy /b` | admin (SeBackupPrivilege) | **no** — sharing is not an ACL | no | low, because it fails | Windows |
| SQLite backup API / `VACUUM INTO` | user | only if the file opens | no | low | all |
| In-process injection (hollowing, etc.) | user | yes | yes | highest — this is the AV-signature route | Windows |

Reading the table: the only rows that are simultaneously *unprivileged*, *reliable* and *ABE-free* are
CDP-on-a-copy and, on Windows, handle duplication. Everything else trades one of the three away.

## 10. Open questions

1. **Handle duplication.** Does `DuplicateHandle` on the browser's `Cookies` handle actually yield readable
   data, or does Chromium open it with flags that make the duplicate unusable? Untested, and the single most
   valuable unknown here.
2. **136 downstream and policy.** Does Brave 158 refuse a debugging flag on its default profile the way Chrome
   does? Does Edge? And is `RemoteDebuggingAllowed` the correct policy name, in which version? One command and
   one policy page would settle both.
3. **API status details.** Does current Brave still honour `Network.getAllCookies` (deprecated in the schema),
   and does `Storage.getCookies` on a page session error or merely scope to the store?
4. **ABE and the copied profile.** That a copied `Local State` still unwraps on the same machine is reasoned
   from path-binding, not measured. Copy the profile, launch, read one cookie — one test closes it. Likewise,
   confirm empirically that session cookies are absent after a graceful close rather than trusting the
   memory-only model.

## 11. Sources

| Source | Used for |
|---|---|
| `ChromeDevTools/devtools-protocol` → `json/browser_protocol.json` (v1.3, fetched 2026-11) | every command name, parameter list and `Cookie`/`CookieParam` field in §2.2 |
| Chrome security blog, "Changes to remote debugging in Chrome 136", Will Harris, 2025-03-17 | the 136 restriction, quoted verbatim in §2.3 |
| Microsoft Learn, `CreateFileW` (`fileapi.h`) | `dwShareMode` semantics, share mode 0, `FILE_FLAG_BACKUP_SEMANTICS`, `SeBackupPrivilege` wording |
| `sqlite.org/backup.html`, `uri.html`, `lang_vacuum.html` | backup guarantees, `mode=ro`/`immutable=1`/`nolock=1`, `VACUUM INTO` |
| Microsoft Learn, `Win32_ShadowCopy` / `vssadmin` | VSS creation path and privilege requirement |
| Local measurement, reference machine | Brave `Network/Cookies` lock behaviour, `DevToolsActivePort` absence, metadata vs. contents |

## Confidence

| Claim | Confidence |
|---|---|
| CDP command names, parameters, `Cookie` shape | **High** — read from the published schema |
| `Storage.getCookies` returns the whole store, HttpOnly included, no per-domain permission | **High** — no domain parameter exists in the schema; the only gate is endpoint access |
| Chrome 136 requires a non-default `--user-data-dir` for both debugging transports | **High** — vendor blog, quoted |
| Windows share mode 0 defeats copy, plain open, and SQLite open | **High** — measured twice on this machine |
| `SeBackupPrivilege` / `FILE_FLAG_BACKUP_SEMANTICS` do not defeat sharing | **High** — documented separation of ACL check and share check |
| Unix locks are advisory, so live copy succeeds; `immutable=1` silently returns stale data | **High** — POSIX and SQLite documentation; not measured here |
| Backup API cannot open a share-mode-0 file; VSS requires admin and solves the lock | **High** — same `CreateFile`; documented VSS privilege |
| ABE key survives a same-machine profile copy | **Medium** — reasoned from path/account binding, untested |
| Handle duplication works; Brave/Edge inherit the 136 restriction; `RemoteDebuggingAllowed` naming | **Low** — plausible, untested |
