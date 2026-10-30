# M1 — MAPI/HTTP, Autodiscover and Dovecot Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Revision 2 (2026-10-30).** The maintainer decided that new code is
written in Rust while the existing C core (libmapi, emsmdb, nspi, mapistore)
stays in C and keeps being fixed. Revision 1 planned a C daemon on
libmicrohttpd; its unfinished Task 1 is kept for reference only on the
`m1-mapihttp` branch (commit `139ee83a`, not to be merged). Task 0 and its
results are unchanged.

**Goal:** A Rust service on 127.0.0.1 behind nginx that serves Autodiscover POX with the `mapiHttp` Protocol element and the MAPI/HTTP mailbox endpoint (`/mapi/emsmdb`: Connect, Execute, Disconnect, NotificationWait, PING), verifies HTTP Basic credentials through Dovecot's auth socket, and hands ROP buffers to the existing C EMSMDB code through a narrow C API.

**Architecture:** New Cargo workspace at the repository root with one crate, `mapihttpd/`. HTTP, request validation, sessions, Dovecot authentication, MAPI/HTTP body framing and Autodiscover are safe Rust. The only C call path is a new library `liboc_emsmdb` with four functions that take and return plain byte buffers, strings and integers plus an opaque session handle (see "C boundary" below). All C calls run on one dedicated worker thread because `emsmdbp`/mapistore state is not documented as thread-safe.

**Tech Stack:** Rust 1.85 (Debian 13 `rustc`/`cargo`), tokio, hyper 1 + hyper-util, quick-xml, base64, hmac + sha2, getrandom; C, talloc and Samba NDR on the C side; autoconf/Make; GitHub Actions.

**Spec:** maintainer direction in [doc/MODERNIZATION.md, "Project direction (2026-10-30)"](../../doc/MODERNIZATION.md#project-direction-2026-10-30); normative protocol sources [MS-OXCMAPIHTTP] revision 15.0 (2025-05-20) and [MS-OXDSCLI] (release 2025-08-19), downloaded from Microsoft's Open Specifications site on 2026-10-30.

## Interface findings

Protocol (every line cites the specification section it relies on):

- Transport: HTTPS, HTTP/1.1, **POST only** for all requests (MS-OXCMAPIHTTP 2.1). The service sees plain HTTP from nginx on 127.0.0.1; TLS is nginx's job.
- Authentication methods listed: Basic, NTLM, Negotiate (MS-OXCMAPIHTTP 1.7). "All requests MUST be authenticated prior to being processed"; no anonymous requests (2.2.2; code 8 "Anonymous Not Allowed", 2.2.3.3.3). Only Basic is in scope.
- Required request headers: Host, X-RequestType, X-RequestId, Content-Type, Content-Length (2.2.2.1). `Content-Type: application/mapi-http` (2.2.2.1, 2.2.3.2.2).
- Response format: `200 OK` with X-RequestType, X-ResponseCode, X-RequestId, X-ServerApplication headers, then META-TAGS, ADDITIONAL HEADERS and RESPONSE BODY (2.2.2.2). Non-200 only for 401, 302 or exceptional 5xx (2.2.2.2, paragraph after the formats).
- Meta-tags `PROCESSING`, `PENDING`, `DONE` (2.2.7). Server MUST respond immediately with `PROCESSING`, send `PENDING` keep-alives while processing, and return X-PendingPeriod in the immediate response (3.2.5.2). A server that can return the whole response immediately may skip chunking (3.2.5.2). Exact layout used here is the one in example 4.1: headers, `PROCESSING\r\n`, `DONE\r\n`, `X-ResponseCode: 0`, `X-ElapsedTime`, `X-StartTime`, empty line, body.
- X-ResponseCode values 0–18 (2.2.3.3.3); used here: 0, 1, 2 Invalid Verb, 3 Invalid Path, 4 Invalid Header, 5 Invalid Request Type, 6 Invalid Context Cookie, 7 Missing Header, 8 Anonymous Not Allowed, 9 Too Large, 10 Context Not Found, 12 Invalid Request Body, 13 Missing Cookie, 15 Invalid Sequence.
- X-RequestType values for the mailbox endpoint: Connect, Execute, Disconnect, NotificationWait, PING (2.2.3.3.1; bodies 2.2.4.1–2.2.4.4; PING 2.2.6 has no request or response body).
- Session context: created on Connect/Bind and returned via Set-Cookie; cookie names are implementation-specific (3.2.5.1). The server MUST store the authentication context with the session and fail with 10 if it differs on later requests (3.2.5.1). One request at a time per session, otherwise 15 (3.2.5.1). Every response includes the session's Set-Cookie headers (3.2.5.2). Disconnect releases state and invalidates the cookie; later use MUST fail (3.2.5.4).
- Timers: keep-alive interval default 15 s; NotificationWait completes after 5 minutes without events; an idle-time timer exists (3.2.2). X-ExpirationInfo is returned in every response with milliseconds until session timeout (2.2.3.3.8). The idle timeout value itself is not fixed by the specification.
- Connect request body: UserDn (null-terminated ASCII), Flags, DefaultCodePage, LcidSort, LcidString, AuxiliaryBufferSize, AuxiliaryBuffer; fields mirror EcDoConnectEx [in] (2.2.4.1.1). Success body: StatusCode, ErrorCode, PollsMax, RetryCount, RetryDelay, DnPrefix, DisplayName, AuxiliaryBufferSize, AuxiliaryBuffer (2.2.4.1.2).
- Execute request body: Flags, RopBufferSize, RopBuffer (= rgbIn of EcDoRpcExt2), MaxRopOut, AuxiliaryBufferSize, AuxiliaryBuffer (2.2.4.2.1). Success body: StatusCode (MUST be 0), ErrorCode, Flags, RopBufferSize, RopBuffer (= rgbOut), AuxiliaryBufferSize, AuxiliaryBuffer (2.2.4.2.2).
- Failure bodies (2.2.4.1.3, 2.2.4.2.3, 2.2.4.3.3, 2.2.4.4.3) carry an RPC_HEADER_EXT before auxiliary data except in early Exchange 2016 builds (Appendix A notes <2>–<5>).
- Autodiscover: server MUST answer POST at `https://<Server>/autodiscover/autodiscover.xml` (MS-OXDSCLI 3.2.5). Request/response namespaces in MS-OXDSCLI 2.2.1. `X-MapiHttpCapability` request header is an integer > 0 (2.2.2.1); `X-AnchorMailbox` SHOULD accompany it (2.2.2.2). If valid, the response MUST include `<Protocol Type="mapiHttp" Version="N">` and MUST NOT include Protocol Type `EXCH` or `EXPR` (3.2.5.1); version 1 contains `MailStore` and `AddressBook`, each with at least one of `InternalUrl`/`ExternalUrl` (3.2.5.1 table). Example response: MS-OXDSCLI 4.4. Error response example: 4.5.

Code (this repository):

- `mapiproxy/servers/default/emsmdb/dcesrv_exchange_emsmdb.c:225` `EcDoRpc_process_transaction(TALLOC_CTX *, struct emsmdbp_context *, struct mapi_request *, struct mapi_response **)` is the ROP dispatcher and takes no dcerpc state. It is `static`.
- `dcesrv_exchange_emsmdb.c:1149-1226` `dcesrv_EcDoRpcExt2`: after the dcerpc checks, lines ~1171-1219 are transport-independent (pull `mapi2k7_request` from rgbIn, call the dispatcher, push `RPC_HEADER_EXT` + `mapi_response`, XOR obfuscation, capacity checks). This is the code to extract.
- `dcesrv_exchange_emsmdb.c:53-110` `emsmdb_connect_context` needs a `dcesrv_call_state` for the account name and creates a dcerpc policy handle; it validates the user DN against `mailNickname`/`legacyExchangeDN`/`displayName` from SamDB.
- `mapiproxy/servers/default/emsmdb/emsmdbp.c:86` `emsmdbp_init(lp_ctx, username, oc_ctx)` **fails when SamDB cannot be opened** (`samdb_init` at `emsmdbp.c:44`, checked right after the call). `emsmdbp_verify_user`/`emsmdbp_verify_userdn` (`emsmdbp.c:197`, `:261`) query SamDB (`msExchUserAccountControl`) and require a `dcesrv_call_state`.
- ROP handlers also query `samdb_ctx`: `oxcstor.c:71` (Logon), `oxcmsg.c:47`, `:722`, `oxomsg.c:321`, `emsmdbp_object.c:1337`, `:2458`. The `oxc*.c` handlers contain no `dce_call` references.
- NSPI logic (`mapiproxy/servers/default/nspi/emsabp.c:36-49`, `:85`) is SamDB-only.
- Existing Autodiscover code `mapiproxy/services/ocsmanager/ocsmanager/controllers/autodiscover.py` is Python 2/Pylons/LDB and returns RPC-era settings; behavior reference only.
- Test pattern: `Makefile:1811-1817` (`check-emsmdb` builds `bin/emsmdb` from a smoke file, uses `-Wl,--wrap=talloc_strdup` for allocation failure). CI: `.github/workflows/modernization.yml`.

**Consequence (blocks the lab acceptance, not the M1 code):** without SamDB, `emsmdbp_init` returns NULL, so a real Connect cannot create a session and RopLogon cannot resolve the mailbox. Replacing these lookups is M2 work. See decision 5.

## C boundary

The Rust crate never sees Samba, talloc, dcerpc or NDR types. The whole
interface is one header, `mapiproxy/servers/default/emsmdb/oc_emsmdb.h`:

```c
typedef struct oc_emsmdb_session oc_emsmdb_session;	/* opaque */

uint32_t oc_emsmdb_init(const char *smb_conf_path);
uint32_t oc_emsmdb_connect(const char *username, const char *user_dn,
			   uint32_t flags, uint32_t code_page,
			   uint32_t lcid_sort, uint32_t lcid_string,
			   oc_emsmdb_session **session,
			   const char **display_name, const char **dn_prefix);
uint32_t oc_emsmdb_execute(oc_emsmdb_session *session, uint32_t flags,
			   const uint8_t *rop_in, size_t rop_in_len,
			   uint8_t *rop_out, size_t rop_out_cap,
			   size_t *rop_out_len);
void	 oc_emsmdb_disconnect(oc_emsmdb_session *session);
```

Return values are MAPI status codes (`MAPI_E_SUCCESS` = 0), which go
straight into the MAPI/HTTP `ErrorCode` fields (MS-OXCMAPIHTTP 2.2.4.1.2,
2.2.4.2.2). Rust parses the MAPI/HTTP body framing (UserDn, Flags,
RopBufferSize, auxiliary sizes) so untrusted length fields are checked in
safe code; the ROP buffer itself is still parsed by the existing C NDR code.

Memory model:

- **C owns everything it allocates, with talloc.** `oc_emsmdb_init` creates a
  process-wide talloc root (loadparm, mapistore). Each session is a talloc
  child of that root, freed only by `oc_emsmdb_disconnect`. Rust never frees
  a C pointer and C never frees a Rust pointer.
- **Inputs are borrowed for the call only.** `username`, `user_dn` and
  `rop_in` belong to Rust; C copies anything it keeps before returning.
- **Outputs go into Rust-owned memory or are borrowed from the session.**
  `oc_emsmdb_execute` writes at most `rop_out_cap` bytes into a buffer Rust
  allocated (`Vec<u8>` of `MaxRopOut`, capped at 0x40000) and sets
  `*rop_out_len`; too small → `ecBufferTooSmall`, nothing past the cap is
  written. `display_name` and `dn_prefix` point into the session and stay
  valid until the next call on that session; Rust copies them at once.
- **Handles stay on one thread.** The Rust wrapper around
  `*mut oc_emsmdb_session` is not `Send`; it lives in a table owned by the C
  worker thread, and HTTP tasks refer to it by session id over a channel.
  Dropping the wrapper calls `oc_emsmdb_disconnect` exactly once.
- **No callbacks.** C never calls into Rust, so no Rust panic can unwind
  through C. C errors are return codes; C code must not `abort()` on bad
  input.
- Auxiliary buffers are not passed to C in M1; responses carry an empty
  auxiliary buffer. `shortcut: client performance data is dropped, pass it
  through when a C consumer needs it`.

**Bindings: hand-written (recommended) rather than bindgen.** Four
functions with only integers, byte pointers and C strings fit in one
reviewed `extern "C"` block in `mapihttpd/src/ffi.rs`. bindgen would add a
libclang build dependency (heavier Debian build-depends and CI) and, since
`oc_emsmdb.h` must not include Samba headers, generates nothing a
hand-written block does not already state. Drift is caught by the
`c-backend` integration test (Task 4), which calls every symbol through the
real library (execute and disconnect with a NULL session, which C rejects),
and by keeping header and `ffi.rs` changes in the same commit.

## Design decisions

Maintainer decisions of 2026-10-30 are marked **Approved**. Task 0 (done,
go) confirmed decisions 3, 4 and 7 and added the Bearer rule to decision 4.

1. **Language and HTTP stack — Approved (revision 2): new code in Rust.**
   hyper 1 with hyper-util on tokio, used directly rather than through axum:
   the service has three POST routes, and axum adds tower and its middleware
   stack to the vendored tree for routing we do not need. `#![deny(unsafe_code)]`
   at the crate root; only `mod ffi` has `#[allow(unsafe_code)]`, and every
   `unsafe` block there carries a `// SAFETY:` comment (clippy
   `undocumented_unsafe_blocks` = deny). No own TLS: nginx terminates it.
   Dependency versions are kept at or below Debian 13's packaged versions
   (tokio 1.43, hyper 1.5, hyper-util 0.1.10, quick-xml 0.36, base64 0.22,
   hmac 0.12, sha2 0.10, getrandom 0.2) so a later Debian package can switch
   from `vendor/` to `librust-*-dev`.
2. **Non-chunked responses in M1.** Every handled request is answered once with `PROCESSING\r\nDONE\r\n` + additional headers + body, which 3.2.5.2 allows when the response is immediately available. X-PendingPeriod is still sent (3.2.5.2). NotificationWait is the exception: it is held, then answered. `shortcut: no PENDING keep-alives during long ROP batches, upgrade when IMAP-backed Execute can exceed the client's pending period`.
3. **Session cookie.** One cookie `MapiContext=<32 hex chars from getrandom>` with `Path=/mapi/; Secure; HttpOnly` (name is implementation-specific per 3.2.5.1). The session stores the username and an HMAC-SHA-256 of `user:password` keyed with a per-process random key; a request whose Basic credentials hash differently gets code 10 (3.2.5.1). Idle timeout `--session-idle-seconds`, default 1800 (implementation choice; the specification fixes no value). No sequence cookie in M1; concurrency is enforced with a per-session busy flag → code 15.
4. **Authentication: Basic → Dovecot AUTH PLAIN.** Credentials are checked against Dovecot only on Connect and when the credential hash changes, not on every request. `service=` is configurable (`--dovecot-service`, default `openchange`), so a Dovecot passdb can scope it. `rip` comes from `X-Real-IP` only when the TCP peer is 127.0.0.1. Missing/invalid credentials and any non-Basic scheme (Outlook sends `Bearer` first on every request, Task 0 finding 1) → HTTP 401 with `WWW-Authenticate: Basic realm="openchange"`; a non-Basic scheme never reaches Dovecot. Dovecot `FAIL ... code=temp_fail` → HTTP 503, never 401. M1 keeps only the credential hash. M6's DAV backend will forward the user's Basic credentials to SOGo (maintainer decision: no `SOGoTrustProxyAuthentication`), so from M6 the password is held in session memory only, never on disk or in logs; that change belongs to the M6 plan.
5. **SamDB gate — Approved.** Rust talks to EMSMDB through `trait Backend { connect; execute; disconnect }`; the production implementation is the C boundary above, tests use a fake. `oc_emsmdb_connect` still fails without SamDB until M2 replaces the directory lookups, and the service turns that into a well-formed Connect failure body. **M1 lab acceptance:** Autodiscover returns `mapiHttp` to Outlook, Basic credentials are verified by Dovecot, and the Connect request reaches the service and gets a well-formed MAPI/HTTP response. **Outlook profile creation is M2's acceptance.**
6. **Address book endpoint (`/mapi/nspi`).** M1 routes it and answers PING (2.2.6); other request types return X-ResponseCode 5. NSPI request types (2.2.5.x) move to M2 because `emsabp` is SamDB-only.
7. **Autodiscover without `X-MapiHttpCapability` — Approved.** The service has no EXCH/EXPR (RPC) settings to return. It answers with an MS-OXDSCLI 4.5-style Error response.
8. **LegacyDN and identity strings in M1** come from command-line options (`--org`, `--ou`) plus the mailbox local part, until M2 reads PostfixAdmin. Example values only use `example.invalid`.
9. **Configuration is command-line options** (`--port`, `--dovecot-socket`, `--dovecot-service`, `--external-host`, `--org`, `--ou`, `--session-idle-seconds`, `--notification-wait-seconds`, `--smb-conf`), parsed with the standard library and set in the systemd unit. `shortcut: no configuration file, add one in M7 with the packaging work`.

## Global Constraints

- New code is Rust; existing C changes only where the C boundary needs it (Task 4). Migration of other C code happens only when there is a clear gain, as a separately planned change.
- `--enable-mapihttp` is off by default; default `./configure && make all` must not need cargo or rustc. Enabled without `cargo` ≥ 1.85 → `AC_MSG_ERROR`.
- Builds use only vendored crates: `cargo build --offline --locked`; `Cargo.lock` and `vendor/` are committed; `.cargo/config.toml` replaces crates.io with `vendor/`.
- No `unsafe` outside `mapihttpd/src/ffi.rs`; `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` pass.
- Listen address is 127.0.0.1 only; no option to bind other addresses in M1.
- Only MAPI/HTTP; no RPC/TCP or RPC/HTTP paths are added. Basic only; no NTLM/Kerberos/SamDB code is added.
- The RPC module behavior is unchanged: `check-emsmdb` and the other 16 targets in `doc/CONTINUITY.md` keep passing.
- Tests make no network calls (in-memory streams, `UnixStream::pair`, fixtures only) and need no Dovecot, nginx or Outlook.
- C boundary tests run with `CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'`.
- No real hostnames, IPs, domains or credentials; use `example.invalid`.
- Request body limit 16 MiB → code 9 (implementation choice; nginx `client_max_body_size` set to the same value in the example).
- Gromox/grommunio may be read for behavior only; no code is copied.
- Passwords, `Authorization` header values and session cookies are never written to logs, captures, fixtures or disk; Rust types holding them do not derive `Debug` or implement it with redaction.

## Review Focus

0. **Bearer first (Task 0 finding 1):** Outlook sends `Authorization: Bearer` before Basic on every request. It must get HTTP 401 with `WWW-Authenticate: Basic realm="openchange"`, without contacting Dovecot, without touching a session and without a failed-login log line that fail2ban or Dovecot's penalty would count. A Bearer request carrying a valid session cookie is still 401, never served from the session. Tests in Tasks 1, 2 and 6.
1. **Session hijack by cookie reuse with other credentials:** same cookie, different Basic user → code 10, session untouched (3.2.5.1). Test in Task 2.
2. **Concurrent requests on one session** (Outlook retries during a slow Execute) → second request gets 15 and the first completes (3.2.5.1). Test in Task 2.
3. **Dovecot temporary failure** (SQL down) must not look like a wrong password: 503, no session created, no lockout. Test in Task 3.
4. **Oversized or truncated bodies** (RopBufferSize larger than the remaining body, MaxRopOut above 0x40000, a Connect cut short) → code 12 or the RPC path's `ecRpcFailed`, never a read or write past a buffer on either side of the C boundary. Tests in Tasks 4 and 5.
5. **Disconnect then reuse** of the old cookie, and expiry after the idle timeout → code 10, with X-ExpirationInfo reflecting the configured value (3.2.5.4, 2.2.3.3.8); expiry also calls `oc_emsmdb_disconnect` exactly once. Tests in Tasks 2 and 5.

---

### Task 0: Lab spike — observe real Outlook before writing code — **Done 2026-10-30: GO**

Run by the maintainer on a disposable Debian VM: nginx with TLS (public
certificate) in front of a Python standard-library listener on 127.0.0.1 that
answered Autodiscover with a static `mapiHttp` response and `/mapi/` with HTTP
200, `X-ResponseCode: 1` and an empty body. The results are recorded here
instead of a separate `doc/MAPIHTTP_SPIKE.md`. Fixtures, provenance and the
decoded bodies: [`testsuite/modernization/mapihttp/`](../../testsuite/modernization/mapihttp/README.md).

| Question | Classic Microsoft 365 Outlook 16.0.19127.20800, Windows 10.0 build 26100 |
|---|---|
| Reaches lab Autodiscover? | Yes: POST `https://<mail domain>/autodiscover/autodiscover.xml`, `text/xml`, 361 bytes, AcceptableResponseSchema `outlook/responseschema/2006a`. Whether it tried Microsoft 365 endpoints first is not visible from the server. |
| Basic accepted? | Yes. Standard "Windows Security" prompt, then Autodiscover 200 and the Exchange account was created ("restart Outlook"). |
| `X-MapiHttpCapability`? | Sent, value `1`. |
| Connect to `/mapi/emsmdb/`? | Yes, after restart: Bind (45 bytes) to `/mapi/nspi/`, Connect (303 bytes) to `/mapi/emsmdb/`, both with `?MailboxId=`. With `X-ResponseCode: 1` and no body Outlook retried in a loop (24 Connect, 6 Bind) and showed a logon error, as expected. |

Not covered: Outlook 2016/2019 and 2013 SP1 were not available; they move to
the lab acceptance below. Go/no-go: **go**. Decisions 3, 4 and 7 stand;
decision 4 gains the Bearer rule (finding 1).

Findings that change Tasks 1–7:

1. **Bearer first, on every request.** Autodiscover, Bind and Connect each
   arrived first with `Authorization: Bearer ...` (modern authentication);
   only after `401` with `WWW-Authenticate: Basic realm=...` did Outlook
   resend with Basic. MS-OXCMAPIHTTP 1.7 lists only Basic, NTLM and Negotiate;
   Bearer is not defined there. 2.2.2 requires every request to be
   authenticated, and 3.2.5.1 only says the session context stores and checks
   the authentication context, so **nothing in the specification lets the
   session cookie replace per-request authentication or stop the Bearer→401
   round trip**; whether Outlook drops Bearer once it holds a session cookie
   is measured in the lab acceptance. Required behavior: any non-Basic scheme
   → HTTP 401 with the Basic challenge, Dovecot not contacted, no session
   touched, logged at debug level only, never as a failed login (fail2ban
   watches failed logins).
2. **Session cookie after Connect** (decision 3) stays required so Execute
   does not need a Dovecot round trip; Basic credentials are still sent and
   compared by hash. Outlook also sent a `Cookie` header to Autodiscover;
   unknown cookies are ignored.
3. **Headers seen on every request** and what the service does with them:

   | Header | Specification | Service |
   |---|---|---|
   | `X-RequestId` `{GUID}:n` | MS-OXCMAPIHTTP 2.2.3.3.2 | echo (already planned) |
   | `X-ClientInfo` `{GUID}:n` | 2.2.3.3.4: server MUST return it unchanged | echo on every `/mapi/` response |
   | `X-ClientApplication` `Outlook/16.0.19127.20800` | 2.2.3.3.6, informational | debug log only |
   | `X-ServerApplication` (response) | 2.2.3.3.7: on every response, format `Exchange/15.xx.xxxx.xxx` | constant `Exchange/15.02.1544.004`, the value the spike used |
   | `Content-Type: application/mapi-http`, `Accept` | 2.2.2.1, 2.2.3.2.2 | validate Content-Type (already planned) |
   | `X-AnchorMailbox` = e-mail | MS-OXDSCLI 2.2.2.2 | Autodiscover: must match the authenticated user (Task 6); `/mapi/`: ignored |
   | `X-MapiHttpCapability: 1` | MS-OXDSCLI 2.2.2.1 | Autodiscover only (Task 6) |
   | `X-User-Identity`, `X-MS-Negotiate: Server`, `X-Accept: application/json`, `X-MS-CookieUri-Requested: t`, `X-FeatureVersion: 1`, `X-AutoDiscoverArchiveAsSmtp: True`, `Accept-Auth`, `Client-Request-Id`, `Depth: 0` | not defined in MS-OXCMAPIHTTP or MS-OXDSCLI (searched both) | ignored, not echoed, never an error |

4. **Accepted Autodiscover response** (the reference for Task 6): `User` with
   `DisplayName`, `LegacyDN`, `AutoDiscoverSMTPAddress`, `DeploymentId`;
   `Account` with `AccountType` `email`, `Action` `settings`,
   `MicrosoftOnline` `False` and `Protocol Type="mapiHttp" Version="1"`, whose
   `MailStore` and `AddressBook` each carry `InternalUrl` and `ExternalUrl`
   `https://<host>/mapi/{emsmdb,nspi}/?MailboxId=<guid>@<host>` (same form as
   MS-OXDSCLI 4.4). The spike's mailbox GUID was a name-based UUID of the
   address; any value stable per mailbox works.
5. **Auxiliary buffer** of the real Connect contains block types 0x18, 0x4A
   and 0x52, which `exchange.idl` does not define (`exchange.idl:4306-4329`).
   The Connect body codec (Task 5) walks `AUX_HEADER` blocks by `Size` with bounds checks
   and treats their payloads as opaque.
6. **Client-side HTTP proxy:** an authenticating proxy (407) on the client
   network kept every request from arriving. Installation documentation must
   say the MAPI/HTTP and Autodiscover host belongs in the proxy/PAC
   exceptions (Task 7).

- [x] **Step 1:** Windows and Outlook builds recorded (table above); 2016/2019 and 2013 SP1 pending in the lab acceptance.
- [x] **Step 2:** Autodiscover, Basic, `X-MapiHttpCapability` and Connect answered (table above).
- [x] **Step 3:** Connect and Bind bodies sanitized with same-length replacement and checked by hand; provenance in the fixture README.
- [x] **Step 4:** Results and go/no-go recorded in this section.
- [x] **Step 5: Commit** `test(mapihttp): add sanitized Outlook Connect and Bind captures`.

### Task 1: Cargo workspace, build and CI integration, request validation, PING

**Files:**
- Create: `Cargo.toml` (workspace, `members = ["mapihttpd"]`, `resolver = "2"`), `Cargo.lock`, `.cargo/config.toml` (crates.io → `vendor/`), `vendor/` (`cargo vendor --versioned-dirs`), `mapihttpd/Cargo.toml` (`edition = "2021"`, `rust-version = "1.85"`, `[lints]` with `unsafe_code = "deny"`, clippy `undocumented_unsafe_blocks = "deny"`), `mapihttpd/src/main.rs` (options, 127.0.0.1 listener, hyper glue), `mapihttpd/src/request.rs` (validation, routing, reply layout), `mapihttpd/src/auth.rs` (Basic parsing, authenticator trait)
- Modify: `configure.ac` (`AC_ARG_ENABLE(mapihttp)`, `AC_PATH_PROG([CARGO], [cargo])`, version ≥ 1.85 check, summary line), `config.mk.in`, `Makefile` (`bin/openchange-mapihttpd` = `cargo build --offline --locked --release` and copy; `check-mapihttp` = `cargo test --offline --locked`; `clean` runs `cargo clean`), `.gitignore` (`/target/`), `.github/workflows/modernization.yml` (new job `rust` on `debian:13`: `apt-get install cargo rustc rust-clippy rustfmt`, then `cargo fmt --check`, `cargo clippy --offline --locked --all-targets -- -D warnings`, `cargo test --offline --locked`, and `cargo audit` from `cargo install cargo-audit --locked --version <pinned>`; existing jobs untouched)

**Interfaces:**
- Produces:
  - `pub struct MapiRequest<'a> { pub method: &'a str, pub path: &'a str, pub request_type: Option<&'a str>, pub request_id: Option<&'a str>, pub client_info: Option<&'a str>, pub content_type: Option<&'a str>, pub authorization: Option<&'a str>, pub cookie: Option<&'a str>, pub real_ip: Option<IpAddr>, pub body: &'a [u8] }` — the glue reads headers by name only; tests build it directly.
  - `pub struct MapiReply { pub http_status: u16, pub response_code: u32, pub request_type: Option<String>, pub request_id: Option<String>, pub client_info: Option<String>, pub body: Vec<u8>, pub set_cookie: Option<String>, pub expiration_ms: u32 }`
  - `pub async fn handle(srv: &Server, req: MapiRequest<'_>) -> MapiReply` — the single entry the hyper glue calls.
  - `pub fn format_reply(rep: &MapiReply, elapsed_ms: u32, start: &str) -> Vec<u8>` — 4.1 layout (`PROCESSING\r\nDONE\r\nX-ResponseCode: N\r\nX-ElapsedTime: ..\r\nX-StartTime: ..\r\n\r\n<body>`).
  - `pub const SERVER_APPLICATION: &str = "Exchange/15.02.1544.004";` sent as X-ServerApplication on every response (2.2.3.3.7); X-RequestId and X-ClientInfo echoed (2.2.3.3.2, 2.2.3.3.4).
  - `pub enum AuthResult { Ok { user: String }, BadCredentials, TempFail }`; `pub trait Authenticator: Send + Sync { fn authenticate(&self, user: &str, password: &Password, rip: Option<IpAddr>) -> impl Future<Output = AuthResult> + Send; }`; `pub struct Password(String)` with a redacting `Debug`.
  - `pub enum BasicCredentials { Missing, OtherScheme, Malformed, Basic { user: String, password: Password } }` from `pub fn parse_authorization(value: Option<&str>) -> BasicCredentials`.

- [ ] **Step 0: Toolchain.** Debian 13 `rustc`, `cargo`, `rust-clippy`, `rustfmt` 1.85 `.deb` files fetched with `apt-get download` and extracted into `/tmp/openchange-build-tools/root` like the other build dependencies (no system install). `python3 /tmp/openchange-build-tools/run.py cargo --version` → 1.85.
- [ ] **Step 1: Failing tests** (`cargo test`, no sockets except `tokio::io::duplex`):
  - `test_get_rejected`: method `GET` on `/mapi/emsmdb/` → code 2.
  - `test_unknown_path`: `/mapi/other/` → code 3.
  - `test_missing_headers`: no `X-RequestId` → 7; no `X-RequestType` → 7; `Content-Type: text/plain` → 4.
  - `test_bad_request_type`: `X-RequestType: Bind` on `/mapi/emsmdb/` → 5.
  - `test_ping`: authenticated `PING` on both endpoints → code 0, empty body, X-RequestType echoed.
  - `test_anonymous`: no `Authorization` → HTTP 401 with `WWW-Authenticate: Basic realm="openchange"`.
  - `test_bearer_challenged`: `Authorization: Bearer eyJ0eXAi` → HTTP 401 with the same challenge, the fake authenticator's call counter stays 0 (Task 2 adds the cookie half).
  - `test_too_large`: body length 16 MiB + 1 → 9.
  - `test_reply_layout`: `format_reply` output starts with `"PROCESSING\r\nDONE\r\nX-ResponseCode: 0\r\n"` and the body follows the first `"\r\n\r\n"`.
  - `test_response_headers`: `X-ClientInfo: {0589012E-9A4E-4666-9EE1-3C5BD8DDF18B}:558760020` echoed unchanged; X-ServerApplication equals `SERVER_APPLICATION`.
  - `test_glue_outlook_headers`: one raw HTTP/1.1 PING over `tokio::io::duplex` through the hyper glue, carrying every header of the Connect entry in `testsuite/modernization/mapihttp/headers.json` (Authorization replaced by the fake's Basic value) → HTTP 200, code 0.
  - `test_password_debug_redacted`: `format!("{:?}", Password::from("secret"))` does not contain `secret`.
- [ ] **Step 2:** `cargo test --offline --locked` → FAIL.
- [ ] **Step 3: Implement.** Authentication in this task is a fake accepting `user:pass`; Task 3 adds Dovecot.
- [ ] **Step 4:** configure with `--enable-mapihttp`, `make check-mapihttp` and `cargo clippy --offline --locked --all-targets -- -D warnings` and `cargo fmt --check` → PASS; plain configure + `make all` → PASS without cargo on `PATH`. Report `du -sh vendor`.
- [ ] **Step 5: Commits** `build: add Cargo workspace and vendored crates for mapihttpd` then `feat(mapihttpd): validate MAPI/HTTP requests and answer PING`.

### Task 2: Session context table

**Files:**
- Create: `mapihttpd/src/session.rs`
- Test: unit tests in `session.rs` and `request.rs`

**Interfaces:**
- Consumes: `MapiRequest`, `MapiReply`, `handle` (Task 1).
- Produces:
  - `pub struct SessionTable` with `pub fn new(idle: Duration) -> Self` (per-process HMAC key from getrandom).
  - `pub fn credential_hash(&self, user: &str, password: &Password) -> [u8; 32]`.
  - `pub fn create(&self, user: &str, cred_hash: [u8; 32], backend: SessionId, now: Instant) -> String` → the `Set-Cookie` value.
  - `pub fn begin(&self, cookie_header: Option<&str>, cred_hash: [u8; 32], now: Instant) -> Result<SessionGuard, u32>` → `Err(6)` malformed cookie, `Err(10)` unknown/expired/other credentials, `Err(13)` missing cookie, `Err(15)` busy. `SessionGuard` clears the busy flag on drop.
  - `pub fn remove(&self, cookie: &str) -> Option<SessionId>`; `pub fn expire(&self, now: Instant) -> Vec<SessionId>` (callers disconnect the returned backend sessions).
  - `pub type SessionId = u64` (key of the C worker's handle table, Task 4).

- [ ] **Step 1: Failing tests:** `test_connect_sets_cookie` (Set-Cookie matches `^MapiContext=[0-9a-f]{32}; Path=/mapi/; Secure; HttpOnly$`, X-ExpirationInfo == 1800000), `test_execute_without_cookie` → 13, `test_cookie_other_user` → 10 and the original session still works, `test_busy_session` → 15, `test_disconnect_invalidates` → 10 afterwards, `test_idle_expiry` (now + 1801 s) → 10 and `expire` returns its `SessionId` once, `test_cookie_garbage` (`MapiContext=zz`) → 6, `test_bearer_with_live_cookie` → HTTP 401 and the session's last-used time unchanged.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** run → PASS.
- [ ] **Step 5: Commit** `feat(mapihttpd): track session contexts by cookie`.

### Task 3: Dovecot auth protocol client

**Files:**
- Create: `mapihttpd/src/dovecot.rs`
- Test: unit tests in `dovecot.rs` with `tokio::net::UnixStream::pair()` and scripted server lines

**Interfaces:**
- Consumes: `Authenticator`, `AuthResult`, `Password` (Task 1).
- Produces:
  - `pub async fn auth_plain<S: AsyncRead + AsyncWrite + Unpin>(stream: S, service: &str, user: &str, password: &Password, rip: Option<IpAddr>) -> Result<AuthResult, ProtocolError>`
  - `pub struct DovecotAuthenticator { socket: PathBuf, service: String }` implementing `Authenticator` (one connection per check; `ProtocolError` and connect failures → `TempFail`, logged without credentials).
  - Protocol (Dovecot auth protocol v1.3, [2.4.4 docs](https://doc.dovecot.org/2.4.4/developers/design/auth_protocol.html)): client sends `VERSION\t1\t3` and `CPID\t<pid>`; since 2.4.0 the server waits for VERSION before its handshake; read until `DONE`; require major 1 and a `MECH\tPLAIN` line; send `AUTH\t<id>\tPLAIN\tservice=<service>\t[rip=..\t]secured\tresp=<base64(\0user\0password)>` with `resp=` last; parse `OK\t<id>\tuser=...`, `FAIL\t<id>[\tcode=temp_fail]`. Lines are TAB-separated with `\001` escapes and fit 16384 bytes. `no-penalty` is **not** sent (Dovecot's penalty is the brute-force protection).
- [ ] **Step 1: Failing tests:** `test_auth_ok` (fixture replies `OK\t1\tuser=alice@example.invalid` → Ok with that user; asserts the client's AUTH line ends with `resp=AGFsaWNlQGV4YW1wbGUuaW52YWxpZABzZWNyZXQ=`), `test_auth_fail` → BadCredentials, `test_auth_tempfail` (`code=temp_fail`) → TempFail and HTTP 503 through `handle`, `test_major_mismatch` (`VERSION\t2\t0`) → ProtocolError, `test_no_plain` → ProtocolError, `test_tab_in_password` (password with TAB and LF is base64-encoded, never raw), `test_truncated_reply` (EOF mid-handshake) → ProtocolError, `test_overlong_line` (> 16384 bytes) → ProtocolError.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement; `main.rs` uses `DovecotAuthenticator` instead of Task 1's fake. **Step 4:** run → PASS.
- [ ] **Step 5: Commit** `feat(mapihttpd): verify Basic credentials through Dovecot auth`.

### Task 4: C boundary — `liboc_emsmdb` and the Rust FFI module

**Files:**
- Create: `mapiproxy/servers/default/emsmdb/emsmdb_execute.c` (extracted core), `mapiproxy/servers/default/emsmdb/oc_emsmdb.h` (the header in "C boundary", nothing else), `mapiproxy/servers/default/emsmdb/oc_emsmdb.c`, `testsuite/modernization/oc_emsmdb_smoke.c`, `mapihttpd/build.rs`, `mapihttpd/src/ffi.rs`, `mapihttpd/src/backend.rs`
- Modify: `mapiproxy/servers/default/emsmdb/dcesrv_exchange_emsmdb.c:1149-1226` (call the extracted core; `EcDoRpc_process_transaction` becomes non-static or moves with it), `dcesrv_exchange_emsmdb.h`, `Makefile:1159-1176` (add `emsmdb_execute.po` to the module; new `liboc_emsmdb.$(SHLIBEXT)` built only when `OC_MAPIHTTP` is set; `check-oc-emsmdb` next to `check-emsmdb`; `check-mapihttp` adds `--features c-backend` with `OC_EMSMDB_LIBDIR`), `mapihttpd/Cargo.toml` (feature `c-backend`, off by default)

**Interfaces:**
- Produces (C):
  - `enum MAPISTATUS emsmdb_execute_buffer(TALLOC_CTX *mem_ctx, struct emsmdbp_context *ctx, const DATA_BLOB *rop_in, uint32_t flags, uint32_t max_out, DATA_BLOB *rop_out)` — exactly the checks/behavior of current lines ~1171-1219 (capacity 8..0x40000, input 8..UINT16_MAX+8, `RHEF_Last` required, XOR handling, `ecBufferTooSmall`).
  - The four `oc_emsmdb_*` functions of "C boundary". `oc_emsmdb_connect` = `emsmdbp_init` + the user-DN checks of `emsmdb_connect_context` with the username passed in instead of a `dcesrv_call_state`; it fails without SamDB under the current code (decision 5). `oc_emsmdb_execute` copies the `emsmdb_execute_buffer` result into the caller's buffer. NULL session → `ecRpcFailed`; `oc_emsmdb_disconnect(NULL)` is a no-op.
- Produces (Rust):
  - `pub trait Backend: Send + Sync { fn connect(&self, req: ConnectParams) -> impl Future<Output = Result<Connected, u32>> + Send; fn execute(&self, id: SessionId, flags: u32, rop_in: Vec<u8>, max_out: usize) -> impl Future<Output = Result<Vec<u8>, u32>> + Send; fn disconnect(&self, id: SessionId) -> impl Future<Output = ()> + Send; }` with `ConnectParams { username, user_dn, flags, code_page, lcid_sort, lcid_string }` and `Connected { id: SessionId, display_name: String, dn_prefix: String }`.
  - `pub struct FakeBackend` (records calls; scripted results) for Tasks 5–6 tests.
  - `pub struct CBackend` (feature `c-backend`): one OS thread owning `HashMap<SessionId, ffi::Session>`, jobs over a channel; `ffi::Session` wraps the raw pointer, is not `Send`, and calls `oc_emsmdb_disconnect` in `Drop`.
- **Stop rule:** if the emsmdb objects cannot be linked into `liboc_emsmdb` without dcerpc server symbols, or `oc_emsmdb_connect` cannot be written without a `dcesrv_call_state`, stop and report with file:line references before working around it.
- [ ] **Step 1: Failing tests:**
  - C (`make check-oc-emsmdb`, uses `-Wl,--wrap=emsmdbp_init` like `check-emsmdb` uses `--wrap` to fake a session): `test_execute_out_cap` (output larger than `rop_out_cap` → `ecBufferTooSmall`, guard bytes after the cap unchanged), `test_execute_short_input` (`rop_in_len` 4 → `ecRpcFailed`), `test_execute_null_session` → `ecRpcFailed`, `test_connect_without_samdb` (no wrap) → non-zero status, `*session` NULL, no leak, `test_disconnect_null` no-op.
  - Rust (`cargo test --features c-backend`): `test_c_backend_calls` — `oc_emsmdb_connect` against a test `smb.conf` returns a non-zero status and no session; `oc_emsmdb_execute` and `oc_emsmdb_disconnect` with a NULL session behave as above (every symbol is called through the real library).
  - Rust (no feature): `test_fake_backend_records` and `test_session_drop_disconnects_once`.
- [ ] **Step 2:** run → FAIL. **Step 3:** extract and implement. **Step 4:** `make check-oc-emsmdb check-emsmdb CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'` → PASS, rebuild plain; `make check-emsmdb check-mapihttp` → PASS.
- [ ] **Step 5: Commits** `refactor(emsmdb): share the ROP execution core` then `feat(emsmdb): add the oc_emsmdb C API for the MAPI/HTTP service` then `feat(mapihttpd): call EMSMDB through the C boundary`.

### Task 5: EMSMDB request types over HTTP

**Files:**
- Create: `mapihttpd/src/emsmdb.rs` (body codecs and handlers)
- Test: unit tests in `emsmdb.rs`, fixtures from `testsuite/modernization/mapihttp/`

**Interfaces:**
- Consumes: `handle`, `MapiReply` (Task 1); `SessionTable` (Task 2); `Backend`, `FakeBackend` (Task 4).
- Produces: body codecs (little-endian, no alignment) with bounds-checked reads returning `Err(12)`: Connect request/success/failure (2.2.4.1.1–2.2.4.1.3), Execute (2.2.4.2.1–2.2.4.2.3), Disconnect (2.2.4.3.x), NotificationWait (2.2.4.4.x; returns `EventPending` 0 after `--notification-wait-seconds`, default 300 per 3.2.2). Auxiliary input is walked by `AUX_HEADER.Size` and dropped (Task 0 finding 5); responses carry an empty auxiliary buffer.
- [ ] **Step 1: Failing tests** (fake backend records arguments):
  - `test_connect_real_capture`: every `testsuite/modernization/mapihttp/connect-*.bin` parses; for `connect-m365-16.0.19127.20800.bin`: UserDn `/o=Lab/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=spike`, Flags 0, DefaultCodePage 1252, LcidSort and LcidString 0x0416, AuxiliaryBufferSize 202 equal to the bytes present, six auxiliary blocks walked (sizes 50, 24, 28, 52, 32, 8); with the fake backend failing as the SamDB-less C backend does, the reply is HTTP 200 with a well-formed Connect failure body (2.2.4.1.3) and the echoed X-ClientInfo.
  - `test_connect_capture_truncated`: the same file cut at every length from 0 to 302 → code 12 or a failure body, never a panic.
  - `test_bind_real_capture`: `nspi-bind-m365-16.0.19127.20800.bin` POSTed as `Bind` to `/mapi/nspi/` → X-ResponseCode 5 with a well-formed reply (decision 6).
  - `test_connect_body`: UserDn `"/o=example/ou=first/cn=Recipients/cn=alice"`, Flags 0, LcidString 0x409 → backend receives them; success body round-trips DnPrefix and DisplayName.
  - `test_execute_roundtrip`: RopBuffer bytes forwarded unchanged; returned bytes placed in RopBuffer; StatusCode 0.
  - `test_execute_truncated`: RopBufferSize 100 with 20 bytes present → code 12, backend not called.
  - `test_execute_maxropout_too_big`: MaxRopOut 0x40001 → `ecRpcFailed` in ErrorCode, as the RPC path does.
  - `test_notification_wait_timeout`: with the wait set to 1 s (tokio paused time), returns EventPending 0 and refreshes the session expiry (3.2.5.5).
  - `test_disconnect_calls_backend`: Disconnect → backend `disconnect` once, cookie then gets 10.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** `make check-mapihttp check-emsmdb` → PASS.
- [ ] **Step 5: Commit** `feat(mapihttpd): serve Connect, Execute, Disconnect and NotificationWait`.

### Task 6: Autodiscover POX

**Files:**
- Create: `mapihttpd/src/autodiscover.rs`
- Test: unit tests in `autodiscover.rs`, fixtures in `testsuite/modernization/mapihttp/*.xml`

**Interfaces:**
- Consumes: `MapiRequest`, `MapiReply`, `Authenticator` (Tasks 1, 3).
- Produces: `pub async fn autodiscover(srv: &Server, req: MapiRequest<'_>, mapihttp_capability: Option<&str>) -> MapiReply` routed for POST `/autodiscover/autodiscover.xml` (MS-OXDSCLI 3.2.5); same Basic/Dovecot authentication and Bearer rule; the authenticated user must equal the requested `EMailAddress` (no lookups for other users). URLs `https://<--external-host>/mapi/{emsmdb,nspi}/?MailboxId=<guid>@<host>` like MS-OXDSCLI 4.4; the GUID is stable per mailbox: an RFC 9562 version 8 UUID made from the first 16 bytes of SHA-256 of the lower-cased address, with the version and variant bits set (sha2 is already a dependency; the spike's version 5 UUID would add SHA-1).
- [ ] **Step 1: Failing tests:** `test_autodiscover_mapihttp` (header `X-MapiHttpCapability: 1`, request for `alice@example.invalid` → response namespace `http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006`, `User` with `DisplayName`, `LegacyDN`, `AutoDiscoverSMTPAddress` `alice@example.invalid` and `DeploymentId`, `MicrosoftOnline` `False`, `Protocol Type="mapiHttp" Version="1"`, MailStore and AddressBook each with `InternalUrl` and `ExternalUrl` containing `?MailboxId=`, the same MailboxId on a second request, no `EXCH`/`EXPR`; layout of Task 0 finding 4), `test_autodiscover_bearer` (`Authorization: Bearer x` → 401 with the Basic challenge, authenticator not called), `test_autodiscover_capability_2` (value 2 → still Version 1, the highest supported ≤ 2), `test_autodiscover_capability_invalid` (`0`, `abc` → treated as absent per 3.2.5.1 → Error response), `test_autodiscover_other_user` (authenticated bob asks for alice → Error, no data about alice), `test_autodiscover_malformed_xml` and `test_autodiscover_doctype` (any DOCTYPE → rejected before reading further), `test_autodiscover_get` → 405 or Error (POST only), `test_autodiscover_cookie_ignored` (a `Cookie` header changes nothing).
- [ ] **Step 2:** run → FAIL. **Step 3:** implement with quick-xml (stop on `Event::DocType`). **Step 4:** run → PASS.
- [ ] **Step 5: Commit** `feat(mapihttpd): answer Autodiscover with MAPI/HTTP settings`.

### Task 7: Documentation and regression

**Files:**
- Create: `doc/MAPIHTTP.md` (options, systemd unit example, nginx example block with `server_name mail.example.invalid`, `location /mapi/` and `= /autodiscover/autodiscover.xml` → `proxy_pass http://127.0.0.1:<port>`, `proxy_buffering off`, `proxy_read_timeout 330s`, `client_max_body_size 16m`, `proxy_set_header X-Real-IP $remote_addr`; a client-side note that the MAPI/HTTP and Autodiscover host must be in the proxy/PAC exceptions, Task 0 finding 6; how to refresh `vendor/` and run `cargo audit`)
- Modify: `doc/MODERNIZATION.md` (dated M1 section: done/validated/not validated), `doc/CONTINUITY.md`, `testsuite/README.md`

- [ ] **Step 1:** `make check-oc-emsmdb CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'` → PASS; rebuild plain.
- [ ] **Step 2:** `make all` and the 17 targets from `doc/CONTINUITY.md`, plus `check-mapihttp` and `check-oc-emsmdb` → PASS; `cargo fmt --check`, `cargo clippy --offline --locked --all-targets -- -D warnings` → PASS; `cargo audit` result recorded (needs network; the CI job is authoritative); plain configure proves the default build is unaffected.
- [ ] **Step 3:** Document explicitly **not validated**: real Dovecot, nginx, TLS, any Outlook version, Interop-TestSuites, NSPI request types, chunked/PENDING responses, Connect success without SamDB (M2), Outlook 2016/2019/2013 SP1 behavior (Task 0 saw only Microsoft 365 16.0.19127.20800).
- [ ] **Step 4: Commit** `docs: record MAPI/HTTP service validation and limits`.
- [ ] **Step 5:** Report and wait for approval before any push.

## Lab acceptance (after Tasks 1–7, on the disposable VM)

Record Windows build and each Outlook edition/version/build. On at least one Outlook 2016 or 2019 and one classic Microsoft 365 Outlook (2013 SP1 if licensed), with the real Dovecot behind nginx: Autodiscover request and response with `mapiHttp`; Basic prompt accepted and verified by Dovecot; Connect reaches the service and receives a well-formed MAPI/HTTP response (logged without credentials); `check-mapihttp` passes with the Task 0 captures as fixtures. Profile creation is not expected before M2 (decision 5). Also record, from the nginx log, how many 401 responses precede each Execute once a session cookie exists (Task 0 finding 1), and add one sanitized Connect capture per newly tested Outlook build to the fixtures.
