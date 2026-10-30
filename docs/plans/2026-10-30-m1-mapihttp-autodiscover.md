# M1 — MAPI/HTTP, Autodiscover and Dovecot Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A local service on 127.0.0.1 behind nginx that serves Autodiscover POX with the `mapiHttp` Protocol element and the MAPI/HTTP mailbox endpoint (`/mapi/emsmdb`: Connect, Execute, Disconnect, NotificationWait, PING), authenticating HTTP Basic credentials against Dovecot's auth socket and dispatching ROPs to the existing EMSMDB handlers.

**Architecture:** New daemon `openchange-mapihttpd` built from `mapiproxy/servers/mapihttp/`. HTTP framing via libmicrohttpd (decision 1). Request bodies are parsed with Samba NDR pull/push primitives (already linked). Sessions are an in-memory table keyed by a random cookie. ROP processing reuses the dcerpc-free core of `dcesrv_EcDoRpcExt2`, extracted into one shared function that both the RPC module and the daemon call. Authentication speaks the Dovecot auth protocol v1.3 over a UNIX socket.

**Tech Stack:** C, talloc, Samba NDR library, libmicrohttpd, expat (Autodiscover XML; also chosen by the dav plan), autoconf/Make, GitHub Actions.

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

## Design decisions (flag for approval)

1. **Where the HTTP server lives — recommendation: own small daemon on 127.0.0.1 using libmicrohttpd.**
   - Own daemon + libmicrohttpd (recommended): mature HTTP/1.1 parser and chunked output, suspend/resume for 5-minute NotificationWait (MS-OXCMAPIHTTP 3.2.2) without tying up a worker, Debian package `libmicrohttpd-dev`. Run in single-threaded mode because `emsmdbp`/mapistore state is not documented as thread-safe. `shortcut: one thread serializes all sessions, upgrade to a worker pool once backends are audited for thread safety`.
   - FastCGI behind nginx: needs a FastCGI library anyway; each 5-minute NotificationWait occupies a worker process; streaming PROCESSING/PENDING needs `fastcgi_buffering off`. Rejected.
   - Hand-written HTTP parser: smallest dependency footprint but security-sensitive. Rejected.
2. **Non-chunked responses in M1.** Every handled request is answered once with `PROCESSING\r\nDONE\r\n` + additional headers + body, which 3.2.5.2 allows when the response is immediately available. X-PendingPeriod is still sent (3.2.5.2). NotificationWait is the exception: it is held, then answered. `shortcut: no PENDING keep-alives during long ROP batches, upgrade when IMAP-backed Execute can exceed the client's pending period`.
3. **Session cookie.** One cookie `MapiContext=<32 hex chars from getrandom()>` with `Path=/mapi/; Secure; HttpOnly` (name is implementation-specific per 3.2.5.1). The session stores the username and a SHA-256 of `user:password` keyed with a per-process random key; a request whose Basic credentials hash differently gets code 10 (3.2.5.1). Idle timeout configurable `mapihttp:session_idle_seconds`, default 1800 (implementation choice; the specification fixes no value). No sequence cookie in M1; concurrency is enforced with a per-session busy flag → code 15.
4. **Authentication: Basic → Dovecot AUTH PLAIN.** Credentials are checked against Dovecot only on Connect and when the credential hash changes, not on every request. `service=` is configurable (`mapihttp:dovecot_service`, default `openchange`), so a Dovecot passdb can scope it. `rip`/`lip` come from `X-Real-IP` only when the TCP peer is 127.0.0.1. Missing/invalid credentials → HTTP 401 with `WWW-Authenticate: Basic realm="openchange"`. Dovecot `FAIL ... code=temp_fail` → HTTP 503, never 401.
5. **SamDB gate.** M1 adds a seam: `struct mapihttp_backend { connect; execute; disconnect; }`. Production `connect` calls the extracted EMSMDB code; tests use a fake. The real Connect still fails without SamDB until M2 replaces the directory lookups. **Proposed M1 lab acceptance:** Autodiscover returns `mapiHttp` to Outlook, Basic credentials are verified by Dovecot, and the Connect request reaches the service and gets a well-formed MAPI/HTTP response. "Outlook creates the profile" moves to M2's acceptance. Alternative: move M2's directory seam into M1. Maintainer to choose.
6. **Address book endpoint (`/mapi/nspi`).** M1 routes it and answers PING (2.2.6); other request types return X-ResponseCode 5. NSPI request types (2.2.5.x) move to M2 because `emsabp` is SamDB-only. Outlook profile creation needs NSPI, which is consistent with decision 5.
7. **Autodiscover without `X-MapiHttpCapability`.** The service has no EXCH/EXPR (RPC) settings to return. It answers with an MS-OXDSCLI 4.5-style Error response. Outlook 2013 SP1+ behavior is to be confirmed on the acceptance VM.
8. **LegacyDN and identity strings in M1** come from configuration (`mapihttp:org`, `mapihttp:ou`) plus the mailbox local part, until M2 reads PostfixAdmin. Example values only use `example.invalid`.

## Global Constraints

- `--enable-mapihttp` is off by default; default `./configure && make all` must not need libmicrohttpd or expat. Enabled without dependencies → `AC_MSG_ERROR`.
- Listen address is 127.0.0.1 only; no option to bind other addresses in M1.
- Only MAPI/HTTP; no RPC/TCP or RPC/HTTP paths are added. Basic only; no NTLM/Kerberos/SamDB code is added.
- The RPC module behavior is unchanged: `check-emsmdb` and the other 16 targets in `doc/CONTINUITY.md` keep passing.
- Tests make no network calls (socketpair/fixtures only) and need no Dovecot, nginx or Outlook.
- `make check-mapihttp` also passes with `CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'`.
- No real hostnames, IPs, domains or credentials; use `example.invalid`.
- Request body limit 16 MiB → code 9 (implementation choice; nginx `client_max_body_size` set to the same value in the example).
- Gromox/grommunio may be read for behavior only; no code is copied.

## Review Focus

1. **Session hijack by cookie reuse with other credentials:** same cookie, different Basic user → code 10, session untouched (3.2.5.1). Test in Task 2.
2. **Concurrent requests on one session** (Outlook retries during a slow Execute) → second request gets 15 and the first completes (3.2.5.1). Test in Task 2.
3. **Dovecot temporary failure** (SQL down) must not look like a wrong password: 503, no session created, no lockout. Test in Task 3.
4. **Oversized or truncated Execute bodies** (RopBufferSize larger than the remaining body, MaxRopOut above 0x40000) → code 12 or the existing `ecRpcFormat`/`ecBufferTooSmall`, never an out-of-bounds read. Test in Task 4.
5. **Disconnect then reuse** of the old cookie, and expiry after the idle timeout → code 10, with X-ExpirationInfo reflecting the configured value (3.2.5.4, 2.2.3.3.8). Test in Task 2.

---

### Task 1: Build plumbing, daemon skeleton, request validation, PING

**Files:**
- Modify: `configure.ac` (`AC_ARG_ENABLE(mapihttp)`, `PKG_CHECK_MODULES([MHD], [libmicrohttpd])`, expat probe, summary line), `config.mk.in`, `Makefile` (daemon rule `bin/openchange-mapihttpd`, `check-mapihttp` next to `check-emsmdb` at line ~1811), `.github/workflows/modernization.yml` (new job `mapihttp` adding `libmicrohttpd-dev libexpat1-dev`; existing jobs untouched)
- Create: `mapiproxy/servers/mapihttp/mapihttp.h`, `mapihttp_request.c` (header validation, routing), `mapihttpd.c` (libmicrohttpd glue, config, `main`)
- Test: `testsuite/modernization/mapihttp_smoke.c`

**Interfaces:**
- Produces:
  - `struct mapihttp_request { const char *method, *path, *request_type, *request_id, *content_type, *cookie, *authorization, *client_info; const uint8_t *body; size_t body_len; }` — plain fields so tests drive the core without sockets.
  - `struct mapihttp_reply { unsigned http_status; uint32_t response_code; const char *request_type; DATA_BLOB body; const char *set_cookie; uint32_t expiration_ms; };`
  - `void mapihttp_handle(struct mapihttp_server *srv, TALLOC_CTX *mem_ctx, const struct mapihttp_request *req, struct mapihttp_reply *rep)` — the single entry the libmicrohttpd glue calls.
  - `DATA_BLOB mapihttp_format_reply(TALLOC_CTX *, const struct mapihttp_reply *)` — produces the 4.1 layout (`PROCESSING\r\nDONE\r\nX-ResponseCode: N\r\nX-ElapsedTime: ..\r\nX-StartTime: ..\r\n\r\n<body>`).

- [ ] **Step 1: Failing tests**:
  - `test_get_rejected`: method `GET` on `/mapi/emsmdb/` → code 2.
  - `test_unknown_path`: `/mapi/other/` → code 3.
  - `test_missing_headers`: no `X-RequestId` → 7; no `X-RequestType` → 7; `Content-Type: text/plain` → 4.
  - `test_bad_request_type`: `X-RequestType: Bind` on `/mapi/emsmdb/` → 5.
  - `test_ping`: authenticated `PING` on both endpoints → code 0, empty body, X-RequestType echoed.
  - `test_anonymous`: no `Authorization` → HTTP 401 with Basic challenge.
  - `test_too_large`: body_len 16 MiB + 1 → 9.
  - `test_reply_layout`: `mapihttp_format_reply` output starts with `"PROCESSING\r\nDONE\r\nX-ResponseCode: 0\r\n"` and the body follows the first `"\r\n\r\n"`.
- [ ] **Step 2:** `make check-mapihttp` → FAIL.
- [ ] **Step 3: Implement.** Authentication in this task is a fake that accepts `Basic dXNlcjpwYXNz` (`user:pass`); Task 3 replaces it.
- [ ] **Step 4:** configure with `--enable-mapihttp`, `make check-mapihttp` → PASS; plain configure + `make all` → PASS with no libmicrohttpd reference.
- [ ] **Step 5: Commit** `feat(mapihttp): add optional MAPI/HTTP service skeleton`.

### Task 2: Session context table

**Files:**
- Create: `mapiproxy/servers/mapihttp/mapihttp_session.c`
- Test: `testsuite/modernization/mapihttp_smoke.c`

**Interfaces:**
- Produces:
  - `struct mapihttp_session { char cookie[33]; char *username; uint8_t cred_hash[32]; time_t last_used; bool busy; void *backend_ctx; }`
  - `struct mapihttp_session *mapihttp_session_create(struct mapihttp_server *, const char *username, const uint8_t cred_hash[32])`
  - `uint32_t mapihttp_session_lookup(struct mapihttp_server *, const char *cookie_header, const uint8_t cred_hash[32], time_t now, struct mapihttp_session **out)` → returns 0, 6 (malformed cookie), 10 (unknown/expired/other credentials) or 13 (missing cookie).
  - `void mapihttp_session_destroy(struct mapihttp_session *)`; `void mapihttp_session_expire(struct mapihttp_server *, time_t now)`.

- [ ] **Step 1: Failing tests:** `test_connect_sets_cookie` (Set-Cookie matches `^MapiContext=[0-9a-f]{32}; Path=/mapi/; Secure; HttpOnly$`, X-ExpirationInfo == 1800000), `test_execute_without_cookie` → 13, `test_cookie_other_user` → 10 and the original session still works, `test_busy_session` → 15, `test_disconnect_invalidates` → 10 afterwards, `test_idle_expiry` (now + 1801 s) → 10, `test_cookie_garbage` (`MapiContext=zz`) → 6.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** run → PASS.
- [ ] **Step 5: Commit** `feat(mapihttp): track session contexts by cookie`.

### Task 3: Dovecot auth protocol client

**Files:**
- Create: `mapiproxy/servers/mapihttp/dovecot_auth.c`
- Test: `testsuite/modernization/mapihttp_smoke.c` (fixture server on a `socketpair()`, scripted lines)

**Interfaces:**
- Produces:
  - `enum dovecot_auth_result { DOVECOT_AUTH_OK, DOVECOT_AUTH_FAIL, DOVECOT_AUTH_TEMPFAIL, DOVECOT_AUTH_PROTOCOL_ERROR };`
  - `enum dovecot_auth_result dovecot_auth_plain(int fd, const char *service, const char *user, const char *password, const char *rip, TALLOC_CTX *, char **canonical_user)`
  - `int dovecot_auth_connect(const char *socket_path)` (production; tests pass a socketpair fd).
  - Protocol (Dovecot auth protocol v1.3, [2.4.4 docs](https://doc.dovecot.org/2.4.4/developers/design/auth_protocol.html)): client sends `VERSION\t1\t3` and `CPID\t<pid>`; since 2.4.0 the server waits for VERSION before its handshake; read until `DONE`; require major 1 and a `MECH\tPLAIN` line; send `AUTH\t<id>\tPLAIN\tservice=<service>\t[rip=..\t]secured\tno-penalty?\tresp=<base64(\0user\0password)>` with `resp=` last; parse `OK\t<id>\tuser=...`, `FAIL\t<id>[\tcode=temp_fail]`. Lines are TAB-separated with `\001` escapes and fit 16384 bytes.
  - `no-penalty` is **not** sent (Dovecot's penalty is the brute-force protection).
- [ ] **Step 1: Failing tests:** `test_auth_ok` (fixture replies `OK\t1\tuser=alice@example.invalid` → OK, canonical user returned; asserts the client's AUTH line ends with `resp=AGFsaWNlQGV4YW1wbGUuaW52YWxpZABzZWNyZXQ=`), `test_auth_fail` → FAIL, `test_auth_tempfail` (`code=temp_fail`) → TEMPFAIL and HTTP 503 through `mapihttp_handle`, `test_major_mismatch` (`VERSION\t2\t0`) → PROTOCOL_ERROR, `test_no_plain` → PROTOCOL_ERROR, `test_tab_in_password` (password containing TAB and LF is base64-encoded, never raw), `test_truncated_reply` (EOF mid-handshake) → PROTOCOL_ERROR, `test_overlong_line` (> 16384 bytes) → PROTOCOL_ERROR.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement; wire into `mapihttp_handle` replacing Task 1's fake. **Step 4:** run → PASS.
- [ ] **Step 5: Commit** `feat(mapihttp): verify Basic credentials through Dovecot auth`.

### Task 4: EMSMDB request types over HTTP

**Files:**
- Create: `mapiproxy/servers/default/emsmdb/emsmdb_execute.c` (extracted core), `mapiproxy/servers/mapihttp/mapihttp_emsmdb.c` (body parse/push, backend seam)
- Modify: `mapiproxy/servers/default/emsmdb/dcesrv_exchange_emsmdb.c:1149-1226` (call the extracted core; `EcDoRpc_process_transaction` becomes non-static or moves with it), `dcesrv_exchange_emsmdb.h`, `Makefile:1159-1176` (add `emsmdb_execute.po` to the module)
- Test: `testsuite/modernization/mapihttp_smoke.c`; existing `testsuite/modernization/emsmdb_smoke.c` unchanged and still passing

**Interfaces:**
- Produces:
  - `enum MAPISTATUS emsmdb_execute_buffer(TALLOC_CTX *mem_ctx, struct emsmdbp_context *ctx, const DATA_BLOB *rop_in, uint32_t flags, uint32_t max_out, DATA_BLOB *rop_out)` — exactly the checks/behavior of current lines ~1171-1219 (capacity 8..0x40000, input 8..UINT16_MAX+8, `RHEF_Last` required, XOR handling, `ecBufferTooSmall`).
  - `struct mapihttp_backend { enum MAPISTATUS (*connect)(void *priv, TALLOC_CTX *, const char *username, const char *user_dn, uint32_t lcid, void **session_ctx, const char **display_name, const char **dn_prefix); enum MAPISTATUS (*execute)(void *session_ctx, TALLOC_CTX *, const DATA_BLOB *in, uint32_t flags, uint32_t max_out, DATA_BLOB *out); void (*disconnect)(void *session_ctx); void *priv; };`
  - Body codecs (little-endian, NDR primitives with `LIBNDR_FLAG_NOALIGN`): Connect request/success/failure (2.2.4.1.1–2.2.4.1.3), Execute (2.2.4.2.1–2.2.4.2.3), Disconnect (2.2.4.3.x), NotificationWait (2.2.4.4.x; returns `EventPending` 0 after `mapihttp:notification_wait_seconds`, default 300 per 3.2.2).
  - Production backend: `connect` = `emsmdbp_init` + the user-DN checks of `emsmdb_connect_context` with the username from Task 3 instead of a `dcesrv_call_state`. Under the current code it fails without SamDB (decision 5).
- [ ] **Step 1: Failing tests** (fake backend records arguments):
  - `test_connect_body`: UserDn `"/o=example/ou=first/cn=Recipients/cn=alice"`, Flags 0, LcidString 0x409 → backend receives them; success body round-trips DnPrefix and DisplayName.
  - `test_execute_roundtrip`: RopBuffer bytes forwarded unchanged; returned rgbOut placed in RopBuffer; StatusCode 0.
  - `test_execute_truncated`: RopBufferSize 100 with 20 bytes present → code 12, backend not called.
  - `test_execute_maxropout_too_big`: MaxRopOut 0x40001 → `ecRpcFailed` in ErrorCode, as the RPC path does.
  - `test_notification_wait_timeout`: with wait set to 1 s, returns EventPending 0 and refreshes the session expiry (3.2.5.5).
  - `test_rpc_module_unchanged`: `make check-emsmdb` still passes (run in Step 4).
- [ ] **Step 2:** run → FAIL. **Step 3:** extract and implement. **Step 4:** `make check-mapihttp check-emsmdb` → PASS.
- [ ] **Step 5: Commits** `refactor(emsmdb): share the ROP execution core` then `feat(mapihttp): serve Connect, Execute, Disconnect and NotificationWait`.

### Task 5: Autodiscover POX

**Files:**
- Create: `mapiproxy/servers/mapihttp/autodiscover.c`
- Test: `testsuite/modernization/mapihttp_smoke.c`, fixtures in `testsuite/modernization/mapihttp/*.xml`

**Interfaces:**
- Produces: `void autodiscover_handle(struct mapihttp_server *, TALLOC_CTX *, const struct mapihttp_request *, const char *x_mapihttp_capability, struct mapihttp_reply *)` routed for POST `/autodiscover/autodiscover.xml` (MS-OXDSCLI 3.2.5); same Basic/Dovecot authentication; the authenticated user must equal the requested `EMailAddress` (no lookups for other users).
- Configuration: `mapihttp:external_host` (e.g. `mail.example.invalid`), used to build `https://<host>/mapi/emsmdb/?MailboxId=<mailbox>` and `/mapi/nspi/?MailboxId=<mailbox>` like MS-OXDSCLI 4.4.
- [ ] **Step 1: Failing tests:** `test_autodiscover_mapihttp` (header `X-MapiHttpCapability: 1`, request for `alice@example.invalid` → response namespace `http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006`, `Protocol Type="mapiHttp" Version="1"`, MailStore and AddressBook each with `ExternalUrl`, no `EXCH`/`EXPR`), `test_autodiscover_capability_2` (value 2 → still Version 1, the highest supported ≤ 2), `test_autodiscover_capability_invalid` (`0`, `abc` → treated as absent per 3.2.5.1 → Error response), `test_autodiscover_other_user` (authenticated bob asks for alice → Error, no data about alice), `test_autodiscover_malformed_xml` and `test_autodiscover_entity_expansion` (DOCTYPE with entities → rejected), `test_autodiscover_get` → 405 or Error (POST only).
- [ ] **Step 2:** run → FAIL. **Step 3:** implement with expat (`XML_SetEntityDeclHandler` stops parsing). **Step 4:** run → PASS.
- [ ] **Step 5: Commit** `feat(mapihttp): answer Autodiscover with MAPI/HTTP settings`.

### Task 6: Sanitizers, nginx example, documentation, regression

**Files:**
- Create: `doc/MAPIHTTP.md` (configuration keys, nginx example block with `server_name mail.example.invalid`, `location /mapi/` and `= /autodiscover/autodiscover.xml` → `proxy_pass http://127.0.0.1:<port>`, `proxy_buffering off`, `proxy_read_timeout 330s`, `client_max_body_size 16m`, `proxy_set_header X-Real-IP $remote_addr`)
- Modify: `doc/MODERNIZATION.md` (dated M1 section: done/validated/not validated), `doc/CONTINUITY.md`, `testsuite/README.md`

- [ ] **Step 1:** `make -W testsuite/modernization/mapihttp_smoke.c check-mapihttp CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'` → PASS; rebuild plain.
- [ ] **Step 2:** `make all` and the 17 targets from `doc/CONTINUITY.md`, plus `check-mapihttp` → PASS; plain configure proves the default build is unaffected.
- [ ] **Step 3:** Document explicitly **not validated**: real Dovecot, nginx, TLS, any Outlook version, Interop-TestSuites, NSPI request types, chunked/PENDING responses, Connect success without SamDB (M2), Outlook's Basic-auth behavior with Microsoft 365 builds.
- [ ] **Step 4: Commit** `docs: record MAPI/HTTP service validation and limits`.
- [ ] **Step 5:** Report and wait for approval before any push.

## Lab acceptance (after Tasks 1–6, on the disposable VM)

Record Windows build and each Outlook edition/version/build. On at least one Outlook 2016 or 2019 and one classic Microsoft 365 Outlook (2013 SP1 if licensed): Autodiscover request and response with `mapiHttp`; Basic prompt accepted via Dovecot; Connect reaches the service and the response is logged. Full profile creation is expected only after M2 (decision 5).
