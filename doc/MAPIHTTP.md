# Rust MAPI/HTTP service (M1)

`openchange-mapihttpd` serves Autodiscover POX and `/mapi/emsmdb/` on
127.0.0.1 behind nginx. Basic credentials are checked through Dovecot's auth
protocol v1.3; Bearer and missing credentials receive a Basic challenge before
the body is read. Use only a disposable lab VM at this stage.

Request bodies are capped at 16 MiB for MAPI/HTTP and 64 KiB for Autodiscover.

The C backend deliberately rejects every Connect with `MAPI_E_LOGON_FAILED`
until M2 verifies the Dovecot identity against PostfixAdmin and the LegacyDN.
M1 therefore cannot create an Outlook profile or serve mailbox content.
`/mapi/nspi/` supports PING only; Bind and other NSPI operations return code 5.

## Build and checks

Use Rust 1.85 and the native dependencies described in
[MODERNIZATION.md](MODERNIZATION.md). With the appropriate Samba paths:

```sh
./autogen.sh
./configure --enable-mapihttp --with-samba=/usr
make -j2 all
make check-emsmdb check-oc-emsmdb check-mapihttp
cargo fmt --check
cargo clippy --offline --locked --all-targets -- -D warnings
OC_EMSMDB_LIBDIR="$PWD/mapiproxy/servers" \
  cargo clippy --offline --locked --all-targets --features c-backend -- -D warnings
```

The default configure leaves MAPI/HTTP disabled and needs no Rust toolchain.
The enabled Make build links `liboc_emsmdb`; bare Cargo builds without
`c-backend` use a backend that refuses Connect. `make check-mapihttp` runs both
variants, preparing a private LDB configuration for the C integration test.
Standalone C-feature tests also need `OC_EMSMDB_SMB_CONF` pointing at that
fixture and the native library directories in `LD_LIBRARY_PATH` (see Makefile).

## Options

| Option | Default / purpose |
| --- | --- |
| `--port PORT` | Required; listens on 127.0.0.1 only |
| `--dovecot-socket PATH` | Required; Dovecot auth-client UNIX socket |
| `--dovecot-service NAME` | `openchange`; passdb service scope |
| `--external-host HOST` | Required; public HTTPS host in Autodiscover URLs |
| `--org NAME` | `First Organization`; temporary LegacyDN organization |
| `--ou NAME` | `Exchange Administrative Group (FYDIBOHF23SPDLT)` |
| `--session-idle-seconds SECONDS` | `1800`; positive idle timeout |
| `--notification-wait-seconds SECONDS` | `300`; positive wait with EventPending 0 |
| `--smb-conf PATH` | Required with `c-backend`; native provider configuration |

Autodiscover assumes Dovecot returns a canonical full email address. Verify
that in the lab. It returns only the authenticated user's settings, requires
positive `X-MapiHttpCapability`, rejects DOCTYPE, and ignores session cookies.
The mailbox GUID is a stable version 8 UUID derived from the lower-cased email.
M2 will replace the temporary identity strings with directory data.

Sessions use a random `MapiContext` cookie (`Secure; HttpOnly; Path=/mapi/`)
and a keyed credential hash. PING refreshes their idle clock. Idle sessions
are swept every 60 seconds; Disconnect releases the backend handle. A restart
invalidates all sessions. Dovecot exchanges time out after 10 seconds, with
temporary failure returning HTTP 503. Passwords, Authorization and cookies
must never be logged or captured.

One ordinary request and one NotificationWait may run concurrently on a
session (MS-OXCMAPIHTTP 3.1.5.5); a second request in either slot gets code 15.
Pending requests prevent idle expiry, and completion restarts the idle clock.

## Lab systemd example

Install the binary and native libraries in the paths used below, create a
dedicated `openchange` account, and grant it access to the auth socket and
private provider state. These are deployment prerequisites, not actions taken
by the build. Configure the Dovecot auth-client listener to permit this account
and its passdb to accept `service=openchange`; do not use the auth-master socket.

```ini
[Unit]
Description=OpenChange MAPI/HTTP lab service
After=network.target dovecot.service
Requires=dovecot.service

[Service]
User=openchange
Group=openchange
ExecStart=/usr/local/sbin/openchange-mapihttpd --port 8080 --dovecot-socket /run/dovecot/auth-client --external-host mail.example.invalid --smb-conf /etc/openchange/smb.conf
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=multi-user.target
```

The native provider still loads its configuration and state. M1 does not
provide a SamDB-free provisioning procedure; that is M2 work. No Samba daemon
is required. Ensure the installed shared libraries are discoverable by the
dynamic loader before starting the unit.

## nginx example

Use a trusted certificate for the lab hostname. Keep access logging disabled
for these locations; never add Authorization, cookies or bodies to diagnostics.

```nginx
server {
    listen 443 ssl;
    server_name mail.example.invalid;
    ssl_certificate /etc/ssl/certs/mail.example.invalid.pem;
    ssl_certificate_key /etc/ssl/private/mail.example.invalid.key;
    client_max_body_size 16m;

    location /mapi/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_read_timeout 330s;
        access_log off;
    }

    location = /autodiscover/autodiscover.xml {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_read_timeout 330s;
        access_log off;
    }
}
```

The service trusts X-Real-IP only from a TCP peer at 127.0.0.1; nginx must
overwrite it as shown. It forwards Basic authentication by default. M1 sends
one complete response with PROCESSING/DONE and no periodic PENDING data,
including during NotificationWait. Keep the timeout above the configured wait
(330 seconds for the default 300). Client pending-period interoperability
remains unvalidated; a proxy timeout alone does not establish compliance.
Reconnect currently leaves the previous session for the idle sweeper.

Put the Autodiscover and MAPI/HTTP host in the Windows/client proxy and PAC
exceptions. The Task 0 spike found that an authenticating client proxy can
prevent Outlook from reaching the service.

## Refresh vendored dependencies

Keep versions at or below Debian 13's packaged versions, and commit Cargo.lock,
the vendor tree and `.cargo/config.toml` together. On a development machine
with network access, deliberately update the required locked versions, then:

Direct dependencies use exact versions. Check transitive versions against
Debian 13's `librust-*-dev` packages too: regenerating a lockfile can raise
them even when the direct versions remain pinned. Optional backtrace sources
are also capped; backtrace 0.3.69 keeps miniz_oxide within Debian's 0.7 line.

```sh
cargo vendor --locked --versioned-dirs vendor
sh script/vendor-prune.sh
cargo test --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo audit
```

Preserve the existing crates.io replacement in `.cargo/config.toml`.
`vendor-prune.sh` must run from the repository root with GNU sed; it removes
sources for unused Windows/WASI and optional backtrace crates. Linux builds
are supported; those pruned targets are not. Audit requires a separately
installed cargo-audit and network access to the advisory database. The CI
Rust job records its own audit result; a local offline build is no audit.

## Validation limits

Unit tests use fake backends, in-memory HTTP streams and a local fake Dovecot
UNIX socket. C tests use disposable LDB files and malformed buffers, without a
production mailbox or network server. The sanitized Task 0 captures test
parsing; they are not captures of this Rust service.

Not validated against this implementation: real Dovecot, nginx, TLS, any
Outlook version, Interop-TestSuites, NSPI operations beyond PING, chunked or
PENDING responses, successful C Connect, profile creation, mailbox content,
or a complete SamDB-free deployment. Task 0 observed only classic Microsoft
365 Outlook 16.0.19127.20800; Outlook 2016/2019/2013 SP1 still need lab runs.
Record the actual build/check results in [MODERNIZATION.md](MODERNIZATION.md)
and follow the plan's lab acceptance separately.

## Review decisions and deferred minor findings (2026-10-30)

The Task 5/6 review and a separate whole-branch review found no Critical
issues. NotificationWait exclusion, the daemon's library prerequisites/search
path, C-backend CI coverage and Debian version ceilings were fixed. The
NotificationWait correction follows section 3.1.5.5 rather than the plan's
blanket concurrency summary; the regression test first failed, then passed.
Dependency ceilings were checked against local Debian 13 package metadata.
Non-Linux targets have no matching Debian package and retain pruned manifests.

These minor items are deferred; they do not establish successful client
interoperability or weaken the fail-closed Connect decision:

| Item | Effect / triage |
| --- | --- |
| Broad dead-code allowances | Present on backend/FFI/session modules, not auth in the final tree; narrow them during cleanup |
| Empty Cargo-version check after version comparison | Redundant; malformed/old versions already fail configure |
| vendor-prune portability and root guard | Requires GNU sed and an existing vendor directory; documented above; add a guard before generalizing the script |
| Cargo Make prerequisites | Source/lock/manifest changes rebuild; build.rs, `.cargo/config.toml` and vendor-only edits can leave a stale copied binary; force `make -W Cargo.lock all` after those edits |
| Set-Cookie in the `echoed` array | Misleading variable name only; the value is generated by the server |
| Duplicate MapiContext cookies | Only the first is used; ambiguous duplicate requests should be rejected in a future tightening |
| Session-stage error expiration | Error replies lack X-ExpirationInfo; successful session replies include it |
| Dovecot socket test cleanup | A test panic may leave its private socket file |
| Empty Dovecot canonical `user=` | Accepted from the trusted auth socket; needs validation; cannot create a real M1 C session |
| C failed-init pointers | `oc_lp_ctx` can dangle after failed init, but Connect rejects uninitialized state and the Rust worker is one-shot |
| Symbol-check pipeline | `nm` failure can be masked by the negative grep; a successful pipeline alone is weaker evidence than a link/run |
| C integration test setup | Bare C-feature Cargo tests require the LDB seed made by `check-oc-emsmdb`; use `make check-mapihttp` |
| Binary body exhaustion | Trailing bytes and some auxiliary header inconsistencies are ignored; reads remain bounded and auxiliary content is dropped |
| Autodiscover XML validation | Multiple roots, namespaces and attributes are not fully validated; CDATA or text split by comments can reject otherwise valid requests; settings still belong only to the authenticated user |
| PING credential mismatch | A mismatched live cookie falls back to authentication instead of code 10; the original session is untouched; reconcile this with section 3.2.5.1 before claiming full conformance |

The known delayed reconnect cleanup and absent PENDING keep-alives remain
explicit M1 limitations. A cancelled successful C Connect could retain a
worker handle without an HTTP session; real C Connect cannot succeed in M1,
so cancellation cleanup must accompany the M2 success path.
