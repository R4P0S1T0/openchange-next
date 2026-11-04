# Rust MAPI/HTTP service (M1)

`openchange-mapihttpd` serves Autodiscover POX and `/mapi/emsmdb/` on
127.0.0.1 behind nginx. Basic credentials are checked through Dovecot's auth
protocol v1.3; Bearer and missing credentials receive a Basic challenge before
the body is read. Use only a disposable lab VM at this stage.

Request bodies are capped at 16 MiB for MAPI/HTTP and 64 KiB for Autodiscover.

The C backend deliberately rejects every Connect with `MAPI_E_LOGON_FAILED`
until M2 verifies the Dovecot identity against PostfixAdmin and the LegacyDN.
M1 therefore cannot create an Outlook profile or serve mailbox content.
`/mapi/nspi/` serves the address book from the directory snapshot (see
"Address book (M2b)" below).

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
| `--directory-snapshot PATH` | `/var/lib/openchange/directory.tsv`; GAL for `/mapi/nspi/` |

Autodiscover assumes Dovecot returns a canonical full email address. Verify
that in the lab. It returns only the authenticated user's settings, requires
positive `X-MapiHttpCapability`, rejects DOCTYPE, and ignores session cookies.
The mailbox GUID is a stable version 8 UUID derived from the lower-cased email.
M2 will replace the temporary identity strings with directory data.

Sessions use a random `MapiContext` cookie (`Secure; HttpOnly`, `Path=/mapi/emsmdb/`
or `/mapi/nspi/`: each endpoint has its own Session Contexts)
and a keyed credential hash. PING refreshes their idle clock. Idle sessions
are swept every 60 seconds; Disconnect releases the backend handle. A restart
invalidates all sessions. Dovecot exchanges time out after 10 seconds, with
temporary failure returning HTTP 503. Passwords, Authorization and cookies
must never be logged or captured.

One ordinary request and one NotificationWait may run concurrently on a
session (MS-OXCMAPIHTTP 3.1.5.5); a second request in either slot gets code 15.
Pending requests prevent idle expiry, and completion restarts the idle clock.

## Directory (M2a)

PostfixAdmin's MariaDB stays the source of truth. `openchange_directory_sync`
reads `mailbox` and `domain` (read-only) and writes a plain LDB file that the
C backend opens through smb.conf `mapiproxy:directory_url` (for example
`tdb:///var/lib/openchange/directory.ldb`). No AD, LDAP server or Samba
daemon is involved; when the option is unset, the legacy SamDB path is used.

```sh
openchange_directory_sync --mysql-defaults /etc/openchange/directory-my.cnf \
  --org "First Organization" --ou "Exchange Administrative Group (FYDIBOHF23SPDLT)" \
  --output /var/lib/openchange/directory.ldb
```

The option file holds a `[client]` section for a user with `SELECT` on the two
tables only; keep it mode 0600. `--org`/`--ou` must match the daemon's flags.
The file is rebuilt in a temporary file and renamed, mode 0660 with group
`openchange` when that group exists (ldb's tdb backend opens files read-write even
for read-only connects); a failed run leaves the previous file.
Run it from a systemd timer (60 seconds): a mailbox created, disabled or
removed in PostfixAdmin reaches new Connects within one timer period, while
existing MAPI/HTTP sessions live until their idle timeout.

Each mailbox becomes `CN=<email>,CN=Users,DC=openchange` with
`sAMAccountName`/`mail` = the lower-case email (Dovecot's canonical user),
`mailNickname` = local part (bytes outside `[a-z0-9._-]` as `_`) + `-` + the
first 8 hex digits of SHA-256 of the email, and
`legacyExchangeDN` = `/o=<org>/ou=<ou>/cn=Recipients/cn=<mailNickname>`.
An account is enabled (`msExchUserAccountControl` 0) only when both the
mailbox and its domain are active.

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

Use Debian 13's packaged versions by default. The maintainer authorized
bytes 1.11.1 and quick-xml 0.41.0 from crates.io for security fixes; both support
Rust 1.85 and are included in vendor/. Commit Cargo.lock,
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

## Address book (M2b)

`openchange_directory_sync` also writes `directory.tsv` beside the LDB (or
`--snapshot PATH`): one active mailbox per line, lower-case address, TAB,
display name; mode 0640, group `openchange`, replaced atomically. The daemon
reloads it when its content changes. It is the Global Address List: one
container, mail users only, sorted by display name. Nicknames and LegacyDNs
come from the same functions as Autodiscover and the C directory.

Request types served: Bind, Unbind, GetSpecialTable (the GAL row), DNToMId,
QueryRows, GetProps, GetPropList, QueryColumns, UpdateStat, CompareMIds,
ResolveNames, SeekEntries (display name), GetMatches (the CurrentRec object,
or a property/content restriction on ANR, display name, SMTP address or
account, matched by prefix) and GetTemplateInfo (answers MAPI_E_NO_SUPPORT:
no display templates). Other request types (ModProps, ModLinkAtt,
ResortRestriction, GetMailboxUrl, GetAddressBookUrl) still return code 5;
Outlook 16.0.19127 did not send them in the lab. Minimal Entry IDs carry the
snapshot generation, so a MId from an older snapshot never names another
mailbox. Names, addresses and search strings are never logged. The bodies
Outlook sent are fixtures in `testsuite/modernization/mapihttp/`.

## IMAP mail folders (M3)

`mapistore_imap.so` (built when `libetpan-dev` is present; `--disable-imap-backend`
to skip) is installed in `$(libdir)/mapistore_backends` and shows the user's
Dovecot mailbox, read-only. smb.conf `[global]`:

| Option | Default / purpose |
| --- | --- |
| `mapistore:imap_master_password_file` | Required (or `imap_tunnel`); 0600 file with the Dovecot master user's password |
| `mapistore:imap_master_user` | `openchange`; logs in as `<user>*<master>` (`auth_master_user_separator = *`) |
| `mapistore:imap_host` / `imap_port` | `127.0.0.1` / `143`; STARTTLS is required for any non-loopback host |
| `mapistore:imap_max_message_size` | `33554432`; larger messages open with a notice instead of their body |
| `mapistore:imap_tunnel` | A command speaking PREAUTH IMAP on stdio with `$USER` set (tests: Dovecot's `imap` binary) |

Dovecot needs a master passdb restricted to loopback, for example a
`passwd-file` `/etc/dovecot/master-users` (0640 root:dovecot) with
`openchange:{SHA512-CRYPT}…::::::allow_nets=127.0.0.1/32,::1/128` and
`passdb openchange-master { driver = passwd-file; master = yes; passwd_file_path = /etc/dovecot/master-users }`.

INBOX, `\Drafts`, `\Sent` and `\Trash` take over Outlook's Inbox, Drafts,
Sent Items and Deleted Items (their folder IDs are kept); every other
top-level mailbox appears under the mailbox root with its subfolders.
`\Noselect`, `\NonExistent` and `\All` mailboxes are not shown. Messages are
listed from one UID FETCH per folder open and opened with `BODY.PEEK[]`, so
reading in Outlook never marks a message read on the server (M4). If Dovecot
cannot be reached, logon still succeeds with the folders already known. No
subject, address, body or password is logged.

## Validation limits

Unit tests use fake backends, in-memory HTTP streams and a local fake Dovecot
UNIX socket. C tests use disposable LDB files and malformed buffers, without a
production mailbox or network server. The sanitized Task 0 captures test
parsing; they are not captures of this Rust service.

Not validated against this implementation: real Dovecot, nginx, TLS, any
Outlook version, Interop-TestSuites, NSPI request types Outlook did not send, chunked or
PENDING responses, successful C Connect, profile creation, mailbox content,
or a complete SamDB-free deployment. Task 0 observed only classic Microsoft
365 Outlook 16.0.19127.20800; Outlook 2016/2019/2013 SP1 still need lab runs.
Record the actual build/check results in [MODERNIZATION.md](MODERNIZATION.md)
and follow the plan's lab acceptance separately.

## Review decisions and deferred minor findings (2026-10-30)

### Audit gate after the first push

The maintainer authorized a push and a merge only after green CI. Commit
`6762d705` was pushed; its native-library and three Python jobs passed, while
the Rust job failed. Local cargo-audit 0.21.2 reproduced an inability to parse
CVSS 4.0 in the current advisory database. The workflow now uses 0.22.1,
successfully built with Rust 1.85.1. Against database commit
`2295466c4e9df26647fd67d8fa1c705ac2fc7f81`, it initially reported:

| Advisory | Locked crate | Patched version |
| --- | --- | --- |
| RUSTSEC-2026-0007 | bytes 1.9.0 | >=1.11.1 |
| RUSTSEC-2026-0194 | quick-xml 0.36.1 | >=0.41.0 |
| RUSTSEC-2026-0195 | quick-xml 0.36.1 | >=0.41.0 |

The maintainer authorized these two upstream security updates beyond the
Debian 13 package ceiling. bytes 1.11.1 and quick-xml 0.41.0 are pinned,
vendored and compatible with Rust 1.85; no other locked version changes.
The updated audit returns exit status 0 and zero vulnerabilities without any
suppression. The XML reader handles quick-xml's separate GeneralRef events,
preserving entity decoding and whitespace, with a regression test.

Two informational warnings remain, with these dispositions:

- Unmaintained adler 1.0.2 (RUSTSEC-2025-0056) belongs only to the unused,
  pruned backtrace chain. The supported Linux service does not compile it;
  revisit before enabling taskdump/backtrace or expanding supported targets.
- Tokio 1.43.1's AsyncFd constructors are unsound (RUSTSEC-2026-0386).
  The service never calls those APIs; its TCP and UNIX socket types use
  PollEvented instead. Keep this warning visible and revisit if adding AsyncFd.

No advisories are ignored in configuration. A passing version audit is scoped
to the database revision above; it does not establish live interoperability.
The final code (`de5387f6`) passed all ten checks in
[push CI](https://github.com/R4P0S1T0/openchange-next/actions/runs/41116650682) and
[PR CI](https://github.com/R4P0S1T0/openchange-next/actions/runs/41116658873).
The maintainer-authorized merge into main includes that code and these updated
handoff records. Live lab acceptance remains outstanding.

### Earlier code review

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
| Autodiscover XML validation | Multiple roots, namespaces and attributes are not fully validated; CDATA can reject otherwise valid requests; settings still belong only to the authenticated user |
| PING credential mismatch | A mismatched live cookie falls back to authentication instead of code 10; the original session is untouched; reconcile this with section 3.2.5.1 before claiming full conformance |

The known delayed reconnect cleanup and absent PENDING keep-alives remain
explicit M1 limitations. A cancelled successful C Connect could retain a
worker handle without an HTTP session; real C Connect cannot succeed in M1,
so cancellation cleanup must accompany the M2 success path.
