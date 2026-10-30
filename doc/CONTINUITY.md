# Development continuity — 2026-10-30

## Next step for the next agent

The maintainer changed the project direction on 2026-10-30; read
[project direction](MODERNIZATION.md#project-direction-2026-10-30) first.
Target: Outlook 2013 SP1+ (2016/2019/2021/2024, classic Microsoft 365) over
MAPI/HTTP only, against Postfix, Dovecot 2.4, SOGo 5.12, MariaDB/PostfixAdmin
and nginx on one server, with no AD, LDAP or Samba daemon.

**M1 implementation is integrated locally on `m1-rust`.** Tasks 1–4 were
previously reviewed; Tasks 5–6 have now been reviewed and merged, including
NotificationWait concurrency and native build fixes. Task 7 records validation
in [MAPIHTTP.md](MAPIHTTP.md) and the dated M1 section in
[MODERNIZATION.md](MODERNIZATION.md#m1-local-validation-2026-10-30).
Plan: [`docs/plans/2026-10-30-m1-mapihttp-autodiscover.md`](../docs/plans/2026-10-30-m1-mapihttp-autodiscover.md)
(revision 2, approved; the earlier approval wait is obsolete).

Next: obtain maintainer approval before pushing or merging to `main`, run the
updated CI, then perform the plan's lab acceptance against real Dovecot/nginx
and Outlook on a disposable VM. C Connect deliberately fails closed until M2
implements Dovecot-user/PostfixAdmin-mailbox/LegacyDN identity verification.
Profile creation remains M2 acceptance. Dovecot's canonical user must be a full
email address for the current Autodiscover implementation; verify this in lab.

The whole-branch review found no Critical issues. Its Important findings were
missing C-backend CI and versions above the Debian 13 cap; both are corrected.
The local build also exposed missing transitive-library search paths, now fixed.
The protocol exception in MS-OXCMAPIHTTP 3.1.5.5 overrides the plan's blanket
one-request concurrency summary: NotificationWait has a separate in-flight slot.
Deferred minor findings and deliberate limits are listed in MAPIHTTP.md.
Revision 1's unfinished C daemon remains reference-only on `m1-mapihttp`.
The [DAV calendar plan](../docs/plans/2026-10-30-mapistore-dav-calendar-readonly.md)
remains deferred to M6. No production deployment is authorized.

Do not touch:

- `.build/worktrees/task1-ldb-reverse` (do not reapply its diff to `main`, do not delete it);
- `.superpowers/sdd/`, `.build/sql-lab-*`;
- the untracked draft `docs/plans/2026-10-29-openchange-incremental-namedprops.md`;
- any production server, existing AD/schema, or global machine configuration.

Verification commands already used. Run them through the extracted toolchain
wrapper, which sets `PATH`, `PKG_CONFIG_*`, `CPPFLAGS` and `LDFLAGS` for
`/tmp/openchange-build-tools/root` (no system packages are installed):

```sh
python3 /tmp/openchange-build-tools/run.py make all
python3 /tmp/openchange-build-tools/run.py make check-binary-properties \
  check-property-blobs check-recipient-blobs check-propsdump \
  check-libmapi-modernization check-ndr-modernization check-mapiadmin \
  check-ocpf-lexer check-mapiproxy-registries check-mapiproxy-rpc \
  check-asyncemsmdb check-nspi check-emsmdb check-mpm-pack check-mpm-cache \
  check-namedprops check-mysql-utils
```

New C targets (`check-oc-emsmdb`, `check-mapistore-dav`) must also run with
`CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'`; Rust code
must pass `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` and
`cargo audit`. Rust is not installed system-wide here: Debian 13 `rustc`,
`cargo`, `rust-clippy` and `rustfmt` are extracted into the toolchain root
(M1 Task 1, Step 0), as libmicrohttpd 1.0.1 already was for revision 1. SQL tests use
only an explicit disposable endpoint. Push only after asking the maintainer.

## Decisions and open questions (2026-10-30)

Decided by the maintainer:

- Language policy: new code is written in Rust; the existing C core
  (libmapi, emsmdb, nspi, mapistore) stays in C and keeps being fixed.
  Migrate C code only gradually and only with a clear gain, as a separately
  planned change. Rust reaches C only through narrow C APIs (bytes, strings,
  integers, opaque handles; talloc stays in C); no `unsafe` outside the FFI
  module; crates are vendored.

- M1 acceptance is Autodiscover + Dovecot authentication + a well-formed
  Connect response, including a real Outlook Connect captured in the lab and
  used (sanitized) as a test fixture. Outlook profile creation moves to M2,
  because `emsmdbp_init` and RopLogon need SamDB today
  (`mapiproxy/servers/default/emsmdb/emsmdbp.c:44`, `:86`; `oxcstor.c:71`).
- HTTP server: own daemon on 127.0.0.1, in Rust (hyper/tokio) since plan
  revision 2; libmicrohttpd (revision 1) is dropped.
- SOGo DAV: no `SOGoTrustProxyAuthentication` (open SOGo issue
  [#5987](https://bugs.sogo.nu/view.php?id=5987)) and no SOGo configuration
  change. The DAV backend forwards the user's Basic credentials, held in session
  memory only, never on disk or in logs.
- Autodiscover without `X-MapiHttpCapability` returns an error.
- Interop-TestSuites is optional, after M2. The repository is active (not
  archived, last push 2025-06-25) and contains `MS-OXCMAPIHTTP`; its documented
  system under test is Exchange 2007–2016.
- The Windows "new Outlook" stays out of scope as a recorded risk; the session
  idle timeout of 1800 s is an implementation choice (the specification fixes
  no value).

Answered in the lab (M1 Task 0, 2026-10-30): classic Microsoft 365 Outlook
16.0.19127.20800 accepts Basic after a 401, sends `X-MapiHttpCapability: 1`,
accepts the `mapiHttp` Autodiscover response and sends Connect. A client-side
authenticating HTTP proxy must have the server host in its exceptions.

Still open (answered in the lab):

1. Do Outlook 2016/2019 (and 2013 SP1 if licensed) behave the same? (M1 lab
   acceptance)
2. Does Outlook stop sending Bearer first once it holds a session cookie?
   The specification does not say (M1 lab acceptance).
3. Does SOGo DAV accept Basic credentials for an account with TOTP enabled? (M6)

## Reviewed implementation (named properties)

Commit `5cab4bdb29bff508cd38fc491ac0f1f1865bfc9c` on `main` contains the completed
five-task named-property increment. It was pushed to
[R4P0S1T0/openchange-next](https://github.com/R4P0S1T0/openchange-next/commit/5cab4bdb29bff508cd38fc491ac0f1f1865bfc9c).
Separate task and whole-set compliance/quality reviews approved it with no
open findings. Do not repeat these tasks:

1. Validate LDB reverse-name records, numeric IDs, UTF-16 sizes and ownership.
2. Guard GetNamesFromIDs context, input and response allocation boundaries.
3. Require exactly SQL migration version 3; distinguish exact table absence
   from lookup failure without automatically migrating existing tables.
4. Recover failed transaction-start cleanup through own-session termination,
   retaining the borrowed MYSQL handle and returning the original error.
5. Consolidate tests, installation checks and documentation.

See [modernization evidence](MODERNIZATION.md#named-property-consolidated-validation-2026-10-30),
[named-property upgrade/recovery](NAMED_PROPERTIES_UPGRADE.md),
[test commands](../testsuite/README.md) and [staged installation](TEST_INSTALL.md).

## Verified scope

- Incremental default build, 40 tooling tests and 28 Python runtime tests passed;
  the Python runs had no skips after granting required local socket access.
- Live SQL checks passed against private MariaDB 11.8.6 with TCP disabled.
- Four focused harnesses passed ASan/UBSan with default leak detection; ordinary
  binaries were explicitly rebuilt afterward. Dependencies were not instrumented.
- Private DESTDIR installation recorded 149 entries and 11 successful runtime
  checks; uninstall left zero files or symlinks.
- A follow-up passed all 17 non-live focused native Make targets on the same
  source contents: binary-properties, property-blobs, recipient-blobs, propsdump,
  libmapi-modernization, ndr-modernization, mapiadmin, ocpf-lexer,
  mapiproxy-registries, mapiproxy-rpc, asyncemsmdb, nspi, emsmdb, mpm-pack,
  mpm-cache, namedprops and mysql-utils (each with the `check-` prefix).

The baseline uses Debian 13, GCC 14.2.0, Python 3.13.5 and Samba/PIDL 4.22.10.
The follow-up reused the existing isolated build and extracted toolchain; it
was not another fresh bootstrap or an assessment of dependency advisories.
GitHub [CI run 41052249892](https://github.com/R4P0S1T0/openchange-next/actions/runs/41052249892)
for implementation commit `5cab4bdb` completed successfully. The public API
confirmed all four jobs: native-library, tooling (3.11), tooling (3.13) and
python-runtime. This result applies to that commit, not later documentation
commits or a deployed server.

## Remaining blockers

[Server readiness](TEST_SERVER_READINESS.md) and the [lab phases](TEST_LAB_PLAN.md)
remain binding. Inventory and an isolated build on a disposable VM are useful
now. No mailbox content backend exists yet (IMAP for M3/M4 and DAV for M6 are
planned), and the Rust MAPI/HTTP transport, Dovecot authentication and Autodiscover
are implemented only on the milestone branch; only the Task 0 lab spike has
talked to a real Outlook. No Dovecot, SMTP, SOGo, MariaDB/PostfixAdmin
directory or Outlook exchange has been validated.
Do not infer a working mail server from harness or installed-module checks.

Retained technical limits: SQL version metadata does not prove physical
constraints; failed session termination/reconnect restoration can require manual
recovery; simultaneous threaded use of one pooled MYSQL handle is unsupported;
the preserved legacy ROP `0xff` marker can fail generated NDR serialization.

## Local handoff and authorization

The reviewed implementation checkout remains preserved at
`.build/worktrees/task1-ldb-reverse` (an independent detached checkout at the old
base, with the reviewed implementation uncommitted). Root `main` contains the
published implementation commit. Do not reapply that checkout's complete diff
onto `main` or delete it automatically. Local reports and logs are under
`.superpowers/sdd/2026-10-29-openchange-incremental-namedprops/`; they are ignored
artifacts, not required to build a fresh clone. A pre-existing untracked draft
plan under `docs/plans/` was left untouched and is not the current status source.

The private SQL instance is stopped. Its data directory is preserved under
`.build/sql-lab-scvbzafx`, including one failed-run fixture database. Never fall
back to production SQL when repeating tests; select an explicit disposable
endpoint through the documented test environment variables.

The user authorized continued work and local commits/pushes to this fork to
preserve progress. This does not authorize production deployment, destructive
cleanup, existing-domain/schema changes or global machine configuration.
Before new implementation, inspect current Git state and relevant instructions,
continue from the milestone branch after reading the current validation record,
and preserve existing work. The current instruction requires approval before
any push or merge to main.
