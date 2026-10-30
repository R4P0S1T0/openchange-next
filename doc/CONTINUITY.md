# Development continuity — 2026-10-30

## Next step for the next agent

The maintainer changed the project direction on 2026-10-30; read
[project direction](MODERNIZATION.md#project-direction-2026-10-30) first.
Target: Outlook 2013 SP1+ (2016/2019/2021/2024, classic Microsoft 365) over
MAPI/HTTP only, against Postfix, Dovecot 2.4, SOGo 5.12, MariaDB/PostfixAdmin
and nginx on one server, with no AD, LDAP or Samba daemon.

**Next milestone: M1** — MAPI/HTTP, Autodiscover and Dovecot authentication.
Plan: [`docs/plans/2026-10-30-m1-mapihttp-autodiscover.md`](../docs/plans/2026-10-30-m1-mapihttp-autodiscover.md).
Its eight design decisions need maintainer approval before any code is written.
The [dav calendar plan](../docs/plans/2026-10-30-mapistore-dav-calendar-readonly.md)
is deferred until after M1 (milestone M6) and has not started.

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

New targets (`check-mapihttp`, `check-mapistore-dav`) must also run with
`CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'`. SQL tests use
only an explicit disposable endpoint. Push only after asking the maintainer.

## Open questions (2026-10-30)

1. **M1 acceptance vs SamDB.** `emsmdbp_init` fails without SamDB
   (`mapiproxy/servers/default/emsmdb/emsmdbp.c:44`, `:86`) and RopLogon queries
   it (`oxcstor.c:71`). Either M1's lab acceptance stops at a well-formed Connect
   response and profile creation moves to M2, or M2's directory seam moves into
   M1 (M1 plan, decision 5).
2. **HTTP server choice.** Recommended: own daemon with libmicrohttpd on
   127.0.0.1 (M1 plan, decision 1); FastCGI rejected.
3. **SOGo trusted proxy on DAV routes.** Whether SOGo 5.12 honours
   `SOGoTrustProxyAuthentication` on `/SOGo/dav` was not verified. Open SOGo
   issue [#5987](https://bugs.sogo.nu/view.php?id=5987) (5.10.0) reports
   credentials not being checked on DAV/ActiveSync in that mode; test on the lab VM.
4. **Autodiscover without `X-MapiHttpCapability`.** The plan returns an error;
   confirm on each Outlook build that the header is sent (MS-OXDSCLI 3.2.5.1).
5. **Outlook and Basic authentication.** Recent classic Microsoft 365 builds may
   prefer modern authentication; the Basic prompt flow against a non-Microsoft
   server is unverified.
6. **Interop-TestSuites.** The repository is active (not archived, last push
   2025-06-25) and contains `MS-OXCMAPIHTTP`, but its documented system under
   test is Exchange 2007–2016; running it against this server is unverified.
7. **"New Outlook" for Windows** is out of scope; risk that target users are
   migrated away from classic Outlook.
8. **Session idle timeout.** The specification fixes no value; the plan uses
   1800 s as an implementation choice.


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
planned), and the MAPI/HTTP transport, Dovecot authentication and Autodiscover
(M1) are not implemented. No Dovecot, SMTP, SOGo, MariaDB/PostfixAdmin
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
start with milestone M1 once its plan's decisions are approved, and preserve
existing work.
