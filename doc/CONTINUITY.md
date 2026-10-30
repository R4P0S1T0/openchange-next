# Development continuity — 2026-10-30

## Reviewed implementation

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
now. A mailbox content backend still needs selection and qualification, and
modern Outlook transport/authentication/Autodiscover need implementation and
integration. No AD, Samba RPC, SMTP, SOGo or Outlook exchange has been validated.
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
choose a bounded item from the remaining blockers, and preserve existing work.
