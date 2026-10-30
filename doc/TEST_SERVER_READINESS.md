# First test-server milestone

Service deployment to the test server follows the local recovery and security
preparation below, in line with the requested **40% planning milestone**. That percentage is
an approximate work estimate; it does not certify security or Exchange feature
coverage. The milestone is **not ready** as of 2026-10-30.

Inventory and an isolated source build/staged install can already run on a lab
host without starting services. The next steps and storage
blocker are recorded in [the server lab plan](TEST_LAB_PLAN.md).

Since 2026-10-30 the target is the single-server stack in the
[project direction](MODERNIZATION.md#project-direction-2026-10-30): Outlook
2013 SP1+ over MAPI/HTTP, Dovecot authentication, PostfixAdmin users in MariaDB,
IMAP and DAV backends, and **no AD, LDAP or Samba daemon**. Criteria below that
mention RPC or AD record past evidence; new evidence follows milestones M1–M7.

## Acceptance before the first deployment

| Acceptance criterion | Current evidence / remaining work |
| --- | --- |
| Build the required server, plugins and storage components from source on a selected, patched OS | Default `make -j2 all` passes from a source-only copy, including libraries, RPC modules, plugins, default servers and clients; patched deployment baseline and storage installation remain pending |
| Select and validate a mailbox content backend | The repository includes the backend loader and named-property/indexing adapters, but no production mailbox backend implementation. Selected path: new IMAP (M3/M4) and DAV (M6) backends; neither exists yet, so build and operation/ownership tests are pending |
| Pass native and Python regression checks from a source-only checkout | Focused native checks and offline client suite pass (30 successes, one known expected LZXpress failure); the 2026-10-30 follow-up passed all 17 non-live focused native Make targets, 40 Python tooling tests and 28 runtime tests with no skips, plus disposable live SQL. These are separate from the historical source-only build; complete C/server integration suites remain pending |
| Review and test exposed input and authentication boundaries | RPC state isolation, cancellation and pack validation covered; remaining NDR allocation/length handling, default servers, directory/database inputs and cache paths still need review |
| Resolve or explicitly assess security findings affecting the test configuration | Focused fixes have regression tests; repository-wide review and dependency CVE assessment are incomplete |
| Prepare reproducible installation, configuration, startup/health checks and teardown for a disposable instance | Local DESTDIR installation (149 entries), all 11 module/CLI/template runtime checks and removal with zero files/symlinks are covered; disposable mail-stack (Postfix/Dovecot/SOGo/MariaDB/nginx) configuration, startup and live health checks remain pending; no deployment to the user's server has been attempted |
| Produce a reviewable test build with exact dependency versions, checks run and known limitations | Staged install hashes and runtime/removal reports are available; exact patched deployment baseline and complete test-server artifact remain pending |

After these criteria are met, the first server test should establish the test
mail stack (Postfix, Dovecot, SOGo, MariaDB/PostfixAdmin, nginx) with test
accounts only, Autodiscover and MAPI/HTTP sessions authenticated through
Dovecot, mailbox operations and notification behavior. Starting with M1, the
MAPI/HTTP transport is also required; a mailbox backend alone does not complete
the client path.
Outlook compatibility is then measured against explicitly recorded client
versions: at least one Outlook 2016 or 2019 and one classic Microsoft 365
Outlook (2013 SP1 when licensed). Outlook 2010 is not supported; the Windows
"new Outlook" is out of scope and tracked as a risk. Those integration results cannot be inferred from compilation or
substituted backends. Production readiness requires further operational and
upgrade/restore validation beyond this first test milestone.

## Security changes completed in the recovered subset

- Administration preserves existing users, checks SAMR server errors, copies
  metadata literally and uses Samba AES password encoding without a legacy
  cipher fallback. Failed creation rolls back by the newly created account's
  handle. Focused mock-transport and real encoder checks pass; actual directory
  administration and failed-rollback recovery remain integration work.
- NSPI and EMSMDB sessions use Samba policy handles with SID, interface,
  association and authentication-level checks. Directory account ownership is
  checked against the authenticated SID; cross-account connection DNs and
  private mailbox logons are rejected. Backend and notification registration
  cleanup has focused regression coverage.
- Directory recipient and NSPI search values are escaped as literals. NSPI
  validates supported property value types and organization scoping; missing or
  duplicate organization lookups fail safely. Real LDB/TDB checks cover these
  paths; complete directory/protocol semantics remain unverified.
- Packed property readers reject truncated values, missing string terminators,
  excessive multi-value counts and unknown row flags. Nested values remain owned
  after parser destruction; failed rows publish no partial results. Recipient
  property counts/flags and recurrence array ownership have regression checks.
- MAPI NDR lengths, handle tables, RPC frame sizes/flags, compressed plus XOR
  payloads and transaction handle indexes have focused checks. Output encoding
  rejects inconsistent or oversized buffers. These checks do not cover every
  ROP's internal input validation or guarantee rollback after a buffer error.
- Authenticated RPC state uses Samba's scoped state registry. Local and remote
  association IDs are kept separate; failed outgoing connections can be retried.
- Asynchronous waits validate the handle type and cached account against the
  local directory SID and Exchange account status, separate handles and
  authentication/presentation contexts, support cancellation and release their
  fd events, resolver entries and sockets during teardown and setup failure.
- The pack plugin rejects malformed/truncated records, invalid or repeated
  positions, nested/multiple wrappers, missing array terminators and invalid
  lengths. It bounds packed positions to their one-byte wire representation and
  sizes temporary record arrays accordingly. Failed transformations preserve
  the original request. Tests cover allocation failures and payload ownership.
- Pack configuration rejects missing, duplicate, overflowing or partially
  parsed opnums. Raw packed/unpacked payload logging has been removed, and
  initialization no longer loads an unrelated default Samba configuration.
- RPC decoding and encoding respect plugin failures. Decoded hooks are not
  invoked on a failed NDR parse; failed hooks prevent further processing.
- Cache file access is confined to a private service-owned root with link,
  regular-file, owner and size checks. Sync commands use argv, exit failed
  children and verify their status. File and process failure paths, permissions
  and bounded synthetic replies have regression tests. Handle-table bounds and
  ordered request/reply correlation also have real LDB regression checks. Protocol/identity
  scoping and cache-integrity review remain incomplete; the optional cache is
  not yet qualified for an enabled integration configuration.

- SQL connection failures release unpublished resources and pooled metadata;
  credentials are absent from DSN diagnostics. Literal escaping handles quotes
  and backslashes under an explicitly configured UTF-8 session, including
  reconnects. Current escape callers check allocation failure; message property
  transactions roll back. Focused native/sanitizer tests and a private real
  MariaDB check pass. Named property creation/lookup escape client names and
  validate returned IDs; shared result readers handle allocation/fetch failures
  and single-value result shapes. Named-property transactions now serialize
  cooperating writers per SQL database, repeat lookups after waiting and reject
  silent reconnect during writes. Isolated tests and a private MariaDB check
  cover concurrent allocation, rollback and connection loss. Full SQL and
  storage integration review remains pending. Schema version 3 adds Unicode
  property-name identity and database UNIQUE constraints; ambiguous legacy IDs
  stop the upgrade. See [the upgrade procedure](NAMED_PROPERTIES_UPGRADE.md).

These changes are not a complete security audit. The remaining native parser
and server paths are part of the acceptance work above.

## Dependency security baseline

The local investigation uses Samba libraries from Debian package
`2:4.22.10+dfsg-0+deb13u2`, with 4.22.10 PIDL sources for code generation. A
successful ABI check or an upstream version string does not prove that a
distribution package has all applicable security fixes.

Checked again on 2026-10-29, the
[Debian Samba tracker](https://security-tracker.debian.org/tracker/source-package/samba)
lists `2:4.22.11+dfsg-0+deb13u1` in Trixie and
`2:4.22.10+dfsg-0+deb13u2` in Trixie security.
[DSA-6401-1](https://security-tracker.debian.org/tracker/DSA-6401-1) records the
latter as the Trixie fixed version for that advisory.
[CVE-2026-15779](https://security-tracker.debian.org/tracker/CVE-2026-15779)
remains open for `pam_winbind` home-directory creation; applicability must be
assessed on the actual host. The initial lab design does not enable that feature.
The newer [CVE-2026-109411](https://security-tracker.debian.org/tracker/CVE-2026-109411)
is recorded as not affecting Trixie. These observations do not approve the full
dependency stack. Verify actual installed/candidate package revisions and current
applicable advisories for the selected OS before starting services.

See [the modernization report](MODERNIZATION.md) for build commands and the
current blockers. Server OS, resources, network layout and client versions will
be collected when preparing that deployment, rather than assumed now.

## Installation preparation (2026-10-29)

The native installer now creates SONAME links without requiring a host loader
cache update, keeps OpenChange AD templates in its own data directory and removes
its administrative commands, async module, generated headers and Nagios script
on uninstall. `script/check_install.py` checks trusted staged output, loads the
installed libraries/modules and runs CLI help and template discovery from an
empty directory. It records file hashes and rejects incomplete or escaping
layouts before loading code. A fresh source-only local build passes compilation,
focused named-property/MySQL/EMSMDB checks, all 11 installed runtime checks and
removal with zero files/symlinks left. The Python tooling suite passes 39 tests
with one environment-dependent skip. See [the staged-install procedure](TEST_INSTALL.md).

This is installation-layout evidence. No Samba service was started, no AD
schema was provisioned and no host configuration was changed. The live server,
patched dependency review and full security/integration criteria above remain
open; this work does not establish the 40% milestone.
