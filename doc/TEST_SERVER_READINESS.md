# First test-server milestone

The test server will be used after the local recovery and security preparation
below, in line with the requested **40% planning milestone**. That percentage is
an approximate work estimate; it does not certify security or Exchange feature
coverage. The milestone is **not ready** as of 2026-10-28.

## Acceptance before the first deployment

| Acceptance criterion | Current evidence / remaining work |
| --- | --- |
| Build the required server, plugins and storage components from source on a selected, patched OS | Default `make -j2 all` passes from a source-only copy, including libraries, RPC modules, plugins, default servers and clients; patched deployment baseline and storage installation remain pending |
| Pass native and Python regression checks from a source-only checkout | Focused native checks and offline client suite pass (30 successes, one known expected LZXpress failure); complete server suites and current-environment Python socket checks remain pending |
| Review and test exposed input and authentication boundaries | RPC state isolation, cancellation and pack validation covered; remaining NDR allocation/length handling, default servers, directory/database inputs and cache paths still need review |
| Resolve or explicitly assess security findings affecting the test configuration | Focused fixes have regression tests; repository-wide review and dependency CVE assessment are incomplete |
| Prepare reproducible installation, configuration, startup/health checks and teardown for a disposable instance | Pending; no deployment to the user's server has been attempted |
| Produce a reviewable test build with exact dependency versions, checks run and known limitations | Current recovery report exists; complete test-server artifact pending |

After these criteria are met, the first server test should establish real AD
provisioning, RPC authentication, mailbox operations and notification behavior.
Outlook compatibility is then measured against explicitly recorded client
versions. Those integration results cannot be inferred from compilation or
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
  and bounded synthetic replies have regression tests. Protocol/identity
  scoping and cache-integrity review remain incomplete; the optional cache is
  not yet qualified for an enabled integration configuration.

These changes are not a complete security audit. The remaining native parser
and server paths are part of the acceptance work above.

## Dependency security baseline

The local investigation uses Samba libraries from Debian package
`2:4.22.10+dfsg-0+deb13u2`, with 4.22.10 PIDL sources for code generation. A
successful ABI check or an upstream version string does not prove that a
distribution package has all applicable security fixes.

On 2026-10-28 the [Debian Samba security tracker](https://security-tracker.debian.org/tracker/source-package/samba)
lists `2:4.22.11+dfsg-0+deb13u1` in trixie and
`2:4.22.10+dfsg-0+deb13u2` in trixie-security, and still lists an open
`pam_winbind` issue, CVE-2026-15779. Its relevance depends on the deployment
configuration and must be assessed before installation. Check the exact package
versions and current applicable advisories again for the test server's chosen
OS; this report does not approve the full dependency stack as secure.

See [the modernization report](MODERNIZATION.md) for build commands and the
current blockers. Server OS, resources, network layout and client versions will
be collected when preparing that deployment, rather than assumed now.
