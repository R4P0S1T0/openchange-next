openchange-testsuite
======================

Openchange unit tests testsuite utility.
It is using check library for unit testing.

Modernization checks
--------------------

The recovered library tests can run without building the server modules:

    ./autogen.sh
    ./configure --with-samba=/usr
    make check-libmapi-modernization
    make check-mapiproxy-registries

This runs the existing libmapi property/IDSET suites and native NDR request/reply,
array-bound and union-switch regression checks. Python-only tooling checks are:

    python3 -m unittest discover -s testsuite/modernization -v

With Samba 4.22.10 and matching PIDL, the main RPC module can be checked without
starting a server or installing plugins:

    make check-mapiproxy-rpc

This loads the actual module and uses Samba's state registry with synthetic
authentication tokens. Outgoing connections and the transport server ID are
substituted. It covers interface selection, bind/unbind, authentication state
isolation, malformed requests, credential ownership, remote association IDs and
connection retries; it does not validate network authentication or Outlook.

The asynchronous RPC lifecycle can be checked separately:

    make check-asyncemsmdb

This builds the asynchronous module and compiles its callback code into a
harness with real Samba state APIs and tevent. Storage/directory access,
nanomsg, RPC replies and private NDR registration are substituted. It exercises
ownership checks, setup failures, multiple contexts and handles, wait completion,
cancellation, call destruction and resource cleanup. It does not test real
notification delivery or an AD DC.

Administration failure paths and the installed Samba AES encoder can be checked:

    make check-mapiadmin

The first harness substitutes RPC/LDAP access and never modifies a real account.
It checks server errors, preserving existing users, connection lifetime, literal
metadata, failed setup and rollback by the newly created account's handle.
The separate crypto harness uses Samba's real AES encoder and NDR serialization.
Actual account creation/LDAP extension is not covered by these isolated checks.

Default address-book and mailbox boundaries have separate checks:

    make check-nspi check-emsmdb

These use actual server entry points, real Samba policy handles and local
LDB/TDB fixtures. They cover identity/SID and handle ownership, failed setup,
disconnect/association cleanup, mailbox authorization before provisioning,
notification registration cleanup, table arithmetic and malformed RPC buffers.
Directory/storage factories, cache transport and selected allocation failures
are substituted. They do not start AD, memcached or a network RPC server.
The OCPF scanner can be checked with `make check-ocpf-lexer`; it generates the
actual Flex scanner and covers owned strings, size limits, Unicode, quoting and
truncated input.
The NDR checks also exercise request/reply payload ownership, length bounds,
compressed/XOR frames and nonzero serialization offsets.

The custom pack plugin's parser and transformations have an additional check:

    make check-mpm-pack

It exercises actual serialization round trips, mixed and >255-operation
requests, truncated/malformed positions and wrappers, 16-bit length bounds,
configuration validation, allocation failure and nested payload ownership.
The main RPC smoke test also substitutes failing plugin hooks to verify that
their errors stop processing and that malformed NDR never reaches decoded hooks.

Cache file I/O and synchronization process handling can be checked with:

    make check-mpm-cache

This uses real disposable private files and LDB data, external sync programs,
links/FIFOs and a simulated RPC transport identity. It checks path confinement,
permissions, size bounds, bounded read replies, configuration failure and child
process handling. It does not validate cache isolation across accounts, complete
request/reply handle matching, atomic cache completion or sync timeouts.

For the Python runtime tests and isolated SQL database options, see
[the modernization guide](../doc/MODERNIZATION.md).

SQL connection utilities can be checked without a server:

    make check-mysql-utils

The driver is substituted for failure tests; real talloc and pool code are used.
The optional `make check-mysql-live` requires OPENCHANGE_TEST_MYSQL_HOST or OPENCHANGE_TEST_MYSQL_SOCKET (and
optionally PORT, USER and PASSWORD with the same prefix) pointing to a disposable
SQL server. It creates random openchange_test_* databases and drops them after
the checks. It does not read production configuration as a fallback.

Named-property creation and rollback have a separate isolated check:

    make check-namedprops

It calls the actual GetPropertyIdsFromNames ROP with a temporary LDB database.
It checks literal names, repeated names, invalid requests, allocation failures,
lookup/start/create/commit/cancel failures, transaction rollback and ID exhaustion.
It also calls the LDB reverse getter and GetNamesFromIDs: stored kind/GUID/LID
validation, UTF-16 name-size limits, missing contexts, malformed input arrays,
allocation failure, mixed reply sizes and response-owned string lifetime.
SQL allocation bounds and transaction commands are covered by `check-mysql-utils`
with a substituted driver, including lock timeouts, recursive transaction
rejection and lock/reconnect cleanup. `make check-mysql-live` additionally covers
two SQL connections allocating IDs, connection-loss rollback and termination of
a live session after an injected rollback failure on an explicitly
selected disposable endpoint. Use `OPENCHANGE_TEST_MYSQL_SOCKET` for a local
socket, or the host/port variables above. Live RPC is not covered. The Python runtime SQL suite also exercises the actual
version-3 schema migration, Unicode property identity, UNIQUE constraints and
refusal to remap ambiguous legacy IDs. See
[the upgrade procedure](../doc/NAMED_PROPERTIES_UPGRADE.md).

The SQL utility harness also calls the actual initializer with a substituted
driver. It checks exact table lookup, lookup errors, required migration version
3, failed creation/postvalidation and no migration of existing tables. The live
harness repeats the metadata gate with ordinary/quoted database names and a
wildcard-like sibling table; physical v3 constraints are checked by the Python
migration suite. Existing databases require the documented offline upgrade;
version metadata alone is not a physical schema audit.

Start-cleanup checks inject GET_LOCK result-read or START TRANSACTION failure
after acquisition plus RELEASE_LOCK failure. They verify own-session recovery,
unchanged borrowed handles, conservative manual recovery and controls that must
leave existing sessions alive. The live START/release injection requires actual
lock release to another connection and reconnect/reuse of the same handle.
Failed session identification/termination or reconnect restoration can require
quiescing users and recovering the affected service/connection pool. Concurrent
threaded use of a MYSQL handle is not covered.

On 2026-10-30, the cumulative checks passed locally: full/incremental build,
namedprops/MySQL/EMSMDB/NDR targets, 40 tooling tests, 28 runtime tests (no skips),
live SQL, focused ASan/UBSan with default leak detection, ordinary rebuild, and
all 11 staged-install runtime checks followed by empty uninstall. SQL used an
explicit private MariaDB 11.8.6 UNIX socket with TCP disabled; socket tests
required execution outside the restricted sandbox. Dependencies were not
sanitizer-instrumented. No network server, Outlook exchange or new remote CI
run was validated. See [the consolidated results](../doc/MODERNIZATION.md#named-property-consolidated-validation-2026-10-30).

Staged installation checks
--------------------------

After building, use `make install DESTDIR=/absolute/temporary/root` and
`/usr/bin/python3 script/check_install.py /absolute/temporary/root` to check
installed library/module loading, CLI help and Python/template discovery. The
checker emits a JSON manifest and runs outside the source tree. Python Samba and
MySQLdb bindings are required. It starts no server and provisions no directory.
See [the staged-install procedure](../doc/TEST_INSTALL.md) for removal checks and
limits. The Python tooling suite includes checker regression tests.

Usage
-----

Build Openchange as usual. Test suite goes to:

    bin/openchange-testsuite

To run all tests:

    bin/openchange-testsuite

By default, check runs in 'fork mode'. Which makes it hard to debug. To run in 'no-fork mode':

    CK_FORK=no bin/openchange-testsuite

To run just one testsuite or testcase, pass the name of the suite in CK_RUN_SUITE environment
variable or CK_RUN_CASE for a test case respectively:

    CK_RUN_SUITE="libmapistore named properties: interface" bin/openchange-testsuite

or

    CK_RUN_CASE="Interface" bin/openchange-testsuite

To check which tests are run, use `CK_VERBOSITY` environment
variable with `verbose` value as follows:

    CK_VERBOSITY=verbose bin/openchange-testsuite

To review all available options, go to the following link:

    http://check.sourceforge.net/doc/check_html/check_3.html#SRunner-Output

Check for memory leaks
----------------------

To check for memory leaks, run as:

    bin/openchange-testsuite --leak-report

or
    bin/openchange-testsuite --leak-report-full

for more detailed leak report.


----------

**List of "known" memory leaks (coming from Samba)**

 - struct tevent_ops_list
 - struct ldb_hooks
 - struct backends_list_entry
 - struct loaded
 - struct bitmap
 - struct loadparm_context


Enjoy!
