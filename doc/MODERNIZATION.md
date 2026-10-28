# OpenChange modernization

## Status on 2026-10-28

The client library and selected Python components now build/run with modern
Debian dependencies. The complete server and Outlook interoperability are
**not yet validated**. This is a recovery milestone, not a production release.

Validated locally with Debian 13, GCC 14.2.0, Autoconf 2.72, Automake/aclocal
1.17, Samba/PIDL 4.22.10, Python 3.13.5 and MariaDB 11.8.6:

- Autoconf bootstrap and configure complete. Python 3.11+ replaces Python 2 in
  configure, using sysconfig through `AM_PATH_PYTHON`, and the Python embedding
  header/link probe passes.
- `libmapi.so.2.3` compiles, links and loads without unresolved symbols.
- `make check-libmapi-modernization` passes: request/reply NDR round trips,
  malformed array rejection, restriction union switches, and the **8 existing
  Check tests** for libmapi properties and IDSETs.
- The last full Python validation (2026-10-27) passed **22 Python tooling/socket
  tests** and **25 Python runtime tests**. Five socket tests encounter permission
  restrictions in the current sandbox and are not reported as passing here.
  Runtime tests exercise disposable LDB files, real SQL schema upgrades and
  rollbacks, Unicode LDIF, failed-import rollback, and administration CLI help.
- Incremental `make -q libmapi` succeeds without rebuilding generated protocols.
- `libmapiproxy.so.2.3`, `libmapistore.so.2.3` and `libmapiserver.so.2.3`
  compile and load together after libmapi.
- The main RPC module, `mapiproxy/dcesrv_mapiproxy.so`, now compiles, links and
  loads with Samba 4.22.10. `make check-mapiproxy-rpc` exercises its registered
  callbacks and real Samba state APIs with synthetic authentication tokens and
  a substituted outgoing connection. This does not start or authenticate a
  network server.
- `mapiproxy/dcesrv_asyncemsmdb.so` now builds, loads and initializes with current
  Samba. `make check-asyncemsmdb` passes its isolated asynchronous lifecycle
  checks. The pack plugin also builds and passes `make check-mpm-pack`.
  The cache plugin also builds and passes `make check-mpm-cache`.
  `make mapiproxy` now also builds the default NSPI, EMSMDB and RFR servers.
  The NSPI and EMSMDB modules load without preloading support libraries;
  `make check-nspi check-emsmdb` passes the focused server/backend checks.
- `make check-mapiproxy-registries` passes for module/server/backend ownership,
  table growth, duplicate backend registration, all three allocation failure
  stages, session identity and destructor/refcount behavior. AddressSanitizer,
  UndefinedBehaviorSanitizer and LeakSanitizer also pass these checks.
- A separate source-only copy under `.build/native-validation` also builds and
  passes the native checks, and its library loads successfully. Generated files
  from the working tree were not copied into that validation build.

CI is configured for the native library on Debian 13, Python tooling on 3.11
and 3.13, and runtime tests with distribution Samba bindings and a MariaDB 11.8
service. The workflow has not been run on GitHub in this session.

## What changed

The top-level hand-maintained Makefile no longer initializes Automake's build
rules, which required an unavailable `compile` helper. Bootstrap tool overrides
are supported, obsolete Autoconf macros were replaced, and generated IDL file
dependencies now point to their actual `gen_ndr/` paths.

Samba feature probes select the Kerberos policy names and setter signature,
NDR flag type, array accessor signature and switch token accessors. The custom
NDR parser propagates current accessor errors and allocates reply reference
pointers when requested. Internal-only MAPI memory types no longer create NDR
table entries for serialization functions that never existed. Legacy feature
branches remain in the code but were not validated against Samba 4.1.18.

Provisioning, mailbox/migration modules and the five `setup/openchange_*`
commands now import/run with Python 3. The SQL manager handles an initially
unset version, quotes validated table identifiers, and checks exact table names
rather than LIKE wildcards. Tests opt into a database endpoint explicitly and
create/remove unique `openchange_test_*` databases.

UNIX socket transfer uses Python's public sendmsg/recvmsg APIs, adopts received
descriptors, preserves socket family, and closes descriptors on invalid input.
Tests cover real transfer between processes and repeated transfers without fd
leaks. This utility port does not port the entire RPC-over-HTTP service.

## Run the checks

A read-only prerequisite inventory needs only Python's standard library:

```sh
python3 script/doctor.py
python3 script/doctor.py --json
python3 script/doctor.py --strict
python3 -m unittest discover -s testsuite/modernization -v
```

The doctor installs nothing. Default mode returns 0 even on an unprepared
machine; `--strict` returns 1 for missing, incompatible, unchecked or unverified
prerequisites. Configure still performs the actual header/link checks. The
Samba release is read from `samba/version.h`, because `samba-hostconfig.pc`
reports its library API version (0.0.1), not the Samba distribution release.
The historical full-server baseline remains 4.1.18 in `script/samba4_ver.sh`;
4.22.10 has only been validated for the subset listed above.

For Python runtime tests, install the distribution's Python Samba bindings and
MySQLdb driver, then generate the named-property data:

```sh
libmapi/conf/mparse.pl --parser=mapistore_namedprops_python --outputdir=python/openchange/migration/ libmapi/conf/mapi-named-properties
PYTHONPATH=python /usr/bin/python3 -m unittest discover -s python/openchange/tests -v
```

SQL tests are skipped unless an endpoint is explicitly provided. Against an
isolated test server, set `OPENCHANGE_TEST_MYSQL_SOCKET`, or
`OPENCHANGE_TEST_MYSQL_HOST` and optionally `OPENCHANGE_TEST_MYSQL_PORT`.
Credentials use `OPENCHANGE_TEST_MYSQL_USER` (default root) and
`OPENCHANGE_TEST_MYSQL_PASSWORD`. The account needs permission to create/drop
its disposable `openchange_test_*` databases. No production configuration is
read as a fallback.

For the native library, the full dependency recipe and pinned PIDL archive
checksum are in [.github/workflows/modernization.yml](../.github/workflows/modernization.yml).
With those prerequisites on PATH:

```sh
./autogen.sh
./configure --with-samba=/usr
make check-libmapi-modernization
make check-ocpf-lexer
make check-mapiproxy-registries
make check-mapiproxy-rpc
make check-asyncemsmdb
make check-nspi check-emsmdb
make mapiproxy
make check-mpm-pack
make check-mpm-cache
make -q libmapi
```

Use `AUTOCONF`, `AUTOHEADER`, `ACLOCAL`, `ACLOCAL_PATH`, `PYTHON`,
`PYTHON_CONFIG`, `PKG_CONFIG_PATH`, `CPPFLAGS` and `LDFLAGS` for custom prefixes.
Python modules installed outside the interpreter's search path require the
corresponding `PYTHONPATH`.

## Server support recovery

Module, server and storage-backend registration now uses talloc-owned copies
rather than the old realloc/abort allocation helpers. Allocation failures return
an error without losing prior entries or leaking partial copies. Backend name
copies remain valid when the caller's buffer changes, and duplicate backend
registration remains idempotent.

Session identity uses the current `dcesrv_server_id` accessor when available,
with a feature-probed legacy fallback. The session comparator previously had a
misplaced parenthesis, comparing zero bytes and rejecting every session. It now
compares all identifier fields (including unique_id when present) and context
IDs. Tests cover mismatches and reference/destructor behavior.

Module configuration uses Samba's public list API. An explicit
`mapiproxy/samba_compat.h` boundary declares the remaining exported string-list
ABI functions absent from installed headers; their signatures and basic list
operations are checked against Samba 4.22.10. This is a compatibility boundary,
not a claim that all private Samba dependencies have been removed. The native
registry test isolates the storage error setter; it does not load plugins,
execute SQL operations or dispatch RPC requests.

The GCC 14 link failure from `nil_string` being defined in a shared header is
fixed with an extern declaration and one existing definition. Missing system
includes and generated notification integer-format headers are also repaired.
The indexing backend uses the declared multibyte-safe string replacement API.

Run the new native checks after configure:

```sh
make check-mapiproxy-registries
make -W testsuite/modernization/registry_smoke.c check-mapiproxy-registries CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'
```

LeakSanitizer required execution outside the tracing sandbox for local
validation. No sanitizer options were disabled to obtain a passing result.

## Main RPC module recovery

The bind callback now uses Samba's connection-context signature. Per-call state
is initialized only after the authentication gate, using Samba's connection
state API, which separates presentation contexts, authentication contexts and
principal SIDs. The state is owned by the presentation context so its Samba
registry entry and outgoing pipe are removed when that context is freed.
NSPI hooks use the same lookup and keep the saved Exchange name under that
state's ownership.

Outgoing connections are opened on the first authenticated request; the old
`delegated_auth` option no longer controls connection timing. Delegated
credentials are borrowed from the current authenticated call rather than
cached from bind. Remote association IDs are kept separately in Samba's
principal/interface association state, reused across connections, and never
written into Samba's local association group. Failed connections remain
retryable; zero or changed remote IDs are rejected.

The module also uses current packet logging, endpoint registration, module
initialization and generated server initialization signatures. Interface
structures are zeroed before callback assignment, the UUID lookup's inverted
comparison is corrected, and a shutdown callback is provided. Configure detects
and links `dcerpc-server-core` for the state APIs. These server changes target
Samba 4.22.10; they have not been tested with historical Samba/PIDL versions.
Enable `mapiproxy` explicitly in `dcerpc endpoint servers`; the obsolete,
inactive configuration-default hook has been removed.

The remaining private client fields (`conn`, `binding` and `last_fault_code`)
are accessed through `SOURCE4_LIBRPC_INTERNALS` in the main module, as Samba's
own `source4/rpc_server/remote/dcesrv_remote.c` does. This is an explicit private
ABI dependency, not a complete move to public APIs.

The new check loads the linked module, registers its interfaces and exercises
bind/unbind, UUID/version selection, anonymous and invalid-opnum rejection,
NDR parsing, state isolation, credential ownership, remote association reuse,
connection failures and retries. The outgoing transport and transport server
ID are substituted; Kerberos/NTLM negotiation and wire-level bind/alter/unbind
remain untested. UndefinedBehaviorSanitizer passes. LeakSanitizer cannot finish
under this session's tracing sandbox (it reports the ptrace restriction), so
no successful address/leak sanitizer result is claimed for this module.
The native checks also pass in a separate source-only build under
`.build/rpc-validation`; no generated files or compiled libraries were copied
from the working tree into that build.

## Asynchronous RPC recovery

The asynchronous module uses current bind/init signatures and the current
`samdb_connect`/`samdb_connect_url` ABI, checked against Samba 4.22.10 source.
The latter remains a private ABI boundary; loading the module does not validate
an actual directory connection. Initialization errors return a failure instead
of aborting, and failed directory initialization releases its temporary context.

Sessions are held in Samba's authenticated connection state, with separate lists
of handles per presentation/authentication context. A session's cached account
name must match the current authenticated account, as recorded by the EMSMDB
producer. A second outstanding wait for the same scoped handle returns busy.
The asynchronous flag is set only after a request and fd handler exist. Each
pending wait uses a cancellable tevent request exposed through the call's
`subreq`, so cancellation, call destruction and unbind release the handler.
Unbind cancels only that presentation context's waits and leaves other calls in
Samba's queue intact. Session teardown closes its nanomsg socket, removes its
resolver registration and releases its storage context, including on failure.

The notification receiver rejects negative/empty reads before NDR parsing,
releases malformed messages, and accepts only the implemented notification
version. Port selection converts the socket's network-order port before
constructing the nanomsg address. A parent-folder helper's uninitialized-value
check is corrected to validate its output pointer. The libmapiserver SONAME
symlink and asynchronous module library dependencies are now built explicitly.
The Samba RPC entrypoint declaration is kept separate from OpenChange's own
no-argument plugin entrypoint contract.

`make check-asyncemsmdb` compiles the real callback code with Samba's state APIs
and tevent, substituting directory/storage backends, nanomsg, RPC reply transport
and the private NDR table registration. Generated debug logging is disabled in
that harness. Checks cover authentication/ownership rejection, missing handles,
directory and setup failures, multiple handles and contexts, busy waits,
malformed reads, completion, cancellation, freeing a pending call, repeat
unbind and resource accounting. Completion is simulated; real notification
delivery, directory/cache connections and network RPC are not exercised.
The actual shared module also loads and initializes without those substitutions.
UndefinedBehaviorSanitizer passes the lifecycle checks; full notification
processing still needs integration tests.
The asynchronous, main RPC, libmapi/NDR and registry checks also pass in the
source-only build under `.build/async-validation`.

## Focused pack/RPC security recovery

The pack plugin now builds without its old raw-payload dump calls. Packing and
unpacking distinguish an absent wrapper from malformed data, check allocation
and NDR failures, and preserve the original request on rejection. Output length
is calculated from serialization with the two-byte header included; it cannot
wrap the 16-bit field. Temporary decoded arrays are bounded by the number of
positions representable by the custom wire format. Calls beyond position 255
remain unpacked, avoiding position truncation.

Unpacking rejects gaps beyond available records, duplicate/decreasing positions,
empty or truncated blobs, multiple/nested wrappers and zero-opnum records.
Decoded arrays must have a terminator within their talloc allocation. Unchanged
payloads retain ownership of their old allocation tree during a transformation.
Configuration accepts complete, distinct opnums and does not load a separate
default Samba configuration. Configuration teardown clears the global pointer.

`make check-mpm-pack` covers serialization round trips, mixed records, 300-call
requests, nested payload ownership, malformed wrappers/positions, length bounds,
bad configuration and allocation failures. The shared plugin loads normally,
and the test also passes with UndefinedBehaviorSanitizer.
Local AddressSanitizer/UndefinedBehaviorSanitizer heap checks also pass with
`ASAN_OPTIONS=detect_leaks=0`: leak detection is explicitly disabled for this
run because of the tracing sandbox. This is not a passing LeakSanitizer check.
CI is configured to run the pack check with address/undefined sanitizers and
the default leak detection, but that CI run has not been executed here.

The RPC parser now respects raw, decoded and output plugin failures and never
invokes decoded hooks after an NDR error. The main RPC smoke test injects hook
failures to verify that processing stops before encoding or dispatch. Native
checks pass in the working tree and the separate source-only validation tree.
This does not complete the review of the underlying NDR parsers, other plugins,
default mailbox servers or dependency security.

## Focused cache recovery

The cache plugin no longer calls removed string-replacement or server-ID
formatting functions. Cache synchronization substitutes the filename in argv
without a shell, exits the child immediately when exec fails, waits for its own
child through EINTR, rejects nonzero/signal exits and marks the stream cached
only after reopening a file of the expected size. The logical stream offset is
preserved so already delivered remote bytes are not repeated after a sync.
Command arguments are no longer printed into the log.

The cache root must be a private directory owned by the service account. File
operations walk relative directory descriptors with `openat` and `O_NOFOLLOW`,
reject parent traversal, directory/file symlinks, hardlinks, FIFOs and mismatched
owners, and set close-on-exec on opened descriptors. New directories use 0700;
new data files and LDB databases use 0600. Cached reopens check file size, and
failed opens do not report success or replace a live FILE pointer. Metadata
database opens reject existing symlinks and hardlinks before LDB connects.

Reads/writes enforce the stream's declared size, validate pointers and offsets,
handle seek/short I/O/flush errors, and support zero-byte operations. Stream
objects are zero initialized. Configuration rejects unsafe roots, missing or
relative sync commands, negative thresholds and incompatible ahead/sync options.
Failed initialization preserves the previous cache, and teardown closes streams
and clears the global cache pointer. It no longer loads an unrelated Samba
default configuration. Selected hook callers now propagate file I/O errors.

Synthetic cache replies are limited to a single bounded ReadStream operation
with a single handle and sufficient output budget. Batches and complex handle
tables are relayed instead. Response arrays are terminated, allocations checked,
and relay is disabled only after a successful local read. Failed remote reads
do not consume their undefined response union. Unknown attachment parents are
left for the server instead of dereferenced by the cache.

`make check-mpm-cache` exercises real temporary files, links, traversal, FIFOs,
permissions, stream bounds, reply serialization, sync success/failure/signals,
exec/fork failure, EINTR, child reaping, literal filename arguments and config
failure/replacement with a disposable LDB. The module loads normally and checks
pass in the separate source-only validation tree. Local address/undefined
sanitizer checks pass with leak detection explicitly disabled for the tracing
sandbox, as described above; a complete LeakSanitizer run remains pending.

The cache is still **not qualified for an enabled integration configuration**.
Request/reply handle mapping and authentication scoping, file namespaces across
accounts/properties, atomic content completion/invalidation and sync-command
timeouts still require review and tests. File hardening alone does not resolve
those protocol and cache-integrity concerns.

## Default address-book and mailbox servers

NSPI and EMSMDB use Samba's current `dcesrv_handle_create/lookup` interfaces.
UUID-only global session lists have been removed. A handle lookup checks the
association, interface, primary user SID and minimum authentication level;
zero wire handles are rejected before lookup because Samba otherwise allocates
a new handle. Backend contexts are owned by their policy handles and released
on disconnect or association teardown. NSPI binds always verify the Exchange
account, including requests with ordinary zero flags.

Both directory providers use the current `samdb_connect`/`samdb_connect_url`
ABI and own their directory connections and event contexts per session.
Directory records used as session owners must contain the authenticated
primary SID. This prevents same-name accounts in trusted domains from being
accepted as local accounts. Disabled, duplicate, missing and malformed account
records fail closed. Connect-as and mailbox delegation are not implemented;
connection DNs and private mailbox logons are restricted to the authenticated
owner. Logon escapes LDAP filters and checks authorization before provisioning.

Mailbox connection replies copy their strings and do not modify the directory
record's legacy DN. Unsupported client versions fail before allocating a
session. Async connection registration walks all endpoint interfaces, cleans up
failed registrations and removes the notification-cache entry and async handle
when the owning mailbox session ends. MAPI handle stores close their temporary
TDB through their own destructor, including partial setup failures.

The custom MAPI NDR parser checks ROP lengths, handle-table alignment and bounds
before subtracting or allocating, checks allocation failures, and retains decoded
arrays and payloads through encoding. Serialization uses buffer-relative byte
counts and checks the declared size. RPC frames validate their version, flags
and encoded/decoded sizes; compressed plus XOR payloads are handled together
without modifying the caller's input. Decompression has a bounded output and
cannot repeat an unconsumed full chunk indefinitely. Property-tag construction
uses unsigned shifts so high IDs remain valid constants with sanitizers.

Mailbox transaction dispatch validates primary and secondary handle indexes,
keeps a reply-owned handle table, returns an explicit unsupported-operation
error and checks response lengths and encoder failures. `EcDoRpcExt2` accepts
one final frame; chained requests remain unsupported. Output capacity is checked
after processing, so a buffer-size failure is not a transaction rollback and
must not be treated as proof that state-changing operations did not run.

`make check-nspi check-emsmdb` uses real Samba policy handles and local LDB/TDB
fixtures. It exercises cross-user/interface/association and authentication-level
rejection, account SID matching, cleanup, setup/registration failures, old
versions, reply encoding, malformed RPC frames and handle indexes, and mailbox
logon authorization before writes. Directory/storage connection factories,
notification-cache transport and selected allocation/process failures are
substituted. This is not an AD, memcached or Outlook integration test.

The default-server, backend, custom NDR and OCPF scanner checks also pass with
AddressSanitizer and UndefinedBehaviorSanitizer in the source-only
`.build/server-validation` copy. The sanitizer build exposed and helped remove
duplicate protocol globals. Local heap/UB checks used `ASAN_OPTIONS=detect_leaks=0`
because LeakSanitizer cannot run under this sandbox's ptrace restriction; this
run does not validate leak detection or the remote CI workflow.

## OCPF reader and shared protocol ownership

The OCPF lexer now builds with current Flex. String tokens belong to the parser
context, have a 16383-byte limit, and reject unterminated strings/comments using
Flex's actual EOF convention. Quoting, Unicode, lifetime, size boundaries and
truncated input have a generated-scanner check in `make check-ocpf-lexer`.
The parser initializes one scanner, checks setup failure and propagates lexical
errors. Other OCPF grammar/numeric/property paths still require review.

RPC modules, pack/cache plugins and libmapiserver link the protocol implementation
from libmapi instead of embedding duplicate copies of NDR tables and routines.
This removes duplicate global definitions exposed by AddressSanitizer. The build
also declares generated headers/version prerequisites for parallel compilation.

## Remaining blockers

The focused `mapiproxy` build and server boundary checks pass. The complete
repository build currently stops in `libmapiadmin/mapiadmin_user.c`, which
includes Samba's unavailable private `ldap_ndr.h`. The full C/server suite and an installation against a disposable
AD controller remain to be validated. The RPC modules need real bind/unbind,
authentication, relay and notification tests against disposable servers.
Remaining ROP implementation, directory/schema, cache identity/integrity and
storage-backend paths still require review; these focused changes do not certify
the server as secure.

Other unfinished work:

- Python C extension bindings in `pyopenchange/` still use Python 2 APIs;
  `--enable-pyopenchange` is not supported by this recovery milestone.
- Web services and several standalone maintenance scripts still need Python 3
  migration. Importing provision.py does not validate a full AD provisioning.
- The complete C/server suite, directory schema installation on an AD DC,
  authentication and Outlook/client interoperability remain untested.
- PIDL warns about deprecated subcontexts and skips unused high-level wrappers
  for legacy scalar output arguments. The low-level `_r` client APIs used by
  libmapi are generated, but protocol cleanup needs separate wire-level tests.
- Compiler warnings and historical security/operational assumptions remain.

For this investigation, tools and development packages were extracted under
`/tmp/openchange-build-tools`; no system packages were installed. A disposable
MariaDB was started there with `--skip-networking`, solely for SQL tests. This
instance was shut down after validation. Download caches were moved under
`.build/tool-cache` to recover space in `/tmp`. The temporary dependency prefix
is an investigation aid, not a distributable server environment.

## Planning estimate

The requested first test-server milestone is tracked through concrete build,
security and deployment acceptance criteria in
[Test server readiness](TEST_SERVER_READINESS.md). It has not been reached.

As of 2026-10-28, a rough engineering estimate is **20–30% of the modernization
work**, using **25%** as a planning reference. This is a subjective estimate of
remaining work toward a maintained, usable release, not a measured percentage
of working Exchange features or a delivery-date prediction.

| Stage | Evidence-based status |
| --- | --- |
| Reference build | Libraries, RPC modules, plugins and default servers recovered; full repository build pending |
| Python 3 and bindings | Provisioning/migration subset recovered; extensions and services pending |
| Samba/C adaptation | Focused RPC, pack/cache, NSPI and EMSMDB checks pass; full protocol/integration work pending |
| End-to-end server validation | AD provisioning, authentication, mail/calendar and Outlook pending |
| Packaging and operation | Reproducible deployment, backup/restore and upgrades pending |

The estimate must be revised when a feature/protocol acceptance matrix and
end-to-end test results exist. Passing more compilation checks alone does not
establish a corresponding increase in product readiness.

## Delivery stages and acceptance criteria

1. **Recover a reference build.** Capture exact dependency versions and build
   commands in an isolated environment. Build libraries, server modules and
   generated NDR code; run the existing C and Python suites. Record failures
   before changing interfaces. Keep a historical environment for comparisons.
2. **Port Python and bindings.** Migrate provisioning, migrations and services
   to Python 3 alongside the C extension module initialization and string APIs.
   Replace distutils. Test bytes/text round trips, database migrations, and
   provisioning against a disposable directory and database.
3. **Adapt Samba and the C build.** Select and pin a maintained dependency
   baseline after API investigation. Update RPC/IDL integration and compiler
   compatibility. Run C tests and address/undefined-behavior sanitizers;
   compile the server, not just client libraries.
4. **Exercise the server.** Automate disposable directory, database and mailbox
   provisioning. Test authentication, address book, send/receive, folders,
   attachments, calendars and permissions. Record the precise Outlook/client
   versions and protocols tested; define additional protocol work from results.
5. **Package and operate.** Produce reproducible development images and release
   packages, configuration examples, health checks, structured logs, backup and
   restore procedures, and tested upgrade/rollback paths.

Each stage needs executable checks before it is marked complete. A complete
Exchange replacement also requires an agreed feature/protocol matrix; the
historical project goals alone are not evidence of supported functionality.
