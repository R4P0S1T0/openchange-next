# OpenChange modernization

## Status on 2026-10-28

The complete default native build and selected Python components now build/run with modern
Debian dependencies. The complete server and Outlook interoperability are
**not yet validated**. This is a recovery milestone, not a production release.

Validated locally with Debian 13, GCC 14.2.0, Autoconf 2.72, Automake/aclocal
1.17, Samba/PIDL 4.22.10, Python 3.13.5 and MariaDB 11.8.6:

- Autoconf bootstrap and configure complete. Python 3.11+ replaces Python 2 in
  configure, using sysconfig through `AM_PATH_PYTHON`, and the Python embedding
  header/link probe passes.
- `make -j2 all` succeeds in a fresh source-only copy. The standalone tools use
  checked Samba utility declarations, C++ objects wait for generated headers,
  and OCPF/C++ SONAME links are built before their consumers. Ten CLI help
  commands also pass without missing symbols or libraries.
- With reference fixtures installed into a private prefix and a temporary
  profile database, `mapitest --no-server` reports **30 passes, no unexpected
  failures and one known expected LZXpress recompression failure**. Exact
  Outlook compression-byte parity remains unresolved.
- `make check-propsdump` covers capture ownership after parser destruction,
  failed ROP replies, invalid indices and truncated files with generated NDR.
  It passes natively and with ASan/UBSan (local leak detection disabled).
- `libmapi.so.2.3` compiles, links and loads without unresolved symbols.
- `make check-libmapi-modernization` passes: request/reply NDR round trips,
  malformed array rejection, restriction union switches, and the **8 existing
  Check tests** for libmapi properties and IDSETs.
- The current Python validation (2026-10-28) passes **30 Python tooling/socket
  tests** and **25 Python runtime tests**. Socket tests were run outside the
  restricted sandbox; SQL used a fresh private MariaDB directory and a UNIX
  socket with TCP disabled. The daemon was stopped and its data removed.
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

CI covers the native build on Debian 13, Python tooling on 3.11 and 3.13,
and runtime tests with distribution Samba bindings and a MariaDB 11.8 service.
All four jobs passed for commit ee10e26e in
[GitHub Actions run 40725147679](https://github.com/R4P0S1T0/openchange-next/actions/runs/40725147679).
Later commits need their own reviewed workflow results.

The complete focused native check set also passes locally with AddressSanitizer,
UndefinedBehaviorSanitizer and LeakSanitizer outside the sandbox. Earlier
per-block notes below record the initial detect_leaks=0 runs; the current
out-of-sandbox run closes that local leak-check restriction for these harnesses,
not for live server workloads.

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
make -j2 all
make check-propsdump
make check-binary-properties check-property-blobs check-recipient-blobs
make check-libmapi-modernization
make check-ocpf-lexer
make check-mapiadmin
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

## Administration recovery

`libmapiadmin.so.2.3` now builds and loads with the selected Samba baseline.
SAMR calls use the public generic binding-handle API and check both transport
and server status. Connection state, event contexts and policy handles remain
owned by the administration context after individual calls return. Failed
connection setup publishes no partially initialized state.

Creating an existing user returns `MAPI_E_COLLISION` without deleting it.
Metadata strings are copied literally instead of used as format strings, and
passwords are no longer included in debug logs. Password setup uses Samba's AES
SAMR encoder and level 31 with no legacy-cipher fallback. Generated passwords
have at least 32 characters; ordinary account creation no longer disables
password expiry. Session-key copies are wiped before release. Failed creation
rolls back through the exact new account's handle, without resolving a username
again. A rollback RPC can itself fail; the reported account then needs explicit
administrative cleanup rather than being assumed absent.

Configure probes `init_samr_CryptPasswordAES` in the matching Samba private
library. The default private-library directory is Samba's pkg-config libdir
plus `/samba`; split SDK/runtime layouts can set
`--with-samba-private-libdir=DIR`. The encoder declaration was checked against
Samba 4.22.10's `source3/rpc_client/init_samr.h`. This dependency is a private ABI
boundary and must be retested when the Samba package changes. Older controllers
without AES SAMR support are not approved for this administration path.

`make check-mapiadmin` exercises server-error responses, existing-user
preservation, connection ownership, password/metadata failures, literal percent
characters, empty RID replies and exact-handle rollback using substituted RPC
and LDAP transport. A separate check calls the installed Samba AES encoder and
serializes its SAMR request with real NDR code. These checks pass natively and
with ASan/UBSan in the source-only copy (local leak detection remains disabled).
No real directory account has been created or deleted during these checks;
end-to-end administration and LDAP extension still require integration testing.

## Asynchronous notification identity

A new asynchronous wait validates the handle type and nonzero UUID before
using cached state. The cached short account name is then resolved in the local
directory: exactly one enabled Exchange account with an objectSid matching the
authenticated primary SID is required. This prevents a same-named account from
a trusted domain from inheriting the local account's cached session. The real
LDB-backed lifecycle harness covers wrong SID, missing/disabled accounts,
missing account-control attributes, invalid handle type and zero UUID, alongside
completion/cancellation cleanup. Native and ASan/UBSan checks pass; no real
cross-domain authentication has been attempted.

## Packed property and recurrence decoding

The shared property reader now checks every NDR return value and publishes an
offset only after a complete value has been decoded. Multi-value counts are
bounded by the remaining wire bytes before generated code allocates arrays;
string values must contain their one-byte or UTF-16 terminator. Decoded strings,
binary data and nested arrays are owned by the returned value after the parser
is freed. Unsupported types continue to fail rather than guessing their size.

Row assembly uses the same checked path, rejects unknown layout/property flags,
keeps caller column tags immutable and represents absent columns as PT_ERROR /
MAPI_E_NOT_FOUND. A malformed row publishes neither partial properties nor an
advanced cursor. `emsmdb_get_SRowSet` now returns MAPISTATUS and clears cRows on
failure; table, message, recipient and capture-reader callers propagate parser
errors. ModifyRecipients also rejects excess property counts and truncated
layout/error bytes before indexing its property data.

`make check-property-blobs check-recipient-blobs check-propsdump` exercises every
previously supported scalar/array type, every truncated prefix of the fixtures,
large counts, missing columns, invalid flags, allocation failure and real
RPC-capture assembly. The existing recurrence test exposed another lifetime bug:
recurrence dates and exception arrays were copied after their parser had freed
them. Both recurrence readers now allocate nested data under their result,
without the freed-memory copies or additional talloc references. The test checks
nested content and complete result cleanup.

Native and ASan/UBSan checks pass, including the 8 Check tests and EMSMDB boundary
checks; local leak detection is disabled due to sandbox restrictions. The full
source-copy build and 30-case offline client suite also pass (the known expected
LZXpress failure remains). These are local parsing/lifetime checks, not evidence
of live mailbox, recurrence or Outlook interoperability.

## Binary property ownership

The property wrappers for global object IDs, address-book and one-off entry IDs,
folder/message/server IDs, time zones and persistent data now allocate decoded
children under the returned object before freeing the NDR context. Allocation
failure frees the parser as well. SizedXid arrays retain their nested LocalId
blobs across result growth, preserve the old allocation on realloc failure and
clear the output count on failure.

`make check-binary-properties` uses generated binary fixtures, frees the wire
buffer and then reads the decoded nested data. It checks complete result cleanup
and sweeps allocation limits while parsing two XIDs. The existing persistent-data
fixtures also inspect nested elements and cleanup. Native, source-copy and
ASan/UBSan checks pass (local leak detection disabled). This addresses ownership;
all binary property formats still need further semantic and length-limit review.

The fixed-structure binary readers share a small allocation/cleanup path through
Samba's public ndr_pull_struct_blob API. Their exported signatures and talloc
type names remain unchanged. The generated fixture checks also verify those
types, nested ownership and cleanup; calendar and persistent-data fixtures pass
with the shared reader, natively and with ASan/UBSan. This removes roughly 280
lines of duplicated parser setup and error handling.

## Literal recipient directory lookup

ModifyRecipients now escapes the complete legacyExchangeDN before an exact LDB
search. A wildcard, parenthesis or backslash in a supplied name cannot become
filter syntax and select another account. Full and prefix-compressed names are
validated, duplicate matches remain unresolved, and directory errors are
returned rather than treated as successful external-name resolution. Returned
names are copied under the caller before temporary search data is freed.

The real temporary LDB in `make check-recipient-blobs` covers normal and
compressed names, literal filter characters, wildcard attempts, invalid prefixes
and duplicate directory entries. Native/source-copy and ASan/UBSan checks pass,
alongside EMSMDB regression checks. Broader recipient-resolution behavior and
actual directory interoperability remain integration work.

## Property list allocation failures

SPropTagArray_add and SRow_addprop now retain their original pointer and count
when growth fails, reject overflowing counts and return an allocation error.
Row appends no longer copy an uninitialized slot. Message recipient callers
check both appended values and appended column tags and release their unpublished
message if either operation fails. The property-blob harness checks real talloc
allocation limits, unchanged data after failure, replacement without allocation,
invalid array state and count overflow. Native/source-copy and ASan/UBSan checks
pass. Other property-list helpers and callers still need review.

## Persistent property array bounds

The hand-written persistent-data and persistent-element array readers now use
the actual NDR cursor instead of summing untrusted declared sizes. Both enforce
their IDL item-count limits, grow arrays geometrically and publish results only
after complete decoding. Allocation/parse failures release temporary arrays and
restore the caller's memory context and flags. Nested values stay under the
result even when its array moves. Existing sentinel-free arrays remain accepted
at a complete record boundary for compatibility with the historical fixtures.

The binary-property check adds truncated header/payload prefixes, nonzero input
offsets, allocation-limit sweeps and over-limit arrays (100,001 persistent data
records and 10,001 elements). Native/source-copy and ASan/UBSan checks pass,
including the existing 8 Check tests; the complete default build also passes.
This does not validate every binary property's declared-size semantics.

## Organization directory lookup

Organization/group parsing validates nonempty components in protocol order
before subtracting pointers or allocating output strings. Invalid input and
allocation failure leave both outputs empty. Organization lookup requires a
configuration base DN and exactly one matching directory object, handles empty
or duplicate results without indexing them, and copies the actual result DN
instead of trusting an optional distinguishedName attribute.

The EMSMDB backend harness exercises real LDB lookups for missing configuration,
no result, a literal organization containing filter characters, duplicate results,
malformed names and allocation failure. Native and ASan/UBSan checks pass; actual
AD schema/provisioning remains untested.

## Address-book search boundaries

NSPI property searches validate matching property tags and accept only their
supported text/string-array representations before reading the value as text.
Null values and empty arrays fail explicitly; numeric properties are rejected
instead of being reinterpreted as strings. User values and the authenticated
organization name are escaped as LDAP literals. The legacyExchangeDN branch no
longer emits an invalid extra filter clause. Organization filters and temporary
search data are owned by the request, and MID arrays are published only after
all directory records have been mapped successfully.

The real LDB/TDB backend harness covers Unicode/ANSI and multivalue text,
literal wildcard/parenthesis characters, injection attempts, cross-organization
matches, exact legacy DNs, UPN lookup, result limits, malformed restrictions,
TDB-write failures and allocation failure. Native/source-copy and ASan/UBSan
checks pass. Numeric restrictions, additional restriction forms and full
comparison/operator semantics remain protocol work; these tests do not prove
AD's ANR behavior or live Outlook search compatibility.

## Cache RPC table validation

Cache callbacks validate declared handle counts against their allocated tables,
reject missing operation-array terminators and check primary/creation-output
indices before indexing. Replies are matched to requests in order, skipping
Release requests and unsolicited notifications, so repeated opnums no longer
reuse the first request's metadata. The complete correlation is checked before
cache state changes. A changed ReadStream handle bypasses cache writes; read-ahead
rejects malformed reply shapes and stops cleanly on a failed ROP without reading
its absent property union.

`make check-mpm-cache` adds invalid lengths/allocations, missing output slots,
invalid primary/secondary indices, malformed reply arrays and read-ahead failure
cases. A real LDB fixture tracks two OpenMessage operations, checks distinct
returned handles, verifies unchanged state after an invalid second reply and
covers Release/Notify ordering. Native/source-copy and ASan/UBSan checks pass.
Identity/store namespaces, atomic cache publication and sync-command timeouts
remain unqualified; the cache is still not approved for an enabled test setup.

## Cache property file keys

Message and attachment stream paths now include the property tag. Distinct
properties no longer truncate or reuse the same physical file. Reopening a
stored filename requires the exact path computed from its message/attachment
and property metadata; arbitrary or legacy filenames are rejected. These paths
still lack the fully qualified identity/store namespace described above, so
this is not approval to enable the plugin.

The cache harness writes different properties of one message and one attachment,
checks that their bytes remain independent and rejects cross-property filenames.
It also checks a symlink inserted into an expected directory and runs the sync
argv checks with spaces and shell metacharacters in the private root path.
Native/source-copy and ASan/UBSan checks pass. This changes the experimental cache
file layout: an enabled recovery test must start with a fresh disposable cache;
old cache records are not migrated or deleted automatically.

## Build version provenance

The version header depends on Git HEAD and the active branch reference, including
linked worktrees. C/C++ objects depend normally on that header, so moving to a
new commit updates the version compiled into binaries. Unchanged generated
content preserves its timestamp. The generator reads the source checkout's Git
metadata, handles quoted paths and emits escaped string macros; an archive nested
inside another repository no longer inherits its parent's hash.

Eight temporary-repository tests exercise source selection, archives, branches,
detached worktrees, unchanged timestamps, quoting, missing input and the actual
Make rules. The full native build passes in the checkout and source-only copy;
`make -q libmapi` is quiet after the build. Source archives intentionally omit a
Git revision; build/release records must identify their source commit separately.

## Property list copying and deletion

SRow_addprop and SRowSet_propcpy share checked append logic. Row-set copies now
copy the actual property value, preserving string pointers instead of pointing
into the temporary by-value union. Growth failure preserves the affected row's
pointer/count, returns an error and sets GetLastError. Both recipient callers
stop before ModifyRecipients if copying fails. Existing row-set append semantics
(including duplicate tags) remain; earlier rows can already be updated if a later
row fails.

Tag deletion compacts its existing allocation and does not realloc or write past
an exact-sized array when no tag matches. Tests cover deletion under a real
allocation limit, duplicate/removing-all/missing tags, string row-set copies,
append semantics, overflow and allocation failure. Native/source-copy, ASan,
UBSan and LeakSanitizer checks pass, and the offline client suite still reports
30 successes and its one known expected LZXpress failure.

## SQL connection failure and diagnostics

The MySQL connection helper clears failed outputs, validates port digits/range,
checks client/parser/pool allocations and closes a connected client if it cannot
be registered. Closing the pool frees its metadata as well as its connections.
Raw connection strings and password-derived hashes no longer appear in pool or
schema-creation diagnostics. Database creation quotes identifiers by doubling
backticks, as described by
[MariaDB's identifier quoting documentation](https://mariadb.com/docs/server/reference/system-tables/sys-schema/sys-schema-stored-functions/quote_identifier).

`make check-mysql-utils` substitutes only the database driver and selected
allocation/pool failures. It exercises invalid/null URIs, parser allocation,
connection failure, pool reuse/cleanup, quoted identifiers and credential-free
messages. `make check-mysql-live` requires an explicitly selected disposable SQL
host and uses random test database names; it checks real creation/selection,
connection reuse and removal for both normal and backtick-containing names.

Native/source-copy, ASan/UBSan and LeakSanitizer checks pass. The live C check
also passes against a private MariaDB 11.8.6 on a temporary loopback port, with
no fixture databases remaining; the daemon and directory were removed. CI now
includes these checks with its own MariaDB service. Full storage-backend suites,
SQL literal escaping/modes and query-data logging still require review.

## SQL literal encoding and allocation failures

The shared literal escape now protects both apostrophes and backslashes. Pooled
connections explicitly select `utf8mb4` and remove only `NO_BACKSLASH_ESCAPES`
from their session SQL mode. A checked initialization command reapplies that
mode after reconnect, as specified by the [MariaDB Connector/C options API](https://mariadb.com/docs/connectors/mariadb-connector-c/api-functions/mysql_optionsv).
Connection establishment no longer retries `mysql_real_connect` on the same
handle after a missing-database failure: it connects once, then selects or
creates the database. The previous retry lost the initialization command in
the live failure test.

Every current `_sql` call site checks escape allocation failure before formatting
SQL, including list builders, table restrictions and message property writes.
An active message transaction rolls back on that failure. Two previously raw
MAPIStore URI writes now escape their literals, and table usernames are copied
into table-owned storage. The query runner rejects null connections/queries.
This covers the shared escape contract; it is not a complete audit of all SQL,
transaction semantics or database permissions, nor a prepared-statement port.

`make check-mysql-utils` now runs both substituted-driver and actual backend
query-builder checks. The latter injects allocation failures before SQL and
inside a message transaction, checks rollback, and covers mailbox/indexing
builders. Native and ASan/UBSan/LeakSanitizer runs pass. `make all` also passes
in the main and source-only validation trees.

The real C live check covers new/existing databases, quoted identifiers,
connection reuse, apostrophe/backslash/Unicode literal round trips, charset and
SQL mode before/after a forced connection restart. It passes under sanitizers
against a private MariaDB instance whose global mode includes
`NO_BACKSLASH_ESCAPES`; its unique fixture databases and private server directory
are removed afterward. This local database proof does not replace AD or mailbox
server integration. The previous pool commit `bec73a14` also passed all four
[GitHub CI jobs](https://github.com/R4P0S1T0/openchange-next/actions/runs/40731020676).

## Named property queries and SQL result ownership

Named property lookup and creation now escape client-supplied property names
using the configured connection contract. Creation formats a checked key and
INSERT directly instead of assembling a list of unchecked intermediate fields.
It no longer logs the entire inserted record. Invalid kinds, null names and
allocation failures return errors before SQL; mapped IDs outside 16 bits or
invalid numeric results are rejected without overwriting the caller's output.

The shared result readers free driver results on every failure, check row and
copy allocations, and publish only complete results. A single-row, single-column
query now returns its value instead of an empty array. The existing provisioning
layout still skips the first locale column for one-row multi-column results;
its two-column case now returns the actual folder name. Unsigned numeric parsing
accepts decimal digits through `UINT64_MAX`, rejects empty/signed/overflowing or
partially parsed input, and preserves the output on failure. Stored PT_I8 and
timestamps already use unsigned decimal formatting.

Focused tests cover row shapes, missing/failing results, SQL NULL, oversized row
counts, allocation/copy failure, numeric limits, missing properties and invalid
mapped IDs. Native and ASan/UBSan/LeakSanitizer runs pass, as do both full native
build trees. The private MariaDB check exercises the actual named property
lookup/create code with apostrophes, backslashes, accented text and supplementary
Unicode, numeric property IDs, and a literal injection-shaped missing name.
Its real row/scalar checks also verify the repaired result shapes and integer
limits. Fixture databases and the private server directory are removed.

ID allocation/concurrency and the remaining
storage operations still need review; this is not full backend qualification.
The preceding literal-encoding commit `87844f3c` passed all four
[GitHub CI jobs](https://github.com/R4P0S1T0/openchange-next/actions/runs/40734736817).

## SQL diagnostic data exposure

Shared connection/query/result diagnostics and mailbox row-fetch errors no
longer include SQL text or free-form driver error messages, which can repeat
private input values. They retain operation labels, numeric driver error codes
and the five-character SQLSTATE. Slow queries report only elapsed time through
the configured logger; the unconditional SQL dump to stdout is removed. Failed
clock reads skip timing without changing the database operation's result.

The substituted driver test captures stdout and debug messages for failed and
artificially slow queries containing a private payload. It checks that stdout
stays empty, the payload is absent, and error code/SQLSTATE/timing remain useful.
It also injects both initial and final clock-read failures. Native and
ASan/UBSan/LeakSanitizer checks pass; both full build trees and the private real
SQL check pass. This change does not establish a repository-wide logging or
data-retention policy; other storage/debug output still requires review.

## Named property reverse decoding

The MySQL reverse lookup now validates result/row presence, column count, kind,
GUID and 32-bit numeric property ID before publishing output. Driver results and
partially allocated names are released on every failure. Names and strings are
owned by the caller's context; allocation failures leave a null output. Property
type reads use the checked scalar helper and reject values outside 16 bits.

String property names use the project's UTF-8-to-UTF-16 length helper instead of
`strlen * 2 + 2`. Their encoded size must fit the one-byte protocol field before
assignment. Focused tests cover accented text, surrogate pairs, oversized names,
malformed values, failed result/copy/fetch operations and constrained output
allocation. Native and ASan/UBSan/LeakSanitizer checks pass, along with both full
build trees. The real private SQL test now verifies reverse names, GUIDs, numeric
property IDs, property types and independently recorded UTF-16 sizes after a
forced reconnect. The private server and all fixture data are removed afterward.
The LDB named-property backend and broader protocol semantics remain separate
review work.

## Remaining blockers

The default `make all`, offline client checks and focused server boundary
checks pass. The full C/server suite and an installation against a disposable
AD controller remain to be validated. The RPC modules need real bind/unbind,
authentication, relay and notification tests against disposable servers.
Remaining ROP implementation, directory/schema, cache identity/integrity and
storage-backend paths still require review; these focused changes do not certify
the server as secure.

The [server lab plan](TEST_LAB_PLAN.md) permits inventory and staged source-build
checks on the target host now, while service deployment remains gated. This
checkout has no production mailbox content backend: its named-property/indexing
adapters are metadata services, and the external backend must be selected and
qualified before functional mailbox tests.

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

## Named-property transaction recovery (2026-10-29)

`GetPropertyIdsFromNames` now rejects invalid flags and malformed names, checks
creation failures, and cancels active transactions when lookup, allocation or
commit fails. It returns a protocol error on ID exhaustion instead of aborting
or wrapping the ID. Error replies publish no partial ID array. Both LDB and SQL
backends expose cancellation and bound allocation to 0x8001–0xfffe.

LDB lookup escapes filter literals and distinguishes a missing mapping from
backend errors and duplicate rows. LDB creation constructs messages with escaped
DN components and literal attribute values, replacing interpolated LDIF input.

`make check-namedprops` exercises the actual ROP, interface and LDB backend using
a disposable local database and injected transaction failures. The SQL driver
harness in `make check-mysql-utils` also checks allocation boundaries and
start/commit/rollback commands. The named-property and SQL utility harnesses
pass locally with AddressSanitizer, UndefinedBehaviorSanitizer and default leak
detection; `make check-emsmdb` also passes natively.

SQL named-property transactions now acquire a database-scoped advisory lock
with a five-second acquisition timeout, hold it through commit/rollback and
release it explicitly. Recursive use of the same pooled connection is rejected.
Automatic reconnect is disabled while the transaction holds its lock; a lost
connection cannot silently continue outside that transaction. Failed rollback
keeps a surviving session's lock, while reconnect is restored for a later retry.
The ROP repeats its lookup after acquiring the transaction, so a writer that
waited uses an existing mapping instead of inserting a duplicate.

The live SQL harness passes against a private MariaDB 11.8.6 instance with TCP
disabled. Two independent connections exercise allocation from an empty table,
visibility of the first writer's mapping and distinct subsequent IDs. Killing
a connection during a write verifies rollback, commit failure and later retry.
The live check also passes with address/undefined sanitizers and default leak
detection. The temporary server was shut down after validation.
The test supports `OPENCHANGE_TEST_MYSQL_SOCKET` as well as an explicit host.

These locks coordinate writers using this backend on one SQL server. External
writers must follow the same locking protocol; multi-primary/failover behavior,
threaded sharing of pooled connections, real server/Outlook and complete storage
integration remain unvalidated. Lock ownership and release follow the
[MariaDB advisory-lock contract](https://mariadb.com/docs/server/reference/sql-functions/secondary-functions/miscellaneous-functions/get_lock).

## Staged installation preparation (2026-10-29)

The default installer now creates all seven SONAME links on Linux as well as
other supported platforms, without relying on `ldconfig`. AD templates are
installed beside the other OpenChange setup data rather than in Samba's own
tree. This removes a Python 2-only discovery command from the Makefile and
matches the installed `find_setup_dir()` search. Standalone support-library
install rules create their output directories. Uninstall removes all installed
administrative commands, both RPC modules, generated headers and the Nagios
script.

`script/check_install.py` inventories a trusted DESTDIR tree with SHA-256 hashes
and link targets, validates installed AD/mailbox templates against the source,
loads seven libraries and nine modules and runs four native and five Python
administrative help commands. It verifies installed Python and template lookup
from an empty working directory. Nine tooling tests cover inventory, missing or
duplicate libraries, bad links, special files, altered templates and runtime
failure. Native CI now performs installation, these runtime checks and removal,
and uploads the JSON/report logs. CI needs Python Samba and MySQLdb bindings for
these checks. See [the staged-install guide](TEST_INSTALL.md).

Local validation passes from a fresh source-only copy: bootstrap/configure,
`make -j2 all`, named-property/MySQL/EMSMDB checks, full staged install, all 11
installed runtime checks and uninstall with zero remaining files or symlinks.
The Python tooling suite reports 39 tests, with one environment-dependent skip.
No generated files or compiled libraries were copied into that build.

This does not validate server startup, actual provisioning, network RPC,
Outlook, the Nagios plugin or an operating/deployment configuration. Dependency
security review and storage integration remain required before server testing.

## Named-property review follow-up (2026-10-29)

SQL migration version 3 gives property names `utf8mb4_bin` identity, preserves
GUID case equivalence, normalizes the inactive string-property numeric arm to
NULL, adds three UNIQUE keys and checks property kinds/ID bounds. It rejects
existing ambiguous mappings before changing data. Three conflicting IDs in the
shared default seed are corrected for new databases; existing stores are never
renumbered automatically. Upgrade and recovery details are in
[Named-property schema version 3](NAMED_PROPERTIES_UPGRADE.md).

Duplicate SQL inserts report an existing mapping, and the ROP re-fetches the
winner with a current locking read. A collision involving a different name
fails safely. Failed rollback now logs the retained-lock state and driver status;
closing a borrowed pooled MYSQL pointer without coordinating its users remains
unsafe, so automatic pool-wide invalidation is not claimed.

The new regression checks exercise actual SQL migration, Unicode/case/accent
identity, constraints, ambiguous legacy data, duplicate inserts and seed
uniqueness. These changes do not implement mailbox storage or modern Outlook
transports.

## Failed SQL transaction recovery (2026-10-29)

Named-property cancellation now attempts to terminate the failed server session
when ROLLBACK fails, without freeing the pooled MYSQL handle that other contexts
borrow. Automatic reconnect stays disabled while the full SQL connection ID is
read and that session is terminated. The request still returns a database error;
a later retry can reconnect with the configured charset and SQL mode. If the
session cannot be identified or terminated, its surviving lock is retained with
a diagnostic requiring recovery.

Substituted-driver tests cover successful cleanup, session IDs above 32 bits,
failed session lookup, reconnect-option failure and failed termination. A live
SQL test injects a rollback error while the real transaction remains active,
checks advisory-lock release from another connection, verifies the write was
rolled back and reuses the same pooled handle after reconnect. This avoids
requiring a pool-wide ownership refactor for the successful recovery path;
threaded sharing and failed termination remain outside that guarantee.

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
| Reference build | Default native build recovered from a source-only checkout; full test suite pending |
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
