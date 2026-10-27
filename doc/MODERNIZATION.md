# OpenChange modernization

## Status on 2026-10-27

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
- **22 Python tooling/socket tests** and **25 Python runtime tests** pass.
  Runtime tests exercise disposable LDB files, real SQL schema upgrades and
  rollbacks, Unicode LDIF, failed-import rollback, and administration CLI help.
- Incremental `make -q libmapi` succeeds without rebuilding generated protocols.
- `libmapiproxy.so.2.3`, `libmapistore.so.2.3` and `libmapiserver.so.2.3`
  compile and load together after libmapi. The actual RPC server module still
  fails to build; loading these support libraries does not start a server.
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
make check-mapiproxy-registries
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

## Remaining blockers

`make mapiproxy` now reaches **`mapiproxy/dcesrv_mapiproxy.c`**. Current Samba
no longer exposes the connection-context `private_data`/`assoc_group` fields or
the binding layout used by that module. Generated RPC server initialization
functions also take a context parameter, unlike the historical declarations in
`dcesrv_mapiproxy_proto.h`. These connection-state, binding and lifecycle APIs
need adaptation together with real bind/unbind/authentication tests.

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
