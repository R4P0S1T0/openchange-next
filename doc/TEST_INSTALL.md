# Staged installation check

This checks a build's installation layout before preparing a disposable server.
It does not start Samba, provision AD, connect Outlook, enable the cache plugin,
or certify the dependency stack as secure. The first deployment is still gated
by [test-server readiness](TEST_SERVER_READINESS.md). Inventory and source-build
work on a lab host can follow [the server lab plan](TEST_LAB_PLAN.md) now.

Use the Debian 13 build prerequisites from
[the native CI job](../.github/workflows/modernization.yml), including
`python3-samba` and `python3-mysqldb` for the administrative tools. PIDL must
match the Samba generation used for the build. Use the distribution Python
interpreter so its Samba bindings match the installed libraries.

From a source-only checkout:

```sh
./autogen.sh
./configure --with-samba=/usr --prefix=/opt/openchange-test
make -j2 all
make check-namedprops check-mysql-utils check-emsmdb
python3 -m unittest discover -s testsuite/modernization -v

oc_stage=$(mktemp -d /tmp/openchange-install.XXXXXX)
make install DESTDIR="$oc_stage" > install.log 2>&1
/usr/bin/python3 script/check_install.py "$oc_stage" > install.json
```

No root access is needed for `DESTDIR`. The configured prefix is the eventual
installation location; `DESTDIR` only places that layout under a temporary root.
Do not point `DESTDIR` at a populated system tree. The checker loads code from
that tree, so use only trusted build output.

The JSON report records installed file SHA-256 hashes, symlink targets and
runtime check results. It rejects missing SONAME links, duplicate required
artifacts, broken/external links, special files and missing/changed AD or
mailbox templates before executing checks. It loads all seven libraries and
nine modules, exercises four native CLI help commands and five administrative
CLI help commands, and verifies installed Python/template discovery. Checks run
from an empty temporary working directory with the staged Python package and
library directory first on their search paths. They do not invoke module
initializers or establish live network services.

On a normal installation the loader must still find the configured library
directory, for example through the distribution's linker configuration. This
staged check uses `LD_LIBRARY_PATH` rather than modifying the host loader cache.
External dependencies can be supplied through existing `LD_LIBRARY_PATH` and
`PYTHONPATH` when validating an extracted toolchain; the report is not proof
that those dependencies will exist on the target server.

Keep `install.json`, `install.log`, the source revision and local diff, configure
arguments, the compiler version and the chosen OS package inventory with the
review artifact. An installed file manifest alone is not a reproducible build
or a dependency security assessment. CI uploads its staged install/removal
reports; no successful remote CI run is implied by local results.

Before removing the temporary install, optionally archive it for inspection:

```sh
tar -czf installed-files.tar.gz -C "$oc_stage" .
make uninstall DESTDIR="$oc_stage" > uninstall.log 2>&1
test -z "$(find "$oc_stage" \( -type f -o -type l \) -print -quit)"
```

The last check permits empty directories but requires removal of every installed
file and symlink. AD templates are installed under OpenChange's own
`share/setup/AD`; uninstall does not remove Samba-owned schema files.
The archive is an installation-layout artifact, not a deployment package.
The legacy Nagios script is present in the default install but remains outside
the validated CLI set and must not be enabled based on this check.

Remaining work includes a patched dependency baseline, the full exposed-input
review, a concrete storage backend, server configuration, AD provisioning,
startup/health checks, authentication and mailbox/client integration tests.
