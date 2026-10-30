# Named-property schema version 3

Version 3 fixes SQL property-name identity and moves uniqueness enforcement into
the database. It is validated against MariaDB 11.8.6; other database releases
need their own migration/constraint checks.

The table and text fields use `utf8mb4` with `utf8mb4_bin`, so names differing
in case or accents remain distinct and four-byte characters are representable.
GUID text retains case-insensitive ASCII comparison because hexadecimal GUID
case does not change the property set. UNIQUE keys cover `mappedId`,
`(type,oleguid,propId)` and `(type,oleguid,propName)`. A CHECK requires the
appropriate numeric/string arm and IDs between 0x8000 and 0xfffe. The inactive
numeric arm of string properties is NULL, including legacy zero values.

On a duplicate-key insert, the C backend reports `MAPISTORE_ERR_EXIST` and the
ROP looks up the name again. The SQL lookup uses a locking read so that a
concurrent commit is visible despite an earlier transaction snapshot. If only
the proposed ID collided with another name, the lookup fails and the ROP rolls
back; it never returns that other property's ID.

## Existing databases

Stop named-property writers and keep a database/mailbox backup before applying
the schema change. Use the administrative tool with the existing private
configuration rather than putting database credentials in a shell command:

```sh
openchange_migrate --configfile=/path/to/lab-smb.conf --target-version=3 named_properties
openchange_migrate --configfile=/path/to/lab-smb.conf --list named_properties
```

The C backend now requires `SELECT MAX(version) FROM migrations WHERE
app='named_properties'` to return exactly 3 before publishing its context.
An existing named-property table with missing migration metadata, version 2,
an unknown future version, NULL/invalid data or a read failure is rejected with
`MAPISTORE_ERR_DATABASE_INIT` and an upgrade diagnostic without credentials.
Initialization does not migrate or change an existing named-property table.
The table lookup matches the exact name; a failed lookup is rejected before
the migration bridge can run. Only confirmed absence permits schema creation.
Apply and verify the upgrade above before restarting writers. A new database
continues to use the existing migration bridge, then passes the same version
check before initialization succeeds.

This version check reads migration metadata; it does not audit the physical
schema or constraints. Recording version 3 with `--fake` does not certify that
the database has the v3 constraints or correct data.

The migration takes the same database advisory lock as the C backend. It checks
for duplicate IDs/identities and invalid rows before normalizing values or
changing the schema. A conflict stops the upgrade, preserves the mappings and
does not record version 3. Do not fake that version or restart writers against
a rejected upgrade. External tools that ignore the lock must also be stopped
for schema maintenance; the UNIQUE keys protect subsequent normal writes.

The old default fixture contained three ID collisions. The new shared LDB/SQL
seed uses 0x8001 for PidLidUnknown1004, 0x8002 for PidLidUnknown822c and 0x8003 for
`urn:schemas-microsoft-com:office:outlook#noaclui`. Existing stores are **not**
renumbered automatically: an ID may already appear in stored mailbox data, and
resolving that ambiguity requires a mailbox-aware migration. A new disposable
lab can recreate its database from the corrected seed. Existing LDB databases
also require their own data assessment; the SQL schema migration does not edit
them.

Downgrading from version 3 removes its constraints but retains UTF-8 capability.
Converting back to utf8mb3 could lose four-byte names, so the rollback does not
perform that conversion. Migration DDL is not a transactional database restore.

## Failed transaction cleanup and connection ownership

If ROLLBACK fails, the C backend logs the driver error number and SQLSTATE
without SQL values or credentials. With automatic reconnect disabled, it reads
that connection's full SQL session ID and attempts `KILL CONNECTION` on that
same session. It does not call `mysql_close()` on the shared MYSQL pointer.
Borrowing contexts keep valid client handles; a later retry can reconnect with
the configured character set and SQL mode.

Terminating a session rolls back its transaction and releases its advisory
lock according to [MariaDB's KILL semantics](https://mariadb.com/docs/server/reference/sql-statements/administrative-sql-statements/kill).
The failed request still returns a database error; recovery never publishes
partial property IDs or reports a failed write as committed. Native tests also
cover session IDs above 32 bits, so cleanup does not rely on a truncated client
thread ID.

The same recovery applies when transaction start fails after lock acquisition:
if reading the GET_LOCK result or START TRANSACTION fails, the backend first
tries RELEASE_LOCK. Only a failed cleanup triggers termination of its own
session. A clean lock timeout, a lock already owned by that session or a failed
pre-acquisition lookup does not terminate the session. Reconnect is disabled
while identifying/terminating it and restored on exit; failures are logged.
The start still reports its original database error, without committing or
publishing property IDs.

If identifying or terminating the session fails, the diagnostic states that a
surviving session retains its lock. Stop/quiesce its users and restart the
affected service/connection pool before retrying. The fallback preserves
serialization rather than freeing a lock around an uncertain transaction.
This does not add support for concurrent threaded use of one MYSQL handle.

## Validation

Native tests cover duplicate-key classification, a ROP refetch after an insert
race, rollback/start-cleanup diagnostics, session termination and conservative
recovery failures, including GET_LOCK result-read failure after acquisition and
controls that must leave an existing session alive. A generator test rejects
duplicate seed IDs or identities. Actual SQL schema tests cover fresh import,
a legacy charset upgrade, case/accent/four-byte names, all three UNIQUE keys, GUID case, invalid
union arms, downgrade/upgrade and rejection of ambiguous existing mappings.
The live C harness covers its lookup/insert paths, concurrent writers and
connection loss using a disposable SQL endpoint. An injected ROLLBACK error
leaves a real transaction alive; the check observes lock release from an
independent connection, verifies rollback, then reuses the borrowed client handle
and confirms that pool lookup still returns it. A separate injection fails START
after real lock acquisition and simulates RELEASE_LOCK failure; an independent
connection waits for and acquires the released lock, then the borrowed handle
reconnects and starts another transaction. CI runs both the native and
Python SQL suites; its result must be checked for the exact published commit.

Local review validation passes: the full build, 17 native make check targets,
40 Python tooling tests (one environment-dependent skip), 28 runtime tests and
the live C SQL check on a private MariaDB instance with TCP disabled. Focused
named-property/MySQL harnesses and the live SQL check also pass with ASan/UBSan
and default leak detection. The SQL instance and its data were removed afterward.
