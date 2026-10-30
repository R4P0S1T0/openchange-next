/* Explicit, disposable SQL endpoint only; unique databases are removed after use. */
#include "mapiproxy/util/mysql.h"
#include <sys/wait.h>
#include <signal.h>
#include <poll.h>
#include <string.h>

/* Route all test connections, including pooled ones, to the explicit socket. */
static MYSQL *test_connect(MYSQL *connection, const char *host, const char *user,
    const char *password, const char *database, unsigned port, const char *socket, unsigned long flags)
{
    const char *test_socket = getenv("OPENCHANGE_TEST_MYSQL_SOCKET");
    return mysql_real_connect(connection, host, user, password, database, port,
        test_socket && *test_socket ? test_socket : socket, flags);
}
#define mysql_real_connect test_connect
#include <unistd.h>
static bool fail_rollback, fail_start, fail_release;
static unsigned start_failures, release_failures;
static int test_query(MYSQL *connection, const char *sql)
{
    if (fail_rollback && !strcmp(sql, "ROLLBACK")) return 1;
    if (fail_start && !strcmp(sql, "START TRANSACTION")) { start_failures++; return 1; }
    if (fail_release && strstr(sql, "RELEASE_LOCK")) { release_failures++; return 1; }
    return mysql_query(connection, sql);
}
#define mysql_query test_query
#include "mapiproxy/util/mysql.c"
#define migrate_named_properties_schema test_migrate_named_properties_schema
#define mapistore_errstr test_mapistore_errstr
#include "mapiproxy/libmapistore/backends/namedprops_mysql.c"

static unsigned migration_calls;
int test_migrate_named_properties_schema(const char *uri) { migration_calls++; return 1; }
const char *test_mapistore_errstr(enum mapistore_error error) { return "test error"; }

void mapistore_set_errno(int status) { errno = status; }

#define FAIL() do { fprintf(stderr, "Live SQL failure at line %d\n", __LINE__); goto end; } while (0)

static bool scalar_equals(MYSQL *connection, const char *sql, const char *expected)
{
    MYSQL_RES *rows;
    MYSQL_ROW row;
    bool equal;
    if (mysql_query(connection, sql) != 0) { fprintf(stderr, "Scalar query: %s\n", mysql_error(connection)); return false; }
    rows = mysql_store_result(connection);
    if (rows == NULL) return false;
    row = mysql_fetch_row(rows);
    equal = row && row[0] && !strcmp(row[0], expected);
    if (!equal) fprintf(stderr, "Scalar mismatch: expected %s, got %s\n", expected, row && row[0] ? row[0] : "NULL");
    mysql_free_result(rows);
    return equal;
}

static bool force_reconnect(MYSQL *connection, const char *host, const char *user,
    const char *password, unsigned port)
{
    MYSQL *control = mysql_init(NULL);
    char statement[64];
    bool killed;
    if (!control) return false;
    if (!mysql_real_connect(control, host, user, password, NULL, port, NULL, 0)) {
        mysql_close(control); return false;
    }
    snprintf(statement, sizeof(statement), "KILL CONNECTION %lu", mysql_thread_id(connection));
    killed = mysql_query(control, statement) == 0;
    mysql_close(control);
    return killed && mysql_ping(connection) == 0;
}

static bool literals_roundtrip(TALLOC_CTX *ctx, MYSQL *connection)
{
    const char *payloads[] = {"backslash\\' OR 1=1 --", "caf\xc3\xa9\\' literal", "line\nquote'"};
    for (size_t j = 0; j < sizeof(payloads) / sizeof(payloads[0]); j++) {
        const char *escaped = _sql(ctx, payloads[j]);
        char *statement = escaped ? talloc_asprintf(ctx, "SELECT '%s'", escaped) : NULL;
        if (!statement || !scalar_equals(connection, statement, payloads[j])) return false;
    }
    return true;
}

static bool named_properties_roundtrip(TALLOC_CTX *ctx, MYSQL *connection)
{
    struct namedprops_context backend = { .data = connection };
    struct MAPINAMEID name = { .ulKind = MNID_STRING };
    const char *values[] = {"name'", "backslash\\' OR 1=1 --", "caf\xc3\xa9", "emoji \xf0\x9f\x98\x80", "X-Foo", "x-foo", "cafe"};
    const unsigned sizes[] = {12, 44, 10, 18, 12, 12, 10};
    uint16_t mapped, type;
    struct MAPINAMEID *decoded;
    name.lpguid = GUID_random();
    if (mysql_query(connection, "CREATE TABLE named_properties (`type` INT, propType INT, "
        "oleguid VARCHAR(36) NOT NULL, mappedId INT UNSIGNED NOT NULL, propId BIGINT UNSIGNED, propName VARCHAR(255), "
        "UNIQUE(mappedId), UNIQUE(type,oleguid,propId), UNIQUE(type,oleguid,propName)) "
        "CHARACTER SET utf8mb4 COLLATE utf8mb4_bin") != 0) return false;
    for (size_t j = 0; j < sizeof(values) / sizeof(values[0]); j++) {
        name.kind.lpwstr.Name = values[j];
        if (create_id(&backend, name, 32768 + j) != MAPISTORE_SUCCESS ||
            get_mapped_id(&backend, name, &mapped) != MAPISTORE_SUCCESS || mapped != 32768 + j) return false;
        if (get_nameid(&backend, mapped, ctx, &decoded) != MAPISTORE_SUCCESS) return false;
        if (decoded->ulKind != MNID_STRING || !GUID_equal(&name.lpguid, &decoded->lpguid) ||
            strcmp(decoded->kind.lpwstr.Name, values[j]) || decoded->kind.lpwstr.NameSize != sizes[j]) {
            talloc_free(decoded); return false;
        }
        talloc_free(decoded);
        if (get_nameid_type(&backend, mapped, &type) != MAPISTORE_SUCCESS || type != PT_NULL) return false;
    }
    name.kind.lpwstr.Name = "X-Foo";
    if (create_id(&backend, name, 42000) != MAPISTORE_ERR_EXIST ||
        get_mapped_id(&backend, name, &mapped) != MAPISTORE_SUCCESS || mapped != 32772) return false;
    name.kind.lpwstr.Name = "another name";
    if (create_id(&backend, name, 32772) != MAPISTORE_ERR_EXIST ||
        get_mapped_id(&backend, name, &mapped) != MAPISTORE_ERR_NOT_FOUND) return false;
    name.kind.lpwstr.Name = "missing' OR 1=1 --";
    if (get_mapped_id(&backend, name, &mapped) != MAPISTORE_ERR_NOT_FOUND) return false;
    name.ulKind = MNID_ID; name.kind.lid = UINT32_MAX;
    if (create_id(&backend, name, 65534) != MAPISTORE_SUCCESS ||
        get_mapped_id(&backend, name, &mapped) != MAPISTORE_SUCCESS || mapped != 65534 ||
        get_nameid(&backend, mapped, ctx, &decoded) != MAPISTORE_SUCCESS) return false;
    bool valid = decoded->ulKind == MNID_ID && decoded->kind.lid == UINT32_MAX &&
        GUID_equal(&name.lpguid, &decoded->lpguid);
    talloc_free(decoded);
    return valid;
}

/* This exercises the real initializer; physical v3 constraints have separate migration tests. */
static bool named_properties_schema_gate(TALLOC_CTX *ctx, MYSQL *connection, const char *database,
    const char *host, const char *user, const char *password, const char *port)
{
    TALLOC_CTX *attempt = talloc_new(ctx);
    struct loadparm_context *lp = attempt ? loadparm_init(attempt) : NULL;
    struct namedprops_context *backend;
    bool ok = false;
    if (!lp || !lpcfg_set_cmdline(lp, "namedproperties:mysql_user", user) ||
        !lpcfg_set_cmdline(lp, "namedproperties:mysql_pass", password) ||
        !lpcfg_set_cmdline(lp, "namedproperties:mysql_host", host) ||
        !lpcfg_set_cmdline(lp, "namedproperties:mysql_port", port) ||
        !lpcfg_set_cmdline(lp, "namedproperties:mysql_db", database)) goto end;
    migration_calls = 0;
    if (mysql_query(connection, "CREATE TABLE namedXproperties (value INT)")) goto end;
    for (unsigned i = 0; i < 4; i++) {
        if (i == 1 && mysql_query(connection, "CREATE TABLE migrations (app VARCHAR(64), version INT)")) goto end;
        if (i == 2 && mysql_query(connection, "INSERT INTO migrations VALUES ('named_properties',2)")) goto end;
        if (i == 3 && mysql_query(connection, "INSERT INTO migrations VALUES ('named_properties',3)")) goto end;
        backend = (void *)1;
        if (mapistore_namedprops_mysql_init(attempt, lp, &backend) !=
            (i == 3 ? MAPISTORE_SUCCESS : MAPISTORE_ERR_DATABASE_INIT)) {
            fprintf(stderr, "Live named-property schema gate failed case %u (missing table/record, v2, v3)\n", i);
            goto end;
        }
        if ((backend != NULL) != (i == 3) || migration_calls ||
            !scalar_equals(connection, "SELECT COUNT(*) FROM named_properties", "8") ||
            !scalar_equals(connection, "SELECT COUNT(*) FROM namedXproperties", "0")) {
            fprintf(stderr, "Live schema gate mutated existing tables or invoked migration in case %u\n", i);
            goto end;
        }
        if (backend) talloc_free(backend);
        if (i && !scalar_equals(connection, "SELECT COUNT(*) FROM migrations", i == 1 ? "0" : i == 2 ? "1" : "2")) goto end;
    }
    ok = true;
end:
    talloc_free(attempt);
    return ok;
}

static bool named_properties_concurrency(MYSQL *connection, const char *database,
    const char *host, const char *user, const char *password, unsigned port)
{
    struct namedprops_context backend = { .data = connection };
    struct MAPINAMEID shared = { .ulKind = MNID_ID, .kind.lid = 42 };
    uint16_t id;
    int ready[2], status;
    pid_t child;
    bool success = false, active = false;
    char byte;
    if (mysql_query(connection, "DELETE FROM named_properties") || pipe(ready)) return false;
    if (transaction_start(&backend) != MAPISTORE_SUCCESS) goto pipes;
    active = true;
    child = fork();
    if (child < 0) goto pipes;
    if (child == 0) {
        MYSQL *second = mysql_init(NULL);
        struct namedprops_context writer = { .data = second };
        struct MAPINAMEID other = shared;
        bool ok = false;
        close(ready[0]); alarm(15);
        other.kind.lid++;
        if (!second || !mysql_real_connect(second, host, user, password, database, port, NULL, 0)) goto child_end;
        if (get_mapped_id(&writer, shared, &id) != MAPISTORE_ERR_NOT_FOUND) goto child_end;
        if (write(ready[1], "R", 1) != 1) goto child_end;
        if (transaction_start(&writer) != MAPISTORE_SUCCESS) goto child_end;
        if (get_mapped_id(&writer, shared, &id) != MAPISTORE_SUCCESS || id != 0x8001 ||
            next_unused_id(&writer, &id) != MAPISTORE_SUCCESS || id != 0x8002 ||
            create_id(&writer, other, id) != MAPISTORE_SUCCESS) {
            transaction_cancel(&writer); goto child_end;
        }
        ok = transaction_commit(&writer) == MAPISTORE_SUCCESS;
child_end:
        if (second) mysql_close(second);
        close(ready[1]); _exit(ok ? 0 : 1);
    }
    {
        struct pollfd waiting = { .fd = ready[0], .events = POLLIN };
        if (poll(&waiting, 1, 10000) <= 0 || read(ready[0], &byte, 1) != 1) goto child_failed;
    }
    if (next_unused_id(&backend, &id) != MAPISTORE_SUCCESS || id != 0x8001 ||
        create_id(&backend, shared, id) != MAPISTORE_SUCCESS ||
        transaction_commit(&backend) != MAPISTORE_SUCCESS) goto child_failed;
    active = false;
    if (waitpid(child, &status, 0) != child) goto pipes;
    success = WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
        scalar_equals(connection, "SELECT COUNT(*) FROM named_properties", "2") &&
        scalar_equals(connection, "SELECT COUNT(DISTINCT mappedId) FROM named_properties", "2");
    goto pipes;
child_failed:
    kill(child, SIGKILL); waitpid(child, &status, 0);
pipes:
    if (active) transaction_cancel(&backend);
    close(ready[0]); close(ready[1]);
    return success;
}

static bool named_properties_lost_transaction(MYSQL *connection, const char *host,
    const char *user, const char *password, unsigned port)
{
    struct namedprops_context backend = { .data = connection };
    struct MAPINAMEID name = { .ulKind = MNID_ID, .kind.lid = 777 };
    uint16_t id;
    if (transaction_start(&backend) != MAPISTORE_SUCCESS) return false;
    if (transaction_start(&backend) != MAPISTORE_ERR_DATABASE_OPS ||
        next_unused_id(&backend, &id) != MAPISTORE_SUCCESS ||
        create_id(&backend, name, id) != MAPISTORE_SUCCESS) {
        transaction_cancel(&backend); return false;
    }
    /* The killed transaction must not reconnect and report a successful commit. */
    if (force_reconnect(connection, host, user, password, port) ||
        transaction_commit(&backend) != MAPISTORE_ERR_DATABASE_OPS ||
        transaction_cancel(&backend) != MAPISTORE_ERR_DATABASE_OPS) return false;
    if (mysql_ping(connection) || get_mapped_id(&backend, name, &id) != MAPISTORE_ERR_NOT_FOUND ||
        transaction_start(&backend) != MAPISTORE_SUCCESS) return false;
    return transaction_cancel(&backend) == MAPISTORE_SUCCESS;
}

static bool named_properties_failed_rollback(MYSQL *connection, const char *database, const char *host,
    const char *user, const char *password, unsigned port)
{
    struct namedprops_context backend = { .data = connection };
    struct MAPINAMEID name = { .ulKind = MNID_ID, .kind.lid = 778 };
    MYSQL *observer = mysql_init(NULL), *borrowed = connection;
    uint16_t id;
    uint64_t old_session, new_session;
    bool ok = false;
    if (!observer || !mysql_real_connect(observer, host, user, password, database, port, NULL, 0)) FAIL();
    if (select_first_uint(connection, "SELECT CONNECTION_ID()", &old_session) != MYSQL_SUCCESS ||
        transaction_start(&backend) != MAPISTORE_SUCCESS ||
        next_unused_id(&backend, &id) != MAPISTORE_SUCCESS ||
        create_id(&backend, name, id) != MAPISTORE_SUCCESS) FAIL();
    /* Inject a ROLLBACK error while the real session and transaction stay alive. */
    fail_rollback = true;
    if (transaction_cancel(&backend) != MAPISTORE_ERR_DATABASE_OPS) FAIL();
    fail_rollback = false;
    /* Session termination may finish asynchronously; wait for ownership from another session. */
    if (!scalar_equals(observer, "SELECT GET_LOCK("NAMEDPROPS_LOCK",5)", "1") ||
        !scalar_equals(observer, "SELECT RELEASE_LOCK("NAMEDPROPS_LOCK")", "1")) FAIL();
    /* Both borrowers retain a valid handle and use a new, correctly configured session. */
    if (mysql_ping(borrowed) ||
        select_first_uint(borrowed, "SELECT CONNECTION_ID()", &new_session) != MYSQL_SUCCESS || new_session == old_session ||
        !scalar_equals(borrowed, "SELECT @@character_set_connection", "utf8mb4") ||
        !scalar_equals(borrowed, "SELECT @@SESSION.sql_mode NOT LIKE '%NO_BACKSLASH_ESCAPES%'", "1") ||
        get_mapped_id(&backend, name, &id) != MAPISTORE_ERR_NOT_FOUND ||
        transaction_start(&backend) != MAPISTORE_SUCCESS) FAIL();
    ok = transaction_cancel(&backend) == MAPISTORE_SUCCESS;
end:
    fail_rollback = false;
    if (observer) mysql_close(observer);
    return ok;
}

static bool named_properties_failed_start(MYSQL *connection, const char *database, const char *host,
    const char *user, const char *password, unsigned port)
{
    struct namedprops_context backend = { .data = connection };
    MYSQL *observer = mysql_init(NULL), *borrowed = connection;
    uint64_t old_session, new_session;
    unsigned starts = start_failures, releases = release_failures;
    bool ok = false;
    if (!observer || !mysql_real_connect(observer, host, user, password, database, port, NULL, 0)) FAIL();
    if (select_first_uint(connection, "SELECT CONNECTION_ID()", &old_session) != MYSQL_SUCCESS) FAIL();
    /* Leave the acquired real lock intact when START and its RELEASE_LOCK cleanup fail. */
    fail_start = fail_release = true;
    if (transaction_start(&backend) != MAPISTORE_ERR_DATABASE_OPS ||
        start_failures != starts + 1 || release_failures != releases + 1) FAIL();
    fail_start = fail_release = false;
    /* Session termination may finish asynchronously; wait for ownership from another session. */
    if (!scalar_equals(observer, "SELECT GET_LOCK("NAMEDPROPS_LOCK",5)", "1") ||
        !scalar_equals(observer, "SELECT RELEASE_LOCK("NAMEDPROPS_LOCK")", "1")) FAIL();
    if (backend.data != borrowed || mysql_ping(borrowed) ||
        select_first_uint(borrowed, "SELECT CONNECTION_ID()", &new_session) != MYSQL_SUCCESS || new_session == old_session ||
        !scalar_equals(borrowed, "SELECT @@character_set_connection", "utf8mb4") ||
        !scalar_equals(borrowed, "SELECT @@SESSION.sql_mode NOT LIKE '%NO_BACKSLASH_ESCAPES%'", "1") ||
        transaction_start(&backend) != MAPISTORE_SUCCESS) FAIL();
    ok = transaction_cancel(&backend) == MAPISTORE_SUCCESS;
end:
    fail_start = fail_release = false;
    if (!ok) transaction_cancel(&backend);
    if (observer) mysql_close(observer);
    return ok;
}

static bool result_roundtrip(TALLOC_CTX *ctx, MYSQL *connection)
{
    struct StringArrayW_r *array;
    uint64_t number = 7;
    if (select_all_strings(ctx, connection, "SELECT 'only'", &array) != MYSQL_SUCCESS) return false;
    if (array->cValues != 1 || strcmp(array->lppszW[0], "only")) { talloc_free(array); return false; }
    talloc_free(array);
    if (select_all_strings(ctx, connection, "SELECT 'en', 'Drafts'", &array) != MYSQL_SUCCESS) return false;
    if (array->cValues != 1 || strcmp(array->lppszW[0], "Drafts")) { talloc_free(array); return false; }
    talloc_free(array);
    return select_first_uint(connection, "SELECT '18446744073709551615'", &number) == MYSQL_SUCCESS &&
        number == UINT64_MAX && select_first_uint(connection, "SELECT '-1'", &number) == MYSQL_ERROR &&
        number == UINT64_MAX;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    const char *host = getenv("OPENCHANGE_TEST_MYSQL_HOST");
    const char *user = getenv("OPENCHANGE_TEST_MYSQL_USER");
    const char *password = getenv("OPENCHANGE_TEST_MYSQL_PASSWORD");
    const char *port = getenv("OPENCHANGE_TEST_MYSQL_PORT");
    uint64_t nonce;
    MYSQL *connection = NULL;
    char *drop = NULL;
    int result = 1, i;
    if ((!host || !*host) && getenv("OPENCHANGE_TEST_MYSQL_SOCKET")) host = "localhost";
    if (!ctx || !host || !*host || getentropy(&nonce, sizeof(nonce)) != 0) {
        fprintf(stderr, "Live SQL check needs OPENCHANGE_TEST_MYSQL_HOST or OPENCHANGE_TEST_MYSQL_SOCKET and a disposable endpoint\n");
        talloc_free(ctx); return 1;
    }
    if (!user) user = "root";
    if (!password) password = "";
    if (!port) port = "3306";
    for (i = 0; i < 2; i++) {
        char *name = talloc_asprintf(ctx, "openchange_test_%"PRIx64"%s", nonce, i ? "`quoted" : "");
        char *uri;
        MYSQL *reused = NULL;
        connection = NULL;
        MYSQL_RES *rows;
        MYSQL_ROW row;
        char *quoted;
        if (!name) FAIL();
        quoted = mysql_quote_dbname(ctx, name);
        drop = quoted ? talloc_asprintf(ctx, "DROP DATABASE IF EXISTS %s", quoted) : NULL;
        if (!drop) FAIL();
        uri = talloc_asprintf(ctx, "mysql://%s:%s@%s:%s/%s", user, password, host, port, name);
        if (!uri || !create_connection(uri, &connection)) FAIL();
        if (create_connection(uri, &reused) != connection || !reused) FAIL();
        if (mysql_query(connection, "SELECT DATABASE()") != 0) FAIL();
        rows = mysql_store_result(connection);
        if (!rows) FAIL();
        row = mysql_fetch_row(rows);
        if (!row || !row[0] || strcmp(row[0], name) != 0) { mysql_free_result(rows); FAIL(); }
        mysql_free_result(rows);
        if (!scalar_equals(connection, "SELECT @@SESSION.sql_mode NOT LIKE '%NO_BACKSLASH_ESCAPES%'", "1") ||
            !scalar_equals(connection, "SELECT @@character_set_connection", "utf8mb4")) FAIL();
        if (!literals_roundtrip(ctx, connection)) FAIL();
        close_all_connections(); connection = NULL;
        if (!create_connection(uri, &connection)) FAIL();
        if (!force_reconnect(connection, host, user, password, strtoul(port, NULL, 10)) ||
            !scalar_equals(connection, "SELECT @@SESSION.sql_mode NOT LIKE '%NO_BACKSLASH_ESCAPES%'", "1") ||
            !scalar_equals(connection, "SELECT @@character_set_connection", "utf8mb4") ||
            !scalar_equals(connection, "SELECT DATABASE()", name) ||
            !literals_roundtrip(ctx, connection) || !named_properties_roundtrip(ctx, connection) ||
            !named_properties_schema_gate(ctx, connection, name, host, user, password, port) ||
            !result_roundtrip(ctx, connection) ||
            !named_properties_concurrency(connection, name, host, user, password, strtoul(port, NULL, 10)) ||
            !named_properties_lost_transaction(connection, host, user, password, strtoul(port, NULL, 10)) ||
            !named_properties_failed_rollback(connection, name, host, user, password, strtoul(port, NULL, 10)) ||
            !named_properties_failed_start(connection, name, host, user, password, strtoul(port, NULL, 10))) FAIL();
        if (create_connection(uri, &reused) != connection || !reused) FAIL();
        if (mysql_query(connection, drop) != 0) FAIL();
        drop = NULL;
        close_all_connections(); connection = NULL;
    }
    result = 0;
    puts("Live SQL creation/reopen/reuse, literal round trips, charset/mode, forced reconnect, named properties/results and schema gate, concurrent allocation, connection-loss rollback, failed-rollback/start recovery and cleanup: OK");
end:
    if (drop && connection && mysql_query(connection, drop))
        fprintf(stderr, "Disposable SQL database cleanup failed (error %u)\n", mysql_errno(connection));
    close_all_connections(); talloc_free(ctx);
    return result;
}
