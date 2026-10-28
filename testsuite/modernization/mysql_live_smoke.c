/* Explicit, disposable SQL endpoint only; unique databases are removed after use. */
#include "mapiproxy/util/mysql.c"
#include <unistd.h>
#include "mapiproxy/libmapistore/backends/namedprops_mysql.c"

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

static bool named_properties_roundtrip(MYSQL *connection)
{
    struct namedprops_context backend = { .data = connection };
    struct MAPINAMEID name = { .ulKind = MNID_STRING };
    const char *values[] = {"name'", "backslash\\' OR 1=1 --", "caf\xc3\xa9", "emoji \xf0\x9f\x98\x80"};
    uint16_t mapped;
    name.lpguid = GUID_random();
    if (mysql_query(connection, "CREATE TABLE named_properties (`type` INT, propType INT, "
        "oleguid VARCHAR(36), mappedId INT UNSIGNED, propId BIGINT UNSIGNED, propName TEXT) "
        "CHARACTER SET utf8mb4") != 0) return false;
    for (size_t j = 0; j < sizeof(values) / sizeof(values[0]); j++) {
        name.kind.lpwstr.Name = values[j];
        if (create_id(&backend, name, 32768 + j) != MAPISTORE_SUCCESS ||
            get_mapped_id(&backend, name, &mapped) != MAPISTORE_SUCCESS || mapped != 32768 + j) return false;
    }
    name.kind.lpwstr.Name = "missing' OR 1=1 --";
    if (get_mapped_id(&backend, name, &mapped) != MAPISTORE_ERR_NOT_FOUND) return false;
    name.ulKind = MNID_ID; name.kind.lid = UINT32_MAX;
    return create_id(&backend, name, 65534) == MAPISTORE_SUCCESS &&
        get_mapped_id(&backend, name, &mapped) == MAPISTORE_SUCCESS && mapped == 65534;
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
    int result = 1, i;
    if (!ctx || !host || !*host || getentropy(&nonce, sizeof(nonce)) != 0) {
        fprintf(stderr, "Live SQL check needs OPENCHANGE_TEST_MYSQL_HOST and a disposable endpoint\n");
        talloc_free(ctx); return 1;
    }
    if (!user) user = "root";
    if (!password) password = "";
    if (!port) port = "3306";
    for (i = 0; i < 2; i++) {
        char *name = talloc_asprintf(ctx, "openchange_test_%"PRIx64"%s", nonce, i ? "`quoted" : "");
        char *uri;
        MYSQL *connection = NULL, *reused = NULL;
        MYSQL_RES *rows;
        MYSQL_ROW row;
        char *quoted, *drop;
        if (!name) FAIL();
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
            !literals_roundtrip(ctx, connection) || !named_properties_roundtrip(connection) ||
            !result_roundtrip(ctx, connection)) FAIL();
        quoted = mysql_quote_dbname(ctx, name);
        drop = quoted ? talloc_asprintf(ctx, "DROP DATABASE %s", quoted) : NULL;
        if (!drop || mysql_query(connection, drop) != 0) FAIL();
        close_all_connections();
    }
    result = 0;
    puts("Live SQL creation/reopen/reuse, literal round trips, charset/mode, forced reconnect, named properties/results and cleanup: OK");
end:
    close_all_connections(); talloc_free(ctx);
    return result;
}
