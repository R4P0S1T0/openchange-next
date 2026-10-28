/* Explicit, disposable SQL endpoint only; unique databases are removed after use. */
#include "mapiproxy/util/mysql.c"
#include <unistd.h>

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
            !literals_roundtrip(ctx, connection)) FAIL();
        quoted = mysql_quote_dbname(ctx, name);
        drop = quoted ? talloc_asprintf(ctx, "DROP DATABASE %s", quoted) : NULL;
        if (!drop || mysql_query(connection, drop) != 0) FAIL();
        close_all_connections();
    }
    result = 0;
    puts("Live SQL creation/reopen/reuse, literal round trips, charset/mode, forced reconnect and cleanup: OK");
end:
    close_all_connections(); talloc_free(ctx);
    return result;
}
