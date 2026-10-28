/* Explicit, disposable SQL endpoint only; unique databases are removed after use. */
#include "mapiproxy/util/mysql.c"
#include <unistd.h>

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
        if (!name) goto end;
        uri = talloc_asprintf(ctx, "mysql://%s:%s@%s:%s/%s", user, password, host, port, name);
        if (!uri || !create_connection(uri, &connection)) goto end;
        if (create_connection(uri, &reused) != connection || !reused) goto end;
        if (mysql_query(connection, "SELECT DATABASE()") != 0) goto end;
        rows = mysql_store_result(connection);
        if (!rows) goto end;
        row = mysql_fetch_row(rows);
        if (!row || !row[0] || strcmp(row[0], name) != 0) { mysql_free_result(rows); goto end; }
        mysql_free_result(rows);
        quoted = mysql_quote_dbname(ctx, name);
        drop = quoted ? talloc_asprintf(ctx, "DROP DATABASE %s", quoted) : NULL;
        if (!drop || mysql_query(connection, drop) != 0) goto end;
        close_all_connections();
    }
    result = 0;
    puts("Live SQL connection reuse, normal/quoted database creation, selected-name verification and cleanup: OK");
end:
    close_all_connections(); talloc_free(ctx);
    return result;
}
