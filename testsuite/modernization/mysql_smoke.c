/* Actual SQL connection code with a substituted driver; no database is contacted. */
#include "libmapi/libmapi.h"
#include "mapiproxy/util/mysql.h"
#include <assert.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

static enum { FAIL_NONE, FAIL_INIT, FAIL_AUTH, FAIL_QUERY, FAIL_SELECT, FAIL_ENTRY, FAIL_COPY, FAIL_CHARSET, FAIL_INIT_COMMAND, FAIL_POOL } failure;
static bool need_database, charset_set, mode_set;
static bool lock_held, reconnect_enabled = true;
static bool lock_timeout, fail_reconnect_option, duplicate_entry;
static const char *fail_statement;
static unsigned clock_mode, clock_calls;
static int fixture_clock_gettime(clockid_t id, struct timespec *value)
{
    if (!clock_mode) return clock_gettime(id, value);
    if (clock_mode == 2 || (clock_mode == 3 && clock_calls++)) return -1;
    value->tv_sec = clock_calls++ * 2; value->tv_nsec = 0;
    return 0;
}
static unsigned initialized, connected, closed, selections;
static MYSQL_RES result_fixture;
static uint64_t result_rows_count = 1;
static unsigned result_fields = 1, result_cursor, acquired, released;
static char *result_values[3][4] = {{"one"}};
static bool fail_store, fail_fetch, fail_result_copy, fail_escape;
static MYSQL_RES *fixture_mysql_store_result(MYSQL *mysql)
{ if (fail_store) return NULL; result_cursor = 0; acquired++; return &result_fixture; }
static void fixture_mysql_free_result(MYSQL_RES *result)
{ assert(result == &result_fixture && released < acquired); released++; }
static my_ulonglong fixture_mysql_num_rows(MYSQL_RES *result) { return result_rows_count; }
static unsigned fixture_mysql_field_count(MYSQL *mysql) { return result_fields; }
static MYSQL_ROW fixture_mysql_fetch_row(MYSQL_RES *result)
{ return fail_fetch || result_cursor >= result_rows_count ? NULL : result_values[result_cursor++]; }
static char logs[8192], query[512];
static size_t logged;
static void fixture_debug(const char *format, ...)
{
    va_list args;
    int written;
    va_start(args, format);
    written = vsnprintf(logs + logged, sizeof(logs) - logged, format, args);
    va_end(args);
    if (written > 0) logged += (size_t)written < sizeof(logs) - logged ? (size_t)written : sizeof(logs) - logged - 1;
}
static MYSQL *fixture_mysql_init(MYSQL *existing)
{
    if (failure == FAIL_INIT) return NULL;
    initialized++; charset_set = mode_set = false; selections = 0;
    return calloc(1, sizeof(MYSQL));
}
static int fixture_mysql_options(MYSQL *mysql, enum mysql_option option, const void *value)
{
    assert(mysql);
    if (option == MYSQL_OPT_RECONNECT) {
        if (fail_reconnect_option) return 1;
        reconnect_enabled = *(const my_bool *)value;
    }
    if (option == MYSQL_SET_CHARSET_NAME) {
        if (failure == FAIL_CHARSET) return 1;
        assert(!strcmp(value, "utf8mb4")); charset_set = true;
    }
    if (option == MYSQL_INIT_COMMAND) {
        if (failure == FAIL_INIT_COMMAND) return 1;
        assert(strstr(value, "NO_BACKSLASH_ESCAPES")); mode_set = true;
    }
    return 0;
}
static MYSQL *fixture_mysql_connect(MYSQL *mysql, const char *host, const char *user,
    const char *password, const char *database, unsigned port, const char *socket, unsigned long flags)
{
    assert(mysql && host && user && charset_set && mode_set);
    connected++;
    assert(database == NULL);
    if (failure == FAIL_AUTH) return NULL;
    return mysql;
}
static void fixture_mysql_close(MYSQL *mysql) { assert(mysql); closed++; free(mysql); }
static unsigned fixture_mysql_errno(MYSQL *mysql) { return duplicate_entry ? 1062 : 1234; }
static const char *fixture_mysql_sqlstate(MYSQL *mysql) { return "42000"; }
static int fixture_mysql_query(MYSQL *mysql, const char *sql)
{
    assert(mysql && strlen(sql) < sizeof(query)); strcpy(query, sql);
    if (duplicate_entry && !strncmp(sql, "INSERT", 6)) return 1;
    if (failure == FAIL_QUERY || (fail_statement && strstr(sql, fail_statement))) return 1;
    if (strstr(sql, "IS_USED_LOCK")) result_values[0][0] = lock_held ? "1" : "0";
    if (strstr(sql, "GET_LOCK")) {
        assert(!reconnect_enabled && !lock_held);
        lock_held = !lock_timeout;
        result_values[0][0] = lock_held ? "1" : "0";
    }
    if (strstr(sql, "RELEASE_LOCK")) {
        result_values[0][0] = lock_held ? "1" : NULL;
        lock_held = false;
    }
    if (!strcmp(sql, "START TRANSACTION")) assert(lock_held && !reconnect_enabled);
    return 0;
}
static int fixture_mysql_select(MYSQL *mysql, const char *database)
{ return failure == FAIL_SELECT || (selections++ == 0 && (need_database || failure == FAIL_QUERY)); }

#undef OC_DEBUG
#define OC_DEBUG(level, ...) fixture_debug(__VA_ARGS__)
#define mysql_init fixture_mysql_init
#define mysql_options fixture_mysql_options
#define mysql_real_connect fixture_mysql_connect
#define mysql_close fixture_mysql_close
#define mysql_errno fixture_mysql_errno
#define mysql_sqlstate fixture_mysql_sqlstate
#define clock_gettime fixture_clock_gettime
#define mysql_query fixture_mysql_query
#define mysql_select_db fixture_mysql_select
#define mysql_store_result fixture_mysql_store_result
#define mysql_free_result fixture_mysql_free_result
#define mysql_num_rows fixture_mysql_num_rows
#define mysql_field_count fixture_mysql_field_count
#define mysql_fetch_row fixture_mysql_fetch_row
#include "mapiproxy/util/mysql.c"
#include "mapiproxy/libmapistore/backends/namedprops_mysql.c"

void mapistore_set_errno(int status) { errno = status; }

void *__real__talloc_zero(const void *, size_t, const char *);
void *__wrap__talloc_zero(const void *, size_t, const char *);
char *__real_talloc_strdup(const void *, const char *);
char *__wrap_talloc_strdup(const void *, const char *);
bool __real_htable_add(struct htable *, size_t, const void *);
bool __wrap_htable_add(struct htable *, size_t, const void *);
void *__wrap__talloc_zero(const void *ctx, size_t size, const char *name)
{
    return (failure == FAIL_ENTRY && !strcmp(name, "struct conn_v")) ||
        (fail_escape && strstr(name, "mapiproxy/util/mysql.c:")) ? NULL : __real__talloc_zero(ctx, size, name);
}
char *__wrap_talloc_strdup(const void *ctx, const char *value)
{
    return (failure == FAIL_COPY && !strncmp(value, "mysql://", 8)) || fail_result_copy ? NULL : __real_talloc_strdup(ctx, value);
}
bool __wrap_htable_add(struct htable *table, size_t hash, const void *entry)
{ return failure == FAIL_POOL ? false : __real_htable_add(table, hash, entry); }

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "MySQL utility check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static int result_checks(TALLOC_CTX *ctx)
{
    MYSQL *connection = (MYSQL *)1;
    struct StringArrayW_r *array = (void *)1;
    const char *text = (void *)1;
    uint64_t number = 7;
    TALLOC_CTX *limited;
    size_t blocks;
    const char *invalid[] = {NULL, "", "-1", "+1", " 1", "1 ", "1x", "18446744073709551616"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        CHECK(!convert_string_to_ull(invalid[i], &number) && number == 7);
    }
    CHECK(convert_string_to_ull("18446744073709551615", &number) && number == UINT64_MAX);
    CHECK(convert_string_to_ull("0", &number) && number == 0);
    CHECK(!convert_string_to_ull("1", NULL));
    CHECK(select_all_strings(ctx, connection, "SELECT value", &array) == MYSQL_SUCCESS);
    CHECK(array->cValues == 1 && !strcmp(array->lppszW[0], "one")); talloc_free(array);
    result_fields = 2; result_values[0][0] = "en"; result_values[0][1] = "Drafts";
    CHECK(select_all_strings(ctx, connection, "SELECT locale, name", &array) == MYSQL_SUCCESS);
    CHECK(array->cValues == 1 && !strcmp(array->lppszW[0], "Drafts")); talloc_free(array);
    result_fields = 3; result_values[0][2] = "Calendar";
    CHECK(select_all_strings(ctx, connection, "SELECT locale, names", &array) == MYSQL_SUCCESS);
    CHECK(array->cValues == 2 && !strcmp(array->lppszW[1], "Calendar")); talloc_free(array);
    result_rows_count = 2; result_fields = 1; result_values[0][0] = "one"; result_values[1][0] = "two";
    CHECK(select_all_strings(ctx, connection, "SELECT values", &array) == MYSQL_SUCCESS);
    CHECK(array->cValues == 2 && !strcmp(array->lppszW[1], "two")); talloc_free(array);
    result_rows_count = 0;
    CHECK(select_all_strings(ctx, connection, "SELECT empty", &array) == MYSQL_SUCCESS);
    CHECK(array->cValues == 0); talloc_free(array);
    result_rows_count = (uint64_t)UINT32_MAX + 1;
    CHECK(select_all_strings(ctx, connection, "SELECT oversized", &array) == MYSQL_ERROR && !array);
    result_rows_count = 1;
    blocks = talloc_total_blocks(ctx);
    fail_fetch = true;
    CHECK(select_first_string(ctx, connection, "SELECT value", &text) == MYSQL_ERROR && !text);
    CHECK(select_all_strings(ctx, connection, "SELECT value", &array) == MYSQL_ERROR && !array);
    fail_fetch = false; result_values[0][0] = NULL;
    CHECK(select_first_string(ctx, connection, "SELECT NULL", &text) == MYSQL_ERROR && !text);
    CHECK(select_all_strings(ctx, connection, "SELECT NULL", &array) == MYSQL_ERROR && !array);
    result_values[0][0] = "one"; fail_result_copy = true;
    CHECK(select_first_string(ctx, connection, "SELECT value", &text) == MYSQL_ERROR && !text);
    CHECK(select_all_strings(ctx, connection, "SELECT value", &array) == MYSQL_ERROR && !array);
    fail_result_copy = false; fail_store = true;
    CHECK(select_first_string(ctx, connection, "SELECT value", &text) == MYSQL_ERROR && !text);
    fail_store = false;
    CHECK(talloc_total_blocks(ctx) == blocks && acquired == released);
    limited = talloc_new(ctx); CHECK(limited && talloc_set_memlimit(limited, 1) == 0);
    CHECK(select_first_string(limited, connection, "SELECT value", &text) == MYSQL_ERROR && !text);
    CHECK(select_all_strings(limited, connection, "SELECT value", &array) == MYSQL_ERROR && !array);
    talloc_free(limited);
    CHECK(acquired == released);
    return 0;
}

static int named_property_checks(void)
{
    struct namedprops_context context = { .data = (MYSQL *)1 };
    struct MAPINAMEID name = { .ulKind = MNID_STRING };
    uint16_t mapped = 7;
    name.kind.lpwstr.Name = "name\\' OR 1=1 --";
    result_values[0][0] = "32769";
    CHECK(get_mapped_id(&context, name, &mapped) == MAPISTORE_SUCCESS && mapped == 32769);
    CHECK(strstr(query, "name\\\\\\' OR 1=1 --"));
    CHECK(create_id(&context, name, mapped) == MAPISTORE_SUCCESS);
    CHECK(strstr(query, "propName='name\\\\\\' OR 1=1 --'"));
    duplicate_entry = true;
    CHECK(create_id(&context, name, mapped) == MAPISTORE_ERR_EXIST);
    duplicate_entry = false;
    fail_escape = true; query[0] = 0;
    CHECK(create_id(&context, name, mapped) == MAPISTORE_ERR_NO_MEMORY && query[0] == 0);
    CHECK(get_mapped_id(&context, name, &mapped) == MAPISTORE_ERR_NO_MEMORY && query[0] == 0);
    fail_escape = false;
    result_rows_count = 0;
    CHECK(get_mapped_id(&context, name, &mapped) == MAPISTORE_ERR_NOT_FOUND);
    result_rows_count = 1; result_values[0][0] = "65536";
    CHECK(get_mapped_id(&context, name, &mapped) == MAPISTORE_ERR_DATABASE_OPS && mapped == 32769);
    result_values[0][0] = "-1";
    CHECK(get_mapped_id(&context, name, &mapped) == MAPISTORE_ERR_DATABASE_OPS && mapped == 32769);
    fail_fetch = true;
    CHECK(get_mapped_id(&context, name, &mapped) == MAPISTORE_ERR_DATABASE_OPS);
    fail_fetch = false; fail_store = true;
    CHECK(get_mapped_id(&context, name, &mapped) == MAPISTORE_ERR_DATABASE_OPS);
    fail_store = false; name.kind.lpwstr.Name = NULL; query[0] = 0;
    CHECK(create_id(&context, name, 1) == MAPISTORE_ERR_INVALID_PARAMETER && query[0] == 0);
    CHECK(get_mapped_id(&context, name, &mapped) == MAPISTORE_ERR_INVALID_PARAMETER && query[0] == 0);
    name.ulKind = 99;
    CHECK(create_id(&context, name, 1) == MAPISTORE_ERR_INVALID_PARAMETER && query[0] == 0);
    CHECK(get_mapped_id(&context, name, &mapped) == MAPISTORE_ERR_INVALID_PARAMETER && query[0] == 0);
    CHECK(acquired == released);
    return 0;
}

static int named_property_transaction_checks(void)
{
    struct namedprops_context backend = { .data = (MYSQL *)1 };
    uint16_t id = 17;
    const char *invalid[] = {"65534", "65535", "65536", "18446744073709551615", "-1", "junk"};
    CHECK(next_unused_id(NULL, &id) == MAPISTORE_ERR_INVALID_PARAMETER);
    CHECK(next_unused_id(&backend, NULL) == MAPISTORE_ERR_INVALID_PARAMETER);
    result_values[0][0] = "0";
    CHECK(next_unused_id(&backend, &id) == MAPISTORE_SUCCESS && id == 0x8001);
    result_values[0][0] = "32768";
    CHECK(next_unused_id(&backend, &id) == MAPISTORE_SUCCESS && id == 0x8001);
    result_values[0][0] = "65533";
    CHECK(next_unused_id(&backend, &id) == MAPISTORE_SUCCESS && id == 0xfffe);
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        result_values[0][0] = (char *)invalid[i]; id = 17;
        CHECK(next_unused_id(&backend, &id) != MAPISTORE_SUCCESS && id == 17);
    }
    fail_fetch = true;
    CHECK(next_unused_id(&backend, &id) == MAPISTORE_ERR_DATABASE_OPS && id == 17);
    fail_fetch = false;
    CHECK(transaction_start(&backend) == MAPISTORE_SUCCESS && !strcmp(query, "START TRANSACTION"));
    CHECK(lock_held && !reconnect_enabled);
    CHECK(transaction_start(&backend) == MAPISTORE_ERR_DATABASE_OPS && lock_held && !reconnect_enabled);
    CHECK(transaction_commit(&backend) == MAPISTORE_SUCCESS && !lock_held && reconnect_enabled);
    CHECK(transaction_start(&backend) == MAPISTORE_SUCCESS);
    CHECK(transaction_cancel(&backend) == MAPISTORE_SUCCESS && !lock_held && reconnect_enabled);
    lock_timeout = true;
    CHECK(transaction_start(&backend) == MAPISTORE_ERR_DATABASE_OPS && !lock_held && reconnect_enabled);
    lock_timeout = false; fail_reconnect_option = true;
    CHECK(transaction_start(&backend) == MAPISTORE_ERR_DATABASE_OPS && !lock_held);
    fail_reconnect_option = false; fail_statement = "START TRANSACTION";
    CHECK(transaction_start(&backend) == MAPISTORE_ERR_DATABASE_OPS && !lock_held && reconnect_enabled);
    fail_statement = NULL;
    CHECK(transaction_start(&backend) == MAPISTORE_SUCCESS);
    fail_statement = "COMMIT";
    CHECK(transaction_commit(&backend) == MAPISTORE_ERR_DATABASE_OPS && lock_held && !reconnect_enabled);
    fail_statement = "ROLLBACK";
    CHECK(transaction_cancel(&backend) == MAPISTORE_ERR_DATABASE_OPS && lock_held && reconnect_enabled);
    CHECK(strstr(logs, "rollback failed") && strstr(logs, "retains its lock"));
    fail_statement = NULL;
    CHECK(transaction_cancel(&backend) == MAPISTORE_SUCCESS && !lock_held && reconnect_enabled);
    CHECK(transaction_start(&backend) == MAPISTORE_SUCCESS);
    fail_statement = "RELEASE_LOCK";
    CHECK(transaction_commit(&backend) == MAPISTORE_ERR_DATABASE_OPS && lock_held && reconnect_enabled);
    fail_statement = NULL;
    CHECK(transaction_cancel(&backend) == MAPISTORE_SUCCESS && !lock_held && reconnect_enabled);
    failure = FAIL_QUERY;
    CHECK(transaction_start(&backend) == MAPISTORE_ERR_DATABASE_OPS && !lock_held);
    failure = FAIL_NONE;
    CHECK(acquired == released);
    return 0;
}

static int named_property_read_checks(TALLOC_CTX *ctx)
{
    struct namedprops_context backend = { .data = (MYSQL *)1 };
    struct MAPINAMEID *name = (void *)1;
    const char *guid = "00112233-4455-6677-8899-aabbccddeeff";
    TALLOC_CTX *limited;
    uint16_t type = 7;
    size_t blocks = talloc_total_blocks(ctx);
    char oversized[128]; memset(oversized, 'a', sizeof(oversized) - 1); oversized[127] = 0;
    result_fields = 4;
    result_values[0][0] = "1"; result_values[0][1] = (char *)guid;
    result_values[0][2] = "caf\xc3\xa9"; result_values[0][3] = NULL;
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_SUCCESS);
    CHECK(name && name->ulKind == MNID_STRING && name->kind.lpwstr.NameSize == 10);
    CHECK(!strcmp(name->kind.lpwstr.Name, "caf\xc3\xa9") && talloc_parent(name) == ctx);
    CHECK(talloc_parent(name->kind.lpwstr.Name) == name); talloc_free(name);
    result_values[0][2] = "\xf0\x9f\x98\x80";
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_SUCCESS);
    CHECK(name->kind.lpwstr.NameSize == 6); talloc_free(name);
    result_values[0][2] = oversized;
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_ERR_INVALID_DATA && !name);
    result_values[0][2] = "\xff";
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_ERR_INVALID_DATA && !name);
    result_values[0][2] = NULL;
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_ERR_INVALID_DATA && !name);
    result_values[0][2] = "valid"; result_values[0][1] = "bad-guid";
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_ERR_INVALID_DATA && !name);
    result_values[0][1] = (char *)guid; result_values[0][0] = "99";
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_ERR_INVALID_DATA && !name);
    result_values[0][0] = "0"; result_values[0][3] = "4294967295";
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_SUCCESS && name->kind.lid == UINT32_MAX);
    talloc_free(name); result_values[0][3] = "4294967296";
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_ERR_INVALID_DATA && !name);
    result_values[0][0] = "1"; fail_result_copy = true;
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_ERR_NO_MEMORY && !name);
    fail_result_copy = false; fail_fetch = true;
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_ERR_DATABASE_OPS && !name);
    fail_fetch = false; fail_store = true;
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_ERR_DATABASE_OPS && !name);
    fail_store = false; result_rows_count = 0;
    CHECK(get_nameid(&backend, 32769, ctx, &name) == MAPISTORE_ERR_NOT_FOUND && !name);
    result_rows_count = 1;
    limited = talloc_new(ctx); CHECK(limited && talloc_set_memlimit(limited, 1) == 0);
    CHECK(get_nameid(&backend, 32769, limited, &name) == MAPISTORE_ERR_NO_MEMORY && !name);
    talloc_free(limited);
    result_fields = 1; result_values[0][0] = "31";
    CHECK(get_nameid_type(&backend, 32769, &type) == MAPISTORE_SUCCESS && type == 31);
    result_values[0][0] = "65536";
    CHECK(get_nameid_type(&backend, 32769, &type) == MAPISTORE_ERR_DATABASE_OPS && type == 31);
    CHECK(talloc_total_blocks(ctx) == blocks && acquired == released);
    return 0;
}

static int diagnostic_checks(void)
{
    MYSQL *connection = (MYSQL *)1;
    MYSQL_RES *result;
    FILE *output = tmpfile();
    int saved;
    const char *private_sql = "SELECT 'private-message-data'";
    CHECK(output); fflush(stdout); saved = dup(fileno(stdout)); CHECK(saved >= 0);
    CHECK(dup2(fileno(output), fileno(stdout)) >= 0);
    logged = 0; logs[0] = 0; failure = FAIL_QUERY;
    CHECK(execute_query(connection, private_sql) == MYSQL_ERROR);
    CHECK(strstr(logs, "1234") && strstr(logs, "42000") && !strstr(logs, "private-message-data"));
    failure = FAIL_NONE; fail_store = true;
    CHECK(select_without_fetch(connection, private_sql, &result) == MYSQL_ERROR && !result);
    fail_store = false; clock_mode = 1; clock_calls = 0;
    CHECK(execute_query(connection, private_sql) == MYSQL_SUCCESS);
    CHECK(strstr(logs, "slow query: 2.000 seconds") && !strstr(logs, "private-message-data"));
    for (clock_mode = 2; clock_mode <= 3; clock_mode++) {
        clock_calls = 0; logged = 0; logs[0] = 0;
        CHECK(execute_query(connection, private_sql) == MYSQL_SUCCESS && logs[0] == 0);
    }
    clock_mode = 0;
    fflush(stdout); CHECK(ftell(output) == 0);
    CHECK(dup2(saved, fileno(stdout)) >= 0); close(saved); fclose(output);
    return 0;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL), *pool = talloc_autofree_context(), *limited;
    const char *uri = "mysql://user:fixture-secret@host:23306/database";
    MYSQL *mysql = (void *)1, *first;
    char *host, *user, *password, *database;
    int port;
    size_t blocks = talloc_total_blocks(pool);
    static const char * const invalid[] = {
        NULL, "", "mysql://user:fixture-secret@/db", "mysql://user:fixture-secret@host:/db",
        "mysql://u:p@h:65536/d", "mysql://u:p@h:18446744073709551616/d",
        "mysql://u:p@h:-1/d", "mysql://u:p@h:+1/d", "mysql://u:p@h: 1/d"
    };
    CHECK(ctx);
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        CHECK(create_connection(invalid[i], &mysql) == NULL && mysql == NULL);
    }
    CHECK(initialized == 0 && ht.elems == 0);
    CHECK(parse_connection_string(ctx, "mysql://user@host:65535/db", &host, &port, &user, &password, &database));
    CHECK(port == 65535 && password == NULL && !strcmp(host, "host"));
    limited = talloc_new(ctx); CHECK(limited && talloc_set_memlimit(limited, 1) == 0);
    CHECK(!parse_connection_string(limited, uri, &host, &port, &user, &password, &database));
    CHECK(host == NULL && user == NULL && password == NULL && database == NULL && port == 0);
    talloc_free(limited);
    {
        const char payload[] = {'a', '\\', '\'', ' ', 'O', 'R', ' ', '1', '=', '1', 0};
        const char *escaped = _sql(ctx, payload);
        CHECK(escaped && strlen(escaped) == strlen(payload) + 2);
        CHECK(escaped[1] == '\\' && escaped[2] == '\\' && escaped[3] == '\\' && escaped[4] == '\'');
        CHECK(!strcmp(payload + 3, escaped + 5));
        limited = talloc_new(ctx); CHECK(limited && talloc_set_memlimit(limited, 1) == 0);
        CHECK(_sql(limited, payload) == NULL);
        CHECK(!strcmp(_sql(limited, "plain"), "plain"));
        talloc_free(limited);
    }
    for (failure = FAIL_INIT; failure <= FAIL_POOL; failure++) {
        unsigned before = closed, allocated = initialized;
        CHECK(create_connection(uri, &mysql) == NULL && mysql == NULL && ht.elems == 0);
        CHECK(closed - before == initialized - allocated);
        CHECK(talloc_total_blocks(pool) == blocks);
    }
    failure = FAIL_NONE;
    CHECK(create_connection(uri, &mysql) == mysql && mysql != NULL && ht.elems == 1);
    first = mysql;
    {
        unsigned before = initialized;
        CHECK(create_connection(uri, &mysql) == first && initialized == before);
    }
    CHECK(create_connection("mysql://user:fixture-secret@host/second", &mysql) && ht.elems == 2);
    CHECK(create_connection("mysql://user@host/no_password", &mysql) && ht.elems == 3);
    close_all_connections(); CHECK(ht.elems == 0 && closed == initialized && talloc_total_blocks(pool) == blocks);
    need_database = true;
    CHECK(create_connection("mysql://user:fixture-secret@host/db`quoted", &mysql));
    CHECK(!strcmp(query, "CREATE DATABASE `db``quoted`"));
    close_all_connections(); CHECK(closed == initialized && talloc_total_blocks(pool) == blocks);
    CHECK(strstr(logs, "fixture-secret") == NULL && strstr(logs, "mysql://") == NULL);
    CHECK(connected <= initialized);
    query[0] = 0;
    CHECK(execute_query(NULL, "SELECT 1") == MYSQL_ERROR);
    CHECK(execute_query((MYSQL *)1, NULL) == MYSQL_ERROR && query[0] == 0);
    CHECK(result_checks(ctx) == 0);
    CHECK(named_property_checks() == 0);
    CHECK(named_property_transaction_checks() == 0);
    CHECK(named_property_read_checks(ctx) == 0);
    CHECK(diagnostic_checks() == 0);
    talloc_free(ctx);
    puts("MySQL URI/pool failures, escaping, row ownership/shapes, numeric bounds and named property queries: OK");
    return 0;
}
