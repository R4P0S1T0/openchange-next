/* Actual query builders; reject SQL at the driver and inject escape allocation failures. */
#include "libmapi/libmapi.h"
#include "mapiproxy/util/mysql.h"
#include <assert.h>

static bool fail_escape, allow_queries;
static unsigned queries;
static char last_query[4096];
static int fixture_query(MYSQL *connection, const char *sql)
{
    assert(connection && sql && strlen(sql) < sizeof(last_query));
    queries++; strcpy(last_query, sql);
    return allow_queries ? 0 : 1;
}
static const char *fixture_error(MYSQL *connection) { return "fixture SQL rejected"; }
#define mysql_query fixture_query
#define mysql_error fixture_error
#include "mapiproxy/util/mysql.c"
#include "mapiproxy/libmapiproxy/backends/openchangedb_mysql.c"
#include "mapiproxy/libmapistore/backends/indexing_mysql.c"

void *__real__talloc_zero(const void *, size_t, const char *);
void *__wrap__talloc_zero(const void *, size_t, const char *);
void *__wrap__talloc_zero(const void *ctx, size_t size, const char *name)
{
    if (fail_escape && strstr(name, "mapiproxy/util/mysql.c:")) return NULL;
    return __real__talloc_zero(ctx, size, name);
}

void mapistore_set_errno(int status) { }

const char *openchangedb_property_get_attribute(uint32_t tag)
{ assert(tag == PR_DISPLAY_NAME_UNICODE); return "PidTagDisplayName"; }

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "SQL backend check failed at %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL), *limited;
    struct openchangedb_context backend = { .data = (MYSQL *)1 };
    struct indexing_context index = { .data = (MYSQL *)1 };
    char *uri = NULL;
    bool deleted = false;
    struct openchangedb_message message = { .id = 1, .normalized_subject = "subject\\'" };
    struct mapi_SRestriction restriction = {0};
    const char *attr = NULL, *value = NULL;
    const char *items[] = {"first", "second\\'", NULL};
    uint64_t folder = 0;
    CHECK(ctx);
    fail_escape = true;
    CHECK(get_SpecialFolderID(&backend, "user\\'", 1, &folder) == MAPI_E_NOT_ENOUGH_MEMORY);
    CHECK(set_mapistoreURI(&backend, "user", 1, "uri\\'") == MAPI_E_NOT_ENOUGH_MEMORY);
    CHECK(message_save(&backend, &message, 0) == MAPI_E_NOT_ENOUGH_MEMORY);
    message.id = 0; message.message_type = OPENCHANGEDB_MESSAGE_SYSTEM;
    CHECK(message_save(&backend, &message, 0) == MAPI_E_NOT_ENOUGH_MEMORY);
    CHECK(str_list_join_for_sql(ctx, items) == NULL);
    restriction.res.resProperty.ulPropTag = PR_DISPLAY_NAME_UNICODE;
    restriction.res.resProperty.lpProp.value.lpszW = "value\\'";
    CHECK(_table_get_attr_and_value_from_restrictions(ctx, &restriction, &attr, &value) == MAPI_E_NOT_ENOUGH_MEMORY);
    CHECK(mysql_search_existing_fmid(&index, "user\\'", 1, &deleted) == MAPISTORE_ERR_NO_MEMORY);
    CHECK(mysql_record_get_uri(&index, "user\\'", ctx, 1, &uri, &deleted) == MAPISTORE_ERR_NO_MEMORY);
    CHECK(queries == 0);
    {
        const char *names[] = {"name"}, *values[] = {"value'"};
        message.id = 1; message.normalized_subject = NULL;
        message.properties.names = names; message.properties.values = values; message.properties.size = 1;
        allow_queries = true;
        CHECK(message_save(&backend, &message, 0) == MAPI_E_NOT_ENOUGH_MEMORY);
        CHECK(queries == 4 && !strcmp(last_query, "ROLLBACK"));
        allow_queries = false; queries = 0;
    }
    fail_escape = false;
    CHECK(set_mapistoreURI(&backend, "user'", 1, "uri\\'") == MAPI_E_CALL_FAILED);
    CHECK(queries == 1 && strstr(last_query, "user\\'") && strstr(last_query, "uri\\\\\\'"));
    limited = talloc_new(ctx);
    CHECK(limited && talloc_set_memlimit(limited, 1) == 0);
    CHECK(str_list_join_for_sql(limited, items) == NULL);
    talloc_free(ctx);
    puts("SQL builders reject escape allocation failure before issuing queries; URI literals are escaped: OK");
    return 0;
}
