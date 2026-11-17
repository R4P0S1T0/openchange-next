/* The CardDAV fingerprint store's SQL, against a fake driver: values escaped, failures reported. */
#include "libmapi/libmapi.h"
#include "mapiproxy/util/mysql.h"
#include <assert.h>

static bool allow_queries;
static unsigned queries;
static char last_query[4096];
static int fixture_query(MYSQL *connection, const char *sql)
{
    assert(connection && sql && strlen(sql) < sizeof(last_query));
    queries++;
    strcpy(last_query, sql);
    return allow_queries ? 0 : 1;
}
static unsigned fixture_errno(MYSQL *connection) { return 1234; }
static const char *fixture_sqlstate(MYSQL *connection) { return "42000"; }
#define mysql_query fixture_query
#define mysql_errno fixture_errno
#define mysql_sqlstate fixture_sqlstate
#include "mapiproxy/util/mysql.c"
#include "mapiproxy/libmapistore/backends/dav/dav_fpstore.c"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "dav fpstore SQL check failed at %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

int main(void)
{
    struct dav_fpstore s = { .conn = (MYSQL *) 1 };
    uint64_t fp[DAV_F_COUNT] = { 0x0123456789ABCDEFULL, 1 }, got[DAV_F_COUNT];
    char *etag = NULL, **gone = NULL, *live[1] = { "/b/x" };
    size_t ngone = 1, i;
    const char *hex;

    CHECK(strstr(create_table_sql, "dav_fingerprints (user VARCHAR(320), href VARCHAR(1024), etag VARCHAR(255), fp BLOB, "
                 "PRIMARY KEY(user, href(255))) CHARSET utf8mb4 COLLATE utf8mb4_bin"));
    allow_queries = true;
    CHECK(dav_fp_put(&s, "u'1", "/b/x'y\\", fp, "\"e'\"") == MAPISTORE_SUCCESS);
    CHECK(strstr(last_query, "REPLACE INTO dav_fingerprints (user, href, etag, fp) VALUES ('u\\'1', '/b/x\\'y\\\\', '\"e\\'\"', 0x"));
    hex = strstr(last_query, "0x") + 2;
    CHECK(strlen(hex) == DAV_F_COUNT * 16 + 1 && !strncmp(hex, "0123456789ABCDEF0000000000000001", 32));
    for (i = 2; i < DAV_F_COUNT; i++) CHECK(!strncmp(hex + i * 16, "0000000000000000", 16));
    CHECK(dav_fp_delete(&s, "u'1", "/b/x'y") == MAPISTORE_SUCCESS);
    CHECK(!strcmp(last_query, "DELETE FROM dav_fingerprints WHERE user = 'u\\'1' AND href = '/b/x\\'y'"));
    allow_queries = false;
    CHECK(dav_fp_put(&s, "u", "/b/x", fp, "e") == MAPISTORE_ERR_DATABASE_OPS);
    CHECK(dav_fp_get(&s, NULL, "u'1", "/b/x", got, &etag) == MAPISTORE_ERR_DATABASE_OPS && etag == NULL);
    CHECK(!strcmp(last_query, "SELECT etag, HEX(fp) FROM dav_fingerprints WHERE user = 'u\\'1' AND href = '/b/x' AND etag IS NOT NULL"));
    CHECK(dav_fp_prune(&s, "u'1", "/b", live, 1, NULL, &gone, &ngone) == MAPISTORE_ERR_DATABASE_OPS && !gone && !ngone);
    CHECK(!strcmp(last_query, "SELECT href, etag IS NULL FROM dav_fingerprints WHERE user = 'u\\'1'"));
    /* the parts the database never sees */
    CHECK(classify("/b", "/b/y", live, 1) == GONE && classify("/b", "/b/x", live, 1) == LIVE);
    CHECK(classify("/b", "/bb/y", live, 1) == NOT_MEMBER);
    allow_queries = true;
    CHECK(tombstone(&s, "u'1", "/b/y'") == MAPISTORE_SUCCESS);
    CHECK(!strcmp(last_query, "UPDATE dav_fingerprints SET etag = NULL WHERE user = 'u\\'1' AND href = '/b/y\\''"));
    CHECK(parse_hex(hex, got) == false); /* trailing ")" */
    puts("dav fpstore SQL smoke: ok");
    return 0;
}
