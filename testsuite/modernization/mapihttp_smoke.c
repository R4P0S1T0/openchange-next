/* MAPI/HTTP request validation and PING, driven through mapihttp_handle()
 * without sockets. Authentication is a fake that only accepts user:pass. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "mapiproxy/servers/mapihttp/mapihttp.h"
#include "libmapi/oc_log.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "MAPI/HTTP check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

#define BASIC_USER_PASS "Basic dXNlcjpwYXNz"
#define CLIENT_INFO "{0589012E-9A4E-4666-9EE1-3C5BD8DDF18B}:558760020"

static unsigned auth_calls;
static char last_log[1024];
static enum oc_log_level last_level;

/* Captures log lines instead of printing them, so tests can check what is logged. */
void __wrap_oc_log(enum oc_log_level level, const char *fmt, ...);
void __wrap_oc_log(enum oc_log_level level, const char *fmt, ...)
{
    va_list ap;
    last_level = level;
    va_start(ap, fmt);
    vsnprintf(last_log, sizeof(last_log), fmt, ap);
    va_end(ap);
}

static int fake_auth(void *priv, const char *user, const char *password)
{
    (*(unsigned *)priv)++;
    if (strcmp(user, "temp") == 0) return MAPIHTTP_AUTH_TEMPFAIL;
    return strcmp(user, "user") || strcmp(password, "pass") ? MAPIHTTP_AUTH_BAD : MAPIHTTP_AUTH_OK;
}

static struct mapihttp_server srv = { .authenticate = fake_auth, .auth_priv = &auth_calls };

static struct mapihttp_request ping(const char *path)
{
    struct mapihttp_request req = {
        .method = "POST", .path = path, .request_type = "PING",
        .request_id = "{DE412C9D-4AA7-444C-9405-977C4D90FA85}:3",
        .content_type = "application/mapi-http",
        .authorization = BASIC_USER_PASS, .client_info = CLIENT_INFO,
    };
    return req;
}

static uint32_t code(TALLOC_CTX *ctx, const struct mapihttp_request *req)
{
    struct mapihttp_reply rep;
    mapihttp_handle(&srv, ctx, req, &rep);
    return rep.http_status == 200 ? rep.response_code : 1000 + rep.http_status;
}

static int test_get_rejected(TALLOC_CTX *ctx)
{
    struct mapihttp_request req = ping("/mapi/emsmdb/");
    req.method = "GET";
    CHECK(code(ctx, &req) == MAPIHTTP_INVALID_VERB);
    return 0;
}

static int test_unknown_path(TALLOC_CTX *ctx)
{
    struct mapihttp_request req = ping("/mapi/other/");
    CHECK(code(ctx, &req) == MAPIHTTP_INVALID_PATH);
    return 0;
}

static int test_missing_headers(TALLOC_CTX *ctx)
{
    struct mapihttp_request req = ping("/mapi/emsmdb/");
    req.request_id = NULL;
    CHECK(code(ctx, &req) == MAPIHTTP_MISSING_HEADER);
    req = ping("/mapi/emsmdb/");
    req.request_type = NULL;
    CHECK(code(ctx, &req) == MAPIHTTP_MISSING_HEADER);
    req = ping("/mapi/emsmdb/");
    req.content_type = "text/plain";
    CHECK(code(ctx, &req) == MAPIHTTP_INVALID_HEADER);
    return 0;
}

static int test_bad_request_type(TALLOC_CTX *ctx)
{
    struct mapihttp_request req = ping("/mapi/emsmdb/");
    req.request_type = "Bind";
    CHECK(code(ctx, &req) == MAPIHTTP_INVALID_REQUEST_TYPE);
    return 0;
}

static int test_ping(TALLOC_CTX *ctx)
{
    const char *paths[] = { "/mapi/emsmdb/", "/mapi/nspi/" };
    struct mapihttp_request req;
    struct mapihttp_reply rep;
    unsigned i;

    for (i = 0; i < 2; i++) {
        req = ping(paths[i]);
        mapihttp_handle(&srv, ctx, &req, &rep);
        CHECK(rep.http_status == 200 && rep.response_code == MAPIHTTP_SUCCESS);
        CHECK(rep.body.length == 0 && rep.set_cookie == NULL);
        CHECK(rep.request_type && strcmp(rep.request_type, "PING") == 0);
    }
    return 0;
}

static int test_anonymous(TALLOC_CTX *ctx)
{
    struct mapihttp_request req = ping("/mapi/emsmdb/");
    req.authorization = NULL;
    CHECK(code(ctx, &req) == 1401);
    req.authorization = "Basic dXNlcjp3cm9uZw=="; /* user:wrong */
    CHECK(code(ctx, &req) == 1401);
    CHECK(strstr(last_log, "failed login") && strstr(last_log, "'user'") && !strstr(last_log, "wrong"));
    req.authorization = "Basic bm9jb2xvbg=="; /* nocolon */
    CHECK(code(ctx, &req) == 1401);
    req.authorization = "Basic dGVtcDpwYXNz"; /* temp:pass */
    CHECK(code(ctx, &req) == 1503);
    return 0;
}

static int test_bearer_challenged(TALLOC_CTX *ctx)
{
    struct mapihttp_request req = ping("/mapi/emsmdb/");
    unsigned before = auth_calls;
    last_log[0] = '\0';
    req.authorization = "Bearer eyJ0eXAi";
    CHECK(code(ctx, &req) == 1401 && auth_calls == before);
    CHECK(last_log[0] == '\0' || (last_level > OC_LOG_DEBUG && !strstr(last_log, "failed")));
    return 0;
}

static int test_response_headers(TALLOC_CTX *ctx)
{
    struct mapihttp_request req = ping("/mapi/nspi/");
    struct mapihttp_reply rep;
    mapihttp_handle(&srv, ctx, &req, &rep);
    CHECK(rep.client_info && strcmp(rep.client_info, CLIENT_INFO) == 0);
    CHECK(rep.request_id && strcmp(rep.request_id, req.request_id) == 0);
    CHECK(strcmp(MAPIHTTP_SERVER_APPLICATION, "Exchange/15.02.1544.004") == 0);
    return 0;
}

static int test_outlook_headers_ignored(TALLOC_CTX *ctx)
{
    /* Connect entry of testsuite/modernization/mapihttp/headers.json */
    struct mapihttp_request req = {
        .method = "POST", .path = "/mapi/emsmdb/", .request_type = "PING",
        .request_id = "{DE412C9D-4AA7-444C-9405-977C4D90FA85}:2",
        .content_type = "application/mapi-http",
        .authorization = BASIC_USER_PASS,
        .client_info = "{0589012E-9A4E-4666-9EE1-3C5BD8DDF18B}:558760020",
    };
    CHECK(code(ctx, &req) == MAPIHTTP_SUCCESS);
    return 0;
}

static int test_too_large(TALLOC_CTX *ctx)
{
    struct mapihttp_request req = ping("/mapi/emsmdb/");
    req.body_len = MAPIHTTP_MAX_BODY + 1;
    CHECK(code(ctx, &req) == MAPIHTTP_TOO_LARGE);
    req.body_len = MAPIHTTP_MAX_BODY;
    CHECK(code(ctx, &req) == MAPIHTTP_SUCCESS);
    return 0;
}

static int test_reply_layout(TALLOC_CTX *ctx)
{
    const char *head = "PROCESSING\r\nDONE\r\nX-ResponseCode: 0\r\n";
    struct mapihttp_reply rep = { .http_status = 200, .body = data_blob_const("BODY", 4) };
    DATA_BLOB out;
    const char *end;

    gettimeofday(&rep.start, NULL);
    out = mapihttp_format_reply(ctx, &rep);
    CHECK(out.data && out.length > strlen(head));
    CHECK(memcmp(out.data, head, strlen(head)) == 0);
    end = memmem(out.data, out.length, "\r\n\r\n", 4);
    CHECK(end && (const uint8_t *)end + 4 + 4 == out.data + out.length);
    CHECK(memcmp(end + 4, "BODY", 4) == 0);
    CHECK(memmem(out.data, out.length, "\r\nX-ElapsedTime: ", 17));
    CHECK(memmem(out.data, out.length, "\r\nX-StartTime: ", 15));
    return 0;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    int ret = test_get_rejected(ctx) || test_unknown_path(ctx) || test_missing_headers(ctx) ||
        test_bad_request_type(ctx) || test_ping(ctx) || test_anonymous(ctx) ||
        test_bearer_challenged(ctx) || test_response_headers(ctx) ||
        test_outlook_headers_ignored(ctx) || test_too_large(ctx) || test_reply_layout(ctx);

    talloc_free(ctx);
    if (ret == 0) printf("mapihttp: all checks passed\n");
    return ret;
}
