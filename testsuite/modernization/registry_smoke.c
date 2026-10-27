/* Exercise registry ownership and allocation failures without an RPC server. */
#include "libmapi/libmapi.h"
#include "config.h"
#include "mapiproxy/samba_compat.h"
#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "mapiproxy/libmapistore/mapistore_private.h"
#include "mapiproxy/libmapiproxy/libmapiproxy.h"
#include <limits.h>

extern int num_mp_modules;
extern int num_server_modules;
extern int num_backends;

enum fail_stage { FAIL_NONE, FAIL_COPY, FAIL_NAME, FAIL_ARRAY };
static enum fail_stage failure;
static bool allow_release = true;

/* Isolate registry tests from the storage interface and its backend loaders. */
void mapistore_set_errno(int status)
{
    errno = status;
}

static bool on_release(void *data)
{
    (*(int *)data)++;
    return allow_release;
}

void *__real__talloc_memdup(const void *, const void *, size_t, const char *);
void *__real__talloc_realloc_array(const void *, void *, size_t, unsigned, const char *);
char *__real_talloc_strdup(const void *, const char *);
void *__wrap__talloc_memdup(const void *, const void *, size_t, const char *);
void *__wrap__talloc_realloc_array(const void *, void *, size_t, unsigned, const char *);
char *__wrap_talloc_strdup(const void *, const char *);

void *__wrap__talloc_memdup(const void *ctx, const void *p, size_t size, const char *name)
{
    return failure == FAIL_COPY ? NULL : __real__talloc_memdup(ctx, p, size, name);
}

char *__wrap_talloc_strdup(const void *ctx, const char *text)
{
    return failure == FAIL_NAME ? NULL : __real_talloc_strdup(ctx, text);
}

void *__wrap__talloc_realloc_array(const void *ctx, void *p, size_t size, unsigned count, const char *name)
{
    return failure == FAIL_ARRAY ? NULL : __real__talloc_realloc_array(ctx, p, size, count, name);
}

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "registry check failed at %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static int exercise(NTSTATUS (*reg)(const void *),
                    const struct mapiproxy_module *(*lookup)(const char *), int *count)
{
    struct mapiproxy_module module = {0};
    const struct mapiproxy_module *saved;
    char name[64];
    int i, before_count;
    size_t before_blocks;
    CHECK(NT_STATUS_EQUAL(reg(NULL), NT_STATUS_INVALID_PARAMETER));
    CHECK(NT_STATUS_EQUAL(reg(&module), NT_STATUS_INVALID_PARAMETER));
    module.name = "";
    CHECK(NT_STATUS_EQUAL(reg(&module), NT_STATUS_INVALID_PARAMETER));
    CHECK(lookup(NULL) == NULL);
    CHECK(lookup("missing") == NULL);

    strcpy(name, "original");
    module.name = name;
    module.description = "persistent description";
    CHECK(NT_STATUS_IS_OK(reg(&module)));
    saved = lookup("original");
    CHECK(saved != NULL && saved != &module);
    memset(name, 'x', strlen(name));
    CHECK(strcmp(saved->name, "original") == 0);

    for (i = FAIL_COPY; i <= FAIL_ARRAY; i++) {
        before_count = *count;
        before_blocks = talloc_total_blocks(NULL);
        module.name = "failed-registration";
        failure = i;
        CHECK(NT_STATUS_EQUAL(reg(&module), NT_STATUS_NO_MEMORY));
        failure = FAIL_NONE;
        CHECK(*count == before_count);
        CHECK(talloc_total_blocks(NULL) == before_blocks);
        CHECK(lookup("failed-registration") == NULL);
        CHECK(lookup("original") == saved);
    }
    for (i = 0; i < 256; i++) {
        snprintf(name, sizeof(name), "module-%d", i);
        module.name = name;
        CHECK(NT_STATUS_IS_OK(reg(&module)));
    }
    CHECK(lookup("original") == saved);
    for (i = 0; i < 256; i++) {
        snprintf(name, sizeof(name), "module-%d", i);
        CHECK(lookup(name) != NULL);
        CHECK(strcmp(lookup(name)->name, name) == 0);
    }
    before_count = *count;
    *count = INT_MAX;
    CHECK(NT_STATUS_EQUAL(reg(&module), NT_STATUS_NO_MEMORY));
    *count = before_count;
    return 0;
}

static int sessions(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    struct server_id id = {0}, other;
    struct mpm_session *session;
    struct dcesrv_call_state incomplete = {0};
    int released = 0;
    CHECK(ctx != NULL);
    id.pid = 100;
    id.task_id = 2;
    id.vnn = 3;
#ifdef HAVE_STRUCT_SERVER_ID_UNIQUE_ID
    id.unique_id = 4;
#endif
    session = mpm_session_new(ctx, id, 7);
    CHECK(session != NULL);
    CHECK(mpm_session_cmp_sub(session, id, 7));
    CHECK(!mpm_session_cmp_sub(session, id, 8));
    other = id; other.pid++;
    CHECK(!mpm_session_cmp_sub(session, other, 7));
    other = id; other.task_id++;
    CHECK(!mpm_session_cmp_sub(session, other, 7));
    other = id; other.vnn++;
    CHECK(!mpm_session_cmp_sub(session, other, 7));
#ifdef HAVE_STRUCT_SERVER_ID_UNIQUE_ID
    other = id; other.unique_id++;
    CHECK(!mpm_session_cmp_sub(session, other, 7));
#endif
    CHECK(!mpm_session_cmp(NULL, &incomplete));
    CHECK(!mpm_session_cmp(session, NULL));
    CHECK(!mpm_session_cmp(session, &incomplete));
    CHECK(mpm_session_init(ctx, &incomplete) == NULL);
    CHECK(mpm_session_set_private_data(session, &released));
    CHECK(mpm_session_set_destructor(session, on_release));
    CHECK(mpm_session_increment_ref_count(session));
    CHECK(!mpm_session_release(session));
    CHECK(released == 0);
    allow_release = false;
    CHECK(!mpm_session_release(session));
    CHECK(released == 1);
    CHECK(mpm_session_cmp_sub(session, id, 7));
    allow_release = true;
    CHECK(mpm_session_release(session));
    CHECK(released == 2);
    talloc_free(ctx);
    return 0;
}

static int string_lists(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    const char **list = (const char **)str_list_make_empty(ctx);
    char **split;
    char *joined;
    CHECK(ctx != NULL && list != NULL && list[0] == NULL);
    list = str_list_add(list, "name='alice'");
    CHECK(list != NULL);
    list = str_list_add(list, "enabled=1");
    CHECK(list != NULL && list[2] == NULL);
    joined = str_list_join(ctx, list, ',');
    CHECK(joined != NULL && strcmp(joined, "name='alice',enabled=1") == 0);
    split = str_list_make(ctx, "one, two\tthree", NULL);
    CHECK(split != NULL);
    CHECK(strcmp(split[0], "one") == 0 && strcmp(split[1], "two") == 0);
    CHECK(strcmp(split[2], "three") == 0 && split[3] == NULL);
    talloc_free(ctx);
    return 0;
}

static int backend_registry(void)
{
    struct mapistore_backend backend = {0};
    char name[64] = "original-backend";
    int i, before;
    size_t blocks;
    CHECK(mapistore_backend_register(NULL) == MAPISTORE_ERR_INVALID_PARAMETER);
    CHECK(mapistore_backend_register(&backend) == MAPISTORE_ERR_INVALID_PARAMETER);
    backend.backend.name = name;
    CHECK(mapistore_backend_register(&backend) == MAPISTORE_SUCCESS);
    memset(name, 'x', strlen(name));
    CHECK(mapistore_backend_registered("original-backend") == MAPISTORE_SUCCESS);
    before = num_backends;
    backend.backend.name = "original-backend";
    CHECK(mapistore_backend_register(&backend) == MAPISTORE_SUCCESS);
    CHECK(num_backends == before);
    for (i = FAIL_COPY; i <= FAIL_ARRAY; i++) {
        blocks = talloc_total_blocks(NULL);
        backend.backend.name = "failed-backend";
        failure = i;
        CHECK(mapistore_backend_register(&backend) == MAPISTORE_ERR_NO_MEMORY);
        failure = FAIL_NONE;
        CHECK(num_backends == before);
        CHECK(talloc_total_blocks(NULL) == blocks);
        CHECK(mapistore_backend_registered("failed-backend") != MAPISTORE_SUCCESS);
    }
    for (i = 0; i < 256; i++) {
        snprintf(name, sizeof(name), "backend-%d", i);
        backend.backend.name = name;
        CHECK(mapistore_backend_register(&backend) == MAPISTORE_SUCCESS);
    }
    CHECK(mapistore_backend_registered("original-backend") == MAPISTORE_SUCCESS);
    for (i = 0; i < 256; i++) {
        snprintf(name, sizeof(name), "backend-%d", i);
        CHECK(mapistore_backend_registered(name) == MAPISTORE_SUCCESS);
    }
    before = num_backends;
    num_backends = INT_MAX;
    CHECK(mapistore_backend_register(&backend) == MAPISTORE_ERR_NO_MEMORY);
    num_backends = before;
    return 0;
}

int main(void)
{
    talloc_enable_null_tracking();
    if (exercise(mapiproxy_module_register, mapiproxy_module_byname, &num_mp_modules) ||
        exercise(mapiproxy_server_register, mapiproxy_server_byname, &num_server_modules) ||
        sessions() || string_lists() || backend_registry()) return 1;
    puts("Module/server/backend registries, sessions and Samba string-list ABI checks passed");
    return 0;
}
