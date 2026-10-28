/* Test the actual callback code with real tevent and Samba state registries.
 * Storage, directory access, nanomsg and the RPC reply transport are substituted.
 */
#include <util/debug.h>
/* Generated logging otherwise requires Samba's private debug library. */
#undef DEBUG
#undef DEBUGLEVEL
#define DEBUG(level, body) ((void)0)
#define DEBUGLEVEL 0
#include "mapiproxy/servers/default/asyncemsmdb/dcesrv_asyncemsmdb.c"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "async RPC check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

enum fail_stage { FAIL_NONE, FAIL_DATABASE, FAIL_DIRECTORY, FAIL_INFO, FAIL_SESSION,
    FAIL_SOCKET, FAIL_PORT, FAIL_BIND, FAIL_FD, FAIL_RESOLVER };
static enum fail_stage failure;
static unsigned stores, releases, sockets, closes, registrations, deletions, replies;
static const char *owner = "test";
static int pipe_fds[2];
static bool malformed_message;
static char directory_path[] = "/tmp/openchange-async-XXXXXX";

/* The separate main RPC smoke test exercises the private NDR table registry. */
NTSTATUS ndr_table_register(const struct ndr_interface_table *table) { return NT_STATUS_OK; }

int __wrap_socket(int domain, int type, int protocol);
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len);
int __wrap_getsockname(int fd, struct sockaddr *addr, socklen_t *len);
int __wrap_close(int fd);
int __real_close(int fd);

int __wrap_socket(int domain, int type, int protocol)
{
    return failure == FAIL_PORT ? -1 : 5000;
}
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) { return 0; }
int __wrap_getsockname(int fd, struct sockaddr *addr, socklen_t *len)
{
    ((struct sockaddr_in *)addr)->sin_port = htons(25252);
    return 0;
}
int __wrap_close(int fd) { return fd == 5000 ? 0 : __real_close(fd); }

void *mapiproxy_server_openchangedb_init(struct loadparm_context *lp)
{
    static int database;
    return failure == FAIL_DATABASE ? NULL : &database;
}
struct auth_session_info *system_session(struct loadparm_context *lp) { return NULL; }
struct ldb_context *samdb_connect(TALLOC_CTX *ctx, struct tevent_context *ev,
    struct loadparm_context *lp, struct auth_session_info *session,
    const struct tsocket_address *remote, unsigned flags)
{
    struct ldb_context *db;
    struct ldb_dn *base;
    struct ldb_message *account;
    uint8_t sid[] = {1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xe8, 3, 0, 0};
    struct ldb_val value = { .data = sid, .length = sizeof(sid) };
    if (failure == FAIL_DIRECTORY) return NULL;
    db = ldb_init(ctx, ev);
    if (db == NULL || ldb_connect(db, directory_path, 0, NULL) != LDB_SUCCESS) return NULL;
    base = ldb_dn_new(db, db, "DC=test");
    account = ldb_msg_new(db);
    if (!base || !account || ldb_set_opaque(db, "defaultNamingContext", base) != LDB_SUCCESS) return NULL;
    account->dn = ldb_dn_new(account, db, "CN=test,DC=test");
    if (!account->dn || ldb_msg_add_string(account, "sAMAccountName", "test") != 0 ||
        ldb_msg_add_string(account, "msExchUserAccountControl", "0") != 0 ||
        ldb_msg_add_value(account, "objectSid", &value, NULL) != 0 ||
        ldb_add(db, account) != LDB_SUCCESS) return NULL;
    talloc_free(account);
    return db;
}
int samdb_connect_url(TALLOC_CTX *ctx, struct tevent_context *ev,
    struct loadparm_context *lp, struct auth_session_info *session, unsigned flags,
    const char *url, const struct tsocket_address *remote, struct ldb_context **ldb,
    char **error)
{
    *error = NULL;
    *ldb = samdb_connect(ctx, ev, lp, session, remote, flags);
    return *ldb == NULL ? LDB_ERR_OPERATIONS_ERROR : LDB_SUCCESS;
}
struct mapistore_context *mapistore_init(TALLOC_CTX *ctx,
    struct loadparm_context *lp, const char *path)
{
    stores++;
    return talloc_zero(ctx, struct mapistore_context);
}
enum mapistore_error mapistore_release(struct mapistore_context *ctx)
{
    releases++;
    return MAPISTORE_SUCCESS;
}
enum mapistore_error mapistore_set_connection_info(struct mapistore_context *ctx,
    struct ldb_context *sam, struct openchangedb_context *db, const char *name)
{
    return failure == FAIL_INFO ? MAPISTORE_ERROR : MAPISTORE_SUCCESS;
}
enum mapistore_error mapistore_notification_session_get(TALLOC_CTX *ctx,
    struct mapistore_context *store, struct GUID handle, struct GUID *uuid, char **cn)
{
    if (failure == FAIL_SESSION) return MAPISTORE_ERR_NOT_FOUND;
    *uuid = handle;
    *cn = talloc_strdup(ctx, owner);
    return MAPISTORE_SUCCESS;
}
enum mapistore_error mapistore_notification_session_exist(struct mapistore_context *ctx,
    struct GUID handle)
{
    return failure == FAIL_SESSION ? MAPISTORE_ERR_NOT_FOUND : MAPISTORE_SUCCESS;
}
enum mapistore_error mapistore_notification_resolver_add(struct mapistore_context *ctx,
    const char *cn, const char *address)
{
    if (failure == FAIL_RESOLVER) return MAPISTORE_ERROR;
    registrations++;
    return MAPISTORE_SUCCESS;
}
enum mapistore_error mapistore_notification_resolver_delete(struct mapistore_context *ctx,
    const char *cn, const char *address)
{
    deletions++;
    return MAPISTORE_SUCCESS;
}
int nn_socket(int domain, int protocol)
{
    if (failure == FAIL_SOCKET) return -1;
    sockets++;
    return 100;
}
int nn_close(int socket) { closes++; return 0; }
int nn_bind(int socket, const char *address)
{
    if (strcmp(address, "tcp://127.0.0.1:25252") != 0) abort();
    return failure == FAIL_BIND ? -1 : 1;
}
int nn_getsockopt(int socket, int level, int option, void *value, size_t *size)
{
    if (failure == FAIL_FD) return -1;
    *(int *)value = pipe_fds[0];
    return 0;
}
int nn_recv(int socket, void *buffer, size_t length, int flags)
{
    if (!malformed_message) { errno = EAGAIN; return -1; }
    *(char **)buffer = malloc(1);
    **(char **)buffer = 0;
    return 1;
}
int nn_freemsg(void *message) { free(message); return 0; }

void _dcesrv_async_reply(struct dcesrv_call_state *call, const char *func, const char *location)
{
    if (call->subreq != NULL) abort();
    replies++;
}

static struct dcesrv_call_state *new_call(TALLOC_CTX *ctx,
    struct dcesrv_connection_context *context, struct dcesrv_auth *auth, uint32_t handle_id)
{
    struct dcesrv_call_state *call = talloc_zero(ctx, struct dcesrv_call_state);
    struct EcDoAsyncWaitEx *r;
    if (call == NULL) return NULL;
    r = talloc_zero(call, struct EcDoAsyncWaitEx);
    if (r == NULL) return NULL;
    r->in.async_handle = talloc_zero(r, struct policy_handle);
    if (r->in.async_handle == NULL) return NULL;
    r->in.async_handle->uuid.time_low = handle_id;
    r->in.async_handle->handle_type = EXCHANGE_HANDLE_ASYNCEMSMDB;
    call->conn = context->conn;
    call->context = context;
    call->auth_state = auth;
    call->event_ctx = context->conn->event_ctx;
    call->state_flags = DCESRV_CALL_STATE_FLAG_MAY_ASYNC;
    call->r = r;
    return call;
}

static int set_exchange_control(const char *value)
{
    struct ldb_message *message = ldb_msg_new(samdb_ctx);
    int ret;
    if (message == NULL) return -1;
    message->dn = ldb_dn_new(message, samdb_ctx, "CN=test,DC=test");
    if (value == NULL) ret = ldb_msg_add_empty(message, "msExchUserAccountControl", LDB_FLAG_MOD_DELETE, NULL);
    else {
        ret = ldb_msg_add_string(message, "msExchUserAccountControl", value);
        if (ret == LDB_SUCCESS) message->elements[0].flags = LDB_FLAG_MOD_REPLACE;
    }
    if (ret == LDB_SUCCESS) ret = ldb_modify(samdb_ctx, message);
    talloc_free(message);
    return ret;
}

static NTSTATUS dispatch(struct dcesrv_call_state *call)
{
    NTSTATUS status = call->context->iface->dispatch(call, call, call->r);
    return NT_STATUS_IS_OK(status) ? ((struct EcDoAsyncWaitEx *)call->r)->out.result : status;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    const struct dcesrv_endpoint_server *ep;
    struct dcesrv_interface iface;
    struct dcesrv_context *dce;
    struct dcesrv_connection *conn;
    struct dcesrv_connection_context *context, *other;
    struct dcesrv_assoc_group *assoc;
    struct dcesrv_auth auth = {0}, other_auth;
    struct auth_user_info user = { .account_name = "test" };
    struct dom_sid sids[] = {
        { .sid_rev_num = 1, .num_auths = 2, .id_auth = {0,0,0,0,0,5}, .sub_auths = {21,1000} },
        { .sid_rev_num = 1, .num_auths = 1, .id_auth = {0,0,0,0,0,5}, .sub_auths = {11} }
    };
    struct security_token token = { .num_sids = 2, .sids = sids };
    struct auth_session_info session = { .security_token = &token, .info = &user };
    struct dcesrv_call_state *call, *duplicate, *second, *different_auth, *abandoned;
    struct dcesrv_call_state unrelated = {0};
    struct asyncemsmdb_connection *state;
    struct asyncemsmdb_private_data *p;
    unsigned before;
    int stage;
    size_t blocks;

    int directory_fd = mkstemp(directory_path);
    CHECK(ctx != NULL && directory_fd >= 0 && pipe(pipe_fds) == 0);
    close(directory_fd); unlink(directory_path);
    CHECK(_get_random_port() == 25252);
    CHECK(get_mapistore_sogo_PidTagParentFolderId(ctx, NULL, "sogo://mail/", NULL)
        == MAPISTORE_ERR_INVALID_PARAMETER);
    CHECK(NT_STATUS_IS_OK(samba_init_module(ctx)));
    ep = dcesrv_ep_server_byname("asyncemsmdb");
    CHECK(ep != NULL && ep->interface_by_name(&iface, "asyncemsmdb"));
    dce = talloc_zero(ctx, struct dcesrv_context);
    CHECK(dce != NULL);
    dce->lp_ctx = loadparm_init(dce);
    CHECK(dce->lp_ctx != NULL);
    conn = talloc_zero(ctx, struct dcesrv_connection);
    CHECK(conn != NULL);
    conn->dce_ctx = dce;
    conn->event_ctx = tevent_context_init(conn);
    assoc = talloc_zero(ctx, struct dcesrv_assoc_group);
    CHECK(conn->event_ctx != NULL && assoc != NULL);
    conn->assoc_group = assoc;
    context = talloc_zero(conn, struct dcesrv_connection_context);
    other = talloc_zero(conn, struct dcesrv_connection_context);
    CHECK(context != NULL && other != NULL);
    context->conn = other->conn = conn;
    context->iface = other->iface = &iface;
    context->context_id = 1; other->context_id = 2;
    failure = FAIL_DATABASE;
    CHECK(!NT_STATUS_IS_OK(iface.bind(context, &iface)));
    failure = FAIL_DIRECTORY;
    CHECK(!NT_STATUS_IS_OK(iface.bind(context, &iface)));
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "dcerpc_mapiproxy:samdb_url", "sam.ldb"));
    CHECK(!NT_STATUS_IS_OK(iface.bind(context, &iface)));
    blocks = talloc_total_blocks(ctx);
    CHECK(!NT_STATUS_IS_OK(iface.bind(context, &iface)));
    CHECK(talloc_total_blocks(ctx) == blocks);
    failure = FAIL_NONE;
    CHECK(NT_STATUS_IS_OK(iface.bind(context, &iface)));
    CHECK(NT_STATUS_IS_OK(iface.bind(other, &iface)));
    CHECK(conn->state_flags & DCESRV_CALL_STATE_FLAG_PROCESS_PENDING_CALL);
    auth.auth_finished = true;
    auth.session_info = &session;
    other_auth = auth;

    call = new_call(ctx, context, &auth, 1);
    CHECK(call != NULL);
    token.num_sids = 1;
    CHECK(NT_STATUS_EQUAL(dispatch(call), NT_STATUS_ACCESS_DENIED));
    CHECK(!(call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) && stores == 0);
    token.num_sids = 2;
    call->state_flags = 0;
    CHECK(NT_STATUS_EQUAL(dispatch(call), NT_STATUS_NOT_SUPPORTED) && stores == 0);
    call->state_flags = DCESRV_CALL_STATE_FLAG_MAY_ASYNC;
    {
        struct policy_handle *handle = ((struct EcDoAsyncWaitEx *)call->r)->in.async_handle;
        ((struct EcDoAsyncWaitEx *)call->r)->in.async_handle = NULL;
        CHECK(NT_STATUS_EQUAL(dispatch(call), NT_STATUS_INVALID_HANDLE));
        ((struct EcDoAsyncWaitEx *)call->r)->in.async_handle = handle;
    }
    owner = "someone-else";
    CHECK(NT_STATUS_EQUAL(dispatch(call), NT_STATUS_ACCESS_DENIED));
    CHECK(stores == releases && sockets == closes);
    owner = "test";
    sids[0].sub_auths[1]++;
    CHECK(NT_STATUS_EQUAL(dispatch(call), NT_STATUS_ACCESS_DENIED));
    CHECK(stores == releases && sockets == closes);
    sids[0].sub_auths[1]--;
    owner = user.account_name = "missing";
    CHECK(NT_STATUS_EQUAL(dispatch(call), NT_STATUS_ACCESS_DENIED));
    owner = user.account_name = "test";
    CHECK(set_exchange_control("2") == LDB_SUCCESS);
    CHECK(NT_STATUS_EQUAL(dispatch(call), NT_STATUS_ACCESS_DENIED));
    CHECK(set_exchange_control(NULL) == LDB_SUCCESS);
    CHECK(NT_STATUS_EQUAL(dispatch(call), NT_STATUS_ACCESS_DENIED));
    CHECK(set_exchange_control("0") == LDB_SUCCESS);
    {
        struct policy_handle *handle = ((struct EcDoAsyncWaitEx *)call->r)->in.async_handle;
        handle->handle_type = EXCHANGE_HANDLE_NSP;
        CHECK(NT_STATUS_EQUAL(dispatch(call), NT_STATUS_INVALID_HANDLE));
        handle->handle_type = EXCHANGE_HANDLE_ASYNCEMSMDB;
        handle->uuid.time_low = 0;
        CHECK(NT_STATUS_EQUAL(dispatch(call), NT_STATUS_INVALID_HANDLE));
        handle->uuid.time_low = 1;
    }
    for (stage = FAIL_INFO; stage <= FAIL_RESOLVER; stage++) {
        failure = stage;
        CHECK(!NT_STATUS_IS_OK(dispatch(call)));
        CHECK(!(call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) && call->subreq == NULL);
        CHECK(stores == releases && sockets == closes && registrations == deletions);
    }
    failure = FAIL_NONE;
    CHECK(NT_STATUS_IS_OK(dispatch(call)) && call->subreq != NULL);
    CHECK(call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC);
    state = dcesrv_iface_state_find_conn(call, ASYNCEMSMDB_STATE_MAGIC, struct asyncemsmdb_connection);
    CHECK(state != NULL && talloc_parent(state) == context);
    p = state->sessions->data;
    before = stores;
    duplicate = new_call(ctx, context, &auth, 1);
    CHECK(duplicate != NULL && NT_STATUS_EQUAL(dispatch(duplicate), NT_STATUS_DEVICE_BUSY));
    CHECK(stores == before && duplicate->subreq == NULL);
    EcDoAsyncWaitEx_handler(conn->event_ctx, p->fd_event, TEVENT_FD_READ, p);
    malformed_message = true;
    EcDoAsyncWaitEx_handler(conn->event_ctx, p->fd_event, TEVENT_FD_READ, p);
    CHECK(replies == 0 && p->wait != NULL);
    malformed_message = false;
    CHECK(tevent_req_cancel(call->subreq));
    CHECK(replies == 1 && call->subreq == NULL && p->wait == NULL && p->fd_event == NULL);
    CHECK(NT_STATUS_EQUAL(((struct EcDoAsyncWaitEx *)call->r)->out.result, NT_STATUS_CANCELLED));
    failure = FAIL_SESSION;
    CHECK(NT_STATUS_EQUAL(dispatch(duplicate), NT_STATUS_INVALID_HANDLE));
    failure = FAIL_NONE;
    CHECK(NT_STATUS_IS_OK(dispatch(duplicate)) && stores == before);
    tevent_req_done(duplicate->subreq);
    CHECK(replies == 2 && p->wait == NULL && p->fd_event == NULL);
    CHECK(NT_STATUS_IS_OK(((struct EcDoAsyncWaitEx *)duplicate->r)->out.result));
    abandoned = new_call(ctx, context, &auth, 1);
    CHECK(abandoned != NULL && NT_STATUS_IS_OK(dispatch(abandoned)));
    talloc_free(abandoned);
    CHECK(p->wait == NULL && p->fd_event == NULL);

    /* Multiple handles, authentication contexts and presentation contexts stay separate. */
    call = new_call(ctx, context, &auth, 1);
    duplicate = new_call(ctx, context, &auth, 2);
    different_auth = new_call(ctx, context, &other_auth, 1);
    second = new_call(ctx, other, &auth, 1);
    CHECK(call && duplicate && different_auth && second);
    CHECK(NT_STATUS_IS_OK(dispatch(call)) && NT_STATUS_IS_OK(dispatch(duplicate)));
    CHECK(NT_STATUS_IS_OK(dispatch(different_auth)) && NT_STATUS_IS_OK(dispatch(second)));
    CHECK(stores - releases == 4 && sockets - closes == 4);
    conn->pending_call_list = &unrelated;
    before = replies;
    iface.unbind(context, &iface);
    CHECK(replies == before + 3 && second->subreq != NULL);
    CHECK(conn->pending_call_list == &unrelated);
    CHECK(stores - releases == 1 && sockets - closes == 1);
    iface.unbind(context, &iface); /* Repeated teardown is safe. */
    iface.unbind(other, &iface);
    CHECK(stores == releases && sockets == closes && registrations == deletions);
    CHECK(async_connections == NULL && assoc->iface_states == NULL);
    conn->pending_call_list = NULL;
    talloc_free(conn);
    dcesrv_assoc_group_common_destructor(assoc);
    talloc_free(ctx);
    close(pipe_fds[0]); close(pipe_fds[1]); unlink(directory_path);
    puts("Async RPC authentication, ownership, failure cleanup, completion and cancellation checks passed");
    return 0;
}
