/* Actual EMSMDB connection/handle code and Samba policy handles.
 * Mailbox backend and notification cache access are substituted. */
#include <util/debug.h>
#undef DEBUG
#undef DEBUGLEVEL
#define DEBUG(level, body) ((void)0)
#define DEBUGLEVEL 0
#include "mapiproxy/servers/default/emsmdb/dcesrv_exchange_emsmdb.c"
#include "mapiproxy/servers/default/emsmdb/emsmdb_execute.c"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "EMSMDB check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

enum fail_stage { FAIL_NONE, FAIL_INIT, FAIL_USER, FAIL_USER_DN, FAIL_NICKNAME, FAIL_LEGACY_DN, FAIL_DISPLAY_NAME,
    FAIL_BAD_SUFFIX, FAIL_SESSION_UUID, FAIL_NOTIFICATION };
static enum fail_stage failure;
static unsigned created, destroyed, registrations, deletions, string_calls, fail_string;
static struct GUID registered_mailbox, registered_async;
static const char *registered_user;
static struct ldb_message *record;
static DATA_BLOB notification;
static unsigned notification_deletes;

static int backend_destructor(struct emsmdbp_context *ctx) { destroyed++; return 0; }
struct emsmdbp_context *emsmdbp_init(struct loadparm_context *lp, const char *user, void *db)
{
    struct emsmdbp_context *ctx;
    if (failure == FAIL_INIT) return NULL;
    ctx = talloc_zero(NULL, struct emsmdbp_context);
    if (ctx == NULL) return NULL;
    created++; talloc_set_destructor(ctx, backend_destructor);
    ctx->mstore_ctx = talloc_zero(ctx, struct mapistore_context);
    return ctx;
}
bool emsmdbp_verify_user(struct dcesrv_call_state *call, struct emsmdbp_context *ctx)
{ return failure != FAIL_USER; }
bool emsmdbp_verify_userdn(struct dcesrv_call_state *call, struct emsmdbp_context *ctx,
    const char *dn, struct ldb_message **msg)
{ *msg = record; return failure != FAIL_USER_DN; }
bool emsmdbp_set_session_uuid(struct emsmdbp_context *ctx, struct GUID uuid)
{ ctx->session_uuid = uuid; return failure != FAIL_SESSION_UUID; }
enum mapistore_error mapistore_notification_session_add(struct mapistore_context *store,
    struct GUID mailbox, struct GUID async, const char *user)
{
    registrations++; registered_mailbox = mailbox; registered_async = async; registered_user = user;
    return failure == FAIL_NOTIFICATION ? MAPISTORE_ERROR : MAPISTORE_SUCCESS;
}
enum mapistore_error mapistore_notification_session_delete(struct mapistore_context *store, struct GUID async)
{
    if (talloc_get_type(store, struct mapistore_context) == NULL || !GUID_equal(&async, &registered_async)) abort();
    deletions++;
    return MAPISTORE_SUCCESS;
}
enum mapistore_error mapistore_notification_deliver_get(TALLOC_CTX *ctx, struct mapistore_context *store,
    struct GUID uuid, uint8_t **data, size_t *length)
{
    if (notification.data == NULL) return MAPISTORE_ERR_NOT_FOUND;
    *data = notification.data; *length = notification.length; return MAPISTORE_SUCCESS;
}
enum mapistore_error mapistore_notification_deliver_delete(struct mapistore_context *store, struct GUID uuid)
{ notification_deletes++; return MAPISTORE_SUCCESS; }

char *__real_talloc_strdup(const void *ctx, const char *p);
char *__wrap_talloc_strdup(const void *ctx, const char *p);
char *__wrap_talloc_strdup(const void *ctx, const char *p)
{ return ++string_calls == fail_string ? NULL : __real_talloc_strdup(ctx, p); }

static bool make_record(TALLOC_CTX *ctx)
{
    TALLOC_FREE(record);
    record = ldb_msg_new(ctx);
    if (!record) return false;
    return (failure == FAIL_NICKNAME || ldb_msg_add_string(record, "mailNickname", "test") == 0) &&
        (failure == FAIL_LEGACY_DN || ldb_msg_add_string(record, "legacyExchangeDN",
            failure == FAIL_BAD_SUFFIX ? "/o=test/cn=other" : "/o=test/ou=Site/cn=Recipients/cn=test") == 0) &&
        (failure == FAIL_DISPLAY_NAME || ldb_msg_add_string(record, "displayName", "Test User") == 0);
}

static int rpc_transactions(TALLOC_CTX *ctx, struct dcesrv_call_state *call, struct policy_handle *handle)
{
    TALLOC_CTX *request_ctx = talloc_new(ctx);
    struct mapi_request request = { .length = 5, .mapi_len = 9 };
    struct mapi_response *response, placeholder = {0};
    struct emsmdbp_context *backend = dcesrv_find_emsmdb_context(call, handle);
    struct ndr_push *wire, *body;
    struct ndr_pull *pull;
    struct mapi2k7_response decoded = {0};
    struct RPC_HEADER_EXT header = { .Flags = RHEF_Last, .Size = 9, .SizeActual = 9 };
    struct policy_handle reply;
    DATA_BLOB input;
    uint32_t count, capacity = 256, flags = 0, aux = 0, elapsed = 0;
    uint16_t legacy_length = 0;
    struct EcDoRpcExt2 rpc = { .in = { .handle = handle, .pcbOut = &capacity, .pulFlags = &flags },
        .out = { .handle = &reply, .pcbOut = &capacity, .pulFlags = &flags,
            .pcbAuxOut = &aux, .pulTransTime = &elapsed } };
    struct EcDoRpc legacy = { .in = { .handle = handle, .mapi_request = &request, .max_data = UINT16_MAX },
        .out = { .handle = &reply, .mapi_response = &placeholder, .length = &legacy_length } };
    CHECK(request_ctx);
    request.handles = talloc_array(request_ctx, uint32_t, 1);
    request.mapi_req = talloc_zero_array(request_ctx, struct EcDoRpc_MAPI_REQ, 2);
    CHECK(request.handles && request.mapi_req);
    request.handles[0] = 42; request.mapi_req[0].opnum = op_MAPI_GetStatus;
    CHECK(emsmdb_request_valid(&request, &count) && count == 1);
    request.mapi_req[0].handle_idx = 1;
    CHECK(!emsmdb_request_valid(&request, &count));
    CHECK(EcDoRpc_process_transaction(ctx, backend, &request, &response) == ecRpcFormat && response == NULL);
    request.mapi_req[0].handle_idx = 0;
    request.mapi_req[0].opnum = op_MAPI_OpenStream; request.mapi_req[0].u.mapi_OpenStream.handle_idx = 1;
    CHECK(!emsmdb_request_valid(&request, &count));
    request.mapi_req[0].opnum = op_MAPI_GetStatus;
    request.length = 1; CHECK(!emsmdb_request_valid(&request, &count)); request.length = 5;
    request.mapi_len = 10; CHECK(!emsmdb_request_valid(&request, &count)); request.mapi_len = 9;
    request.mapi_req[1].opnum = op_MAPI_GetStatus;
    CHECK(!emsmdb_request_valid(&request, &count)); request.mapi_req[1].opnum = 0;
    CHECK(EcDoRpc_process_transaction(ctx, backend, &request, &response) == MAPI_E_SUCCESS);
    CHECK(response->mapi_repl[0].opnum == op_MAPI_GetStatus && response->mapi_repl[0].error_code == MAPI_E_NO_SUPPORT);
    CHECK(response->handles != request.handles && response->handles[0] == 42);
    CHECK(dcesrv_EcDoRpc(call, ctx, &legacy) == MAPI_E_SUCCESS && legacy_length == 12);
    wire = ndr_push_init_ctx(ctx); CHECK(wire);
    CHECK(ndr_push_RPC_HEADER_EXT(wire, NDR_SCALARS, &header) == NDR_ERR_SUCCESS);
    CHECK(ndr_push_mapi_request(wire, NDR_SCALARS, &request) == NDR_ERR_SUCCESS);
    input = ndr_push_blob(wire); rpc.in.rgbIn = input.data; rpc.in.cbIn = input.length;
    CHECK(dcesrv_EcDoRpcExt2(call, ctx, &rpc) == MAPI_E_SUCCESS && capacity == 20);
    CHECK(GUID_equal(&reply.uuid, &handle->uuid));
    input.data = rpc.out.rgbOut; input.length = capacity;
    pull = ndr_pull_init_blob(&input, ctx); CHECK(pull);
    pull->flags |= LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC;
    CHECK(ndr_pull_mapi2k7_response(pull, NDR_SCALARS, &decoded) == NDR_ERR_SUCCESS);
    CHECK(decoded.mapi_response->handles[0] == 42 && decoded.mapi_response->mapi_repl[0].error_code == MAPI_E_NO_SUPPORT);
    capacity = 10;
    CHECK(dcesrv_EcDoRpcExt2(call, ctx, &rpc) == ecBufferTooSmall && capacity == 0 && rpc.out.rgbOut == NULL);
    capacity = 256; rpc.in.rgbIn[2] = 0; /* Missing last-frame flag. */
    CHECK(dcesrv_EcDoRpcExt2(call, ctx, &rpc) == ecRpcFormat && capacity == 0);
    rpc.in.rgbIn[2] = RHEF_Last; capacity = 256; rpc.in.cbIn--;
    CHECK(dcesrv_EcDoRpcExt2(call, ctx, &rpc) == ecRpcFormat && capacity == 0);
    rpc.in.cbIn++; capacity = 256;
    rpc.in.rgbIn[2] = RHEF_Last | RHEF_XorMagic;
    obfuscate_data(rpc.in.rgbIn + 8, 9, 0xA5);
    flags = pulFlags_NoXorMagic;
    CHECK(dcesrv_EcDoRpcExt2(call, ctx, &rpc) == MAPI_E_SUCCESS && rpc.out.rgbOut[2] == RHEF_Last);
    capacity = 256; flags = 0;
    CHECK(dcesrv_EcDoRpcExt2(call, ctx, &rpc) == MAPI_E_SUCCESS && rpc.out.rgbOut[2] == (RHEF_Last | RHEF_XorMagic));
    body = ndr_push_init_ctx(ctx); CHECK(body);
    CHECK(ndr_push_EcDoRpc_MAPI_REPL(body, NDR_SCALARS, &response->mapi_repl[0]) == NDR_ERR_SUCCESS);
    notification = ndr_push_blob(body);
    CHECK(EcDoRpc_process_transaction(ctx, backend, &request, &response) == ecRpcFormat);
    CHECK(notification_deletes == 0);
    notification = (DATA_BLOB){0};
    CHECK(EcDoRpc_process_transaction(ctx, backend, &request, &response) == MAPI_E_SUCCESS);
    talloc_free(request_ctx);
    CHECK(response->handles[0] == 42);
    return 0;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    struct dcesrv_context *dce = talloc_zero(ctx, struct dcesrv_context);
    struct dcesrv_connection *conn = talloc_zero(ctx, struct dcesrv_connection);
    struct dcesrv_assoc_group *assoc = talloc_zero(ctx, struct dcesrv_assoc_group);
    struct dcesrv_assoc_group *other = talloc_zero(ctx, struct dcesrv_assoc_group);
    struct dcesrv_connection_context pres = {0};
    struct dcesrv_interface iface = {0}, wrong_iface = {0}, async_iface = { .name = "asyncemsmdb" };
    struct dcesrv_endpoint empty_endpoint = {0}, endpoint = {0};
    struct dcesrv_if_list first_entry = { .iface = &iface }, async_entry = { .iface = &async_iface };
    struct dcesrv_auth auth = { .auth_finished = true, .auth_level = DCERPC_AUTH_LEVEL_PRIVACY };
    struct auth_user_info user = { .account_name = "test" };
    struct auth_session_info session = { .info = &user };
    struct dom_sid sids[] = {
        { .sid_rev_num = 1, .num_auths = 2, .id_auth = {0,0,0,0,0,5}, .sub_auths = {21,1000} },
        { .sid_rev_num = 1, .num_auths = 1, .id_auth = {0,0,0,0,0,5}, .sub_auths = {11} }
    };
    struct security_token token = { .num_sids = 2, .sids = sids };
    struct dcesrv_call_state call = {0};
    struct policy_handle wire = {0}, saved, empty = {0}, async_wire = {0};
    uint32_t polls, retry, delay, ixr, timestamp, aux_size;
    const char *prefix, *display;
    struct EcDoConnect connect = { .in = { .szUserDN = "/o=test/ou=Site/cn=Recipients/cn=test" },
        .out = { .handle = &wire, .pcmsPollsMax = &polls, .pcRetry = &retry,
            .pcmsRetryDelay = &delay, .picxr = &ixr, .pullTimeStamp = &timestamp,
            .szDNPrefix = &prefix, .szDisplayName = &display } };
    struct mapi2k7_AuxInfo aux = {0};
    struct EcDoConnectEx extended = { .in = { .szUserDN = connect.in.szUserDN,
            .cbAuxIn = 8, .rgbAuxIn = &aux, .rgwClientVersion = { 11, 0x8000, 1 } },
        .out = { .handle = &wire, .pcmsPollsMax = &polls, .pcRetry = &retry,
            .pcmsRetryDelay = &delay, .picxr = &ixr, .pulTimeStamp = &timestamp,
            .szDNPrefix = &prefix, .szDisplayName = &display, .pcbAuxOut = &aux_size } };
    struct EcDoDisconnect disconnect = { .in = { .handle = &wire }, .out = { .handle = &wire } };
    struct EcDoAsyncConnectEx async = { .in = { .handle = &wire }, .out = { .async_handle = &async_wire } };
    struct dcesrv_handle *handle;
    struct emsmdbp_context *backend;
    struct ndr_push *push;
    enum fail_stage stage;
    unsigned before, i;

    CHECK(ctx && dce && conn && assoc && other);
    dce->lp_ctx = loadparm_init(dce); CHECK(dce->lp_ctx);
    conn->dce_ctx = dce; conn->assoc_group = assoc;
    pres.conn = conn; pres.iface = &iface;
    session.security_token = &token; auth.session_info = &session;
    call.conn = conn; call.context = &pres; call.auth_state = &auth;
    CHECK(make_record(ctx));
    token.num_sids = 1;
    CHECK(dcesrv_EcDoConnect(&call, ctx, &connect) == MAPI_E_LOGON_FAILED && created == 0);
    CHECK(dcesrv_EcDoConnectEx(&call, ctx, &extended) == MAPI_E_LOGON_FAILED && created == 0);
    CHECK(NT_STATUS_EQUAL(dcesrv_exchange_emsmdb_dispatch(&call, ctx, &connect, NULL), NT_STATUS_NET_WRITE_FAULT));
    CHECK(call.fault_code == DCERPC_FAULT_ACCESS_DENIED);
    token.num_sids = 2;
    connect.in.szUserDN = NULL;
    CHECK(dcesrv_EcDoConnect(&call, ctx, &connect) == MAPI_E_NO_ACCESS && created == 0);
    connect.in.szUserDN = extended.in.szUserDN;
    extended.in.cbAuxIn = 7;
    CHECK(dcesrv_EcDoConnectEx(&call, ctx, &extended) == ecRpcFailed && created == 0);
    extended.in.cbAuxIn = 8; extended.in.rgwClientVersion[0] = 10;
    CHECK(dcesrv_EcDoConnectEx(&call, ctx, &extended) == MAPI_E_VERSION && created == 0);
    CHECK(extended.out.rgwBestVersion[0] == 11 && extended.out.rgwBestVersion[1] == 0x8000);
    extended.in.rgwClientVersion[0] = 11;
    for (stage = FAIL_INIT; stage <= FAIL_SESSION_UUID; stage++) {
        failure = stage; CHECK(make_record(ctx));
        CHECK(dcesrv_EcDoConnect(&call, ctx, &connect) != MAPI_E_SUCCESS);
        CHECK(GUID_all_zero(&wire.uuid) && assoc->handles == NULL && created == destroyed);
        CHECK(dcesrv_EcDoConnectEx(&call, ctx, &extended) != MAPI_E_SUCCESS);
        CHECK(GUID_all_zero(&wire.uuid) && assoc->handles == NULL && created == destroyed);
    }
    failure = FAIL_NONE; CHECK(make_record(ctx));
    for (i = 1; i <= 3; i++) {
        fail_string = string_calls + i;
        CHECK(dcesrv_EcDoConnectEx(&call, ctx, &extended) == MAPI_E_NOT_ENOUGH_RESOURCES);
        CHECK(GUID_all_zero(&wire.uuid) && created == destroyed && assoc->handles == NULL);
    }
    fail_string = 0;
    CHECK(dcesrv_EcDoConnect(&call, ctx, &connect) == MAPI_E_SUCCESS);
    CHECK(strcmp(display, "Test User") == 0 && strcmp(prefix, "/O=TEST/OU=SITE/CN=RECIPIENTS/CN=") == 0);
    CHECK(strcmp(ldb_msg_find_attr_as_string(record, "legacyExchangeDN", ""), extended.in.szUserDN) == 0);
    push = ndr_push_init_ctx(ctx);
    CHECK(push && NDR_ERR_CODE_IS_SUCCESS(ndr_table_exchange_emsmdb.calls[NDR_ECDOCONNECT].ndr_push(push, NDR_OUT, &connect)));
    handle = dcesrv_find_emsmdb_handle(&call, &wire);
    backend = dcesrv_find_emsmdb_context(&call, &wire);
    CHECK(handle && backend && talloc_parent(backend) == handle);
    saved = wire;
    CHECK(rpc_transactions(ctx, &call, &wire) == 0);
    CHECK(dcesrv_find_emsmdb_handle(&call, &empty) == NULL && assoc->handles == handle && handle->next == NULL);
    sids[0].sub_auths[1]++;
    CHECK(dcesrv_find_emsmdb_context(&call, &wire) == NULL);
    CHECK(dcesrv_EcDoDisconnect(&call, ctx, &disconnect) == MAPI_E_INVALID_OBJECT && created == destroyed + 1);
    wire = saved; sids[0].sub_auths[1]--;
    auth.auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
    CHECK(dcesrv_find_emsmdb_handle(&call, &wire) == NULL);
    auth.auth_level = DCERPC_AUTH_LEVEL_PRIVACY; pres.iface = &wrong_iface;
    CHECK(dcesrv_find_emsmdb_handle(&call, &wire) == NULL);
    pres.iface = &iface; conn->assoc_group = other;
    CHECK(dcesrv_find_emsmdb_handle(&call, &wire) == NULL);
    conn->assoc_group = assoc;
    CHECK(dcesrv_EcDoAsyncConnectEx(&call, ctx, &async) == ecRejected && registrations == 0);
    /* The asynchronous interface need not be the first endpoint or interface. */
    dce->endpoint_list = &empty_endpoint; empty_endpoint.next = &endpoint;
    endpoint.interface_list = &first_entry; first_entry.next = &async_entry;
    failure = FAIL_NOTIFICATION;
    CHECK(dcesrv_EcDoAsyncConnectEx(&call, ctx, &async) == MAPI_E_LOGON_FAILED);
    CHECK(GUID_all_zero(&async_wire.uuid) && assoc->handles == handle && handle->next == NULL && deletions == 0);
    failure = FAIL_NONE;
    CHECK(dcesrv_EcDoAsyncConnectEx(&call, ctx, &async) == MAPI_E_SUCCESS);
    CHECK(GUID_equal(&registered_mailbox, &saved.uuid) && GUID_equal(&registered_async, &async_wire.uuid));
    CHECK(strcmp(registered_user, "test") == 0 && registrations == 2);
    before = destroyed;
    CHECK(dcesrv_EcDoDisconnect(&call, ctx, &disconnect) == MAPI_E_SUCCESS);
    CHECK(destroyed == before + 1 && created == destroyed && assoc->handles == NULL && deletions == 1);
    CHECK(strcmp(display, "Test User") == 0); /* Reply owns its strings. */
    wire = saved;
    CHECK(dcesrv_EcDoDisconnect(&call, ctx, &disconnect) == MAPI_E_INVALID_OBJECT);
    CHECK(dcesrv_EcDoConnectEx(&call, ctx, &extended) == MAPI_E_SUCCESS);
    push = ndr_push_init_ctx(ctx);
    CHECK(push && NDR_ERR_CODE_IS_SUCCESS(ndr_table_exchange_emsmdb.calls[NDR_ECDOCONNECTEX].ndr_push(push, NDR_OUT, &extended)));
    CHECK(dcesrv_EcDoAsyncConnectEx(&call, ctx, &async) == MAPI_E_SUCCESS);
    talloc_free(assoc);
    CHECK(created == destroyed && deletions == 2);
    talloc_free(ctx);
    puts("EMSMDB authentication, handle isolation, connection replies and notification lifecycle: OK");
    return 0;
}
