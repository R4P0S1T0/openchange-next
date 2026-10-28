/* Exercise the real module and Samba state APIs, with no network or AD DC.
 * The outgoing connection, transport server ID and plugin hooks are substituted.
 */
#define SOURCE4_LIBRPC_INTERNALS 1
#include "mapiproxy/dcesrv_mapiproxy.h"
#include "mapiproxy/dcesrv_mapiproxy_proto.h"
#include <tevent.h>

NTSTATUS samba_init_module(TALLOC_CTX *ctx);

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "RPC check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static unsigned connections;
static uint32_t requested_id, returned_id = 200;
static NTSTATUS connect_status;
static struct cli_credentials *used_credentials;
static NTSTATUS raw_hook_status, decoded_hook_status, push_hook_status;
static unsigned decoded_hooks;

NTSTATUS mapiproxy_module_ndr_pull(struct dcesrv_call_state *call, TALLOC_CTX *ctx,
    struct ndr_pull *pull)
{
    return raw_hook_status;
}
NTSTATUS mapiproxy_module_pull(struct dcesrv_call_state *call, TALLOC_CTX *ctx, void *r)
{
    decoded_hooks++;
    return decoded_hook_status;
}
NTSTATUS mapiproxy_module_push(struct dcesrv_call_state *call, TALLOC_CTX *ctx, void *r)
{
    return push_hook_status;
}

/* These symbols interpose the module's calls, not Samba's state registry. */
struct server_id dcesrv_server_id(struct dcesrv_connection *conn)
{
    return (struct server_id){ .pid = 100 };
}

NTSTATUS dcerpc_pipe_connect_b(TALLOC_CTX *ctx, struct dcerpc_pipe **pp,
    const struct dcerpc_binding *binding, const struct ndr_interface_table *table,
    struct cli_credentials *credentials, struct tevent_context *ev,
    struct loadparm_context *lp)
{
    struct dcerpc_binding *b;
    NTSTATUS status;
    connections++;
    used_credentials = credentials;
    requested_id = dcerpc_binding_get_assoc_group_id(binding);
    if (!NT_STATUS_IS_OK(connect_status)) {
        return connect_status;
    }
    *pp = dcerpc_pipe_init(ctx, ev);
    if (*pp == NULL) {
        return NT_STATUS_NO_MEMORY;
    }
    status = dcerpc_parse_binding(*pp, "ncacn_ip_tcp:localhost", &b);
    if (!NT_STATUS_IS_OK(status)) {
        return status;
    }
    (*pp)->binding = b;
    return dcerpc_binding_set_assoc_group_id(b, returned_id);
}

static struct dcesrv_call_state *new_call(TALLOC_CTX *ctx,
    struct dcesrv_connection *conn, const struct dcesrv_interface *iface,
    struct dcesrv_auth *auth, uint16_t context_id)
{
    struct dcesrv_call_state *call = talloc_zero(ctx, struct dcesrv_call_state);
    if (call == NULL) return NULL;
    call->context = talloc_zero(conn, struct dcesrv_connection_context);
    if (call->context == NULL) { talloc_free(call); return NULL; }
    call->conn = conn;
    call->auth_state = auth;
    call->event_ctx = conn->event_ctx;
    call->context->conn = conn;
    call->context->iface = iface;
    call->context->context_id = context_id;
    call->pkt.ptype = DCERPC_PKT_REQUEST;
    call->pkt.u.request.opnum = NDR_RFRGETNEWDSA;
    return call;
}

static NTSTATUS pull_request(struct dcesrv_call_state *call, DATA_BLOB blob)
{
    struct ndr_pull *pull = ndr_pull_init_blob(&blob, call);
    return call->context->iface->ndr_pull(call, call, pull, &call->r);
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    const struct dcesrv_endpoint_server *ep;
    struct dcesrv_interface iface, found;
    struct GUID unknown = {0};
    struct dcesrv_context *dce;
    struct dcesrv_connection *conn, *other_conn;
    struct dcesrv_assoc_group *assoc;
    struct dcesrv_auth auth = {0}, other_auth;
    struct auth_session_info session = {0};
    struct dom_sid sids[] = {
        { .sid_rev_num = 1, .num_auths = 2, .id_auth = {0,0,0,0,0,5},
          .sub_auths = {21, 1000} },
        { .sid_rev_num = 1, .num_auths = 1, .id_auth = {0,0,0,0,0,5},
          .sub_auths = {11} }
    };
    struct security_token token = { .num_sids = 2, .sids = sids };
    struct dcesrv_call_state *call, *second, *retry;
    struct dcesrv_mapiproxy_private *saved;
    struct RfrGetNewDSA request = {0};
    struct ndr_push *push;
    DATA_BLOB blob;
    unsigned before;

    CHECK(ctx != NULL);
    CHECK(NT_STATUS_IS_OK(samba_init_module(ctx)));
    ep = dcesrv_ep_server_byname("mapiproxy");
    CHECK(ep != NULL);
    CHECK(ep->shutdown_server != NULL);
    CHECK(NT_STATUS_IS_OK(ep->shutdown_server(NULL, ep)));
    memset(&iface, 0xa5, sizeof(iface));
    CHECK(ep->interface_by_name(&iface, "exchange_ds_rfr"));
    CHECK(iface.flags == 0 && iface.local == NULL);
    CHECK(ep->interface_by_uuid(&found, &iface.syntax_id.uuid, iface.syntax_id.if_version));
    CHECK(strcmp(found.name, iface.name) == 0);
    CHECK(!ep->interface_by_uuid(&found, &unknown, iface.syntax_id.if_version));
    CHECK(!ep->interface_by_uuid(&found, &iface.syntax_id.uuid, iface.syntax_id.if_version + 1));

    dce = talloc_zero(ctx, struct dcesrv_context);
    CHECK(dce != NULL);
    dce->lp_ctx = loadparm_init(dce);
    CHECK(dce->lp_ctx != NULL);
    conn = talloc_zero(ctx, struct dcesrv_connection);
    assoc = talloc_zero(ctx, struct dcesrv_assoc_group);
    CHECK(conn != NULL && assoc != NULL);
    conn->dce_ctx = dce;
    conn->event_ctx = tevent_context_init(conn);
    conn->assoc_group = assoc;
    assoc->id = 100; /* Deliberately different from the remote ID. */
    session.security_token = &token;
    auth.auth_finished = true;
    auth.session_info = &session;
    other_auth = auth;
    call = new_call(ctx, conn, &iface, &auth, 1);
    CHECK(call != NULL);
    CHECK(NT_STATUS_IS_OK(iface.bind(call->context, &iface)));
    CHECK(assoc->iface_states == NULL && connections == 0);

    request.in.pUserDN = "/o=test/cn=user";
    push = ndr_push_init_ctx(ctx);
    CHECK(push != NULL);
    CHECK(NDR_ERR_CODE_IS_SUCCESS(ndr_table_exchange_ds_rfr.calls[NDR_RFRGETNEWDSA].ndr_push(push, NDR_IN, &request)));
    blob = ndr_push_blob(push);

    /* The real authentication gate rejects an anonymous token before state. */
    token.num_sids = 1;
    CHECK(NT_STATUS_EQUAL(pull_request(call, blob), NT_STATUS_NET_WRITE_FAULT));
    CHECK(assoc->iface_states == NULL && connections == 0);
    token.num_sids = 2;
    call->pkt.u.request.opnum = UINT16_MAX;
    CHECK(NT_STATUS_EQUAL(pull_request(call, blob), NT_STATUS_NET_WRITE_FAULT));
    CHECK(call->fault_code == DCERPC_FAULT_OP_RNG_ERROR);
    CHECK(assoc->iface_states == NULL);
    call->pkt.u.request.opnum = NDR_RFRGETNEWDSA;

    CHECK(NT_STATUS_IS_OK(pull_request(call, blob)));
    saved = mapiproxy_private(call);
    CHECK(saved != NULL && saved->server_mode && !saved->connected);
    CHECK(saved->exchname == NULL && saved->c_pipe == NULL);
    CHECK(talloc_parent(saved) == call->context);
    CHECK(NT_STATUS_IS_OK(pull_request(call, blob)));
    CHECK(mapiproxy_private(call) == saved);
    call->auth_state = &other_auth;
    CHECK(mapiproxy_private(call) == NULL);
    CHECK(NT_STATUS_IS_OK(pull_request(call, blob)));
    CHECK(mapiproxy_private(call) != saved);
    call->auth_state = &auth;
    CHECK(mapiproxy_private(call) == saved);
    CHECK(NT_STATUS_EQUAL(pull_request(call, (DATA_BLOB){0}), NT_STATUS_NET_WRITE_FAULT));
    CHECK(call->fault_code == DCERPC_FAULT_NDR);
    before = decoded_hooks;
    raw_hook_status = NT_STATUS_INVALID_PARAMETER;
    CHECK(NT_STATUS_EQUAL(pull_request(call, blob), NT_STATUS_NET_WRITE_FAULT));
    CHECK(call->fault_code == DCERPC_FAULT_NDR && decoded_hooks == before);
    raw_hook_status = NT_STATUS_OK;
    CHECK(NT_STATUS_EQUAL(pull_request(call, (DATA_BLOB){0}), NT_STATUS_NET_WRITE_FAULT));
    CHECK(decoded_hooks == before); /* Invalid NDR never reaches decoded hooks. */
    decoded_hook_status = NT_STATUS_INVALID_PARAMETER;
    CHECK(NT_STATUS_EQUAL(pull_request(call, blob), NT_STATUS_NET_WRITE_FAULT));
    CHECK(call->fault_code == DCERPC_FAULT_NDR && decoded_hooks == before + 1);
    decoded_hook_status = NT_STATUS_OK;
    CHECK(NT_STATUS_IS_OK(pull_request(call, blob)));
    push_hook_status = NT_STATUS_INVALID_PARAMETER;
    push = ndr_push_init_ctx(ctx);
    CHECK(push != NULL);
    CHECK(NT_STATUS_EQUAL(iface.ndr_push(call, call, push, call->r), NT_STATUS_NET_WRITE_FAULT));
    CHECK(call->fault_code == DCERPC_FAULT_NDR && push->offset == 0);
    push_hook_status = NT_STATUS_OK;
    iface.unbind(call->context, &iface);
    TALLOC_FREE(call->context);
    CHECK(assoc->iface_states == NULL);

    /* Proxy connections reuse remote IDs across connections in one association. */
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "dcerpc_mapiproxy:server", "false"));
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "dcerpc_mapiproxy:binding", "ncacn_ip_tcp:localhost"));
    call = new_call(ctx, conn, &iface, &auth, 2);
    CHECK(call != NULL);
    CHECK(NT_STATUS_EQUAL(pull_request(call, blob), NT_STATUS_NET_WRITE_FAULT));
    CHECK(connections == 0 && !mapiproxy_private(call)->connected);
    session.credentials = cli_credentials_init(ctx);
    CHECK(session.credentials != NULL);
    CHECK(NT_STATUS_IS_OK(pull_request(call, blob)));
    CHECK(used_credentials == session.credentials && talloc_parent(session.credentials) == ctx);
    session.credentials = NULL;
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "dcerpc_mapiproxy:username", "test"));
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "dcerpc_mapiproxy:password", "test"));
    CHECK(connections == 1 && requested_id == 0 && assoc->id == 100);
    CHECK(mapiproxy_private(call)->connected);
    CHECK(NT_STATUS_IS_OK(pull_request(call, blob)) && connections == 1);
    other_conn = talloc_zero(ctx, struct dcesrv_connection);
    CHECK(other_conn != NULL);
    other_conn->dce_ctx = dce;
    other_conn->event_ctx = conn->event_ctx;
    other_conn->assoc_group = assoc;
    second = new_call(ctx, other_conn, &iface, &auth, 2);
    CHECK(second != NULL && NT_STATUS_IS_OK(pull_request(second, blob)));
    CHECK(connections == 2 && requested_id == 200 && assoc->id == 100);
    CHECK(mapiproxy_private(second) != mapiproxy_private(call));

    /* Failed connections remain retryable and cannot overwrite local IDs. */
    retry = new_call(ctx, conn, &iface, &auth, 3);
    CHECK(retry != NULL);
    connect_status = NT_STATUS_ACCESS_DENIED;
    CHECK(NT_STATUS_EQUAL(pull_request(retry, blob), NT_STATUS_NET_WRITE_FAULT));
    CHECK(!mapiproxy_private(retry)->connected && assoc->id == 100);
    connect_status = NT_STATUS_OK;
    returned_id = 201;
    CHECK(NT_STATUS_EQUAL(pull_request(retry, blob), NT_STATUS_NET_WRITE_FAULT));
    CHECK(!mapiproxy_private(retry)->connected && mapiproxy_private(retry)->c_pipe == NULL);
    returned_id = 0;
    CHECK(NT_STATUS_EQUAL(pull_request(retry, blob), NT_STATUS_NET_WRITE_FAULT));
    returned_id = 200;
    CHECK(NT_STATUS_IS_OK(pull_request(retry, blob)));
    before = connections;
    CHECK(NT_STATUS_IS_OK(pull_request(retry, blob)) && connections == before);
    iface.unbind(call->context, &iface);
    TALLOC_FREE(call->context);
    iface.unbind(second->context, &iface);
    TALLOC_FREE(second->context);
    iface.unbind(retry->context, &iface);
    TALLOC_FREE(retry->context);
    talloc_free(conn);
    talloc_free(other_conn);
    dcesrv_assoc_group_common_destructor(assoc);
    CHECK(assoc->iface_states == NULL);
    talloc_free(ctx);
    puts("RPC module registration, bind/unbind, authentication isolation and remote association checks passed");
    return 0;
}
