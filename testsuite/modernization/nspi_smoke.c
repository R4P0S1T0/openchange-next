/* Actual NSPI entry points and Samba policy handles; the directory backend is
 * substituted so authorization and cleanup can run without an AD controller. */
#include <util/debug.h>
#undef DEBUG
#undef DEBUGLEVEL
#define DEBUG(level, body) ((void)0)
#define DEBUGLEVEL 0
#include "mapiproxy/servers/default/nspi/dcesrv_exchange_nsp.c"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "NSPI check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static unsigned created, destroyed;
static bool fail_init, allow_user = true, allow_codepage = true, fail_guid, fail_copy;
static struct GUID directory_guid = { .time_low = 1234 };

static int backend_destructor(struct emsabp_context *ctx) { destroyed++; return 0; }
struct emsabp_context *emsabp_init(struct loadparm_context *lp, TDB_CONTEXT *db)
{
    struct emsabp_context *ctx;
    if (fail_init) return NULL;
    ctx = talloc_zero(NULL, struct emsabp_context);
    if (ctx != NULL) { created++; talloc_set_destructor(ctx, backend_destructor); }
    return ctx;
}
bool emsabp_verify_user(struct dcesrv_call_state *call, struct emsabp_context *ctx)
{ return allow_user; }
bool emsabp_verify_codepage(struct emsabp_context *ctx, uint32_t codepage)
{ return allow_codepage; }
void emsabp_enable_debug(struct emsabp_context *ctx) { }
const struct GUID *samdb_ntds_objectGUID(struct ldb_context *db)
{ return fail_guid ? NULL : &directory_guid; }
void *__real__talloc_memdup(const void *ctx, const void *p, size_t size, const char *name);
void *__wrap__talloc_memdup(const void *ctx, const void *p, size_t size, const char *name);
void *__wrap__talloc_memdup(const void *ctx, const void *p, size_t size, const char *name)
{ return fail_copy ? NULL : __real__talloc_memdup(ctx, p, size, name); }

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    struct dcesrv_context *dce = talloc_zero(ctx, struct dcesrv_context);
    struct dcesrv_connection *conn = talloc_zero(ctx, struct dcesrv_connection);
    struct dcesrv_assoc_group *assoc = talloc_zero(ctx, struct dcesrv_assoc_group);
    struct dcesrv_assoc_group *other = talloc_zero(ctx, struct dcesrv_assoc_group);
    struct dcesrv_connection_context pres = {0};
    struct dcesrv_interface iface = {0}, wrong_iface = {0};
    struct dcesrv_auth auth = { .auth_finished = true, .auth_level = DCERPC_AUTH_LEVEL_PRIVACY };
    struct auth_session_info session = {0};
    struct dom_sid sids[] = {
        { .sid_rev_num = 1, .num_auths = 2, .id_auth = {0,0,0,0,0,5}, .sub_auths = {21,1000} },
        { .sid_rev_num = 1, .num_auths = 1, .id_auth = {0,0,0,0,0,5}, .sub_auths = {11} }
    };
    struct security_token token = { .num_sids = 2, .sids = sids };
    struct dcesrv_call_state call = {0};
    struct policy_handle wire = {0}, saved, empty = {0};
    struct STAT stat = { .CodePage = 1252 };
    struct NspiBind bind = { .in = { .pStat = &stat }, .out = { .handle = &wire } };
    struct NspiUnbind unbind = { .in = { .handle = &wire }, .out = { .handle = &wire } };
    struct dcesrv_handle *handle;
    struct emsabp_context *backend;
    uint32_t ids[] = { 100, 200, 300 }, row, last;
    struct PropertyTagArray_r mids = { .cValues = 3, .aulPropTag = ids };
    int32_t delta;
    struct NspiUpdateStat update = { .in = { .pStat = &stat, .plDelta = &delta }, .out = { .pStat = &stat } };

    CHECK(ctx && dce && conn && assoc && other);
    dce->lp_ctx = loadparm_init(dce);
    CHECK(dce->lp_ctx);
    conn->dce_ctx = dce; conn->assoc_group = assoc;
    pres.conn = conn; pres.iface = &iface;
    session.security_token = &token; auth.session_info = &session;
    call.conn = conn; call.context = &pres; call.auth_state = &auth;

    token.num_sids = 1;
    dcesrv_NspiBind(&call, ctx, &bind);
    CHECK(bind.out.result == MAPI_E_LOGON_FAILED && created == 0 && assoc->handles == NULL);
    CHECK(NT_STATUS_EQUAL(dcesrv_exchange_nsp_dispatch(&call, ctx, &bind, NULL), NT_STATUS_NET_WRITE_FAULT));
    CHECK(call.fault_code == DCERPC_FAULT_ACCESS_DENIED);
    token.num_sids = 2;
    bind.in.dwFlags = fAnonymousLogin;
    dcesrv_NspiBind(&call, ctx, &bind);
    CHECK(bind.out.result == MAPI_E_LOGON_FAILED && created == 0);
    bind.in.dwFlags = 0;
    bind.in.pStat = NULL;
    dcesrv_NspiBind(&call, ctx, &bind);
    CHECK(bind.out.result == MAPI_E_INVALID_PARAMETER && created == 0);
    bind.in.pStat = &stat; stat.CodePage = CP_UNICODE;
    dcesrv_NspiBind(&call, ctx, &bind);
    CHECK(bind.out.result == MAPI_E_NO_SUPPORT && created == 0);
    stat.CodePage = 1252; fail_init = true;
    dcesrv_NspiBind(&call, ctx, &bind);
    CHECK(bind.out.result == MAPI_E_FAILONEPROVIDER && created == 0);
    fail_init = false; allow_user = false;
    dcesrv_NspiBind(&call, ctx, &bind);
    CHECK(bind.out.result == MAPI_E_LOGON_FAILED && created == destroyed);
    allow_user = true; allow_codepage = false;
    dcesrv_NspiBind(&call, ctx, &bind);
    CHECK(bind.out.result == MAPI_E_UNKNOWN_CPID && created == destroyed);
    allow_codepage = true; fail_guid = true;
    dcesrv_NspiBind(&call, ctx, &bind);
    CHECK(bind.out.result == MAPI_E_FAILONEPROVIDER && created == destroyed);
    fail_guid = false; fail_copy = true;
    dcesrv_NspiBind(&call, ctx, &bind);
    CHECK(bind.out.result == MAPI_E_NOT_ENOUGH_RESOURCES && created == destroyed);
    fail_copy = false;
    CHECK(assoc->handles == NULL && GUID_all_zero(&wire.uuid));
    dcesrv_NspiBind(&call, ctx, &bind);
    CHECK(bind.out.result == MAPI_E_SUCCESS && created == destroyed + 1);
    CHECK(bind.out.mapiuid != &directory_guid && GUID_equal(bind.out.mapiuid, &directory_guid));
    handle = dcesrv_find_nsp_handle(&call, &wire);
    backend = dcesrv_find_emsabp_context(&call, &wire);
    CHECK(handle && backend && talloc_parent(backend) == handle);
    saved = wire;
    CHECK(dcesrv_find_nsp_handle(&call, &empty) == NULL && assoc->handles == handle);
    CHECK(dcesrv_find_nsp_handle(&call, NULL) == NULL && handle->next == NULL);
    wire.handle_type++;
    CHECK(dcesrv_find_nsp_handle(&call, &wire) == NULL);
    wire = saved; sids[0].sub_auths[1]++;
    CHECK(dcesrv_find_emsabp_context(&call, &wire) == NULL);
    dcesrv_NspiUnbind(&call, ctx, &unbind);
    CHECK(unbind.out.result == MAPI_E_INVALID_OBJECT && created == destroyed + 1);
    wire = saved; sids[0].sub_auths[1]--;
    auth.auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
    CHECK(dcesrv_find_nsp_handle(&call, &wire) == NULL);
    auth.auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
    pres.iface = &wrong_iface;
    CHECK(dcesrv_find_nsp_handle(&call, &wire) == NULL);
    pres.iface = &iface; conn->assoc_group = other;
    CHECK(dcesrv_find_nsp_handle(&call, &wire) == NULL);
    conn->assoc_group = assoc; token.num_sids = 1;
    dcesrv_NspiUnbind(&call, ctx, &unbind);
    CHECK(unbind.out.result == MAPI_E_LOGON_FAILED && created == destroyed + 1);
    token.num_sids = 2; wire = saved;
    dcesrv_NspiUnbind(&call, ctx, &unbind);
    CHECK(unbind.out.result == 1 && created == destroyed && assoc->handles == NULL);
    CHECK(GUID_all_zero(&wire.uuid));
    wire = saved; dcesrv_NspiUnbind(&call, ctx, &unbind);
    CHECK(unbind.out.result == MAPI_E_INVALID_OBJECT);
    dcesrv_NspiBind(&call, ctx, &bind);
    CHECK(bind.out.result == MAPI_E_SUCCESS);
    talloc_free(assoc);
    CHECK(created == destroyed);

    stat.CurrentRec = MID_CURRENT; stat.TotalRecs = 0; stat.NumPos = UINT32_MAX;
    position_in_table(&stat, &mids, &row, &last);
    CHECK(row == 0 && last == 2);
    stat.TotalRecs = UINT32_MAX;
    position_in_table(&stat, &mids, &row, &last);
    CHECK(row == 2); /* Multiplication must not wrap at 32 bits. */
    stat.CurrentRec = 999;
    position_in_table(&stat, &mids, &row, &last);
    CHECK(row == 0);
    mids.cValues = 0;
    position_in_table(&stat, &mids, &row, &last);
    CHECK(row == 0 && last == 0);
    mids.cValues = 3;
    CHECK(nspi_row_delta(2, INT32_MIN, 2) == 0);
    CHECK(nspi_row_delta(UINT32_MAX, INT32_MAX, UINT32_MAX) == UINT32_MAX);
    stat.CurrentRec = MID_BEGINNING_OF_TABLE; stat.NumPos = 0; stat.Delta = 1;
    dcesrv_do_NspiUpdateStat(&update, &mids);
    CHECK(update.out.result == MAPI_E_SUCCESS && stat.NumPos == 1 && delta == 1);
    stat.CurrentRec = MID_BEGINNING_OF_TABLE; stat.NumPos = UINT32_MAX; stat.Delta = INT32_MIN;
    dcesrv_do_NspiUpdateStat(&update, &mids);
    CHECK(update.out.result == MAPI_E_INVALID_PARAMETER && stat.NumPos == UINT32_MAX);
    talloc_free(ctx);
    puts("NSPI authorization, policy handles, cleanup and table bounds: OK");
    return 0;
}
