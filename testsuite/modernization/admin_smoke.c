/* Actual administration code; RPC, LDAP connection and AES setup are substituted.
 * No accounts are created or removed by this harness. */
#include "libmapiadmin/mapiadmin_user.c"
#include "libmapiadmin/mapiadmin.c"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "Administration check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

enum fail_stage { FAIL_NONE, FAIL_PIPE, FAIL_CONNECT, FAIL_DOMAIN, FAIL_OPEN_DOMAIN,
    FAIL_EXISTS, FAIL_CREATE, FAIL_POLICY, FAIL_KEY, FAIL_AES, FAIL_PASSWORD, FAIL_ATTRIBUTES,
    FAIL_LOOKUP_EMPTY, FAIL_LOOKUP_DENIED, FAIL_OPEN_USER, FAIL_DELETE };
static enum fail_stage failure;
static unsigned pipes, closed_pipes, creates, passwords, attributes, deletes, aes_calls, ldap_calls;
static bool literal_fields;
struct pipe_marker { int unused; };
static int pipe_destructor(struct pipe_marker *marker) { closed_pipes++; return 0; }

NTSTATUS dcerpc_pipe_connect(TALLOC_CTX *ctx, struct dcerpc_pipe **pipe, const char *binding,
    const struct ndr_interface_table *table, struct cli_credentials *creds,
    struct tevent_context *ev, struct loadparm_context *lp)
{
    struct pipe_marker *marker;
    if (failure == FAIL_PIPE) return NT_STATUS_ACCESS_DENIED;
    *pipe = talloc_zero(ctx, struct dcerpc_pipe);
    if (!*pipe) return NT_STATUS_NO_MEMORY;
    marker = talloc_zero(*pipe, struct pipe_marker);
    if (!marker) return NT_STATUS_NO_MEMORY;
    talloc_set_destructor(marker, pipe_destructor); pipes++;
    return NT_STATUS_OK;
}
NTSTATUS dcerpc_binding_handle_transport_session_key(struct dcerpc_binding_handle *h,
    TALLOC_CTX *ctx, DATA_BLOB *key)
{
    uint8_t bytes[16] = {1};
    *key = data_blob_talloc(ctx, bytes, sizeof(bytes));
    return failure == FAIL_KEY ? NT_STATUS_ACCESS_DENIED : NT_STATUS_OK;
}
NTSTATUS init_samr_CryptPasswordAES(TALLOC_CTX *ctx, const char *password, DATA_BLOB *salt,
    DATA_BLOB *key, struct samr_EncryptedPasswordAES *encrypted)
{
    aes_calls++;
    if (!password || key->length != 16 || salt->length != 16) abort();
    encrypted->cipher = talloc_zero_array(ctx, uint8_t, 32);
    encrypted->cipher_len = 32;
    return failure == FAIL_AES ? NT_STATUS_NOT_SUPPORTED : NT_STATUS_OK;
}
struct dom_sid *dom_sid_add_rid(TALLOC_CTX *ctx, const struct dom_sid *domain, uint32_t rid)
{ return talloc_memdup(ctx, domain, sizeof(*domain)); }
char *ldap_encode_ndr_dom_sid(TALLOC_CTX *ctx, const struct dom_sid *sid) { return NULL; }
struct ldb_dn *samdb_search_dn(struct ldb_context *db, TALLOC_CTX *ctx, struct ldb_dn *base,
    const char *format, ...) { return NULL; }
struct ldb_context *ldb_wrap_connect(TALLOC_CTX *ctx, struct tevent_context *ev,
    struct loadparm_context *lp, const char *url, struct auth_session_info *session,
    struct cli_credentials *credentials, unsigned flags)
{ ldap_calls++; return NULL; }

NTSTATUS dcerpc_binding_handle_call(struct dcerpc_binding_handle *h, const struct GUID *object,
    const struct ndr_interface_table *table, uint32_t opnum, TALLOC_CTX *ctx, void *request)
{
    static const struct dom_sid domain = { .sid_rev_num = 1, .num_auths = 1,
        .id_auth = {0,0,0,0,0,5}, .sub_auths = {21} };
    switch (opnum) {
    case NDR_SAMR_CONNECT: {
        struct samr_Connect *r = request;
        r->out.result = failure == FAIL_CONNECT ? NT_STATUS_ACCESS_DENIED : NT_STATUS_OK;
        break;
    }
    case NDR_SAMR_LOOKUPDOMAIN: {
        struct samr_LookupDomain *r = request;
        *r->out.sid = talloc_memdup(ctx, &domain, sizeof(domain));
        r->out.result = failure == FAIL_DOMAIN ? NT_STATUS_ACCESS_DENIED : NT_STATUS_OK;
        break;
    }
    case NDR_SAMR_OPENDOMAIN: {
        struct samr_OpenDomain *r = request;
        r->out.domain_handle->uuid.time_low = 2;
        r->out.result = failure == FAIL_OPEN_DOMAIN ? NT_STATUS_ACCESS_DENIED : NT_STATUS_OK;
        break;
    }
    case NDR_SAMR_CREATEUSER2: {
        struct samr_CreateUser2 *r = request;
        creates++;
        if (failure == FAIL_CREATE) return NT_STATUS_ACCESS_DENIED;
        r->out.user_handle->uuid.time_low = 3; *r->out.rid = 1001;
        r->out.result = failure == FAIL_EXISTS ? NT_STATUS_USER_EXISTS : NT_STATUS_OK;
        break;
    }
    case NDR_SAMR_GETUSERPWINFO: {
        struct samr_GetUserPwInfo *r = request;
        r->out.info->min_password_length = 8;
        r->out.result = failure == FAIL_POLICY ? NT_STATUS_ACCESS_DENIED : NT_STATUS_OK;
        break;
    }
    case NDR_SAMR_SETUSERINFO: {
        struct samr_SetUserInfo *r = request;
        if (r->in.level == 31) {
            passwords++;
            if (r->in.info->info31.password.cipher_len == 0) abort();
            r->out.result = failure == FAIL_PASSWORD ? NT_STATUS_PASSWORD_RESTRICTION : NT_STATUS_OK;
        } else if (r->in.level == 21) {
            attributes++;
            literal_fields = strcmp(r->in.info->info21.comment.string, "%n %s") == 0 &&
                strcmp(r->in.info->info21.full_name.string, "Full %x") == 0 &&
                strcmp(r->in.info->info21.description.string, "100% literal") == 0 &&
                !(r->in.info->info21.acct_flags & ACB_PWNOEXP);
            r->out.result = failure == FAIL_ATTRIBUTES ? NT_STATUS_ACCESS_DENIED : NT_STATUS_OK;
        } else abort(); /* Never fall back to a legacy password cipher. */
        break;
    }
    case NDR_SAMR_LOOKUPNAMES: {
        struct samr_LookupNames *r = request;
        r->out.rids->count = failure == FAIL_LOOKUP_EMPTY ? 0 : 1;
        r->out.rids->ids = talloc_array(ctx, uint32_t, 1);
        if (!r->out.rids->ids) return NT_STATUS_NO_MEMORY;
        r->out.rids->ids[0] = 1001;
        r->out.result = failure == FAIL_LOOKUP_DENIED ? NT_STATUS_ACCESS_DENIED : NT_STATUS_OK;
        break;
    }
    case NDR_SAMR_OPENUSER: {
        struct samr_OpenUser *r = request;
        r->out.user_handle->uuid.time_low = 3;
        r->out.result = failure == FAIL_OPEN_USER ? NT_STATUS_ACCESS_DENIED : NT_STATUS_OK;
        break;
    }
    case NDR_SAMR_DELETEUSER: {
        struct samr_DeleteUser *r = request;
        if (r->in.user_handle->uuid.time_low != 3) abort();
        deletes++;
        r->out.result = failure == FAIL_DELETE ? NT_STATUS_ACCESS_DENIED : NT_STATUS_OK;
        break;
    }
    default: abort();
    }
    return NT_STATUS_OK;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL), *frame;
    struct mapi_context mapi = {0};
    struct mapi_profile profile = { .server = "test.invalid", .domain = "TEST" };
    struct mapi_session *session = talloc_zero(ctx, struct mapi_session);
    struct mapiadmin_ctx *admin;
    enum fail_stage stage;
    enum MAPISTATUS result;
    unsigned deleted_before, created_before, ldap_before;
    CHECK(ctx && session);
    CHECK(mapiadmin_user_add(NULL) == MAPI_E_NOT_INITIALIZED && GetLastError() == MAPI_E_NOT_INITIALIZED);
    session->mapi_ctx = &mapi; session->profile = &profile;
    mapi.lp_ctx = loadparm_init(ctx); profile.credentials = cli_credentials_init(ctx);
    CHECK(mapi.lp_ctx && profile.credentials);
    for (stage = FAIL_PIPE; stage <= FAIL_ATTRIBUTES; stage++) {
        admin = mapiadmin_init(session); CHECK(admin);
        admin->username = "test"; admin->password = "test-only-password";
        admin->comment = "%n %s"; admin->fullname = "Full %x"; admin->description = "100% literal";
        failure = stage; deleted_before = deletes; created_before = creates; ldap_before = ldap_calls;
        result = mapiadmin_user_add(admin);
        CHECK(result != MAPI_E_SUCCESS);
        CHECK(ldap_calls == ldap_before);
        if (stage <= FAIL_OPEN_DOMAIN) {
            CHECK(admin->user_ctx == NULL && admin->handle == NULL && creates == created_before);
            CHECK(deletes == deleted_before);
        } else if (stage == FAIL_EXISTS || stage == FAIL_CREATE) {
            CHECK(deletes == deleted_before && creates == created_before + 1);
            if (stage == FAIL_EXISTS) CHECK(result == MAPI_E_COLLISION);
        } else CHECK(deletes == deleted_before + 1);
        CHECK(mapiadmin_release(admin) == MAPI_E_SUCCESS && pipes == closed_pipes);
    }
    failure = FAIL_NONE;
    admin = mapiadmin_init(session); CHECK(admin); admin->username = "test";
    admin->comment = "%n %s"; admin->fullname = "Full %x"; admin->description = "100% literal";
    frame = talloc_new(ctx); CHECK(frame);
    CHECK(mapiadmin_samr_connect(admin, frame) == MAPI_E_SUCCESS);
    talloc_free(frame);
    CHECK(admin->user_ctx && talloc_parent(admin->user_ctx) == admin && admin->handle->uuid.time_low == 2);
    deleted_before = deletes; ldap_before = ldap_calls;
    CHECK(mapiadmin_user_add(admin) != MAPI_E_SUCCESS); /* Substitute LDAP failure after account setup. */
    CHECK(literal_fields && admin->password && strlen(admin->password) >= 32);
    CHECK(deletes == deleted_before + 1 && ldap_calls == ldap_before + 1);
    failure = FAIL_LOOKUP_EMPTY; deleted_before = deletes;
    CHECK(mapiadmin_user_del(admin) == MAPI_E_NOT_FOUND && deletes == deleted_before);
    failure = FAIL_LOOKUP_DENIED;
    CHECK(mapiadmin_user_del(admin) == MAPI_E_NOT_FOUND && deletes == deleted_before);
    failure = FAIL_OPEN_USER;
    CHECK(mapiadmin_user_del(admin) == MAPI_E_NOT_FOUND && deletes == deleted_before);
    failure = FAIL_DELETE;
    CHECK(mapiadmin_user_del(admin) == MAPI_E_CALL_FAILED && deletes == deleted_before + 1);
    CHECK(mapiadmin_release(admin) == MAPI_E_SUCCESS && pipes == closed_pipes);
    CHECK(aes_calls && passwords && attributes);
    talloc_free(ctx);
    puts("Administration server errors, existing-user preservation, literal fields and exact-handle rollback: OK");
    return 0;
}
