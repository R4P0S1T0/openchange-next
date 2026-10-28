/* Real EMSMDB provider, MAPI handles and LDB/TDB lifecycle.
 * Samba directory connection, storage factory and mailbox replica are local substitutes. */
/* The source harness and module intentionally coexist; give its GUID export a private name. */
#define MagicGUIDp smoke_MagicGUIDp
#include "mapiproxy/servers/default/emsmdb/emsmdbp.c"
#include "mapiproxy/libmapiproxy/mapi_handles.c"
#include "mapiproxy/servers/default/emsmdb/oxcstor.c"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "EMSMDB backend check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

enum fail_stage { FAIL_NONE, FAIL_DIRECTORY, FAIL_STORE, FAIL_INFO, FAIL_HANDLES, FAIL_REPLICA, FAIL_OBJECT, FAIL_HANDLE_STORE, FAIL_PROVISION };
static enum fail_stage failure;
static unsigned provisions;
static unsigned stores, store_releases, directories, directory_releases, opened, closed, url_calls;
static struct dom_sid account_sids[] = {
    { .sid_rev_num = 1, .num_auths = 2, .id_auth = {0,0,0,0,0,5}, .sub_auths = {21,1000} },
    { .sid_rev_num = 1, .num_auths = 1, .id_auth = {0,0,0,0,0,5}, .sub_auths = {11} }
};
static struct security_token token = { .num_sids = 2, .sids = account_sids };
static char directory_path[] = "/tmp/openchange-emsmdb-XXXXXX";
struct directory_marker { int unused; };
int __real_tdb_store(TDB_CONTEXT *, TDB_DATA, TDB_DATA, int);
int __wrap_tdb_store(TDB_CONTEXT *, TDB_DATA, TDB_DATA, int);
int __wrap_tdb_store(TDB_CONTEXT *db, TDB_DATA key, TDB_DATA value, int flags)
{ return failure == FAIL_HANDLE_STORE ? -1 : __real_tdb_store(db, key, value, flags); }

static int directory_destructor(struct directory_marker *marker) { directory_releases++; return 0; }

TDB_CONTEXT *__real_tdb_open(const char *, int, int, int, mode_t);
int __real_tdb_close(TDB_CONTEXT *);
TDB_CONTEXT *__wrap_tdb_open(const char *, int, int, int, mode_t);
int __wrap_tdb_close(TDB_CONTEXT *);
TDB_CONTEXT *__wrap_tdb_open(const char *name, int hash, int flags, int oflags, mode_t mode)
{
    TDB_CONTEXT *tdb;
    if (failure == FAIL_HANDLES) return NULL;
    tdb = __real_tdb_open(name, hash, flags, oflags, mode);
    if (tdb) opened++;
    return tdb;
}
int __wrap_tdb_close(TDB_CONTEXT *tdb) { closed++; return __real_tdb_close(tdb); }
struct auth_session_info *system_session(struct loadparm_context *lp) { return NULL; }
struct ldb_context *samdb_connect(TALLOC_CTX *owner, struct tevent_context *ev,
    struct loadparm_context *lp, struct auth_session_info *session,
    const struct tsocket_address *remote, unsigned flags)
{
    struct ldb_context *db;
    struct ldb_dn *base;
    struct directory_marker *marker;
    if (failure == FAIL_DIRECTORY) return NULL;
    db = ldb_init(owner, ev);
    if (!db) return NULL;
    directories++;
    marker = talloc_zero(db, struct directory_marker);
    if (!marker) { talloc_free(db); return NULL; }
    talloc_set_destructor(marker, directory_destructor);
    if (ldb_connect(db, directory_path, 0, NULL) != LDB_SUCCESS) { talloc_free(db); return NULL; }
    base = ldb_dn_new(db, db, "DC=test");
    if (!base || ldb_set_opaque(db, "defaultNamingContext", base) != LDB_SUCCESS) {
        talloc_free(db); return NULL;
    }
    return db;
}
int samdb_connect_url(TALLOC_CTX *owner, struct tevent_context *ev,
    struct loadparm_context *lp, struct auth_session_info *session, unsigned flags,
    const char *url, const struct tsocket_address *remote, struct ldb_context **db, char **error)
{
    url_calls++; *error = NULL;
    *db = samdb_connect(owner, ev, lp, session, remote, flags);
    return *db ? LDB_SUCCESS : LDB_ERR_OPERATIONS_ERROR;
}
struct mapistore_context *mapistore_init(TALLOC_CTX *ctx, struct loadparm_context *lp, const char *path)
{
    struct mapistore_context *store;
    if (failure == FAIL_STORE) return NULL;
    store = talloc_zero(ctx, struct mapistore_context);
    if (store) stores++;
    return store;
}
enum mapistore_error mapistore_release(struct mapistore_context *store)
{ store_releases++; return MAPISTORE_SUCCESS; }
enum mapistore_error mapistore_set_connection_info(struct mapistore_context *store,
    struct ldb_context *db, struct openchangedb_context *oc, const char *user)
{
    if (failure == FAIL_INFO) return MAPISTORE_ERROR;
    store->conn_info = talloc_zero(store, struct mapistore_connection_info);
    return store->conn_info ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
}
enum MAPISTATUS openchangedb_get_MailboxReplica(struct openchangedb_context *oc,
    const char *user, uint16_t *id, struct GUID *guid)
{
    *id = 1; *guid = (struct GUID){ .time_low = 42 };
    return failure == FAIL_REPLICA ? MAPI_E_NOT_FOUND : MAPI_E_SUCCESS;
}

enum MAPISTATUS emsmdbp_mailbox_provision(struct emsmdbp_context *ctx, const char *user)
{ provisions++; return failure == FAIL_PROVISION ? MAPI_E_DISK_ERROR : MAPI_E_SUCCESS; }
enum MAPISTATUS emsmdbp_mailbox_provision_public_freebusy(struct emsmdbp_context *ctx, const char *dn)
{ return MAPI_E_SUCCESS; }
enum MAPISTATUS openchangedb_get_SystemFolderID(struct openchangedb_context *oc,
    const char *user, uint32_t folder, uint64_t *id)
{ *id = folder; return MAPI_E_SUCCESS; }
enum MAPISTATUS openchangedb_get_MailboxGuid(struct openchangedb_context *oc, const char *user, struct GUID *guid)
{ *guid = (struct GUID){ .time_low = 42 }; return MAPI_E_SUCCESS; }
struct emsmdbp_object *emsmdbp_object_mailbox_init(TALLOC_CTX *ctx, struct emsmdbp_context *backend,
    const char *dn, bool private_store)
{ return failure == FAIL_OBJECT ? NULL : talloc_zero(ctx, struct emsmdbp_object); }

static int mailbox_logon(TALLOC_CTX *ctx, struct emsmdbp_context *backend)
{
    struct EcDoRpc_MAPI_REQ request = { .opnum = op_MAPI_Logon };
    struct EcDoRpc_MAPI_REPL reply = {0};
    uint32_t handle = UINT32_MAX;
    uint16_t size = 0;
    unsigned before = provisions;
    request.u.mapi_Logon.LogonFlags = LogonPrivate;
    request.u.mapi_Logon.EssDN = "/o=Org/cn=other";
    CHECK(EcDoRpc_RopLogon(ctx, backend, &request, &reply, &handle, &size) == MAPI_E_NO_ACCESS);
    CHECK(reply.error_code == MAPI_E_NO_ACCESS && size == 6 && provisions == before);
    request.u.mapi_Logon.EssDN = "*"; size = 0;
    CHECK(EcDoRpc_RopLogon(ctx, backend, &request, &reply, &handle, &size) == ecUnknownUser);
    CHECK(provisions == before && backend->handles_ctx->handles == NULL && handle == UINT32_MAX);
    request.u.mapi_Logon.EssDN = "/o=Org/cn=test";
    failure = FAIL_PROVISION; size = 0;
    CHECK(EcDoRpc_RopLogon(ctx, backend, &request, &reply, &handle, &size) == MAPI_E_DISK_ERROR);
    CHECK(reply.error_code == MAPI_E_DISK_ERROR && backend->handles_ctx->handles == NULL);
    failure = FAIL_HANDLE_STORE; size = 0;
    CHECK(EcDoRpc_RopLogon(ctx, backend, &request, &reply, &handle, &size) == MAPI_E_CORRUPT_STORE);
    CHECK(reply.error_code == MAPI_E_CORRUPT_STORE && size == 6 && backend->handles_ctx->handles == NULL);
    failure = FAIL_OBJECT; size = 0;
    CHECK(EcDoRpc_RopLogon(ctx, backend, &request, &reply, &handle, &size) == MAPI_E_NOT_ENOUGH_RESOURCES);
    CHECK(reply.error_code == MAPI_E_NOT_ENOUGH_RESOURCES && size == 6 && backend->handles_ctx->handles == NULL);
    failure = FAIL_NONE; size = 0;
    CHECK(EcDoRpc_RopLogon(ctx, backend, &request, &reply, &handle, &size) == MAPI_E_SUCCESS);
    CHECK(reply.error_code == MAPI_E_SUCCESS && handle != UINT32_MAX && backend->handles_ctx->handles != NULL);
    CHECK(mapi_handles_delete(backend->handles_ctx, handle) == MAPI_E_SUCCESS);
    return 0;
}

static int add_user(struct ldb_context *db, const char *dn, const char *name,
    const char *exdn, const char *enabled)
{
    TALLOC_CTX *tmp = talloc_new(db);
    struct ldb_message *msg = ldb_msg_new(tmp);
    int ret;
    uint8_t sid[] = {1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xe8, 3, 0, 0};
    struct ldb_val val = { .data = sid, .length = sizeof(sid) };
    if (!msg) return -1;
    msg->dn = ldb_dn_new(msg, db, dn);
    if (!msg->dn || ldb_msg_add_string(msg, "objectClass", "user") ||
        ldb_msg_add_string(msg, "sAMAccountName", name) ||
        (exdn && ldb_msg_add_string(msg, "legacyExchangeDN", exdn)) ||
        (enabled && ldb_msg_add_string(msg, "msExchUserAccountControl", enabled))) {
        talloc_free(tmp); return -1;
    }
    if (ldb_msg_add_value(msg, "objectSid", &val, NULL) != 0) { talloc_free(tmp); return -1; }
    ret = ldb_add(db, msg); talloc_free(tmp); return ret;
}

static int organization_names(TALLOC_CTX *ctx, struct emsmdbp_context *backend)
{
    static const char * const invalid[] = {
        "/ou=Group/o=Org/cn=User", "/o=/ou=Group/cn=User",
        "/o=Org/ou=/cn=User", "/o=Org/cn=User/ou=Group", "/o=Org/ou=Group"
    };
    char *saved = backend->szUserDN, *organization, *group;
    struct ldb_context *db = backend->samdb_ctx;
    struct ldb_dn *base = ldb_dn_new(db, db, "CN=Configuration,DC=test"), *result;
    struct ldb_message *message;
    TALLOC_CTX *limited;
    backend->szUserDN = "/o=Org (Ops)*/ou=Group/cn=Recipients/cn=test";
    CHECK(emsmdbp_get_org_dn(backend, &result) == MAPI_E_NOT_FOUND && result == NULL);
    CHECK(base && ldb_set_opaque(db, "configurationNamingContext", base) == LDB_SUCCESS);
    CHECK(emsmdbp_fetch_organizational_units(ctx, backend, &organization, &group) == MAPI_E_SUCCESS);
    CHECK(!strcmp(organization, "Org (Ops)*") && !strcmp(group, "Group"));
    talloc_free(organization); talloc_free(group);
    CHECK(emsmdbp_get_org_dn(backend, &result) == MAPI_E_NOT_FOUND && result == NULL);
    message = ldb_msg_new(ctx); CHECK(message);
    message->dn = ldb_dn_new(message, db, "CN=org,CN=Configuration,DC=test");
    CHECK(message->dn && ldb_msg_add_string(message, "objectClass", "msExchOrganizationContainer") == 0);
    CHECK(ldb_msg_add_string(message, "cn", "Org (Ops)*") == 0 && ldb_add(db, message) == LDB_SUCCESS);
    CHECK(emsmdbp_get_org_dn(backend, &result) == MAPI_E_SUCCESS);
    CHECK(ldb_dn_compare(result, message->dn) == 0 && talloc_parent(result) == backend); talloc_free(result);
    message->dn = ldb_dn_new(message, db, "CN=duplicate,CN=Configuration,DC=test");
    CHECK(message->dn && ldb_add(db, message) == LDB_SUCCESS);
    CHECK(emsmdbp_get_org_dn(backend, &result) == MAPI_E_NOT_FOUND && result == NULL);
    talloc_free(message);
    limited = talloc_new(ctx); CHECK(limited && talloc_set_memlimit(limited, 1) == 0);
    CHECK(emsmdbp_fetch_organizational_units(limited, backend, &organization, &group) == MAPI_E_NOT_ENOUGH_MEMORY);
    CHECK(organization == NULL && group == NULL); talloc_free(limited);
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        backend->szUserDN = discard_const(invalid[i]);
        CHECK(emsmdbp_fetch_organizational_units(ctx, backend, &organization, &group) == MAPI_E_BAD_VALUE);
        CHECK(organization == NULL && group == NULL);
    }
    backend->szUserDN = saved;
    return 0;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL), *owner;
    struct loadparm_context *lp = loadparm_init(ctx);
    struct emsmdbp_context *first, *second;
    struct dcesrv_call_state call = {0};
    struct dcesrv_auth auth = { .auth_finished = true };
    struct auth_user_info user = { .account_name = "test" };
    struct auth_session_info session = { .info = &user, .security_token = &token };
    struct ldb_message *msg;
    struct mapi_handles_context *handles;
    enum fail_stage stage;
    int fd = mkstemp(directory_path);
    CHECK(ctx && lp && fd >= 0);
    close(fd); unlink(directory_path);
    CHECK(emsmdbp_init(NULL, "test", NULL) == NULL);
    CHECK(emsmdbp_init(lp, NULL, NULL) == NULL);
    for (stage = FAIL_DIRECTORY; stage <= FAIL_HANDLES; stage++) {
        failure = stage;
        CHECK(emsmdbp_init(lp, "test", NULL) == NULL);
        CHECK(stores == store_releases && directories == directory_releases && opened == closed);
    }
    failure = FAIL_NONE;
    first = emsmdbp_init(lp, "test", NULL); second = emsmdbp_init(lp, "test", NULL);
    CHECK(first && second && first->samdb_ctx != second->samdb_ctx);
    CHECK(organization_names(ctx, first) == 0);
    CHECK(first->mem_ctx == first && talloc_parent(first->samdb_ctx) == first);
    CHECK(add_user(first->samdb_ctx, "CN=test,DC=test", "test", "/o=Org/cn=test", "0") == LDB_SUCCESS);
    CHECK(add_user(first->samdb_ctx, "CN=other,DC=test", "other", "/o=Org/cn=other", "0") == LDB_SUCCESS);
    CHECK(add_user(first->samdb_ctx, "CN=disabled,DC=test", "disabled", "/o=Org/cn=disabled", "2") == LDB_SUCCESS);
    CHECK(add_user(first->samdb_ctx, "CN=unknown,DC=test", "unknown", "/o=Org/cn=unknown", "4") == LDB_SUCCESS);
    CHECK(add_user(first->samdb_ctx, "CN=missing,DC=test", "missing", "/o=Org/cn=missing", NULL) == LDB_SUCCESS);
    auth.session_info = &session; call.auth_state = &auth;
    CHECK(emsmdbp_verify_user(&call, first));
    account_sids[0].sub_auths[1]++;
    CHECK(!emsmdbp_verify_user(&call, second));
    CHECK(!emsmdbp_verify_userdn(&call, second, "/o=Org/cn=test", &msg));
    account_sids[0].sub_auths[1]--;
    CHECK(strcmp(first->username, "test") == 0 && first->mstore_ctx->conn_info->repl_id == 1);
    CHECK(emsmdbp_verify_userdn(&call, first, "/o=Org/cn=test", &msg) && msg);
    CHECK(mailbox_logon(ctx, first) == 0);
    CHECK(!emsmdbp_verify_userdn(&call, first, "/o=Org/cn=other", &msg) && msg == NULL);
    user.account_name = "disabled"; CHECK(!emsmdbp_verify_user(&call, second));
    CHECK(!emsmdbp_verify_userdn(&call, second, "/o=Org/cn=disabled", &msg));
    user.account_name = "unknown"; CHECK(!emsmdbp_verify_user(&call, second));
    CHECK(!emsmdbp_verify_userdn(&call, second, "/o=Org/cn=unknown", &msg));
    user.account_name = "missing"; CHECK(!emsmdbp_verify_user(&call, second));
    user.account_name = "*"; CHECK(!emsmdbp_verify_user(&call, second));
    CHECK(!emsmdbp_verify_userdn(&call, second, "*", &msg));
    user.account_name = NULL; CHECK(!emsmdbp_verify_user(&call, second));
    user.account_name = "test"; failure = FAIL_REPLICA;
    CHECK(!emsmdbp_verify_user(&call, second));
    failure = FAIL_NONE;
    CHECK(add_user(first->samdb_ctx, "CN=duplicate,DC=test", "test", "/o=Org/cn=test", "0") == LDB_SUCCESS);
    CHECK(!emsmdbp_verify_user(&call, second));
    CHECK(!emsmdbp_verify_userdn(&call, second, "/o=Org/cn=test", &msg));
    CHECK(emsmdbp_destructor(first) && emsmdbp_destructor(second));
    CHECK(opened == closed && stores == store_releases && directories == directory_releases);
    CHECK(lpcfg_set_cmdline(lp, "dcerpc_mapiproxy:samdb_url", "test-url"));
    first = emsmdbp_init(lp, "test", NULL); CHECK(first && url_calls == 1);
    talloc_free(first);
    owner = talloc_new(ctx); handles = mapi_handles_init(owner); CHECK(handles);
    CHECK(mapi_handles_release(handles) == MAPI_E_SUCCESS);
    talloc_free(owner); CHECK(opened == closed);
    CHECK(stores == store_releases && directories == directory_releases);
    talloc_free(ctx); unlink(directory_path);
    puts("EMSMDB provider ownership, failed setup, account checks and MAPI handle cleanup: OK");
    return 0;
}
