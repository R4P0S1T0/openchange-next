/* Actual NSPI backend lifecycle and user checks, with real LDB/TDB fixtures.
 * Only the Samba directory connection factory is substituted. */
#include "mapiproxy/servers/default/nspi/emsabp.c"
#include "mapiproxy/servers/default/nspi/emsabp_tdb.c"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "NSPI backend check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static bool fail_directory, fail_tdb, fail_store;
static unsigned opened, closed, directories, released, url_calls;
static struct dom_sid account_sids[] = {
    { .sid_rev_num = 1, .num_auths = 2, .id_auth = {0,0,0,0,0,5}, .sub_auths = {21,1000} },
    { .sid_rev_num = 1, .num_auths = 1, .id_auth = {0,0,0,0,0,5}, .sub_auths = {11} }
};
static struct security_token token = { .num_sids = 2, .sids = account_sids };
static char directory_path[] = "/tmp/openchange-nspi-XXXXXX";
static TDB_CONTEXT *shared;
const struct GUID *samdb_ntds_objectGUID(struct ldb_context *db) { return NULL; }

TDB_CONTEXT *__real_tdb_open(const char *, int, int, int, mode_t);
int __real_tdb_close(TDB_CONTEXT *);
int __real_tdb_store(TDB_CONTEXT *, TDB_DATA, TDB_DATA, int);
TDB_CONTEXT *__wrap_tdb_open(const char *, int, int, int, mode_t);
int __wrap_tdb_close(TDB_CONTEXT *);
int __wrap_tdb_store(TDB_CONTEXT *, TDB_DATA, TDB_DATA, int);
TDB_CONTEXT *__wrap_tdb_open(const char *name, int hash, int flags, int oflags, mode_t mode)
{
    TDB_CONTEXT *tdb;
    if (fail_tdb) return NULL;
    tdb = __real_tdb_open(name, hash, flags, oflags, mode);
    if (tdb) opened++;
    return tdb;
}
int __wrap_tdb_close(TDB_CONTEXT *tdb) { closed++; return __real_tdb_close(tdb); }
int __wrap_tdb_store(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA value, int flags)
{ return fail_store ? -1 : __real_tdb_store(tdb, key, value, flags); }
struct directory_marker { int unused; };
static int directory_destructor(struct directory_marker *marker) { released++; return 0; }
struct auth_session_info *system_session(struct loadparm_context *lp) { return NULL; }
struct ldb_context *samdb_connect(TALLOC_CTX *owner, struct tevent_context *ev,
    struct loadparm_context *lp, struct auth_session_info *session,
    const struct tsocket_address *remote, unsigned flags)
{
    struct ldb_context *db;
    struct ldb_dn *base;
    struct directory_marker *marker;
    if (fail_directory) return NULL;
    db = ldb_init(owner, ev);
    if (!db) return NULL;
    directories++;
    /* Observe release without replacing LDB's own destructor. */
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
TDB_CONTEXT *mapiproxy_server_emsabp_tdb_init(struct loadparm_context *lp) { return shared; }

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
    ret = ldb_add(db, msg);
    talloc_free(tmp);
    return ret;
}

static int search_boundaries(TALLOC_CTX *ctx, struct emsabp_context *backend)
{
    static const char * const entries[][3] = {
        {"literal", "/o=Org/ou=Site/cn=literal", "Alice (Ops)*"},
        {"general", "/o=Org/ou=Site/cn=general", "Alice General"},
        {"foreign", "/o=Other/ou=Site/cn=foreign", "Alice (Ops)*"},
        {"orgstar", "/o=Org*/ou=Site/cn=orgstar", "Scoped"},
        {"orgother", "/o=OrgA/ou=Site/cn=orgother", "Scoped"}
    };
    struct Restriction_r restriction = { .rt = RES_PROPERTY };
    struct PropertyValue_r value = { .ulPropTag = PidTagDisplayName };
    struct PropertyTagArray_r mids = {0};
    struct STAT state = { .SortType = SortTypeDisplayName };
    struct ldb_message *message;
    char *dn, *filter;
    const char *saved_org = backend->organization_name;
    TALLOC_CTX *query = talloc_new(ctx);
    CHECK(query);
    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        message = ldb_msg_new(ctx); CHECK(message);
        message->dn = ldb_dn_new_fmt(message, backend->samdb_ctx, "CN=%s,DC=test", entries[i][0]);
        CHECK(message->dn && ldb_msg_add_string(message, "objectClass", "user") == 0);
        CHECK(ldb_msg_add_string(message, "legacyExchangeDN", entries[i][1]) == 0);
        CHECK(ldb_msg_add_string(message, "displayName", entries[i][2]) == 0);
        if (i == 0) {
            CHECK(ldb_msg_add_string(message, "proxyAddresses", "SMTP:alice@example.test") == 0);
            CHECK(ldb_msg_add_string(message, "userPrincipalName", "alice@example.test") == 0);
        }
        CHECK(ldb_add(backend->samdb_ctx, message) == LDB_SUCCESS); talloc_free(message);
    }
    restriction.res.resProperty.ulPropTag = value.ulPropTag;
    restriction.res.resProperty.lpProp = &value;
    value.value.lpszW = "Alice (Ops)*";
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_SUCCESS && mids.cValues == 1);
    CHECK(talloc_parent(mids.aulPropTag) == query);
    CHECK(emsabp_tdb_fetch_dn_from_MId(query, backend->ttdb_ctx, mids.aulPropTag[0], &dn) == MAPI_E_SUCCESS);
    CHECK(!strcmp(dn, "CN=literal,DC=test"));
    value.value.lpszW = "*";
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_SUCCESS && mids.cValues == 1);
    value.value.lpszW = "Alice";
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 1) == MAPI_E_TABLE_TOO_BIG);
    CHECK(mids.cValues == 0 && mids.aulPropTag == NULL);
    value.value.lpszW = "Alice General"; fail_store = true;
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_CORRUPT_STORE);
    CHECK(mids.cValues == 0 && mids.aulPropTag == NULL); fail_store = false;
    value.value.lpszW = "*)(objectClass=*)";
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_NOT_FOUND);
    CHECK(mids.cValues == 0 && mids.aulPropTag == NULL);
    value.ulPropTag = restriction.res.resProperty.ulPropTag = PidTagEmailAddress;
    value.value.lpszW = entries[0][1];
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_SUCCESS && mids.cValues == 1);
    value.ulPropTag = restriction.res.resProperty.ulPropTag = PidTagDisplayName;
    value.value.lpszW = "Scoped"; backend->organization_name = "Org*";
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_SUCCESS && mids.cValues == 1);
    CHECK(emsabp_tdb_fetch_dn_from_MId(query, backend->ttdb_ctx, mids.aulPropTag[0], &dn) == MAPI_E_SUCCESS);
    CHECK(!strcmp(dn, "CN=orgstar,DC=test"));
    CHECK(emsabp_include_organization_restriction(query, backend, "(objectClass=user)", &filter) == MAPI_E_SUCCESS);
    CHECK(talloc_parent(filter) == query);
    backend->organization_name = saved_org;
    restriction.res.resProperty.lpProp = NULL;
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_INVALID_PARAMETER);
    restriction.res.resProperty.lpProp = &value;
    value.ulPropTag = PidTagObjectType;
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_INVALID_PARAMETER);
    restriction.res.resProperty.ulPropTag = PidTagObjectType; value.value.l = 0x41414141;
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_NO_SUPPORT);
    value.ulPropTag = restriction.res.resProperty.ulPropTag = PR_DISPLAY_NAME;
    value.value.lpszA = "Alice (Ops)*";
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_SUCCESS && mids.cValues == 1);
    value.ulPropTag = restriction.res.resProperty.ulPropTag = PidTagAnr;
    value.value.lpszW = "alice@example.test";
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_SUCCESS && mids.cValues == 1);
    {
        const char *address[] = {"SMTP:alice@example.test"};
        value.ulPropTag = restriction.res.resProperty.ulPropTag = PR_EMS_AB_PROXY_ADDRESSES;
        value.value.MVszA.cValues = 1; value.value.MVszA.lppszA = address;
        CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_SUCCESS && mids.cValues == 1);
        value.ulPropTag = restriction.res.resProperty.ulPropTag = PR_EMS_AB_PROXY_ADDRESSES_UNICODE;
        value.value.MVszW.cValues = 1; value.value.MVszW.lppszW = address;
        CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_SUCCESS && mids.cValues == 1);
    }
    value.ulPropTag = restriction.res.resProperty.ulPropTag = PR_EMS_AB_PROXY_ADDRESSES;
    value.value.MVszA.cValues = 0; value.value.MVszA.lppszA = NULL;
    CHECK(emsabp_search(query, backend, &mids, &restriction, &state, 0) == MAPI_E_INVALID_PARAMETER);
    {
        TALLOC_CTX *limited = talloc_new(ctx);
        CHECK(limited && talloc_set_memlimit(limited, 1) == 0);
        CHECK(emsabp_search(limited, backend, &mids, NULL, &state, 0) == MAPI_E_NOT_ENOUGH_MEMORY);
        CHECK(mids.cValues == 0 && mids.aulPropTag == NULL);
        talloc_free(limited);
    }
    talloc_free(query);
    return 0;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    struct loadparm_context *lp = loadparm_init(ctx);
    struct emsabp_context *first, *second;
    struct dcesrv_call_state call = {0};
    struct dcesrv_auth auth = { .auth_finished = true };
    struct auth_user_info user = { .account_name = "test" };
    struct auth_session_info session = { .info = &user, .security_token = &token };
    unsigned before;
    int fd = mkstemp(directory_path);
    CHECK(ctx && lp && fd >= 0);
    close(fd); unlink(directory_path);
    CHECK(emsabp_init(NULL, NULL) == NULL);
    fail_directory = true;
    CHECK(emsabp_init(lp, NULL) == NULL && opened == 0);
    fail_directory = false; fail_tdb = true;
    CHECK(emsabp_init(lp, NULL) == NULL && opened == 0);
    fail_tdb = false; fail_store = true;
    CHECK(emsabp_init(lp, NULL) == NULL && opened == closed);
    fail_store = false;
    first = emsabp_init(lp, NULL); second = emsabp_init(lp, NULL);
    CHECK(first && second && first != second && first->samdb_ctx != second->samdb_ctx);
    CHECK(first->mem_ctx == first && talloc_parent(first->samdb_ctx) == first);
    CHECK(first->ttdb_ctx != second->ttdb_ctx && opened == closed + 2);
    CHECK(add_user(first->samdb_ctx, "CN=test,DC=test", "test", "/o=Org/ou=Site/cn=test", "0") == LDB_SUCCESS);
    CHECK(add_user(first->samdb_ctx, "CN=disabled,DC=test", "disabled", "/o=Org/ou=Site", "2") == LDB_SUCCESS);
    CHECK(add_user(first->samdb_ctx, "CN=missing,DC=test", "missing", NULL, "0") == LDB_SUCCESS);
    CHECK(add_user(first->samdb_ctx, "CN=bad,DC=test", "bad", "/ou=Site/o=Org", "0") == LDB_SUCCESS);
    CHECK(add_user(first->samdb_ctx, "CN=empty,DC=test", "empty", "/o=/ou=Site", "0") == LDB_SUCCESS);
    CHECK(add_user(first->samdb_ctx, "CN=noattribute,DC=test", "noattribute", "/o=Org/ou=Site", NULL) == LDB_SUCCESS);
    auth.session_info = &session; call.auth_state = &auth;
    CHECK(emsabp_verify_user(&call, first));
    account_sids[0].sub_auths[1]++;
    CHECK(!emsabp_verify_user(&call, second));
    account_sids[0].sub_auths[1]--;
    CHECK(strcmp(first->account_name, "test") == 0 && strcmp(first->organization_name, "Org") == 0);
    CHECK(search_boundaries(ctx, first) == 0);
    CHECK(second->account_name == NULL && second->organization_name == NULL);
    user.account_name = "disabled"; CHECK(!emsabp_verify_user(&call, second));
    user.account_name = "missing"; CHECK(!emsabp_verify_user(&call, second));
    user.account_name = "bad"; CHECK(!emsabp_verify_user(&call, second));
    user.account_name = "empty"; CHECK(!emsabp_verify_user(&call, second));
    user.account_name = "noattribute"; CHECK(!emsabp_verify_user(&call, second));
    user.account_name = "*"; CHECK(!emsabp_verify_user(&call, second));
    user.account_name = "test)(sAMAccountName=*)"; CHECK(!emsabp_verify_user(&call, second));
    user.account_name = NULL; CHECK(!emsabp_verify_user(&call, second));
    CHECK(second->account_name == NULL);
    CHECK(emsabp_destructor(first)); CHECK(emsabp_destructor(second));
    CHECK(opened == closed);
    CHECK(lpcfg_set_cmdline(lp, "dcerpc_mapiproxy:samdb_url", "test-url"));
    first = emsabp_init(lp, NULL);
    CHECK(first && url_calls == 1);
    talloc_free(first); CHECK(opened == closed);
    fail_directory = true;
    CHECK(emsabp_init(lp, NULL) == NULL && url_calls == 2);
    fail_directory = false;
    shared = tdb_open(NULL, 0, TDB_INTERNAL, O_RDWR | O_CREAT, 0600);
    CHECK(shared);
    before = closed; fail_store = true;
    CHECK(emsabp_tdb_init(ctx, lp) == NULL && closed == before);
    fail_store = false;
    CHECK(emsabp_tdb_init(ctx, lp) == shared);
    CHECK(emsabp_tdb_init(ctx, lp) == shared);
    tdb_close(shared); CHECK(opened == closed);
    CHECK(directories == released);
    talloc_free(ctx); unlink(directory_path);
    puts("NSPI backend isolation, cleanup, user lookup and shared TDB ownership: OK");
    return 0;
}
