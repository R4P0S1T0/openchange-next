/* oc_emsmdb C API with the real ROP execution core from liboc_emsmdb.
 * emsmdbp_init is substituted only where a session is needed without SamDB. */
#include "mapiproxy/servers/default/emsmdb/oc_emsmdb.c"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "oc_emsmdb check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static bool fake_init;
static unsigned created, destroyed;

static int fake_destructor(struct emsmdbp_context *ctx) { destroyed++; return 0; }
struct emsmdbp_context *__real_emsmdbp_init(struct loadparm_context *, const char *, void *);
struct emsmdbp_context *__wrap_emsmdbp_init(struct loadparm_context *, const char *, void *);
struct emsmdbp_context *__wrap_emsmdbp_init(struct loadparm_context *lp, const char *user, void *db)
{
    struct emsmdbp_context *ctx;
    if (!fake_init) return __real_emsmdbp_init(lp, user, db);
    ctx = talloc_zero(NULL, struct emsmdbp_context);
    if (ctx == NULL) return NULL;
    /* No notification context: notification delivery reports nothing pending. */
    ctx->mstore_ctx = talloc_zero(ctx, struct mapistore_context);
    if (ctx->mstore_ctx == NULL) { talloc_free(ctx); return NULL; }
    created++; talloc_set_destructor(ctx, fake_destructor);
    return ctx;
}

/* One GetStatus ROP on one handle; its reply frame is 20 bytes. */
static DATA_BLOB get_status_request(TALLOC_CTX *mem_ctx)
{
    struct mapi_request request = { .length = 5, .mapi_len = 9 };
    struct RPC_HEADER_EXT header = { .Flags = RHEF_Last, .Size = 9, .SizeActual = 9 };
    struct ndr_push *wire = ndr_push_init_ctx(mem_ctx);
    request.handles = talloc_array(mem_ctx, uint32_t, 1);
    request.mapi_req = talloc_zero_array(mem_ctx, struct EcDoRpc_MAPI_REQ, 2);
    if (wire == NULL || request.handles == NULL || request.mapi_req == NULL) return data_blob_null;
    request.handles[0] = 42; request.mapi_req[0].opnum = op_MAPI_GetStatus;
    if (ndr_push_RPC_HEADER_EXT(wire, NDR_SCALARS, &header) != NDR_ERR_SUCCESS ||
        ndr_push_mapi_request(wire, NDR_SCALARS, &request) != NDR_ERR_SUCCESS) return data_blob_null;
    return ndr_push_blob(wire);
}

static bool untouched(const uint8_t *p, size_t from, size_t to)
{
    for (; from < to; from++) if (p[from] != 0xEE) return false;
    return true;
}

/* openchangedb needs a rootDSE; there is no provisioning in the test tree. */
static int seed_openchangedb(const char *conf)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    struct loadparm_context *lp = loadparm_init(ctx);
    struct ldb_context *ldb;
    struct ldb_message *msg;
    int ret;
    CHECK(ctx && lp && lpcfg_load(lp, conf));
    ldb = ldb_init(ctx, NULL);
    CHECK(ldb && ldb_connect(ldb, talloc_asprintf(ctx, "%s/openchange.ldb", lpcfg_private_dir(lp)), 0, NULL) == LDB_SUCCESS);
    msg = ldb_msg_new(ctx);
    CHECK(msg && (msg->dn = ldb_dn_new(msg, ldb, "@ROOTDSE")));
    CHECK(ldb_msg_add_string(msg, "rootDomainNamingContext", "DC=example,DC=invalid") == 0 &&
        ldb_msg_add_string(msg, "defaultNamingContext", "DC=example,DC=invalid") == 0);
    ret = ldb_add(ldb, msg);
    CHECK(ret == LDB_SUCCESS || ret == LDB_ERR_ENTRY_ALREADY_EXISTS);
    talloc_free(ctx);
    return 0;
}

static int test_disconnect_null(void) { oc_emsmdb_disconnect(NULL); return 0; }

static int test_execute_null_session(void)
{
    uint8_t in[16] = {0}, out[16];
    size_t len = 99;
    CHECK(oc_emsmdb_execute(NULL, 0, in, sizeof in, out, sizeof out, &len) == ecRpcFailed && len == 0);
    return 0;
}

static int test_connect_without_samdb(const char *conf)
{
    oc_emsmdb_session *session = (oc_emsmdb_session *)&session;
    const char *name = NULL, *prefix = NULL;
    size_t blocks;
    CHECK(oc_emsmdb_connect("user", "/o=example.invalid/cn=user", 0, 1252, 1033, 1033,
        &session, &name, &prefix) == MAPI_E_NOT_INITIALIZED && session == NULL);
    CHECK(oc_emsmdb_init(conf) == MAPI_E_SUCCESS && oc_root != NULL);
    CHECK(oc_emsmdb_init(conf) == MAPI_E_SUCCESS);
    session = (oc_emsmdb_session *)&session;
    CHECK(oc_emsmdb_connect("user", "", 0, 1252, 1033, 1033, &session, &name, &prefix) == MAPI_E_NO_ACCESS &&
        session == NULL);
    /* The first SamDB attempt may cache Samba module state; the second must not grow anything. */
    CHECK(oc_emsmdb_connect("user", "/o=example.invalid/cn=user", 0, 1252, 1033, 1033,
        &session, &name, &prefix) != MAPI_E_SUCCESS);
    blocks = talloc_total_blocks(NULL);
    session = (oc_emsmdb_session *)&session;
    CHECK(oc_emsmdb_connect("user", "/o=example.invalid/cn=user", 0, 1252, 1033, 1033,
        &session, &name, &prefix) == MAPI_E_LOGON_FAILED && created == 0);
    CHECK(session == NULL && name && name[0] == '\0' && prefix && prefix[0] == '\0');
    CHECK(talloc_total_blocks(NULL) == blocks);
    return 0;
}

#define ORG_OU "/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn="
#define USER_LDIF(mail, nick, control) \
    "dn: CN=" mail ",CN=Users,DC=openchange\nobjectClass: user\nsAMAccountName: " mail "\nmail: " mail \
    "\ndisplayName: Name " nick "\nmailNickname: " nick "\nlegacyExchangeDN: " ORG_OU nick \
    "\nmsExchUserAccountControl: " control "\n\n"

/* Mirrors what openchange_directory_sync writes (python/openchange/directory.py). */
static const char directory_ldif[] =
    "dn: @ATTRIBUTES\nlegacyExchangeDN: CASE_INSENSITIVE\nsAMAccountName: CASE_INSENSITIVE\n"
    "mail: CASE_INSENSITIVE\nmailNickname: CASE_INSENSITIVE\ncn: CASE_INSENSITIVE\n\n"
    "dn: @ROOTDSE\ndefaultNamingContext: DC=openchange\nconfigurationNamingContext: CN=Configuration,DC=openchange\n\n"
    USER_LDIF("alice@example.invalid", "alice-0001", "0")
    USER_LDIF("bob@example.invalid", "bob-0002", "0")
    USER_LDIF("carol@example.invalid", "carol-0003", "2")
    USER_LDIF("a*b@example.invalid", "a_b-0004", "0")
    USER_LDIF("ab@example.invalid", "ab-0005", "0");

static int seed_directory(const char *conf)
{
    TALLOC_CTX *mem = talloc_new(NULL);
    struct loadparm_context *lp = loadparm_init(mem);
    struct ldb_context *ldb;
    struct ldb_ldif *ldif;
    const char *text = directory_ldif, *url;
    CHECK(mem && lp && lpcfg_load(lp, conf));
    url = lpcfg_parm_string(lp, NULL, "mapiproxy", "directory_url");
    ldb = ldb_init(mem, NULL);
    CHECK(url && ldb && ldb_connect(ldb, url, 0, NULL) == LDB_SUCCESS);
    while ((ldif = ldb_ldif_read_string(ldb, &text)) != NULL) {
        CHECK(ldb_add(ldb, ldif->msg) == LDB_SUCCESS);
        ldb_ldif_read_free(ldb, ldif);
    }
    talloc_free(mem);
    return 0;
}

/* mapiproxy:directory_url names a plain LDB; it is opened without Samba's SamDB modules. */
static int test_directory_ldb_opens(const char *conf)
{
    TALLOC_CTX *mem = talloc_new(NULL);
    struct loadparm_context *lp = loadparm_init(mem);
    struct ldb_result *res;
    struct emsmdbp_context *ctx;
    CHECK(mem && lp && lpcfg_load(lp, conf) && seed_directory(conf) == 0);
    ctx = __real_emsmdbp_init(lp, "alice@example.invalid", oc_db_ctx);
    CHECK(ctx != NULL);
    CHECK(ldb_get_default_basedn(ctx->samdb_ctx) && ldb_get_config_basedn(ctx->samdb_ctx));
    CHECK(strcmp(ldb_dn_get_linearized(ldb_get_default_basedn(ctx->samdb_ctx)), "DC=openchange") == 0);
    CHECK(strcmp(ldb_dn_get_linearized(ldb_get_config_basedn(ctx->samdb_ctx)), "CN=Configuration,DC=openchange") == 0);
    CHECK(ldb_search(ctx->samdb_ctx, mem, &res, ldb_get_default_basedn(ctx->samdb_ctx), LDB_SCOPE_SUBTREE,
        NULL, "sAMAccountName=alice@example.invalid") == LDB_SUCCESS && res->count == 1);
    talloc_free(ctx);
    talloc_free(mem);
    return 0;
}

static uint32_t connect_as(const char *user, const char *dn, oc_emsmdb_session **session,
                           const char **name, const char **prefix)
{
    *session = (oc_emsmdb_session *)session;
    return oc_emsmdb_connect(user, dn, 0, 1252, 1033, 1033, session, name, prefix);
}

static int test_connect_success(void)
{
    oc_emsmdb_session *session;
    const char *name, *prefix;
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    CHECK(session != NULL && strcmp(name, "Name alice-0001") == 0);
    CHECK(strcmp(prefix, "/O=FIRST ORGANIZATION/OU=EXCHANGE ADMINISTRATIVE GROUP (FYDIBOHF23SPDLT)/CN=RECIPIENTS/CN=") == 0);
    CHECK(session->ctx && strcmp(session->ctx->username, "alice@example.invalid") == 0);
    oc_emsmdb_disconnect(session);
    return 0;
}

static int test_connect_dn_case_insensitive(void)
{
    oc_emsmdb_session *session;
    const char *name, *prefix;
    CHECK(connect_as("alice@example.invalid",
        "/O=FIRST ORGANIZATION/OU=EXCHANGE ADMINISTRATIVE GROUP (FYDIBOHF23SPDLT)/CN=RECIPIENTS/CN=ALICE-0001",
        &session, &name, &prefix) == MAPI_E_SUCCESS && session != NULL);
    oc_emsmdb_disconnect(session);
    return 0;
}

static int test_connect_rejected(const char *user, const char *dn)
{
    oc_emsmdb_session *session;
    const char *name, *prefix;
    CHECK(connect_as(user, dn, &session, &name, &prefix) == MAPI_E_LOGON_FAILED);
    CHECK(session == NULL && name[0] == '\0' && prefix[0] == '\0');
    return 0;
}

static int test_connect_other_users_dn(void)
{
    return test_connect_rejected("alice@example.invalid", ORG_OU "bob-0002");
}

static int test_connect_inactive(void)
{
    return test_connect_rejected("carol@example.invalid", ORG_OU "carol-0003");
}

static int test_connect_unknown_user(void)
{
    return test_connect_rejected("nobody@example.invalid", ORG_OU "alice-0001");
}

static int test_connect_filter_metacharacters(void)
{
    oc_emsmdb_session *session;
    const char *name, *prefix;
    if (test_connect_rejected("a*b@example.invalid", ORG_OU "ab-0005")) return 1;
    CHECK(connect_as("a*b@example.invalid", ORG_OU "a_b-0004", &session, &name, &prefix) == MAPI_E_SUCCESS);
    oc_emsmdb_disconnect(session);
    return 0;
}

static int test_connect_fails_closed(void)
{
    oc_emsmdb_session *session = NULL;
    const char *name, *prefix;
    fake_init = true;
    CHECK(oc_emsmdb_connect("user", "/o=example.invalid/cn=user", 0, 1252, 1033, 1033,
        &session, &name, &prefix) == MAPI_E_LOGON_FAILED);
    fake_init = false;
    CHECK(session == NULL && created == 1 && destroyed == 1);
    return 0;
}

static int test_execute(void)
{
    oc_emsmdb_session *session = talloc_zero(oc_root, oc_emsmdb_session);
    DATA_BLOB in = get_status_request(session);
    uint8_t out[32];
    size_t len;
    CHECK(session && in.length == 17);
    fake_init = true; session->ctx = talloc_steal(session, emsmdbp_init(NULL, "user", NULL)); fake_init = false;
    CHECK(session->ctx);

    /* test_execute_short_input */
    len = 99;
    CHECK(oc_emsmdb_execute(session, 0, in.data, 4, out, sizeof out, &len) == ecRpcFailed && len == 0);
    CHECK(oc_emsmdb_execute(session, 0, in.data, in.length, out, 4, &len) == ecRpcFailed && len == 0);
    CHECK(oc_emsmdb_execute(session, 0, in.data, in.length, out, sizeof out, NULL) == ecRpcFailed);

    /* test_execute_out_cap */
    memset(out, 0xEE, sizeof out);
    CHECK(oc_emsmdb_execute(session, 0, in.data, in.length, out, 16, &len) == ecBufferTooSmall && len == 0);
    CHECK(untouched(out, 0, sizeof out));
    CHECK(oc_emsmdb_execute(session, 0, in.data, in.length, out, 20, &len) == MAPI_E_SUCCESS && len == 20);
    CHECK(out[2] == RHEF_Last && untouched(out, 20, sizeof out));
    in.data[2] = 0; /* Missing last-frame flag. */
    CHECK(oc_emsmdb_execute(session, 0, in.data, in.length, out, sizeof out, &len) == ecRpcFormat && len == 0);

    oc_emsmdb_disconnect(session);
    CHECK(destroyed == 2);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s smb.conf\n", argv[0]); return 2; }
    talloc_enable_null_tracking();
    if (seed_openchangedb(argv[1]) || test_disconnect_null() || test_execute_null_session() || test_connect_without_samdb(argv[1]) ||
        test_directory_ldb_opens(argv[1]) ||
        test_connect_success() || test_connect_dn_case_insensitive() || test_connect_other_users_dn() ||
        test_connect_inactive() || test_connect_unknown_user() || test_connect_filter_metacharacters() ||
        test_connect_fails_closed() || test_execute()) return 1;
    talloc_free(oc_root);
    printf("oc_emsmdb null handles, directory connect checks and bounded execute: OK\n");
    return 0;
}
