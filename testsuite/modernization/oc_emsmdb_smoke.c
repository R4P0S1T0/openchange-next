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

/* Connection strings carry passwords: openchangedb must never log them, whatever the outcome. */
static int test_openchangedb_url_not_logged(void)
{
    const char *urls[] = { "mysql://u:s3cret-marker@127.0.0.1:1/db", "bogus://u:s3cret-marker@host/db" };
    char path[] = "/tmp/oc-emsmdb-log-XXXXXX", buf[8192];
    int fd = mkstemp(path), saved_err = dup(2), saved_out = dup(1);
    size_t i, n;
    FILE *f;
    CHECK(fd >= 0 && saved_err >= 0 && saved_out >= 0);
    for (i = 0; i < 2; i++) {
        TALLOC_CTX *mem = talloc_new(NULL);
        struct loadparm_context *lp = loadparm_init(mem);
        struct openchangedb_context *db = NULL;
        CHECK(mem && lp && lpcfg_set_cmdline(lp, "mapiproxy:openchangedb", urls[i]));
        fflush(stdout); fflush(stderr);
        dup2(fd, 2); dup2(fd, 1);
        (void)openchangedb_initialize(mem, lp, &db);
        fflush(stdout); fflush(stderr);
        dup2(saved_err, 2); dup2(saved_out, 1);
        talloc_free(mem);
    }
    f = fopen(path, "r");
    CHECK(f != NULL);
    n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    fclose(f); unlink(path); close(fd); close(saved_err); close(saved_out);
    CHECK(strstr(buf, "s3cret-marker") == NULL);
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

static const uint32_t provisioned[] = { EMSMDBP_MAILBOX_ROOT, EMSMDBP_DEFERRED_ACTION, EMSMDBP_VIEWS,
    EMSMDBP_REMINDERS, EMSMDBP_TOP_INFORMATION_STORE, EMSMDBP_INBOX, EMSMDBP_OUTBOX, EMSMDBP_SENT_ITEMS,
    EMSMDBP_DELETED_ITEMS };
#define N_PROVISIONED (sizeof provisioned / sizeof provisioned[0])
static uint64_t first_fids[N_PROVISIONED + 1];

/* fids[N_PROVISIONED] is the Calendar, located by name under Top of Information Store like Outlook's lookups. */
static int provisioned_fids(struct emsmdbp_context *ctx, uint64_t *fids)
{
    size_t i;
    for (i = 0; i < N_PROVISIONED; i++)
        CHECK(openchangedb_get_SystemFolderID(ctx->oc_ctx, ctx->username, provisioned[i], fids + i) == MAPI_E_SUCCESS && fids[i]);
    CHECK(openchangedb_get_fid_by_name(ctx->oc_ctx, ctx->username, fids[4], "Calendar", fids + N_PROVISIONED) == MAPI_E_SUCCESS);
    return 0;
}

static int test_provision_native_mailbox(void)
{
    oc_emsmdb_session *session;
    const char *name, *prefix;
    char *uri = NULL;
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    CHECK(emsmdbp_mailbox_provision(session->ctx, "alice@example.invalid") == MAPI_E_SUCCESS);
    if (provisioned_fids(session->ctx, first_fids)) return 1;
    /* Mailbox folder IDs must stay above the public folder range, which openchangedb's MySQL backend
       recognizes by the counter (is_public_folder_id); otherwise mailbox folders are stored as public. */
    for (size_t i = 0; i <= N_PROVISIONED; i++)
        CHECK(((first_fids[i] >> 56) | (((first_fids[i] >> 48) & 0xFF) << 8)) > 1000);
    /* Native folders have no mapistore URI until a backend offers their role. */
    CHECK(openchangedb_get_mapistoreURI(session, session->ctx->oc_ctx, "alice@example.invalid", first_fids[5], &uri, true)
        != MAPI_E_SUCCESS || uri == NULL || uri[0] == '\0');
    oc_emsmdb_disconnect(session);
    return 0;
}

static int test_provision_idempotent(void)
{
    oc_emsmdb_session *session;
    const char *name, *prefix;
    uint64_t again[N_PROVISIONED + 1];
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    CHECK(emsmdbp_mailbox_provision(session->ctx, "alice@example.invalid") == MAPI_E_SUCCESS);
    if (provisioned_fids(session->ctx, again)) return 1;
    CHECK(memcmp(again, first_fids, sizeof again) == 0);
    oc_emsmdb_disconnect(session);
    return 0;
}

/* Outlook creates folders (RopCreateFolder) under native ones; with no backend for the role they stay native. */
static int test_create_native_subfolder(void)
{
    oc_emsmdb_session *session;
    const char *name, *prefix;
    struct emsmdbp_object *mailbox, *ipm, *created = NULL;
    struct SPropValue props[3];
    struct SRow row = { .cValues = 3, .lpProps = props };
    uint64_t fid, found = 0, cn;
    char *uri = NULL;
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    mailbox = emsmdbp_object_mailbox_init(session, session->ctx, ORG_OU "alice-0001", true);
    CHECK(mailbox != NULL);
    CHECK(emsmdbp_object_open_folder(session, session->ctx, mailbox, first_fids[4], &ipm) == MAPISTORE_SUCCESS);
    CHECK(mapistore_indexing_get_new_folderID(session->ctx->mstore_ctx, &fid) == MAPISTORE_SUCCESS);
    CHECK(openchangedb_get_new_changeNumber(session->ctx->oc_ctx, session->ctx->username, &cn) == MAPI_E_SUCCESS);
    props[0].ulPropTag = PR_DISPLAY_NAME_UNICODE; props[0].value.lpszW = "Sync Issues";
    props[1].ulPropTag = PR_CONTAINER_CLASS_UNICODE; props[1].value.lpszW = "IPF.Note";
    props[2].ulPropTag = PidTagChangeNumber; props[2].value.d = cn;
    CHECK(emsmdbp_object_create_folder(session->ctx, ipm, session, fid, &row, true, &created) == MAPI_E_SUCCESS && created);
    CHECK(openchangedb_get_fid_by_name(session->ctx->oc_ctx, session->ctx->username, first_fids[4], "Sync Issues", &found)
        == MAPI_E_SUCCESS && found == fid);
    CHECK(openchangedb_get_mapistoreURI(session, session->ctx->oc_ctx, "alice@example.invalid", fid, &uri, true)
        != MAPI_E_SUCCESS || uri == NULL || uri[0] == '\0');
    oc_emsmdb_disconnect(session);
    return 0;
}

/* A backend offering only the mail role: it must take over the native Inbox, keeping its folder ID. */
static enum mapistore_error fake_list_contexts(const char *user, struct indexing_context *ictx, TALLOC_CTX *mem,
                                               struct mapistore_contexts_list **list)
{
    struct mapistore_contexts_list *entry = talloc_zero(mem, struct mapistore_contexts_list);
    if (entry == NULL) return MAPISTORE_ERR_NO_MEMORY;
    entry->url = talloc_strdup(entry, "fake://inbox/");
    entry->name = talloc_strdup(entry, "Inbox");
    entry->main_folder = true;
    entry->role = MAPISTORE_MAIL_ROLE;
    entry->prev = entry;  /* DLIST head: prev is the tail */
    *list = entry;
    return MAPISTORE_SUCCESS;
}
static enum mapistore_error fake_backend_init(void) { return MAPISTORE_SUCCESS; }

static int test_provision_backend_takes_over_inbox(void)
{
    struct mapistore_backend fake;
    oc_emsmdb_session *session;
    const char *name, *prefix;
    uint64_t again[N_PROVISIONED + 1];
    char *uri = NULL;
    memset(&fake, 0, sizeof fake);
    CHECK(mapistore_backend_init_defaults(&fake) == MAPISTORE_SUCCESS);
    fake.backend.name = "fake"; fake.backend.description = "test"; fake.backend.namespace = "fake://";
    fake.backend.init = fake_backend_init; fake.backend.list_contexts = fake_list_contexts;
    CHECK(mapistore_backend_register(&fake) == MAPISTORE_SUCCESS);
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    CHECK(emsmdbp_mailbox_provision(session->ctx, "alice@example.invalid") == MAPI_E_SUCCESS);
    if (provisioned_fids(session->ctx, again)) return 1;
    CHECK(memcmp(again, first_fids, sizeof again) == 0);
    CHECK(openchangedb_get_mapistoreURI(session, session->ctx->oc_ctx, "alice@example.invalid", first_fids[5], &uri, true)
        == MAPI_E_SUCCESS && strcmp(uri, "fake://inbox/") == 0);
    oc_emsmdb_disconnect(session);
    return 0;
}

/* A later backend offering the fallback role (as M3's may) must not break logon of a native mailbox. */
static enum mapistore_error fake_fallback_contexts(const char *user, struct indexing_context *ictx, TALLOC_CTX *mem,
                                                   struct mapistore_contexts_list **list)
{
    struct mapistore_contexts_list *entry = talloc_zero(mem, struct mapistore_contexts_list);
    if (entry == NULL) return MAPISTORE_ERR_NO_MEMORY;
    entry->url = talloc_strdup(entry, "fakefb://fallback/");
    entry->name = talloc_strdup(entry, "Fallback");
    entry->main_folder = true;
    entry->role = MAPISTORE_FALLBACK_ROLE;
    entry->prev = entry;  /* DLIST head: prev is the tail */
    *list = entry;
    return MAPISTORE_SUCCESS;
}

static int test_provision_fallback_after_native(void)
{
    struct mapistore_backend fake;
    oc_emsmdb_session *session;
    const char *name, *prefix;
    memset(&fake, 0, sizeof fake);
    CHECK(mapistore_backend_init_defaults(&fake) == MAPISTORE_SUCCESS);
    fake.backend.name = "fakefb"; fake.backend.description = "test"; fake.backend.namespace = "fakefb://";
    fake.backend.init = fake_backend_init; fake.backend.list_contexts = fake_fallback_contexts;
    CHECK(mapistore_backend_register(&fake) == MAPISTORE_SUCCESS);
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    CHECK(emsmdbp_mailbox_provision(session->ctx, "alice@example.invalid") == MAPI_E_SUCCESS);
    oc_emsmdb_disconnect(session);
    return 0;
}

/* One private-mailbox RopLogon (MS-OXCSTOR 2.2.1.1.1) as Outlook sends it after Connect. */
static DATA_BLOB logon_request(TALLOC_CTX *mem_ctx, const char *essdn)
{
    struct mapi_request request = {0};
    struct RPC_HEADER_EXT header = { .Flags = RHEF_Last };
    struct ndr_push *rop = ndr_push_init_ctx(mem_ctx), *wire = ndr_push_init_ctx(mem_ctx);
    struct Logon_req logon = { .LogonFlags = LogonPrivate, .OpenFlags = USE_PER_MDB_REPLID_MAPPING | HOME_LOGON | TAKE_OWNERSHIP,
        .StoreState = 0, .EssDN = essdn };
    request.handles = talloc_array(mem_ctx, uint32_t, 1);
    request.mapi_req = talloc_zero_array(mem_ctx, struct EcDoRpc_MAPI_REQ, 2);
    if (!rop || !wire || !request.handles || !request.mapi_req ||
        ndr_push_Logon_req(rop, NDR_SCALARS, &logon) != NDR_ERR_SUCCESS) return data_blob_null;
    request.handles[0] = 0xFFFFFFFF;
    request.mapi_req[0].opnum = op_MAPI_Logon;
    request.mapi_req[0].u.mapi_Logon = logon;
    request.length = 2 + 3 + rop->offset;  /* RopSize + RopId/LogonId/OutputHandleIndex + body */
    request.mapi_len = request.length + 4;
    header.Size = header.SizeActual = request.mapi_len;
    if (ndr_push_RPC_HEADER_EXT(wire, NDR_SCALARS, &header) != NDR_ERR_SUCCESS ||
        ndr_push_mapi_request(wire, NDR_SCALARS, &request) != NDR_ERR_SUCCESS) return data_blob_null;
    return ndr_push_blob(wire);
}

/* Runs one RopLogon on a fresh session and returns its ROP error code (or 0xFFFFFFFF on transport failure). */
static uint32_t logon_as(const char *user, const char *dn, const char *essdn, uint64_t *inbox)
{
    oc_emsmdb_session *session;
    const char *name, *prefix;
    uint8_t out[4096];
    size_t len;
    struct mapi2k7_response decoded = {0};
    struct ndr_pull *pull;
    DATA_BLOB in, blob;
    uint32_t code = 0xFFFFFFFF;
    if (connect_as(user, dn, &session, &name, &prefix) != MAPI_E_SUCCESS) return code;
    in = logon_request(session, essdn);
    if (in.length && oc_emsmdb_execute(session, 0, in.data, in.length, out, sizeof out, &len) == MAPI_E_SUCCESS) {
        blob = data_blob_const(out, len);
        pull = ndr_pull_init_blob(&blob, session);
        decoded.mapi_response = talloc_zero(session, struct mapi_response);
        if (pull && decoded.mapi_response &&
            ndr_pull_mapi2k7_response(pull, NDR_SCALARS | NDR_BUFFERS, &decoded) == NDR_ERR_SUCCESS &&
            decoded.mapi_response->mapi_repl) {
            code = decoded.mapi_response->mapi_repl[0].error_code;
            if (code == MAPI_E_SUCCESS && inbox)
                *inbox = decoded.mapi_response->mapi_repl[0].u.mapi_Logon.LogonType.store_mailbox.Inbox;
        }
    }
    if (code != MAPI_E_SUCCESS) fprintf(stderr, "RopLogon %s as %s: 0x%08x\n", essdn, user, code);
    oc_emsmdb_disconnect(session);
    return code;
}

static int test_logon_private_mailbox(void)
{
    uint64_t inbox = 0;
    CHECK(logon_as("alice@example.invalid", ORG_OU "alice-0001", ORG_OU "alice-0001", &inbox) == MAPI_E_SUCCESS);
    CHECK(inbox == first_fids[5]);
    return 0;
}

static int test_logon_other_users_dn(void)
{
    CHECK(logon_as("alice@example.invalid", ORG_OU "alice-0001", ORG_OU "bob-0002", NULL) == MAPI_E_NO_ACCESS);
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
    if (test_openchangedb_url_not_logged() || test_disconnect_null() || test_execute_null_session() || test_connect_without_samdb(argv[1]) ||
        test_directory_ldb_opens(argv[1]) ||
        test_connect_success() || test_connect_dn_case_insensitive() || test_connect_other_users_dn() ||
        test_connect_inactive() || test_connect_unknown_user() || test_connect_filter_metacharacters() ||
        test_provision_native_mailbox() || test_provision_idempotent() || test_create_native_subfolder() ||
        test_logon_private_mailbox() || test_logon_other_users_dn() ||
        test_provision_backend_takes_over_inbox() || test_provision_fallback_after_native() ||
        test_connect_fails_closed() || test_execute()) return 1;
    talloc_free(oc_root);
    printf("oc_emsmdb null handles, directory connect checks and bounded execute: OK\n");
    return 0;
}
