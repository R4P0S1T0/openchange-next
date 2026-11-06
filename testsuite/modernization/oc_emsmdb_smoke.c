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

#define ORG_DN "CN=First Organization,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=openchange"
#define TEMPLATES "CN=Address-Templates,CN=Addressing," ORG_DN

/* Mirrors what openchange_directory_sync writes (python/openchange/directory.py). */
static const char directory_ldif[] =
    "dn: @ATTRIBUTES\nlegacyExchangeDN: CASE_INSENSITIVE\nsAMAccountName: CASE_INSENSITIVE\n"
    "mail: CASE_INSENSITIVE\nmailNickname: CASE_INSENSITIVE\ncn: CASE_INSENSITIVE\n\n"
    "dn: @ROOTDSE\ndefaultNamingContext: DC=openchange\nconfigurationNamingContext: CN=Configuration,DC=openchange\n\n"
    USER_LDIF("alice@example.invalid", "alice-0001", "0")
    USER_LDIF("bob@example.invalid", "bob-0002", "0")
    USER_LDIF("carol@example.invalid", "carol-0003", "2")
    USER_LDIF("a*b@example.invalid", "a_b-0004", "0")
    USER_LDIF("ab@example.invalid", "ab-0005", "0")
    "dn: " ORG_DN "\nobjectClass: msExchOrganizationContainer\ncn: First Organization\n\n"
    "dn: CN=Addressing," ORG_DN "\nobjectClass: container\n\n"
    "dn: " TEMPLATES "\nobjectClass: container\nmsExchTemplateRDNs: 409\nmsExchTemplateRDNs: 416\n\n"
    "dn: CN=409," TEMPLATES "\nobjectClass: container\ncn: 409\nmsExchTemplateRDNs: EX\nmsExchTemplateRDNs: SMTP\n\n"
    "dn: CN=416," TEMPLATES "\nobjectClass: container\ncn: 416\nmsExchTemplateRDNs: EX\nmsExchTemplateRDNs: SMTP\n\n";

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

/* RopGetAddressTypes for an Outlook locale with no template of its own (en-GB) uses the en-US one. */
static int address_types(uint32_t lcid, enum MAPISTATUS *status, uint16_t *count)
{
    oc_emsmdb_session *session;
    const char *name, *prefix;
    struct EcDoRpc_MAPI_REQ req = { .opnum = op_MAPI_AddressTypes };
    struct EcDoRpc_MAPI_REPL repl = {0};
    uint32_t handles[1] = { 0 };
    uint16_t size = 0;
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    session->ctx->userLanguage = lcid;
    *status = EcDoRpc_RopGetAddressTypes(session, session->ctx, &req, &repl, handles, &size);
    *count = repl.u.mapi_AddressTypes.cValues;
    oc_emsmdb_disconnect(session);
    return 0;
}

static int test_address_types_locale_fallback(void)
{
    enum MAPISTATUS status;
    uint16_t count;
    if (address_types(0x416, &status, &count)) return 1;
    CHECK(status == MAPI_E_SUCCESS && count == 2);
    if (address_types(0x809, &status, &count)) return 1;
    CHECK(status == MAPI_E_SUCCESS && count == 2);
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

/* A backend offering the Drafts role (IMAP \Drafts) takes over the native special folder, keeping its ID. */
static enum mapistore_error drafts_contexts(const char *user, struct indexing_context *ictx, TALLOC_CTX *mem,
                                            struct mapistore_contexts_list **list)
{
    struct mapistore_contexts_list *entry = talloc_zero(mem, struct mapistore_contexts_list);
    if (entry == NULL) return MAPISTORE_ERR_NO_MEMORY;
    entry->url = talloc_strdup(entry, "fakedr://drafts/");
    entry->name = talloc_strdup(entry, "Drafts");
    entry->main_folder = true;
    entry->role = MAPISTORE_DRAFTS_ROLE;
    entry->prev = entry;  /* DLIST head: prev is the tail */
    *list = entry;
    return MAPISTORE_SUCCESS;
}

static int test_provision_backend_takes_over_drafts(void)
{
    struct mapistore_backend fake;
    oc_emsmdb_session *session;
    const char *name, *prefix;
    uint64_t ipm, before, after;
    char *uri = NULL;
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    CHECK(openchangedb_get_SystemFolderID(session->ctx->oc_ctx, "alice@example.invalid", EMSMDBP_TOP_INFORMATION_STORE, &ipm) == MAPI_E_SUCCESS);
    CHECK(openchangedb_get_fid_by_name(session->ctx->oc_ctx, "alice@example.invalid", ipm, "Drafts", &before) == MAPI_E_SUCCESS);
    oc_emsmdb_disconnect(session);
    memset(&fake, 0, sizeof fake);
    CHECK(mapistore_backend_init_defaults(&fake) == MAPISTORE_SUCCESS);
    fake.backend.name = "fakedr"; fake.backend.description = "test"; fake.backend.namespace = "fakedr://";
    fake.backend.init = fake_backend_init; fake.backend.list_contexts = drafts_contexts;
    CHECK(mapistore_backend_register(&fake) == MAPISTORE_SUCCESS);
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    CHECK(emsmdbp_mailbox_provision(session->ctx, "alice@example.invalid") == MAPI_E_SUCCESS);
    CHECK(openchangedb_get_fid_by_name(session->ctx->oc_ctx, "alice@example.invalid", ipm, "Drafts", &after) == MAPI_E_SUCCESS);
    CHECK(after == before);
    CHECK(openchangedb_get_mapistoreURI(session, session->ctx->oc_ctx, "alice@example.invalid", after, &uri, true)
        == MAPI_E_SUCCESS && uri && strcmp(uri, "fakedr://drafts/") == 0);
    oc_emsmdb_disconnect(session);
    return 0;
}

/* A backend offering the Outbox role (the IMAP mailbox Outbox, M4) takes over the native Outbox, keeping its ID. */
static enum mapistore_error outbox_contexts(const char *user, struct indexing_context *ictx, TALLOC_CTX *mem,
                                            struct mapistore_contexts_list **list)
{
    struct mapistore_contexts_list *entry = talloc_zero(mem, struct mapistore_contexts_list);
    if (entry == NULL) return MAPISTORE_ERR_NO_MEMORY;
    entry->url = talloc_strdup(entry, "fakeob://outbox/");
    entry->name = talloc_strdup(entry, "Outbox");
    entry->main_folder = true;
    entry->role = MAPISTORE_OUTBOX_ROLE;
    entry->prev = entry;  /* DLIST head: prev is the tail */
    *list = entry;
    return MAPISTORE_SUCCESS;
}

static int test_outbox_taken_over(void)
{
    struct mapistore_backend fake;
    oc_emsmdb_session *session;
    const char *name, *prefix;
    uint64_t before, after;
    char *uri = NULL;
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    CHECK(openchangedb_get_SystemFolderID(session->ctx->oc_ctx, "alice@example.invalid", EMSMDBP_OUTBOX, &before) == MAPI_E_SUCCESS);
    oc_emsmdb_disconnect(session);
    memset(&fake, 0, sizeof fake);
    CHECK(mapistore_backend_init_defaults(&fake) == MAPISTORE_SUCCESS);
    fake.backend.name = "fakeob"; fake.backend.description = "test"; fake.backend.namespace = "fakeob://";
    fake.backend.init = fake_backend_init; fake.backend.list_contexts = outbox_contexts;
    CHECK(mapistore_backend_register(&fake) == MAPISTORE_SUCCESS);
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    CHECK(emsmdbp_mailbox_provision(session->ctx, "alice@example.invalid") == MAPI_E_SUCCESS);
    CHECK(openchangedb_get_SystemFolderID(session->ctx->oc_ctx, "alice@example.invalid", EMSMDBP_OUTBOX, &after) == MAPI_E_SUCCESS);
    CHECK(after == before);
    CHECK(openchangedb_get_mapistoreURI(session, session->ctx->oc_ctx, "alice@example.invalid", after, &uri, true)
        == MAPI_E_SUCCESS && uri && strcmp(uri, "fakeob://outbox/") == 0);
    oc_emsmdb_disconnect(session);
    return 0;
}

/* Outlook keeps rules and views as FAI messages (MS-OXCMSG 2.2.1.2) in mail folders; a backend that cannot
   store them (IMAP) must not see them: they live in openchangedb, on the backend root folder's record. */
static unsigned fai_backend_creates;
static int fai_root_marker;
static enum mapistore_error sent_contexts(const char *user, struct indexing_context *ictx, TALLOC_CTX *mem,
                                          struct mapistore_contexts_list **list)
{
    struct mapistore_contexts_list *entry = talloc_zero(mem, struct mapistore_contexts_list);
    if (entry == NULL) return MAPISTORE_ERR_NO_MEMORY;
    entry->url = talloc_strdup(entry, "faifake://sent/");
    entry->name = talloc_strdup(entry, "Sent Items");
    entry->main_folder = true;
    entry->role = MAPISTORE_SENTITEMS_ROLE;
    entry->prev = entry;  /* DLIST head: prev is the tail */
    *list = entry;
    return MAPISTORE_SUCCESS;
}
static enum mapistore_error fai_create_context(TALLOC_CTX *mem, struct mapistore_connection_info *ci,
                                               struct indexing_context *ictx, const char *uri, void **ctx)
{ *ctx = &fai_root_marker; return MAPISTORE_SUCCESS; }
static enum mapistore_error fai_root_folder(void *ctx, TALLOC_CTX *mem, uint64_t fid, void **folder)
{ *folder = &fai_root_marker; return MAPISTORE_SUCCESS; }
static enum mapistore_error fai_open_message(void *folder, TALLOC_CTX *mem, uint64_t mid, bool rw, void **msg)
{ return MAPISTORE_ERR_NOT_FOUND; }
static enum mapistore_error fai_delete_message(void *folder, uint64_t mid, uint8_t flags)
{ return MAPISTORE_ERR_NOT_FOUND; }
static enum mapistore_error fai_create_message(void *folder, TALLOC_CTX *mem, uint64_t mid, uint8_t fai, void **msg)
{ fai_backend_creates++; return MAPISTORE_ERR_DENIED; }

/* RopFindRow on the folder's FAI table with Outlook's lookup for its junk e-mail rule (MS-OXORULE 2.2.4):
   AND(class == IPM.ExtendedRule.Message, EXIST(rule name), rule name == name). Returns the ROP error code. */
static uint32_t find_rule(oc_emsmdb_session *session, uint32_t folder_handle, const char *name)
{
    struct EcDoRpc_MAPI_REQ req;
    struct EcDoRpc_MAPI_REPL repl;
    struct mapi_SRestriction_and terms[3];
    uint32_t handles[2] = { folder_handle, 0xFFFFFFFF };
    uint16_t size = 0;

    memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
    req.opnum = op_MAPI_GetContentsTable; req.handle_idx = 0;
    req.u.mapi_GetContentsTable.handle_idx = 1; req.u.mapi_GetContentsTable.TableFlags = TableFlags_Associated;
    if (EcDoRpc_RopGetContentsTable(session, session->ctx, &req, &repl, handles, &size) != MAPI_E_SUCCESS ||
        repl.error_code != MAPI_E_SUCCESS) return 0xFFFFFFFF;
    { /* The columns Outlook sets (RopSetColumns) before it looks the rule up. */
        static enum MAPITAGS columns[] = { PidTagMid, PidTagRuleMessageName };
        struct mapi_handles *th;
        void *to;
        if (mapi_handles_search(session->ctx->handles_ctx, handles[1], &th) != MAPI_E_SUCCESS ||
            mapi_handles_get_private_data(th, &to) != MAPI_E_SUCCESS || !to) return 0xFFFFFFFF;
        ((struct emsmdbp_object *) to)->object.table->prop_count = 2;
        ((struct emsmdbp_object *) to)->object.table->properties = columns;
    }

    memset(terms, 0, sizeof terms);
    terms[0].rt = RES_PROPERTY; terms[0].res.resProperty.relop = RELOP_EQ;
    terms[0].res.resProperty.ulPropTag = PR_MESSAGE_CLASS_UNICODE;
    terms[0].res.resProperty.lpProp.ulPropTag = PR_MESSAGE_CLASS_UNICODE;
    terms[0].res.resProperty.lpProp.value.lpszW = "IPM.ExtendedRule.Message";
    terms[1].rt = RES_EXIST; terms[1].res.resExist.ulPropTag = PidTagRuleMessageName;
    terms[2].rt = RES_PROPERTY; terms[2].res.resProperty.relop = RELOP_EQ;
    terms[2].res.resProperty.ulPropTag = PidTagRuleMessageName;
    terms[2].res.resProperty.lpProp.ulPropTag = PidTagRuleMessageName;
    terms[2].res.resProperty.lpProp.value.lpszW = name;
    memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
    handles[0] = handles[1];
    req.opnum = op_MAPI_FindRow; req.handle_idx = 0;
    req.u.mapi_FindRow.ulFlags = DIR_FORWARD; req.u.mapi_FindRow.origin = BOOKMARK_BEGINNING;
    req.u.mapi_FindRow.res.rt = RES_AND;
    req.u.mapi_FindRow.res.res.resAnd.cRes = 3;
    req.u.mapi_FindRow.res.res.resAnd.res = terms;
    if (EcDoRpc_RopFindRow(session, session->ctx, &req, &repl, handles, &size) != MAPI_E_SUCCESS) return 0xFFFFFFFF;
    if (repl.error_code == MAPI_E_SUCCESS && !repl.u.mapi_FindRow.HasRowData) return 0xFFFFFFFE;
    return repl.error_code;
}

static int test_fai_in_backend_root_kept_in_openchangedb(void)
{
    static uint8_t rules_blob[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    struct mapistore_backend fake;
    oc_emsmdb_session *session;
    const char *name, *prefix;
    struct emsmdbp_object *mailbox, *sent, *msg;
    struct mapi_handles *fh, *mh;
    struct EcDoRpc_MAPI_REQ req;
    struct EcDoRpc_MAPI_REPL repl;
    struct SPropValue prop[2] = { { .ulPropTag = PR_MESSAGE_CLASS_UNICODE, .value.lpszW = "IPM.ExtendedRule.Message" },
                                  { .ulPropTag = PidTagRuleMessageName, .value.lpszW = "Junk E-mail Rule" } };
    struct SRow row = { .cValues = 2, .lpProps = prop };
    uint32_t handles[3];
    uint16_t size = 0;
    uint64_t fid, mid;
    void *data;

    memset(&fake, 0, sizeof fake);
    CHECK(mapistore_backend_init_defaults(&fake) == MAPISTORE_SUCCESS);
    fake.backend.name = "faifake"; fake.backend.description = "test"; fake.backend.namespace = "faifake://";
    fake.backend.init = fake_backend_init; fake.backend.list_contexts = sent_contexts;
    fake.backend.create_context = fai_create_context; fake.context.get_root_folder = fai_root_folder;
    fake.folder.create_message = fai_create_message; fake.folder.open_message = fai_open_message;
    fake.folder.delete_message = fai_delete_message;
    CHECK(mapistore_backend_register(&fake) == MAPISTORE_SUCCESS);
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    CHECK(emsmdbp_mailbox_provision(session->ctx, "alice@example.invalid") == MAPI_E_SUCCESS);
    CHECK(openchangedb_get_SystemFolderID(session->ctx->oc_ctx, "alice@example.invalid", EMSMDBP_SENT_ITEMS, &fid) == MAPI_E_SUCCESS);
    mailbox = emsmdbp_object_mailbox_init(session, session->ctx, ORG_OU "alice-0001", true);
    CHECK(mailbox && mapi_handles_add(session->ctx->handles_ctx, 0, &fh) == MAPI_E_SUCCESS);
    CHECK(emsmdbp_object_open_folder(fh, session->ctx, mailbox, fid, &sent) == MAPISTORE_SUCCESS);
    CHECK(emsmdbp_is_mapistore(sent) && mapi_handles_set_private_data(fh, sent) == MAPI_E_SUCCESS);

    /* RopCreateMessage (associated), as Outlook sends it for a rule. */
    memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
    handles[0] = fh->handle; handles[1] = handles[2] = 0xFFFFFFFF;
    req.opnum = op_MAPI_CreateMessage; req.handle_idx = 0;
    req.u.mapi_CreateMessage.handle_idx = 1; req.u.mapi_CreateMessage.CodePageId = 0x4e4;
    req.u.mapi_CreateMessage.FolderId = fid; req.u.mapi_CreateMessage.AssociatedFlag = 1;
    CHECK(EcDoRpc_RopCreateMessage(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
    CHECK(repl.error_code == MAPI_E_SUCCESS && fai_backend_creates == 0);
    mid = repl.u.mapi_CreateMessage.MessageId.MessageId;
    CHECK(mapi_handles_search(session->ctx->handles_ctx, handles[1], &mh) == MAPI_E_SUCCESS);
    CHECK(mapi_handles_get_private_data(mh, &data) == MAPI_E_SUCCESS && (msg = data) && !emsmdbp_is_mapistore(msg));
    CHECK(emsmdbp_object_set_properties(session->ctx, msg, &row) == MAPI_E_SUCCESS);

    /* Outlook writes the rules blob through a stream and saves the message before it releases the stream. */
    memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
    req.opnum = op_MAPI_OpenStream; req.handle_idx = 1;
    req.u.mapi_OpenStream.handle_idx = 2; req.u.mapi_OpenStream.PropertyTag = PidTagRwRulesStream;
    req.u.mapi_OpenStream.OpenModeFlags = OpenStream_Create;
    CHECK(EcDoRpc_RopOpenStream(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
    CHECK(repl.error_code == MAPI_E_SUCCESS);
    memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
    req.opnum = op_MAPI_WriteStream; req.handle_idx = 2;
    req.u.mapi_WriteStream.data = data_blob_const(rules_blob, sizeof rules_blob);
    CHECK(EcDoRpc_RopWriteStream(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
    CHECK(repl.error_code == MAPI_E_SUCCESS);

    memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
    req.opnum = op_MAPI_SaveChangesMessage; req.handle_idx = 0;
    req.u.mapi_SaveChangesMessage.handle_idx = 1; req.u.mapi_SaveChangesMessage.SaveFlags = KeepOpenReadWrite;
    handles[0] = handles[1];
    CHECK(EcDoRpc_RopSaveChangesMessage(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
    CHECK(repl.error_code == MAPI_E_SUCCESS);
    {
        void *saved = NULL, *reopened = NULL;
        CHECK(openchangedb_message_open(session, session->ctx->oc_ctx, "alice@example.invalid", mid, fid, &reopened, NULL) == MAPI_E_SUCCESS);
        CHECK(openchangedb_message_get_property(session, session->ctx->oc_ctx, reopened, PidTagRwRulesStream, &saved) == MAPI_E_SUCCESS);
        CHECK(((struct Binary_r *) saved)->cb == sizeof rules_blob && memcmp(((struct Binary_r *) saved)->lpb, rules_blob, sizeof rules_blob) == 0);
    }

    /* Outlook's other order: it releases the stream (RopRelease) before it saves the message. */
    {
        uint32_t h2[3] = { fh->handle, 0xFFFFFFFF, 0xFFFFFFFF };
        void *saved = NULL, *reopened = NULL;
        uint64_t mid3;
        memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
        req.opnum = op_MAPI_CreateMessage; req.handle_idx = 0;
        req.u.mapi_CreateMessage.handle_idx = 1; req.u.mapi_CreateMessage.CodePageId = 0x4e4;
        req.u.mapi_CreateMessage.FolderId = fid; req.u.mapi_CreateMessage.AssociatedFlag = 1;
        CHECK(EcDoRpc_RopCreateMessage(session, session->ctx, &req, &repl, h2, &size) == MAPI_E_SUCCESS && repl.error_code == MAPI_E_SUCCESS);
        mid3 = repl.u.mapi_CreateMessage.MessageId.MessageId;
        memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
        req.opnum = op_MAPI_OpenStream; req.handle_idx = 1;
        req.u.mapi_OpenStream.handle_idx = 2; req.u.mapi_OpenStream.PropertyTag = PidTagRwRulesStream;
        req.u.mapi_OpenStream.OpenModeFlags = OpenStream_Create;
        CHECK(EcDoRpc_RopOpenStream(session, session->ctx, &req, &repl, h2, &size) == MAPI_E_SUCCESS && repl.error_code == MAPI_E_SUCCESS);
        memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
        req.opnum = op_MAPI_WriteStream; req.handle_idx = 2;
        req.u.mapi_WriteStream.data = data_blob_const(rules_blob, sizeof rules_blob);
        CHECK(EcDoRpc_RopWriteStream(session, session->ctx, &req, &repl, h2, &size) == MAPI_E_SUCCESS && repl.error_code == MAPI_E_SUCCESS);
        CHECK(mapi_handles_delete(session->ctx->handles_ctx, h2[2]) == MAPI_E_SUCCESS);  /* RopRelease */
        memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
        req.opnum = op_MAPI_SaveChangesMessage; req.handle_idx = 0;
        req.u.mapi_SaveChangesMessage.handle_idx = 1; req.u.mapi_SaveChangesMessage.SaveFlags = KeepOpenReadWrite;
        CHECK(EcDoRpc_RopSaveChangesMessage(session, session->ctx, &req, &repl, h2, &size) == MAPI_E_SUCCESS && repl.error_code == MAPI_E_SUCCESS);
        CHECK(openchangedb_message_open(session, session->ctx->oc_ctx, "alice@example.invalid", mid3, fid, &reopened, NULL) == MAPI_E_SUCCESS);
        CHECK(openchangedb_message_get_property(session, session->ctx->oc_ctx, reopened, PidTagRwRulesStream, &saved) == MAPI_E_SUCCESS);
        CHECK(((struct Binary_r *) saved)->cb == sizeof rules_blob);
        CHECK(openchangedb_message_delete(session->ctx->oc_ctx, "alice@example.invalid", fid, mid3) == MAPI_E_SUCCESS);
    }

    /* The FAI contents table of the backend folder lists it. */
    memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
    handles[0] = fh->handle; handles[1] = 0xFFFFFFFF;
    req.opnum = op_MAPI_GetContentsTable; req.handle_idx = 0;
    req.u.mapi_GetContentsTable.handle_idx = 1; req.u.mapi_GetContentsTable.TableFlags = TableFlags_Associated;
    CHECK(EcDoRpc_RopGetContentsTable(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
    CHECK(repl.error_code == MAPI_E_SUCCESS && repl.u.mapi_GetContentsTable.RowCount == 1);

    /* And it opens by ID, with the class it was saved with. */
    memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
    handles[0] = fh->handle; handles[1] = 0xFFFFFFFF;
    req.opnum = op_MAPI_OpenMessage; req.handle_idx = 0;
    req.u.mapi_OpenMessage.handle_idx = 1; req.u.mapi_OpenMessage.CodePageId = 0x4e4;
    req.u.mapi_OpenMessage.FolderId = fid; req.u.mapi_OpenMessage.MessageId = mid;
    req.u.mapi_OpenMessage.OpenModeFlags = ReadOnly;
    CHECK(EcDoRpc_RopOpenMessage(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
    CHECK(repl.error_code == MAPI_E_SUCCESS);
    CHECK(mapi_handles_search(session->ctx->handles_ctx, handles[1], &mh) == MAPI_E_SUCCESS);
    CHECK(mapi_handles_get_private_data(mh, &data) == MAPI_E_SUCCESS && (msg = data) && !emsmdbp_is_mapistore(msg));
    /* Read from openchangedb directly: the provider's property path needs SamDB, absent here. */
    CHECK(openchangedb_message_get_property(session, session->ctx->oc_ctx, msg->backend_object, PR_MESSAGE_CLASS_UNICODE, &data)
        == MAPI_E_SUCCESS && strcmp(data, "IPM.ExtendedRule.Message") == 0);
    CHECK(find_rule(session, fh->handle, "Junk E-mail Rule") == MAPI_E_SUCCESS);
    CHECK(find_rule(session, fh->handle, "Other Rule") == MAPI_E_NOT_FOUND);

    /* Cached mode uploads FAI messages instead (RopSynchronizationImportMessageChange). */
    {
        struct emsmdbp_object *sync = emsmdbp_object_synccontext_init(fh, session->ctx, sent);
        struct mapi_handles *sh;
        struct Binary_r *key = NULL;
        struct mapi_SPropValue vals[2];
        uint64_t mid2;
        CHECK(sync && mapi_handles_add(session->ctx->handles_ctx, 0, &sh) == MAPI_E_SUCCESS);
        CHECK(mapi_handles_set_private_data(sh, sync) == MAPI_E_SUCCESS);
        CHECK(mapistore_indexing_get_new_folderID(session->ctx->mstore_ctx, &mid2) == MAPISTORE_SUCCESS);
        CHECK(emsmdbp_source_key_from_fmid(session, session->ctx, "alice@example.invalid", mid2, &key) == MAPISTORE_SUCCESS && key);
        vals[0].ulPropTag = PidTagSourceKey; vals[0].value.bin.cb = key->cb; vals[0].value.bin.lpb = key->lpb;
        vals[1].ulPropTag = PidTagMessageClass; vals[1].value.lpszW = "IPM.Microsoft.FolderDesign.NamedView";
        memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
        handles[0] = sh->handle; handles[1] = 0xFFFFFFFF;
        req.opnum = op_MAPI_SyncImportMessageChange; req.handle_idx = 0;
        req.u.mapi_SyncImportMessageChange.handle_idx = 1;
        req.u.mapi_SyncImportMessageChange.ImportFlag = ImportFlag_Associated;
        req.u.mapi_SyncImportMessageChange.PropertyValues.cValues = 2;
        req.u.mapi_SyncImportMessageChange.PropertyValues.lpProps = vals;
        CHECK(EcDoRpc_RopSyncImportMessageChange(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
        CHECK(repl.error_code == MAPI_E_SUCCESS && fai_backend_creates == 0);

        memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
        req.opnum = op_MAPI_SaveChangesMessage; req.handle_idx = 0;
        req.u.mapi_SaveChangesMessage.handle_idx = 1; req.u.mapi_SaveChangesMessage.SaveFlags = KeepOpenReadWrite;
        handles[0] = handles[1];
        CHECK(EcDoRpc_RopSaveChangesMessage(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
        CHECK(repl.error_code == MAPI_E_SUCCESS);

        memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
        handles[0] = fh->handle; handles[1] = 0xFFFFFFFF;
        req.opnum = op_MAPI_GetContentsTable; req.handle_idx = 0;
        req.u.mapi_GetContentsTable.handle_idx = 1; req.u.mapi_GetContentsTable.TableFlags = TableFlags_Associated;
        CHECK(EcDoRpc_RopGetContentsTable(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
        CHECK(repl.error_code == MAPI_E_SUCCESS && repl.u.mapi_GetContentsTable.RowCount == 2);

        /* Outlook's rules wizard restricts the FAI table to rule messages (RopRestrict), then reads the rows. */
        {
            static enum MAPITAGS columns[] = { PidTagMid };
            struct mapi_handles *th;
            struct emsmdbp_object *to;
            enum MAPISTATUS *rv = NULL;
            void **dp, *td;
            CHECK(mapi_handles_search(session->ctx->handles_ctx, handles[1], &th) == MAPI_E_SUCCESS);
            CHECK(mapi_handles_get_private_data(th, &td) == MAPI_E_SUCCESS && (to = td));
            to->object.table->prop_count = 1; to->object.table->properties = columns;
            memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
            handles[0] = handles[1];
            req.opnum = op_MAPI_Restrict; req.handle_idx = 0;
            req.u.mapi_Restrict.restrictions.rt = RES_PROPERTY;
            req.u.mapi_Restrict.restrictions.res.resProperty.relop = RELOP_EQ;
            req.u.mapi_Restrict.restrictions.res.resProperty.ulPropTag = PR_MESSAGE_CLASS_UNICODE;
            req.u.mapi_Restrict.restrictions.res.resProperty.lpProp.ulPropTag = PR_MESSAGE_CLASS_UNICODE;
            req.u.mapi_Restrict.restrictions.res.resProperty.lpProp.value.lpszW = "IPM.ExtendedRule.Message";
            CHECK(EcDoRpc_RopRestrict(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
            CHECK(repl.error_code == MAPI_E_SUCCESS && to->object.table->denominator == 1);
            dp = emsmdbp_object_table_get_row_props(session, session->ctx, to, 0, MAPISTORE_PREFILTERED_QUERY, &rv);
            CHECK(dp && rv[0] == MAPI_E_SUCCESS && *(uint64_t *) dp[0] == mid);
            /* An empty restriction (AND of nothing) shows every row again. */
            memset(&req.u.mapi_Restrict.restrictions, 0, sizeof req.u.mapi_Restrict.restrictions);
            req.u.mapi_Restrict.restrictions.rt = RES_AND;
            CHECK(EcDoRpc_RopRestrict(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
            CHECK(repl.error_code == MAPI_E_SUCCESS && to->object.table->denominator == 2);
        }

        /* Deleting a rule deletes its FAI message. */
        memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
        handles[0] = fh->handle;
        req.opnum = op_MAPI_DeleteMessages; req.handle_idx = 0;
        req.u.mapi_DeleteMessages.cn_ids = 2;
        req.u.mapi_DeleteMessages.message_ids = (uint64_t []) { mid, mid2 };
        CHECK(EcDoRpc_RopDeleteMessages(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
        CHECK(repl.error_code == MAPI_E_SUCCESS);
        memset(&req, 0, sizeof req); memset(&repl, 0, sizeof repl);
        handles[0] = fh->handle; handles[1] = 0xFFFFFFFF;
        req.opnum = op_MAPI_GetContentsTable; req.handle_idx = 0;
        req.u.mapi_GetContentsTable.handle_idx = 1; req.u.mapi_GetContentsTable.TableFlags = TableFlags_Associated;
        CHECK(EcDoRpc_RopGetContentsTable(session, session->ctx, &req, &repl, handles, &size) == MAPI_E_SUCCESS);
        CHECK(repl.error_code == MAPI_E_SUCCESS && repl.u.mapi_GetContentsTable.RowCount == 0);
    }
    oc_emsmdb_disconnect(session);
    return 0;
}

/* Outlook's local free/busy and contact-link messages in native folders carry no public free/busy
   subject ("USER-/CN=RECIPIENTS/CN=name"): they must open all the same. */
static int test_native_message_without_freebusy_subject_opens(void)
{
    oc_emsmdb_session *session;
    const char *name, *prefix;
    struct emsmdbp_object *mailbox, *msg = NULL;
    void *created = NULL;
    uint64_t mid;
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    mailbox = emsmdbp_object_mailbox_init(session, session->ctx, ORG_OU "alice-0001", true);
    CHECK(mailbox && mapistore_indexing_get_new_folderID(session->ctx->mstore_ctx, &mid) == MAPISTORE_SUCCESS);
    CHECK(openchangedb_message_create(session, session->ctx->oc_ctx, "alice@example.invalid", mid, first_fids[1], true, &created) == MAPI_E_SUCCESS);
    CHECK(openchangedb_message_save(session->ctx->oc_ctx, created, 0) == MAPI_E_SUCCESS);
    CHECK(emsmdbp_object_message_open(session, session->ctx, mailbox, first_fids[1], mid, false, &msg, NULL) == MAPISTORE_SUCCESS && msg);
    oc_emsmdb_disconnect(session);
    return 0;
}

/* A backend that cannot reach its store (Dovecot down) must not fail logon or drop folders. */
static bool store_down;
static enum mapistore_error flaky_list_contexts(const char *user, struct indexing_context *ictx, TALLOC_CTX *mem,
                                                struct mapistore_contexts_list **list)
{
    *list = NULL;
    return store_down ? MAPISTORE_ERR_CONN_REFUSED : MAPISTORE_SUCCESS;
}

static int test_provision_store_down_keeps_folders(void)
{
    struct mapistore_backend fake;
    oc_emsmdb_session *session;
    const char *name, *prefix;
    uint64_t again[N_PROVISIONED + 1];
    memset(&fake, 0, sizeof fake);
    CHECK(mapistore_backend_init_defaults(&fake) == MAPISTORE_SUCCESS);
    fake.backend.name = "flaky"; fake.backend.description = "test"; fake.backend.namespace = "flaky://";
    fake.backend.init = fake_backend_init; fake.backend.list_contexts = flaky_list_contexts;
    CHECK(mapistore_backend_register(&fake) == MAPISTORE_SUCCESS);
    CHECK(connect_as("alice@example.invalid", ORG_OU "alice-0001", &session, &name, &prefix) == MAPI_E_SUCCESS);
    store_down = true;
    CHECK(emsmdbp_mailbox_provision(session->ctx, "alice@example.invalid") == MAPI_E_SUCCESS);
    store_down = false;
    if (provisioned_fids(session->ctx, again)) return 1;
    CHECK(memcmp(again, first_fids, sizeof again) == 0);
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
        test_address_types_locale_fallback() ||
        test_logon_private_mailbox() || test_logon_other_users_dn() ||
        test_provision_backend_takes_over_inbox() || test_provision_fallback_after_native() || test_provision_store_down_keeps_folders() ||
        test_provision_backend_takes_over_drafts() || test_outbox_taken_over() ||
        test_fai_in_backend_root_kept_in_openchangedb() || test_native_message_without_freebusy_subject_opens() ||
        test_connect_fails_closed() || test_execute()) return 1;
    talloc_free(oc_root);
    printf("oc_emsmdb null handles, directory connect checks and bounded execute: OK\n");
    return 0;
}
