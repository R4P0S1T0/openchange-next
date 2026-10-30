/* Actual named-property ROP and LDB backend, with injected transaction failures. */
#include "mapiproxy/servers/default/emsmdb/oxcprpt.c"
#include "mapiproxy/libmapistore/backends/namedprops_ldb.c"
#include "mapiproxy/libmapistore/mapistore_namedprops.c"
#include "mapiproxy/libmapiserver/libmapiserver_oxcprpt.c"
#include "mapiproxy/libmapiserver/libmapiserver_oxcdata.c"
#include <assert.h>

void mapistore_set_errno(int status) { errno = status; }

static enum { FAIL_NONE, FAIL_LOOKUP, FAIL_START, FAIL_NEXT, FAIL_CREATE, FAIL_COMMIT, FAIL_CANCEL } failure;
static unsigned starts, commits, cancels, creates;
static struct MAPINAMEID *concurrent_name;
static bool duplicate_insert;
static enum mapistore_error start(struct namedprops_context *backend)
{
    starts++;
    if (concurrent_name) assert(create_id(backend, *concurrent_name, 0x8001) == MAPISTORE_SUCCESS);
    return failure == FAIL_START ? MAPISTORE_ERR_DATABASE_OPS : transaction_start(backend);
}
static enum mapistore_error commit(struct namedprops_context *backend)
{
    commits++;
    return failure == FAIL_COMMIT ? MAPISTORE_ERR_DATABASE_OPS : transaction_commit(backend);
}
static enum mapistore_error cancel(struct namedprops_context *backend)
{
    enum mapistore_error ret = transaction_cancel(backend);
    cancels++;
    return failure == FAIL_CANCEL ? MAPISTORE_ERR_DATABASE_OPS : ret;
}
static enum mapistore_error next(struct namedprops_context *backend, uint16_t *id)
{
    return failure == FAIL_NEXT ? MAPISTORE_ERR_NOT_AVAILABLE : next_unused_id(backend, id);
}
static enum mapistore_error lookup(struct namedprops_context *backend, struct MAPINAMEID name, uint16_t *id)
{
    return failure == FAIL_LOOKUP ? MAPISTORE_ERR_DATABASE_OPS : get_mapped_id(backend, name, id);
}
static enum mapistore_error create(struct namedprops_context *backend, struct MAPINAMEID name, uint16_t id)
{
    creates++;
    if (duplicate_insert) {
        assert(create_id(backend, name, id + 10) == MAPISTORE_SUCCESS);
        return MAPISTORE_ERR_EXIST;
    }
    if ((failure == FAIL_CREATE || failure == FAIL_CANCEL) && creates == 2) return MAPISTORE_ERR_DATABASE_OPS;
    return create_id(backend, name, id);
}

static void run(TALLOC_CTX *ctx, struct namedprops_context *backend,
    struct MAPINAMEID *names, uint16_t count, uint8_t flags, enum MAPISTATUS expected)
{
    struct mapistore_context store = { .nprops_ctx = backend };
    struct emsmdbp_context provider = { .mstore_ctx = &store };
    struct EcDoRpc_MAPI_REQ request = {0};
    struct EcDoRpc_MAPI_REPL response = {0};
    uint32_t handle = 0;
    uint16_t size = 0;
    request.opnum = 0x56; request.handle_idx = 3;
    request.u.mapi_GetIDsFromNames.count = count;
    request.u.mapi_GetIDsFromNames.nameid = names;
    request.u.mapi_GetIDsFromNames.ulFlags = flags;
    starts = commits = cancels = creates = 0;
    assert(EcDoRpc_RopGetPropertyIdsFromNames(ctx, &provider, &request, &response, &handle, &size) == MAPI_E_SUCCESS);
    assert(response.error_code == expected && response.opnum == request.opnum && response.handle_idx == 3);
    assert(size == libmapiserver_RopGetPropertyIdsFromNames_size(&response));
    if (expected == MAPI_E_SUCCESS || expected == MAPI_W_ERRORS_RETURNED) {
        assert(response.u.mapi_GetIDsFromNames.count == count);
        if (expected == MAPI_W_ERRORS_RETURNED) assert(response.u.mapi_GetIDsFromNames.propID[0] == 0);
        if (count == 3 && expected == MAPI_E_SUCCESS) {
            assert(response.u.mapi_GetIDsFromNames.propID[0] == response.u.mapi_GetIDsFromNames.propID[1]);
            assert(response.u.mapi_GetIDsFromNames.propID[2] == response.u.mapi_GetIDsFromNames.propID[0] + 1);
        }
        talloc_free(response.u.mapi_GetIDsFromNames.propID);
    } else {
        assert(!response.u.mapi_GetIDsFromNames.count && !response.u.mapi_GetIDsFromNames.propID);
    }
}

static void ldb_reverse_name_checks(TALLOC_CTX *ctx)
{
    static const char guid[] = "00020329-0000-0000-c000-000000000046";
    char ascii126[127], ascii127[128];
    struct {
        const char *cn, *object_class, *guid;
        enum mapistore_error status;
        unsigned name_size;
    } cases[] = {
        { ascii126, "MNID_STRING", guid, MAPISTORE_SUCCESS, 254 },
        { "0xffffffff", "MNID_ID", guid, MAPISTORE_SUCCESS, 0 },
        { "caf\xc3\xa9", "MNID_STRING", guid, MAPISTORE_SUCCESS, 10 },
        { "\xf0\x9f\x98\x80", "MNID_STRING", guid, MAPISTORE_SUCCESS, 6 },
        { ascii127, "MNID_STRING", guid, MAPISTORE_ERR_INVALID_DATA, 0 },
        { "truncated\xc3", "MNID_STRING", guid, MAPISTORE_ERR_INVALID_DATA, 0 },
        { "name", "MNID_STRING", "bad-guid", MAPISTORE_ERR_INVALID_DATA, 0 },
        { "name", "MNID_STRING", NULL, MAPISTORE_ERR_INVALID_DATA, 0 },
        { "name", NULL, guid, MAPISTORE_ERR_INVALID_DATA, 0 },
        { "name", "unknown", guid, MAPISTORE_ERR_INVALID_DATA, 0 },
        { NULL, "MNID_STRING", guid, MAPISTORE_ERR_INVALID_DATA, 0 },
        { "0x100000000", "MNID_ID", guid, MAPISTORE_ERR_INVALID_DATA, 0 },
        { "-1", "MNID_ID", guid, MAPISTORE_ERR_INVALID_DATA, 0 },
        { " -ffffffffffffffff", "MNID_ID", guid, MAPISTORE_ERR_INVALID_DATA, 0 },
        { "\t-0xffffffffffffffff", "MNID_ID", guid, MAPISTORE_ERR_INVALID_DATA, 0 },
        { " -ffffffff00000001", "MNID_ID", guid, MAPISTORE_ERR_INVALID_DATA, 0 },
        { "0x12junk", "MNID_ID", guid, MAPISTORE_ERR_INVALID_DATA, 0 },
        { "", "MNID_ID", guid, MAPISTORE_ERR_INVALID_DATA, 0 }
    };
    TALLOC_CTX *owner = talloc_new(ctx), *limited;
    struct ldb_context *db = ldb_init(ctx, NULL);
    struct namedprops_context backend = { .data = db, .get_nameid = get_nameid, .get_mapped_id = get_mapped_id };
    struct MAPINAMEID *name, *probe;
    struct MAPINAMEID original = { .ulKind = MNID_STRING };
    uint16_t mapped;
    struct GUID expected_guid;
    struct ldb_message *msg;
    enum mapistore_error status;
    size_t i, limit, blocks;
    char path[] = "/tmp/openchange-reverse-namedprops-XXXXXX";
    int fd = mkstemp(path);

    assert(owner && db && fd >= 0); close(fd); unlink(path);
    assert(ldb_connect(db, path, 0, NULL) == LDB_SUCCESS);
    assert(NT_STATUS_IS_OK(GUID_from_string(guid, &expected_guid)));
    memset(ascii126, 'a', 126); ascii126[126] = '\0';
    memset(ascii127, 'a', 127); ascii127[127] = '\0';
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        msg = ldb_msg_new(ctx); assert(msg);
        /* An OU RDN lets the missing-cn fixture stay absent in LDB. */
        msg->dn = ldb_dn_new_fmt(msg, db, "OU=reverse-%zu", i);
        assert(msg->dn);
        if (cases[i].cn) assert(ldb_msg_add_string(msg, "cn", cases[i].cn) == LDB_SUCCESS);
        if (cases[i].object_class) assert(ldb_msg_add_string(msg, "objectClass", cases[i].object_class) == LDB_SUCCESS);
        if (cases[i].guid) assert(ldb_msg_add_string(msg, "oleguid", cases[i].guid) == LDB_SUCCESS);
        assert(ldb_msg_add_fmt(msg, "mappedId", "%zu", 0x8100 + i) == LDB_SUCCESS);
        assert(ldb_add(db, msg) == LDB_SUCCESS);
        talloc_free(msg);
        name = (void *)1;
        blocks = talloc_total_blocks(owner);
        status = mapistore_namedprops_get_nameid(&backend, 0x8100 + i, owner, &name);
        if (status != cases[i].status) fprintf(stderr, "reverse fixture %zu: status %d, expected %d\n", i, status, cases[i].status);
        assert(status == cases[i].status);
        if (status == MAPISTORE_SUCCESS) {
            assert(name && talloc_parent(name) == owner && GUID_equal(&name->lpguid, &expected_guid));
            if (cases[i].name_size) {
                assert(name->ulKind == MNID_STRING && name->kind.lpwstr.NameSize == cases[i].name_size);
                /* Search temporaries are already freed on return. */
                assert(talloc_parent(name->kind.lpwstr.Name) == name && !strcmp(name->kind.lpwstr.Name, cases[i].cn));
            } else {
                assert(name->ulKind == MNID_ID && name->kind.lid == UINT32_MAX);
            }
            talloc_free(name);
        } else {
            assert(!name);
        }
        assert(talloc_total_blocks(owner) == blocks);
    }
    original.lpguid = expected_guid; original.kind.lpwstr.Name = "roundtrip*(ops),\\caf\xc3\xa9";
    assert(create_id(&backend, original, 0x8201) == MAPISTORE_SUCCESS);
    assert(mapistore_namedprops_get_mapped_id(&backend, original, &mapped) == MAPISTORE_SUCCESS && mapped == 0x8201);
    assert(mapistore_namedprops_get_nameid(&backend, mapped, owner, &name) == MAPISTORE_SUCCESS);
    assert(name->ulKind == MNID_STRING && GUID_equal(&name->lpguid, &original.lpguid));
    assert(!strcmp(name->kind.lpwstr.Name, original.kind.lpwstr.Name));
    talloc_free(name);
    msg = ldb_msg_new(ctx); assert(msg);
    msg->dn = ldb_dn_new(msg, db, "OU=duplicate");
    assert(msg->dn && ldb_msg_add_string(msg, "mappedId", "33024") == LDB_SUCCESS);
    assert(ldb_add(db, msg) == LDB_SUCCESS); talloc_free(msg);
    name = (void *)1;
    assert(mapistore_namedprops_get_nameid(&backend, 0x8100, owner, &name) == MAPISTORE_ERR_INVALID_DATA && !name);
    name = (void *)1;
    assert(mapistore_namedprops_get_nameid(&backend, 0x8200, owner, &name) == MAPISTORE_ERROR && !name);
    assert(get_nameid(&backend, 0x8101, NULL, &name) == MAPISTORE_SUCCESS && name->kind.lid == UINT32_MAX);
    talloc_free(name);
    name = (void *)1;
    assert(get_nameid(NULL, 0x8101, owner, &name) == MAPISTORE_ERR_INVALID_PARAMETER && !name);
    backend.data = NULL; name = (void *)1;
    assert(get_nameid(&backend, 0x8101, owner, &name) == MAPISTORE_ERR_INVALID_PARAMETER && !name);
    backend.data = db;
    assert(get_nameid(&backend, 0x8101, owner, NULL) == MAPISTORE_ERR_INVALID_PARAMETER);

    limited = talloc_new(ctx); assert(limited);
    assert(talloc_set_memlimit(limited, 1) == 0);
    name = (void *)1;
    assert(get_nameid(&backend, 0x8102, limited, &name) == MAPISTORE_ERR_NO_MEMORY && !name);
    assert(talloc_total_blocks(limited) == 1);
    /* Find the object-only budget without assuming talloc's header size. */
    for (limit = 1; limit < 4096; limit++) {
        assert(talloc_set_memlimit(limited, limit) == 0);
        probe = talloc_zero(limited, struct MAPINAMEID);
        if (probe) break;
    }
    assert(probe && limit < 4096); talloc_free(probe);
    name = (void *)1;
    assert(get_nameid(&backend, 0x8102, limited, &name) == MAPISTORE_ERR_NO_MEMORY && !name);
    assert(talloc_total_blocks(limited) == 1);
    talloc_free(limited); talloc_free(owner); talloc_free(db); unlink(path);
    puts("LDB reverse names: Unicode sizes, invalid records, ownership and allocation failures: OK");
}

static void get_names_from_ids_checks(TALLOC_CTX *ctx)
{
    struct ldb_context *db = ldb_init(ctx, NULL);
    struct namedprops_context backend = { .data = db, .get_nameid = get_nameid };
    struct mapistore_context store = { .nprops_ctx = &backend };
    struct emsmdbp_context provider = {0};
    struct EcDoRpc_MAPI_REQ request = {0};
    struct EcDoRpc_MAPI_REPL reply;
    struct GetNamesFromIDs_repl *response = &reply.u.mapi_GetNamesFromIDs;
    struct MAPINAMEID numeric = { .ulKind = MNID_ID }, string = { .ulKind = MNID_STRING };
    struct GUID ps_mapi, zero_guid = {0};
    uint16_t ids[] = { 0x3001, 0x8001, 0x8002, 0x8fff };
    uint32_t handle = 0;
    uint16_t size;
    TALLOC_CTX *owner, *limited;
    size_t blocks;
    char path[] = "/tmp/openchange-get-names-XXXXXX";
    int fd = mkstemp(path);

    assert(db && fd >= 0); close(fd); unlink(path);
    assert(ldb_connect(db, path, 0, NULL) == LDB_SUCCESS);
    request.opnum = 0x55; request.handle_idx = 3;
    size = 11;
    assert(EcDoRpc_RopGetNamesFromIDs(ctx, &provider, &request, &reply, &handle, &size) == MAPI_E_NOT_INITIALIZED);
    provider.mstore_ctx = &store; store.nprops_ctx = NULL;
    assert(EcDoRpc_RopGetNamesFromIDs(ctx, &provider, &request, &reply, &handle, &size) == MAPI_E_NOT_INITIALIZED);
    store.nprops_ctx = &backend;

    memset(&reply, 0xa5, sizeof(reply)); size = 11;
    assert(EcDoRpc_RopGetNamesFromIDs(ctx, &provider, &request, &reply, &handle, &size) == MAPI_E_SUCCESS);
    assert(reply.error_code == MAPI_E_SUCCESS && reply.opnum == 0x55 && reply.handle_idx == 3);
    assert(response->count == 0 && size == 19);
    assert(size == 11 + libmapiserver_RopGetNamesFromIDs_size(&reply));
    talloc_free(response->nameid);

    request.u.mapi_GetNamesFromIDs.PropertyIdCount = 1;
    memset(&reply, 0xa5, sizeof(reply)); size = 11;
    assert(EcDoRpc_RopGetNamesFromIDs(ctx, &provider, &request, &reply, &handle, &size) == MAPI_E_SUCCESS);
    assert(reply.error_code == MAPI_E_INVALID_PARAMETER && reply.opnum == 0x55 && reply.handle_idx == 3);
    assert(!response->count && !response->nameid && size == 17);
    assert(size == 11 + libmapiserver_RopGetNamesFromIDs_size(&reply));

    request.u.mapi_GetNamesFromIDs.PropertyIds = ids;
    limited = talloc_new(ctx);
    assert(limited && talloc_set_memlimit(limited, 1) == 0);
    memset(&reply, 0xa5, sizeof(reply)); size = 11;
    assert(EcDoRpc_RopGetNamesFromIDs(limited, &provider, &request, &reply, &handle, &size) == MAPI_E_SUCCESS);
    assert(reply.error_code == MAPI_E_NOT_ENOUGH_MEMORY && reply.opnum == 0x55 && reply.handle_idx == 3);
    assert(!response->count && !response->nameid && size == 17);
    assert(size == 11 + libmapiserver_RopGetNamesFromIDs_size(&reply));
    assert(talloc_total_blocks(limited) == 1); talloc_free(limited);

    assert(NT_STATUS_IS_OK(GUID_from_string("00020329-0000-0000-c000-000000000046", &numeric.lpguid)));
    string.lpguid = numeric.lpguid;
    numeric.kind.lid = 0x12345678; string.kind.lpwstr.Name = "caf\xc3\xa9";
    assert(create_id(&backend, numeric, 0x8001) == MAPISTORE_SUCCESS);
    assert(create_id(&backend, string, 0x8002) == MAPISTORE_SUCCESS);
    assert(NT_STATUS_IS_OK(GUID_from_string(PS_MAPI, &ps_mapi)));
    blocks = talloc_total_blocks(ctx);
    owner = talloc_new(ctx); assert(owner);
    request.u.mapi_GetNamesFromIDs.PropertyIdCount = 4;
    memset(&reply, 0xa5, sizeof(reply)); size = 11;
    assert(EcDoRpc_RopGetNamesFromIDs(owner, &provider, &request, &reply, &handle, &size) == MAPI_E_SUCCESS);
    assert(reply.error_code == MAPI_E_SUCCESS && reply.opnum == 0x55 && reply.handle_idx == 3);
    assert(response->count == 4 && response->nameid && size == 106);
    assert(size == 11 + libmapiserver_RopGetNamesFromIDs_size(&reply));
    assert(response->nameid[0].ulKind == MNID_ID && GUID_equal(&response->nameid[0].lpguid, &ps_mapi));
    assert(response->nameid[0].kind.lid == 0x3001001f);
    assert(response->nameid[1].ulKind == MNID_ID && GUID_equal(&response->nameid[1].lpguid, &numeric.lpguid));
    assert(response->nameid[1].kind.lid == 0x12345678);
    assert(response->nameid[2].ulKind == MNID_STRING && GUID_equal(&response->nameid[2].lpguid, &string.lpguid));
    assert(response->nameid[2].kind.lpwstr.NameSize == 10);
    assert(!strcmp(response->nameid[2].kind.lpwstr.Name, "caf\xc3\xa9"));
    assert(talloc_parent(talloc_parent(response->nameid[2].kind.lpwstr.Name)) == response->nameid);
    assert(response->nameid[3].ulKind == 0xff && GUID_equal(&response->nameid[3].lpguid, &zero_guid));
    assert(response->nameid[3].kind.lpwstr.NameSize == 0 && !response->nameid[3].kind.lpwstr.Name);
    talloc_steal(ctx, response->nameid); talloc_free(owner);
    assert(!strcmp(response->nameid[2].kind.lpwstr.Name, "caf\xc3\xa9"));
    talloc_free(response->nameid);
    assert(talloc_total_blocks(ctx) == blocks);
    talloc_free(db); unlink(path);
    puts("GetNamesFromIDs: validation, allocation failure, legacy results, sizes and string lifetime: OK");
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    struct ldb_context *db = ldb_init(ctx, NULL);
    struct namedprops_context backend = {
        .data = db, .get_mapped_id = lookup, .next_unused_id = next, .create_id = create,
        .transaction_start = start, .transaction_commit = commit, .transaction_cancel = cancel
    };
    struct MAPINAMEID names[3] = {{ .ulKind = MNID_STRING }, { .ulKind = MNID_STRING }, { .ulKind = MNID_ID }};
    struct ldb_message *msg;
    uint16_t id = 17;
    size_t blocks;
    TALLOC_CTX *limited;
    char path[] = "/tmp/openchange-namedprops-XXXXXX";
    int fd = mkstemp(path);
    assert(ctx && db && fd >= 0); close(fd); unlink(path);
    assert(ldb_connect(db, path, 0, NULL) == LDB_SUCCESS);
    names[0].kind.lpwstr.Name = "name*(ops),\\\noleguid: injected";
    names[1] = names[0]; names[2].kind.lid = 123;
    assert(next_unused_id(&backend, &id) == MAPISTORE_SUCCESS && id == 0x8001);
    assert(get_mapped_id(&backend, names[0], &id) == MAPISTORE_ERR_NOT_FOUND);
    run(ctx, &backend, names, 3, GetIDsFromNames_GetOnly, MAPI_W_ERRORS_RETURNED);
    assert(!starts && !creates);
    for (failure = FAIL_LOOKUP; failure <= FAIL_CANCEL; failure++) {
        run(ctx, &backend, names, 3, GetIDsFromNames_GetOrCreate,
            failure == FAIL_NEXT ? MAPI_E_NOT_ENOUGH_MEMORY : MAPI_E_UNABLE_TO_COMPLETE);
        assert(cancels == (failure != FAIL_LOOKUP && failure != FAIL_START));
        assert(get_mapped_id(&backend, names[0], &id) == MAPISTORE_ERR_NOT_FOUND);
        assert(get_mapped_id(&backend, names[2], &id) == MAPISTORE_ERR_NOT_FOUND);
    }
    failure = FAIL_NONE;
    concurrent_name = &names[0];
    run(ctx, &backend, names, 1, GetIDsFromNames_GetOrCreate, MAPI_E_SUCCESS);
    assert(starts == 1 && commits == 1 && !creates && !cancels);
    assert(get_mapped_id(&backend, names[0], &id) == MAPISTORE_SUCCESS && id == 0x8001);
    /* Use a fresh name for the remaining transaction tests. */
    names[0].kind.lpwstr.Name = "next*(ops),\\\noleguid: injected";
    names[1] = names[0]; concurrent_name = NULL;
    limited = talloc_new(ctx);
    assert(limited && talloc_set_memlimit(limited, 1) == 0);
    run(limited, &backend, names, 3, GetIDsFromNames_GetOrCreate, MAPI_E_NOT_ENOUGH_MEMORY);
    assert(!starts && !creates); talloc_free(limited);
    assert(mapistore_namedprops_transaction_cancel(NULL) == MAPISTORE_ERR_INVALID_PARAMETER);
    run(ctx, &backend, names, 3, GetIDsFromNames_GetOrCreate, MAPI_E_SUCCESS);
    assert(starts == 1 && commits == 1 && creates == 2 && !cancels);
    assert(get_mapped_id(&backend, names[0], &id) == MAPISTORE_SUCCESS && id == 0x8002);
    blocks = talloc_total_blocks(ctx);
    run(ctx, &backend, names, 3, GetIDsFromNames_GetOnly, MAPI_E_SUCCESS);
    assert(!starts && !creates && talloc_total_blocks(ctx) == blocks);
    run(ctx, &backend, NULL, 1, GetIDsFromNames_GetOrCreate, MAPI_E_INVALID_PARAMETER);
    run(ctx, &backend, names, 1, 99, MAPI_E_INVALID_PARAMETER);
    names[0].ulKind = 99;
    run(ctx, &backend, names, 1, GetIDsFromNames_GetOrCreate, MAPI_E_INVALID_PARAMETER);
    names[0].ulKind = MNID_STRING; names[0].kind.lpwstr.Name = NULL;
    run(ctx, &backend, names, 1, GetIDsFromNames_GetOrCreate, MAPI_E_INVALID_PARAMETER);
    run(ctx, &backend, NULL, 0, GetIDsFromNames_GetOrCreate, MAPI_E_SUCCESS);
    names[0].kind.lpwstr.Name = "duplicate winner";
    duplicate_insert = true;
    run(ctx, &backend, names, 1, GetIDsFromNames_GetOrCreate, MAPI_E_SUCCESS);
    duplicate_insert = false;
    assert(get_mapped_id(&backend, names[0], &id) == MAPISTORE_SUCCESS && id == 0x800e);
    names[0].kind.lpwstr.Name = "last";
    assert(create_id(&backend, names[0], 0xfffd) == MAPISTORE_SUCCESS);
    assert(next_unused_id(&backend, &id) == MAPISTORE_SUCCESS && id == 0xfffe);
    names[0].kind.lpwstr.Name = "overflow"; names[2].kind.lid++;
    run(ctx, &backend, names, 3, GetIDsFromNames_GetOrCreate, MAPI_E_NOT_ENOUGH_MEMORY);
    assert(cancels == 1 && get_mapped_id(&backend, names[0], &id) == MAPISTORE_ERR_NOT_FOUND);
    assert(create_id(&backend, names[0], 0xfffe) == MAPISTORE_SUCCESS);
    id = 17;
    assert(next_unused_id(&backend, &id) == MAPISTORE_ERR_NOT_AVAILABLE && id == 17);
    msg = ldb_msg_new(ctx); assert(msg);
    msg->dn = ldb_dn_new(msg, db, "CN=duplicate");
    assert(ldb_msg_add_string(msg, "objectClass", "MNID_STRING") == LDB_SUCCESS);
    assert(ldb_msg_add_string(msg, "oleguid", "00000000-0000-0000-0000-000000000000") == LDB_SUCCESS);
    assert(ldb_msg_add_string(msg, "cn", names[0].kind.lpwstr.Name) == LDB_SUCCESS);
    assert(ldb_msg_add_string(msg, "mappedId", "32770") == LDB_SUCCESS && ldb_add(db, msg) == LDB_SUCCESS);
    assert(get_mapped_id(&backend, names[0], &id) == MAPISTORE_ERR_INVALID_DATA && id == 17);
    ldb_reverse_name_checks(ctx);
    get_names_from_ids_checks(ctx);
    talloc_free(ctx); unlink(path);
    puts("Named properties: literal LDB names, ROP validation, duplicate names, rollback and ID exhaustion: OK");
    return 0;
}
