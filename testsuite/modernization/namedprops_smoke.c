/* Actual named-property ROP and LDB backend, with injected transaction failures. */
#include "mapiproxy/servers/default/emsmdb/oxcprpt.c"
#include "mapiproxy/libmapistore/backends/namedprops_ldb.c"
#include "mapiproxy/libmapistore/mapistore_namedprops.c"
#include "mapiproxy/libmapiserver/libmapiserver_oxcprpt.c"
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
    talloc_free(ctx); unlink(path);
    puts("Named properties: literal LDB names, ROP validation, duplicate names, rollback and ID exhaustion: OK");
    return 0;
}
