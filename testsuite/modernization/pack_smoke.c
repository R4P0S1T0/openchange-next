/* Exercise the actual plugin, including malformed custom wire records. */
#include "mapiproxy/modules/mpm_pack.c"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "pack check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static bool fail_array, fail_copy;
void *__real__talloc_zero_array(const void *, size_t, unsigned, const char *);
void *__wrap__talloc_zero_array(const void *, size_t, unsigned, const char *);
void *__real__talloc_memdup(const void *, const void *, size_t, const char *);
void *__wrap__talloc_memdup(const void *, const void *, size_t, const char *);
void *__wrap__talloc_zero_array(const void *ctx, size_t size, unsigned count, const char *name)
{
    return fail_array ? NULL : __real__talloc_zero_array(ctx, size, count, name);
}
void *__wrap__talloc_memdup(const void *ctx, const void *data, size_t size, const char *name)
{
    return fail_copy ? NULL : __real__talloc_memdup(ctx, data, size, name);
}

static struct EcDoRpc *request(TALLOC_CTX *ctx, unsigned count, bool mixed)
{
    struct EcDoRpc *rpc = talloc_zero(ctx, struct EcDoRpc);
    struct mapi_request *r;
    unsigned i;
    if (rpc == NULL) return NULL;
    r = rpc->in.mapi_request = talloc_zero(rpc, struct mapi_request);
    if (r == NULL) return NULL;
    r->mapi_req = talloc_zero_array(r, struct EcDoRpc_MAPI_REQ, count + 1);
    r->handles = talloc_zero_array(r, uint32_t, 2);
    if (r->mapi_req == NULL || r->handles == NULL) return NULL;
    for (i = 0; i < count; i++) {
        r->mapi_req[i].opnum = mixed && i % 2 ? op_MAPI_GetStatus : op_MAPI_Release;
        r->mapi_req[i].logon_id = i % 16;
        r->mapi_req[i].handle_idx = i % 2;
    }
    r->length = 2 + count * 3;
    r->mapi_len = r->length + 8;
    r->handles[0] = 0x11223344;
    r->handles[1] = 0xaabbccdd;
    return rpc;
}

static int round_trip(TALLOC_CTX *ctx, unsigned count, bool mixed)
{
    struct EcDoRpc *rpc = request(ctx, count, mixed);
    struct ndr_push *before = ndr_push_init_ctx(ctx), *after;
    DATA_BLOB original, result;
    uint32_t length;
    CHECK(rpc != NULL && before != NULL);
    length = rpc->in.mapi_request->length;
    CHECK(NDR_ERR_CODE_IS_SUCCESS(ndr_push_mapi_request(before, NDR_SCALARS, rpc->in.mapi_request)));
    original = ndr_push_blob(before);
    CHECK(NT_STATUS_IS_OK(pack(ctx, rpc)));
    CHECK(rpc->in.mapi_request->mapi_len - rpc->in.mapi_request->length == 8);
    CHECK(NT_STATUS_IS_OK(unpack(ctx, rpc)));
    CHECK(rpc->in.mapi_request->length == length);
    CHECK(rpc->in.mapi_request->mapi_req[count].opnum == 0);
    after = ndr_push_init_ctx(ctx);
    CHECK(after != NULL);
    CHECK(NDR_ERR_CODE_IS_SUCCESS(ndr_push_mapi_request(after, NDR_SCALARS, rpc->in.mapi_request)));
    result = ndr_push_blob(after);
    CHECK(result.length == original.length && memcmp(result.data, original.data, result.length) == 0);
    return 0;
}

static int rejects(TALLOC_CTX *ctx, const uint8_t *data, size_t size)
{
    struct EcDoRpc *rpc = request(ctx, 1, false);
    struct mapi_request *r;
    struct EcDoRpc_MAPI_REQ *saved;
    size_t blocks;
    CHECK(rpc != NULL);
    r = rpc->in.mapi_request;
    r->mapi_req[0].opnum = op_MAPI_proxypack;
    r->mapi_req[0].u.mapi_proxypack.bin.cb = size;
    r->mapi_req[0].u.mapi_proxypack.bin.lpb = talloc_memdup(r->mapi_req, data, size);
    r->length = 7 + size;
    r->mapi_len = r->length + 8;
    saved = r->mapi_req;
    blocks = talloc_total_blocks(ctx);
    CHECK(NT_STATUS_EQUAL(unpack(ctx, rpc), NT_STATUS_INVALID_PARAMETER));
    CHECK(r->mapi_req == saved && r->length == 7 + size);
    CHECK(talloc_total_blocks(ctx) == blocks);
    talloc_free(rpc);
    return 0;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL), *cases;
    struct dcesrv_context *dce = talloc_zero(ctx, struct dcesrv_context);
    struct dcesrv_call_state call = {0};
    struct EcDoRpc *rpc;
    struct EcDoRpc_MAPI_REQ *saved;
    struct mpm_pack *config;
    struct ndr_push *ndr;
    const char *invalid[] = {"", "0x1,0x1", "0x1junk", "-1", "0", "ff", "a5", "100", "100000000000000000000", NULL};
    uint8_t valid[] = {0, op_MAPI_Release, 0, 0};
    uint8_t gap[] = {255, op_MAPI_Release, 0, 0};
    uint8_t duplicate[] = {0, op_MAPI_Release, 0, 0, 0, op_MAPI_Release, 0, 0};
    uint8_t reversed[] = {1, op_MAPI_Release, 0, 0, 0, op_MAPI_Release, 0, 0};
    uint8_t nested[] = {0, op_MAPI_proxypack, 0, 0, 0, 0};
    uint8_t terminator[] = {0, 0, 0, 0};
    unsigned i;
    size_t blocks;

    CHECK(ctx != NULL && dce != NULL);
    dce->lp_ctx = loadparm_init(dce);
    CHECK(dce->lp_ctx != NULL);
    CHECK(NT_STATUS_EQUAL(pack_init(dce), NT_STATUS_INVALID_PARAMETER));
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "mpm_pack:opnums", "0x01"));
    CHECK(NT_STATUS_IS_OK(pack_init(dce)));
    config = mpm;
    for (i = 0; invalid[i]; i++) {
        CHECK(lpcfg_set_cmdline(dce->lp_ctx, "mpm_pack:opnums", invalid[i]));
        CHECK(NT_STATUS_EQUAL(pack_init(dce), NT_STATUS_INVALID_PARAMETER));
        CHECK(mpm == config && mpm->mapi_calls[op_MAPI_Release]);
    }
    cases = talloc_new(ctx);
    CHECK(cases != NULL);
    CHECK(round_trip(cases, 1, false) == 0);
    CHECK(round_trip(cases, 7, true) == 0);
    CHECK(round_trip(cases, 300, false) == 0);
    CHECK(rejects(cases, NULL, 0) == 0);
    for (i = 1; i < sizeof(valid); i++) CHECK(rejects(cases, valid, i) == 0);
    CHECK(rejects(cases, gap, sizeof(gap)) == 0);
    CHECK(rejects(cases, duplicate, sizeof(duplicate)) == 0);
    CHECK(rejects(cases, reversed, sizeof(reversed)) == 0);
    CHECK(rejects(cases, nested, sizeof(nested)) == 0);
    CHECK(rejects(cases, terminator, sizeof(terminator)) == 0);

    rpc = request(cases, 2, true);
    CHECK(rpc != NULL);
    saved = rpc->in.mapi_request->mapi_req;
    blocks = talloc_total_blocks(cases);
    fail_array = true;
    CHECK(NT_STATUS_EQUAL(pack(cases, rpc), NT_STATUS_NO_MEMORY));
    fail_array = false;
    fail_copy = true;
    CHECK(NT_STATUS_EQUAL(pack(cases, rpc), NT_STATUS_NO_MEMORY));
    fail_copy = false;
    CHECK(rpc->in.mapi_request->mapi_req == saved && talloc_total_blocks(cases) == blocks);
    CHECK(NT_STATUS_IS_OK(pack(cases, rpc)));
    saved = rpc->in.mapi_request->mapi_req;
    blocks = talloc_total_blocks(cases);
    fail_array = true;
    CHECK(NT_STATUS_EQUAL(unpack(cases, rpc), NT_STATUS_NO_MEMORY));
    fail_array = false;
    CHECK(rpc->in.mapi_request->mapi_req == saved && talloc_total_blocks(cases) == blocks);
    CHECK(NT_STATUS_IS_OK(unpack(cases, rpc)));

    call.pkt.u.request.opnum = NDR_ECDORPC;
    rpc->in.mapi_request->mapi_len = rpc->in.mapi_request->length - 1;
    CHECK(NT_STATUS_EQUAL(pack_pull(&call, cases, rpc), NT_STATUS_INVALID_PARAMETER));
    rpc = request(cases, 1, false);
    CHECK(rpc != NULL);
    rpc->in.mapi_request->mapi_req[1].opnum = op_MAPI_Release; /* Missing terminator. */
    CHECK(NT_STATUS_EQUAL(pack_pull(&call, cases, rpc), NT_STATUS_INVALID_PARAMETER));
    rpc = request(cases, 2, false);
    CHECK(rpc != NULL);
    rpc->in.mapi_request->mapi_req[0].opnum = op_MAPI_proxypack;
    rpc->in.mapi_request->mapi_req[1].opnum = op_MAPI_proxypack;
    CHECK(NT_STATUS_EQUAL(pack_pull(&call, cases, rpc), NT_STATUS_INVALID_PARAMETER));
    rpc = request(cases, 0, false);
    CHECK(rpc != NULL && NT_STATUS_IS_OK(pack_pull(&call, cases, rpc)));

    /* Invalid custom data is rejected by the real hook, without a pack fallback. */
    rpc = request(cases, 1, false);
    CHECK(rpc != NULL);
    rpc->in.mapi_request->mapi_req[0].opnum = op_MAPI_proxypack;
    CHECK(NT_STATUS_EQUAL(pack_pull(&call, cases, rpc), NT_STATUS_INVALID_PARAMETER));
    mpm->lasthop = false;
    CHECK(NT_STATUS_IS_OK(pack_pull(&call, cases, rpc)));
    mpm->lasthop = true;

    /* Oversized output cannot wrap the 16-bit length field. */
    rpc = request(cases, 1, false);
    CHECK(rpc != NULL);
    saved = talloc_zero_array(cases, struct EcDoRpc_MAPI_REQ, 2);
    CHECK(saved != NULL);
    saved[0].opnum = op_MAPI_WriteStream;
    saved[0].u.mapi_WriteStream.data.length = 65530;
    saved[0].u.mapi_WriteStream.data.data = talloc_zero_array(saved, uint8_t, 65530);
    CHECK(saved[0].u.mapi_WriteStream.data.data != NULL);
    CHECK(NT_STATUS_EQUAL(replace_requests(cases, rpc->in.mapi_request, saved, 1), NT_STATUS_INVALID_PARAMETER));
    ndr = ndr_push_init_ctx(cases);
    CHECK(ndr != NULL); /* The original input is still valid after rejection. */
    CHECK(NDR_ERR_CODE_IS_SUCCESS(ndr_push_mapi_request(ndr, NDR_SCALARS, rpc->in.mapi_request)));

    /* Payloads owned by the original array survive both transformations. */
    rpc = request(cases, 1, false);
    CHECK(rpc != NULL);
    rpc->in.mapi_request->mapi_req[0].opnum = op_MAPI_WriteStream;
    rpc->in.mapi_request->mapi_req[0].u.mapi_WriteStream.data.data = talloc_memdup(rpc->in.mapi_request->mapi_req, "abc", 3);
    rpc->in.mapi_request->mapi_req[0].u.mapi_WriteStream.data.length = 3;
    rpc->in.mapi_request->length = 10;
    rpc->in.mapi_request->mapi_len = 18;
    mpm->mapi_calls[op_MAPI_WriteStream] = true;
    CHECK(NT_STATUS_IS_OK(pack(cases, rpc)) && NT_STATUS_IS_OK(unpack(cases, rpc)));
    CHECK(rpc->in.mapi_request->mapi_req[0].u.mapi_WriteStream.data.length == 3);
    CHECK(memcmp(rpc->in.mapi_request->mapi_req[0].u.mapi_WriteStream.data.data, "abc", 3) == 0);
    rpc = request(cases, 1, false);
    CHECK(rpc != NULL);
    rpc->in.mapi_request->mapi_req[0].opnum = op_MAPI_SetReceiveFolder;
    rpc->in.mapi_request->mapi_req[0].u.mapi_SetReceiveFolder.fid = 0x1122334455667788;
    rpc->in.mapi_request->mapi_req[0].u.mapi_SetReceiveFolder.lpszMessageClass = talloc_strdup(rpc->in.mapi_request->mapi_req, "IPM.Note");
    rpc->in.mapi_request->length = 22;
    rpc->in.mapi_request->mapi_len = 30;
    mpm->mapi_calls[op_MAPI_SetReceiveFolder] = true;
    CHECK(NT_STATUS_IS_OK(pack(cases, rpc)) && NT_STATUS_IS_OK(unpack(cases, rpc)));
    CHECK(rpc->in.mapi_request->length == 22);
    CHECK(strcmp(rpc->in.mapi_request->mapi_req[0].u.mapi_SetReceiveFolder.lpszMessageClass, "IPM.Note") == 0);
    talloc_free(dce);
    CHECK(mpm == NULL);
    talloc_free(ctx);
    puts("Pack wire round trips, malformed positions, length bounds, configuration and allocation failure checks passed");
    return 0;
}
