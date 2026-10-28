/* Regression checks for the hand-written NDR routines against current Samba. */
#include "libmapi/libmapi.h"
#include "libmapi/libmapi_private.h"
#include "gen_ndr/ndr_exchange.h"

_Static_assert(PROP_TAG(PT_LONG, 0xFFFF) == 0xFFFF0003U, "High property IDs remain integer constants");

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "NDR check failed at line %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static int connect_roundtrip(TALLOC_CTX *ctx)
{
    struct EcDoConnectEx request = {0}, decoded = {0};
    struct ndr_push *push = ndr_push_init_ctx(ctx);
    struct ndr_pull *pull;
    uint32_t timestamp = 1234, aux_size = 0;
    DATA_BLOB blob;
    request.in.szUserDN = "/o=OpenChange/ou=Test/cn=Recipients/cn=alice";
    request.in.ulCpid = 1252;
    request.in.rgwClientVersion[0] = 15;
    request.in.pulTimeStamp = &timestamp;
    request.in.pcbAuxOut = &aux_size;
    CHECK(push != NULL);
    CHECK(ndr_push_EcDoConnectEx(push, NDR_IN, &request) == NDR_ERR_SUCCESS);
    blob = ndr_push_blob(push);
    pull = ndr_pull_init_blob(&blob, ctx);
    CHECK(pull != NULL);
    pull->flags |= LIBNDR_FLAG_REF_ALLOC;
    CHECK(ndr_pull_EcDoConnectEx(pull, NDR_IN, &decoded) == NDR_ERR_SUCCESS);
    CHECK(strcmp(decoded.in.szUserDN, request.in.szUserDN) == 0);
    CHECK(decoded.in.ulCpid == 1252);
    CHECK(*decoded.in.pulTimeStamp == timestamp);
    CHECK(pull->offset == blob.length);

    /* A varying array length greater than its maximum must be rejected. */
    CHECK(blob.length > 12);
    memset(blob.data + 8, 0xff, 4);
    memset(&decoded, 0, sizeof(decoded));
    pull = ndr_pull_init_blob(&blob, ctx);
    CHECK(pull != NULL);
    pull->flags |= LIBNDR_FLAG_REF_ALLOC;
    CHECK(ndr_pull_EcDoConnectEx(pull, NDR_IN, &decoded) == NDR_ERR_ARRAY_SIZE);
    return 0;
}

static int reply_roundtrip(TALLOC_CTX *ctx)
{
    struct EcDoConnectEx reply = {0}, decoded = {0};
    struct policy_handle handle = {0};
    const char *prefix = "/o=OpenChange", *display = "Alice";
    uint32_t polls = 100, retry = 2, delay = 3, icxr = 4, timestamp = 5678, aux_size = 0;
    struct ndr_push *push = ndr_push_init_ctx(ctx);
    struct ndr_pull *pull;
    DATA_BLOB blob;
    enum ndr_err_code status;
    reply.out.handle = &handle;
    reply.out.pcmsPollsMax = &polls;
    reply.out.pcRetry = &retry;
    reply.out.pcmsRetryDelay = &delay;
    reply.out.picxr = &icxr;
    reply.out.szDNPrefix = &prefix;
    reply.out.szDisplayName = &display;
    reply.out.pulTimeStamp = &timestamp;
    reply.out.pcbAuxOut = &aux_size;
    reply.out.result = MAPI_E_SUCCESS;
    CHECK(push != NULL);
    CHECK(ndr_push_EcDoConnectEx(push, NDR_OUT, &reply) == NDR_ERR_SUCCESS);
    blob = ndr_push_blob(push);
    pull = ndr_pull_init_blob(&blob, ctx);
    CHECK(pull != NULL);
    pull->flags |= LIBNDR_FLAG_REF_ALLOC;
    status = ndr_pull_EcDoConnectEx(pull, NDR_OUT, &decoded);
    if (status != NDR_ERR_SUCCESS) {
        fprintf(stderr, "reply decode: %s at %u/%zu\n", ndr_errstr(status), pull->offset, blob.length);
    }
    CHECK(status == NDR_ERR_SUCCESS);
    CHECK(strcmp(*decoded.out.szDNPrefix, prefix) == 0);
    CHECK(strcmp(*decoded.out.szDisplayName, display) == 0);
    CHECK(*decoded.out.pcmsPollsMax == polls);
    CHECK(*decoded.out.pulTimeStamp == timestamp);
    CHECK(decoded.out.result == MAPI_E_SUCCESS);
    CHECK(pull->offset == blob.length);
    return 0;
}

static int restriction_switches(TALLOC_CTX *ctx)
{
    union RestrictionVariable value = {0};
    struct ndr_push *push = ndr_push_init_ctx(ctx);
    struct ndr_pull *pull;
    DATA_BLOB blob;
    CHECK(push != NULL);
    CHECK(ndr_push_set_switch_value(push, &value, 0) == NDR_ERR_SUCCESS);
    CHECK(ndr_push_RestrictionVariable(push, NDR_SCALARS | NDR_BUFFERS, &value) == NDR_ERR_SUCCESS);
    blob = ndr_push_blob(push);
    pull = ndr_pull_init_blob(&blob, ctx);
    CHECK(pull != NULL);
    CHECK(ndr_pull_set_switch_value(pull, &value, 0) == NDR_ERR_SUCCESS);
    CHECK(ndr_pull_RestrictionVariable(pull, NDR_SCALARS | NDR_BUFFERS, &value) == NDR_ERR_SUCCESS);
    CHECK(ndr_push_set_switch_value(push, &value, 2) == NDR_ERR_SUCCESS);
    CHECK(ndr_push_RestrictionVariable(push, NDR_SCALARS, &value) == NDR_ERR_BAD_SWITCH);
    return 0;
}

static int rop_buffers(TALLOC_CTX *ctx)
{
    struct EcDoRpc_MAPI_REQ reqs[3] = {0};
    struct EcDoRpc_MAPI_REPL replies[3] = {0};
    uint8_t data[] = { 0x41, 0, 0xff };
    uint32_t handles[] = { 0x12345678 };
    struct mapi_request request = { .length = 13, .mapi_len = 17, .mapi_req = reqs, .handles = handles }, decoded = {0};
    struct mapi_response response = { .length = 19, .mapi_len = 23, .mapi_repl = replies, .handles = handles }, received = {0};
    struct ndr_push *push = ndr_push_init_ctx(ctx);
    struct ndr_pull *pull;
    DATA_BLOB blob;
    uint8_t malformed[][7] = {
        {0,0}, {1,0}, {8,0}, {2,0,1}, {5,0,1,0}, {3,0,0}, {5,0,0,0,0}
    };
    size_t lengths[] = {2,2,2,3,4,3,5};
    unsigned i;
    reqs[0].opnum = op_MAPI_WriteStream;
    reqs[0].u.mapi_WriteStream.data = data_blob_const(data, sizeof(data));
    reqs[1].opnum = op_MAPI_Release;
    CHECK(push && ndr_push_uint8(push, NDR_SCALARS, 0x55) == NDR_ERR_SUCCESS);
    CHECK(ndr_push_mapi_request(push, NDR_SCALARS, &request) == NDR_ERR_SUCCESS);
    CHECK(push->offset == request.mapi_len + 1);
    blob.data = push->data + 1; blob.length = push->offset - 1;
    pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull);
    pull->flags |= LIBNDR_FLAG_REMAINING | LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC;
    NDR_PULL_SET_MEM_CTX(pull, ctx, 0);
    CHECK(ndr_pull_mapi_request(pull, NDR_SCALARS, &decoded) == NDR_ERR_SUCCESS);
    CHECK(pull->offset == blob.length && decoded.mapi_req[1].opnum == op_MAPI_Release);
    CHECK(decoded.mapi_req[2].opnum == 0 && decoded.handles[0] == handles[0]);
    talloc_free(pull);
    CHECK(decoded.mapi_req[0].u.mapi_WriteStream.data.length == sizeof(data));
    CHECK(memcmp(decoded.mapi_req[0].u.mapi_WriteStream.data.data, data, sizeof(data)) == 0);

    replies[0].opnum = op_MAPI_ReadStream;
    replies[0].u.mapi_ReadStream.data = data_blob_const(data, sizeof(data));
    replies[1].opnum = op_MAPI_GetStatus;
    replies[1].error_code = MAPI_E_NOT_FOUND;
    push = ndr_push_init_ctx(ctx); CHECK(push);
    CHECK(ndr_push_uint8(push, NDR_SCALARS, 0x55) == NDR_ERR_SUCCESS);
    CHECK(ndr_push_mapi_response(push, NDR_SCALARS, &response) == NDR_ERR_SUCCESS);
    CHECK(push->offset == response.mapi_len + 1);
    blob.data = push->data + 1; blob.length = push->offset - 1;
    pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull);
    pull->flags |= LIBNDR_FLAG_REMAINING | LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC;
    NDR_PULL_SET_MEM_CTX(pull, ctx, 0);
    CHECK(ndr_pull_mapi_response(pull, NDR_SCALARS, &received) == NDR_ERR_SUCCESS);
    CHECK(pull->offset == blob.length && received.mapi_repl[2].opnum == 0);
    talloc_free(pull);
    CHECK(received.mapi_repl[1].error_code == MAPI_E_NOT_FOUND && received.handles[0] == handles[0]);
    CHECK(memcmp(received.mapi_repl[0].u.mapi_ReadStream.data.data, data, sizeof(data)) == 0);

    for (i = 0; i < sizeof(lengths)/sizeof(lengths[0]); i++) {
        blob = data_blob_const(malformed[i], lengths[i]);
        pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull);
        pull->flags |= LIBNDR_FLAG_REMAINING | LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC;
        CHECK(ndr_pull_mapi_request(pull, NDR_SCALARS, &decoded) != NDR_ERR_SUCCESS);
        pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull);
        pull->flags |= LIBNDR_FLAG_REMAINING | LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC;
        CHECK(ndr_pull_mapi_response(pull, NDR_SCALARS, &received) != NDR_ERR_SUCCESS);
    }
    request.length = 2; request.mapi_len = 6; request.mapi_req = NULL;
    push = ndr_push_init_ctx(ctx); CHECK(push);
    CHECK(ndr_push_mapi_request(push, NDR_SCALARS, &request) == NDR_ERR_SUCCESS);
    blob = ndr_push_blob(push); pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull);
    pull->flags |= LIBNDR_FLAG_REMAINING | LIBNDR_FLAG_NOALIGN;
    CHECK(ndr_pull_mapi_request(pull, NDR_SCALARS, &decoded) == NDR_ERR_SUCCESS);
    CHECK(decoded.mapi_req == NULL && decoded.handles[0] == handles[0]);
    request.length = 0;
    CHECK(ndr_push_mapi_request(push, NDR_SCALARS, &request) != NDR_ERR_SUCCESS);
    response.length = 2; response.mapi_len = 3;
    CHECK(ndr_push_mapi_response(push, NDR_SCALARS, &response) != NDR_ERR_SUCCESS);
    return 0;
}

static int rpc_frames(TALLOC_CTX *ctx)
{
    struct ndr_push *plain = ndr_push_init_ctx(ctx), *compressed, *wire;
    struct ndr_pull *pull, *uncompressed;
    struct mapi2k7_request request = {0};
    struct mapi2k7_response response = {0};
    struct RPC_HEADER_EXT header = {0};
    uint8_t *snapshot;
    DATA_BLOB body, blob;
    unsigned flags;
    CHECK(plain && ndr_push_uint16(plain, NDR_SCALARS, 2) == NDR_ERR_SUCCESS);
    for (flags = 0; flags < 4; flags++) {
        body = ndr_push_blob(plain);
        if (flags & RHEF_Compressed) {
            compressed = ndr_push_init_ctx(ctx); CHECK(compressed);
            CHECK(ndr_push_lzxpress_compress(compressed, plain) == NDR_ERR_SUCCESS);
            body = ndr_push_blob(compressed);
        }
        header.Flags = flags | RHEF_Last;
        header.Size = body.length; header.SizeActual = 2;
        wire = ndr_push_init_ctx(ctx); CHECK(wire);
        wire->flags |= LIBNDR_FLAG_NOALIGN;
        CHECK(ndr_push_RPC_HEADER_EXT(wire, NDR_SCALARS, &header) == NDR_ERR_SUCCESS);
        CHECK(ndr_push_bytes(wire, body.data, body.length) == NDR_ERR_SUCCESS);
        blob = ndr_push_blob(wire);
        if (flags & RHEF_XorMagic) obfuscate_data(blob.data + 8, body.length, 0xA5);
        snapshot = talloc_memdup(ctx, blob.data, blob.length); CHECK(snapshot);
        pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull);
        pull->flags |= LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC;
        NDR_PULL_SET_MEM_CTX(pull, ctx, 0);
        CHECK(ndr_pull_mapi2k7_request(pull, NDR_SCALARS, &request) == NDR_ERR_SUCCESS);
        CHECK(pull->offset == blob.length);
        talloc_free(pull);
        CHECK(request.mapi_request->length == 2 && request.mapi_request->mapi_req == NULL);
        CHECK(memcmp(blob.data, snapshot, blob.length) == 0);
        pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull);
        pull->flags |= LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC;
        CHECK(ndr_pull_mapi2k7_response(pull, NDR_SCALARS, &response) == NDR_ERR_SUCCESS);
        CHECK(response.mapi_response->length == 2 && pull->offset == blob.length);
        CHECK(memcmp(blob.data, snapshot, blob.length) == 0);
        blob.data[0] = 1;
        pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull);
        pull->flags |= LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC;
        CHECK(ndr_pull_mapi2k7_request(pull, NDR_SCALARS, &request) != NDR_ERR_SUCCESS);
        blob.data[0] = 0; blob.data[3] = 0x80;
        pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull);
        pull->flags |= LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC;
        CHECK(ndr_pull_mapi2k7_response(pull, NDR_SCALARS, &response) != NDR_ERR_SUCCESS);
        memcpy(blob.data, snapshot, blob.length); blob.data[4]++; /* Declared frame exceeds input. */
        pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull);
        pull->flags |= LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC;
        CHECK(ndr_pull_mapi2k7_request(pull, NDR_SCALARS, &request) != NDR_ERR_SUCCESS);
    }
    blob = ndr_push_blob(plain); pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull);
    CHECK(ndr_pull_lzxpress_decompress(pull, &uncompressed, -1) == NDR_ERR_RANGE);
    CHECK(ndr_pull_lzxpress_decompress(pull, &uncompressed, 0x10001) == NDR_ERR_RANGE);
    return 0;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    int result;
    CHECK(ctx != NULL);
    result = connect_roundtrip(ctx) || reply_roundtrip(ctx) || restriction_switches(ctx) || rop_buffers(ctx) || rpc_frames(ctx);
    talloc_free(ctx);
    if (result == 0) puts("NDR request/reply round trips, array bounds and union switches passed");
    return result;
}
