/* Regression checks for the hand-written NDR routines against current Samba. */
#include "libmapi/libmapi.h"
#include "libmapi/libmapi_private.h"
#include "gen_ndr/ndr_exchange.h"

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

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    int result;
    CHECK(ctx != NULL);
    result = connect_roundtrip(ctx) || reply_roundtrip(ctx) || restriction_switches(ctx);
    talloc_free(ctx);
    if (result == 0) puts("NDR request/reply round trips, array bounds and union switches passed");
    return result;
}
