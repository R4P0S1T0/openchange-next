/* Actual capture reader with generated RPC/ROP fixtures and real files. */
int propsdump_program_main(int argc, const char **argv);
#define main propsdump_program_main
#include "utils/mapipropsdump.c"
#include <fcntl.h>
#undef main

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "Property dump check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static bool save_capture(const char *path, struct ndr_push *push)
{
    int fd = open(path, O_WRONLY | O_TRUNC);
    ssize_t written;
    if (fd == -1) return false;
    written = write(fd, push->data, push->offset);
    close(fd);
    return written == push->offset;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    struct EcDoRpc_MAPI_REQ operations[2] = { { .opnum = op_MAPI_GetProps } };
    struct EcDoRpc_MAPI_REPL replies[2] = { { .opnum = op_MAPI_GetProps, .error_code = MAPI_E_NO_SUPPORT } };
    enum MAPITAGS tag = PidTagDisplayName;
    uint32_t handle_value = 42, flags = 0, capacity = 256, aux = 0, elapsed = 0, output_size;
    struct policy_handle handle = {0};
    struct mapi_request request = { .mapi_req = operations, .handles = &handle_value };
    struct mapi_response response = { .length = 8, .mapi_len = 12, .mapi_repl = replies, .handles = &handle_value };
    struct RPC_HEADER_EXT header = { .Flags = RHEF_Last };
    struct EcDoRpcExt2 rpc = { .in = { .handle = &handle, .pulFlags = &flags, .pcbOut = &capacity, .pcbAuxOut = &aux },
        .out = { .handle = &handle, .pulFlags = &flags, .pcbOut = &output_size, .pcbAuxOut = &aux, .pulTransTime = &elapsed } };
    const struct ndr_interface_call *call = &ndr_table_exchange_emsmdb.calls[NDR_ECDORPCEXT2];
    struct ndr_push *rop = ndr_push_init_ctx(ctx), *wire, *capture;
    struct SPropTagArray *tags;
    char path[] = "/tmp/openchange-capture-XXXXXX";
    uint8_t opnum = 0;
    int index = -1, fd = mkstemp(path);
    CHECK(ctx && rop && fd >= 0); close(fd);
    operations[0].u.mapi_GetProps.prop_count = 1;
    operations[0].u.mapi_GetProps.properties = &tag;
    rop->flags |= LIBNDR_FLAG_NOALIGN;
    CHECK(ndr_push_EcDoRpc_MAPI_REQ(rop, NDR_SCALARS, &operations[0]) == NDR_ERR_SUCCESS);
    request.length = rop->offset + 2; request.mapi_len = request.length + 4;
    header.Size = header.SizeActual = request.mapi_len;
    wire = ndr_push_init_ctx(ctx); CHECK(wire); wire->flags |= LIBNDR_FLAG_NOALIGN;
    CHECK(ndr_push_RPC_HEADER_EXT(wire, NDR_SCALARS, &header) == NDR_ERR_SUCCESS);
    CHECK(ndr_push_mapi_request(wire, NDR_SCALARS, &request) == NDR_ERR_SUCCESS);
    rpc.in.rgbIn = wire->data; rpc.in.cbIn = wire->offset;
    capture = ndr_push_init_ctx(ctx); CHECK(capture);
    CHECK(ndr_push_EcDoRpcExt2(capture, NDR_IN, &rpc) == NDR_ERR_SUCCESS && save_capture(path, capture));
    tags = process_request(ctx, call, path, &opnum, &index);
    CHECK(tags && tags->cValues == 1 && tags->aulPropTag[0] == tag && index == 0 && opnum == op_MAPI_GetProps);

    wire = ndr_push_init_ctx(ctx); CHECK(wire); wire->flags |= LIBNDR_FLAG_NOALIGN;
    header.Size = header.SizeActual = response.mapi_len;
    CHECK(ndr_push_RPC_HEADER_EXT(wire, NDR_SCALARS, &header) == NDR_ERR_SUCCESS);
    CHECK(ndr_push_mapi_response(wire, NDR_SCALARS, &response) == NDR_ERR_SUCCESS);
    rpc.out.rgbOut = wire->data; output_size = wire->offset;
    capture = ndr_push_init_ctx(ctx); CHECK(capture);
    CHECK(ndr_push_EcDoRpcExt2(capture, NDR_OUT, &rpc) == NDR_ERR_SUCCESS && save_capture(path, capture));
    CHECK(process_response(ctx, call, path, tags, opnum, 0) == -1); /* Failed ROP has no property union. */
    CHECK(process_response(ctx, call, path, tags, opnum, -1) == -1);
    CHECK(process_response(ctx, call, path, tags, opnum, 10000) == -1);
    /* Successful ROPs still need complete packed property data. */
    replies[0].error_code = MAPI_E_SUCCESS;
    for (int valid = 0; valid < 2; valid++) {
        static uint8_t name[] = {'B', 0, 'o', 0, 'b', 0, 0, 0};
        replies[0].u.mapi_GetProps.prop_data.data = name;
        replies[0].u.mapi_GetProps.prop_data.length = valid ? sizeof(name) : 0;
        rop = ndr_push_init_ctx(ctx); CHECK(rop); rop->flags |= LIBNDR_FLAG_NOALIGN;
        CHECK(ndr_push_EcDoRpc_MAPI_REPL(rop, NDR_SCALARS, &replies[0]) == NDR_ERR_SUCCESS);
        response.length = rop->offset + 2; response.mapi_len = response.length + 4;
        header.Size = header.SizeActual = response.mapi_len;
        wire = ndr_push_init_ctx(ctx); CHECK(wire); wire->flags |= LIBNDR_FLAG_NOALIGN;
        CHECK(ndr_push_RPC_HEADER_EXT(wire, NDR_SCALARS, &header) == NDR_ERR_SUCCESS);
        CHECK(ndr_push_mapi_response(wire, NDR_SCALARS, &response) == NDR_ERR_SUCCESS);
        rpc.out.rgbOut = wire->data; output_size = wire->offset;
        capture = ndr_push_init_ctx(ctx); CHECK(capture);
        CHECK(ndr_push_EcDoRpcExt2(capture, NDR_OUT, &rpc) == NDR_ERR_SUCCESS && save_capture(path, capture));
        CHECK(process_response(ctx, call, path, tags, opnum, 0) == (valid ? 0 : -1));
    }
    capture->offset = 3; CHECK(save_capture(path, capture));
    CHECK(process_request(ctx, call, path, &opnum, &index) == NULL);
    unlink(path); talloc_free(ctx);
    puts("Property capture decoding ownership, failed ROPs, index bounds and truncated input: OK");
    return 0;
}
