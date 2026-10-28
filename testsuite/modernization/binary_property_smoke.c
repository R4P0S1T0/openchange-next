/* Real generated wire fixtures must outlive the temporary property parsers. */
#include "libmapi/libmapi.h"
#include "libmapi/libmapi_private.h"
#include "gen_ndr/ndr_property.h"
#include "gen_ndr/ndr_exchange.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "Binary property check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

#define ROUNDTRIP(type, source, verify) do { \
    struct ndr_push *push = ndr_push_init_ctx(ctx); \
    struct type *decoded; \
    struct Binary_r bin; \
    size_t before = talloc_total_blocks(owner); \
    CHECK(push); push->flags |= LIBNDR_FLAG_NOALIGN; \
    CHECK(ndr_push_ ## type(push, NDR_SCALARS, &(source)) == NDR_ERR_SUCCESS); \
    bin.cb = push->offset; bin.lpb = push->data; \
    decoded = get_ ## type(owner, &bin); \
    CHECK(decoded && talloc_parent(decoded) == owner && talloc_get_type(decoded, struct type) == decoded); \
    talloc_free(push); \
    CHECK(verify); \
    talloc_free(decoded); \
    CHECK(talloc_total_blocks(owner) == before); \
} while (0)

static int persistent_limits(TALLOC_CTX *ctx)
{
    TALLOC_CTX *owner = talloc_new(ctx);
    uint8_t *bytes = talloc_zero_array(ctx, uint8_t, 400004);
    DATA_BLOB blob = { .data = bytes, .length = 400004 };
    struct ndr_pull *pull;
    struct PersistDataArray data = {0};
    struct PersistElementArray elements = {0};
    CHECK(owner && bytes);
    for (size_t i = 0; i < blob.length; i += 4) { bytes[i] = 1; bytes[i + 1] = 0x80; }
    pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull); pull->current_mem_ctx = owner;
    CHECK(ndr_pull_PersistDataArray(pull, NDR_SCALARS | NDR_BUFFERS, &data) == NDR_ERR_RANGE);
    CHECK(data.cValues == 0 && data.lpPersistData == NULL && pull->current_mem_ctx == owner && pull->flags == 0);
    CHECK(talloc_total_blocks(owner) == 1); talloc_free(pull);
    blob.length = 40000 + 4;
    for (size_t i = 0; i < blob.length; i += 4) bytes[i + 1] = 0;
    pull = ndr_pull_init_blob(&blob, ctx); CHECK(pull); pull->current_mem_ctx = owner;
    CHECK(ndr_pull_PersistElementArray(pull, NDR_SCALARS | NDR_BUFFERS, &elements) == NDR_ERR_RANGE);
    CHECK(elements.cValues == 0 && elements.lpPersistElement == NULL && pull->current_mem_ctx == owner);
    CHECK(talloc_total_blocks(owner) == 1); talloc_free(pull);
    talloc_free(bytes); talloc_free(owner);
    return 0;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL), *owner = talloc_new(ctx);
    uint8_t payload[] = {7, 8, 9};
    struct GlobalObjectId global = { .Size = sizeof(payload), .Data = payload };
    struct AddressBookEntryId address = { .X500DN = "/o=Test/cn=alice" };
    struct OneOffEntryId off = { .DisplayName.lpszA = "Alice", .AddressType.lpszA = "SMTP", .EmailAddress.lpszA = "alice@example.test" };
    struct PtypServerId server = { .ours = 1, .FolderId = 42, .MessageId = 43, .Instance = 2 };
    struct TimeZoneStruct timezone = { .lBias = 180 };
    struct FolderEntryId folder = { .FolderType = eitLTPrivateFolder };
    struct MessageEntryId message = { .MessageType = eitLTPPrivateMessage };
    struct PersistElement elements[2] = {
        { .ElementID = RSF_ELID_ENTRYID, .ElementDataSize = sizeof(payload), .ElementData.rsf_elid_entryid = { .data = payload, .length = sizeof(payload) } },
        { .ElementID = ELEMENT_SENTINEL }
    };
    struct PersistData persist = { .PersistID = RSF_PID_RSS_SUBSCRIPTION, .DataElementsSize = 11,
        .DataElements = { .cValues = 2, .lpPersistElement = elements } };
    struct PersistData records[2];
    struct PersistDataArray array;
    struct PersistDataArray *decoded_array;
    struct SizedXid xid = { .XidSize = 19, .XID.LocalId = { .data = payload, .length = sizeof(payload) } };
    struct ndr_push *push;
    struct SizedXid *decoded;
    struct Binary_r bin;
    uint32_t count = 99;
    size_t blocks;
    CHECK(ctx && owner && persistent_limits(ctx) == 0);
    ROUNDTRIP(GlobalObjectId, global, decoded->Size == 3 && decoded->Data[2] == 9);
    ROUNDTRIP(AddressBookEntryId, address, !strcmp(decoded->X500DN, "/o=Test/cn=alice"));
    ROUNDTRIP(OneOffEntryId, off, !strcmp(decoded->DisplayName.lpszA, "Alice") && !strcmp(decoded->EmailAddress.lpszA, "alice@example.test"));
    ROUNDTRIP(PtypServerId, server, decoded->FolderId == 42 && decoded->MessageId == 43);
    ROUNDTRIP(TimeZoneStruct, timezone, decoded->lBias == 180);
    ROUNDTRIP(FolderEntryId, folder, decoded->FolderType == eitLTPrivateFolder);
    ROUNDTRIP(MessageEntryId, message, decoded->MessageType == eitLTPPrivateMessage);
    ROUNDTRIP(PersistData, persist, decoded->DataElements.cValues == 2 &&
        decoded->DataElements.lpPersistElement[0].ElementData.rsf_elid_entryid.length == 3 &&
        decoded->DataElements.lpPersistElement[0].ElementData.rsf_elid_entryid.data[2] == 9);
    records[0] = persist; memset(&records[1], 0, sizeof(records[1]));
    array.cValues = 2; array.lpPersistData = records;
    push = ndr_push_init_ctx(ctx); CHECK(push); push->flags |= LIBNDR_FLAG_NOALIGN;
    CHECK(ndr_push_PersistDataArray(push, NDR_SCALARS | NDR_BUFFERS, &array) == NDR_ERR_SUCCESS);
    bin.cb = push->offset; bin.lpb = push->data; blocks = talloc_total_blocks(owner);
    decoded_array = get_PersistDataArray(owner, &bin);
    CHECK(decoded_array && decoded_array->cValues == 2);
    for (uint32_t length = 1; length < bin.cb; length++) {
        struct Binary_r truncated = bin;
        struct PersistDataArray *result;
        truncated.cb = length;
        result = get_PersistDataArray(owner, &truncated);
        if (length == 15) CHECK(result && result->cValues == 1); /* Legacy arrays may omit the sentinel. */
        else CHECK(result == NULL);
        talloc_free(result);
    }
    for (size_t limit = 128; limit <= 2048; limit += 16) {
        TALLOC_CTX *limited = talloc_new(ctx);
        struct PersistDataArray *result;
        CHECK(limited && talloc_set_memlimit(limited, limit) == 0);
        result = get_PersistDataArray(limited, &bin);
        if (result) CHECK(result->cValues == 2);
        talloc_free(result);
        CHECK(talloc_total_blocks(limited) == 1);
        talloc_free(limited);
    }
    {
        DATA_BLOB prefixed = { .length = bin.cb + 3 };
        struct ndr_pull *pull;
        struct PersistDataArray result = {0};
        prefixed.data = talloc_zero_array(ctx, uint8_t, prefixed.length); CHECK(prefixed.data);
        memcpy(prefixed.data + 3, bin.lpb, bin.cb);
        pull = ndr_pull_init_blob(&prefixed, ctx); CHECK(pull); pull->offset = 3;
        pull->current_mem_ctx = owner;
        CHECK(ndr_pull_PersistDataArray(pull, NDR_SCALARS | NDR_BUFFERS, &result) == NDR_ERR_SUCCESS);
        CHECK(pull->offset == prefixed.length && result.cValues == 2 && pull->current_mem_ctx == owner);
        talloc_free(pull); talloc_free(prefixed.data);
        CHECK(result.lpPersistData[0].DataElements.lpPersistElement[0].ElementData.rsf_elid_entryid.data[2] == 9);
        talloc_free(result.lpPersistData);
    }
    talloc_free(push);
    CHECK(decoded_array->lpPersistData[0].DataElements.lpPersistElement[0].ElementData.rsf_elid_entryid.data[2] == 9);
    CHECK(decoded_array->lpPersistData[1].PersistID == PERSIST_SENTINEL);
    talloc_free(decoded_array); CHECK(talloc_total_blocks(owner) == blocks);
    push = ndr_push_init_ctx(ctx); CHECK(push); push->flags |= LIBNDR_FLAG_NOALIGN;
    CHECK(ndr_push_SizedXid(push, NDR_SCALARS, &xid) == NDR_ERR_SUCCESS);
    CHECK(ndr_push_SizedXid(push, NDR_SCALARS, &xid) == NDR_ERR_SUCCESS);
    bin.cb = push->offset; bin.lpb = push->data; blocks = talloc_total_blocks(owner);
    decoded = get_SizedXidArray(owner, &bin, &count);
    CHECK(decoded && count == 2);
    for (size_t limit = 128; limit <= 2048; limit += 16) {
        TALLOC_CTX *limited = talloc_new(ctx);
        struct SizedXid *result;
        uint32_t parsed = 99;
        CHECK(limited && talloc_set_memlimit(limited, limit) == 0);
        result = get_SizedXidArray(limited, &bin, &parsed);
        CHECK(result ? parsed == 2 : parsed == 0);
        talloc_free(result);
        CHECK(talloc_total_blocks(limited) == 1);
        talloc_free(limited);
    }
    talloc_free(push);
    CHECK(decoded[0].XID.LocalId.length == 3 && decoded[0].XID.LocalId.data[2] == 9);
    CHECK(decoded[1].XID.LocalId.length == 3 && decoded[1].XID.LocalId.data[0] == 7);
    talloc_free(decoded); CHECK(talloc_total_blocks(owner) == blocks);
    bin.cb = 1; bin.lpb = payload; count = 99;
    CHECK(get_SizedXidArray(owner, &bin, &count) == NULL && count == 0);
    CHECK(talloc_total_blocks(owner) == blocks);
    talloc_free(ctx);
    puts("Binary property results own decoded strings, IDs, nested persistent elements and XID arrays: OK");
    return 0;
}
