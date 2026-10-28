/* Real scalar/array decoders and row assembly, without a directory or RPC peer. */
#include "libmapi/libmapi.h"
#include "libmapi/libmapi_private.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "Property blob check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static int values(TALLOC_CTX *ctx)
{
    static const struct {
        uint16_t type;
        size_t length;
        uint8_t bytes[20];
    } fixtures[] = {
        {PT_I2, 2, {0x34, 0x12}}, {PT_LONG, 4, {0x78, 0x56, 0x34, 0x12}},
        {PT_ERROR, 4, {0x0f, 1, 4, 0x80}}, {PT_BOOLEAN, 1, {1}},
        {PT_I8, 8, {1, 2, 3, 4, 5, 6, 7, 8}},
        {PT_DOUBLE, 8, {0, 0, 0, 0, 0, 0, 0xf8, 0x3f}},
        {PT_SYSTIME, 8, {1, 2, 3, 4, 5, 6, 7, 8}},
        {PT_CLSID, 16, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
        {PT_STRING8, 4, {'a', 'b', 'c', 0}}, {PT_UNICODE, 4, {0xe9, 0, 0, 0}},
        {PT_BINARY, 5, {3, 0, 7, 8, 9}}, {PT_SVREID, 5, {3, 0, 7, 8, 9}},
        {PT_MV_LONG, 12, {2, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0}},
        {PT_MV_STRING8, 8, {2, 0, 0, 0, 'a', 0, 'b', 0}},
        {PT_MV_UNICODE, 12, {2, 0, 0, 0, 'a', 0, 0, 0, 'b', 0, 0, 0}},
        {PT_MV_BINARY, 10, {2, 0, 0, 0, 1, 0, 7, 1, 0, 8}}
    };
    size_t i, length;
    for (i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
        uint8_t bytes[21] = {0xff};
        enum MAPITAGS tag = PROP_TAG(fixtures[i].type, 0x3001);
        DATA_BLOB blob = { .data = bytes, .length = fixtures[i].length + 1 };
        uint32_t offset = 1;
        const void *value;
        size_t blocks;
        TALLOC_CTX *owner = talloc_new(ctx);
        CHECK(owner != NULL);
        memcpy(bytes + 1, fixtures[i].bytes, fixtures[i].length);
        value = pull_emsmdb_property(owner, &offset, tag, &blob);
        CHECK(value && offset == blob.length && talloc_parent(value) == owner);
        switch (fixtures[i].type) {
        case PT_I2: CHECK(*(const uint16_t *)value == 0x1234); break;
        case PT_LONG: CHECK(*(const uint32_t *)value == 0x12345678); break;
        case PT_BOOLEAN: CHECK(*(const uint8_t *)value == 1); break;
        case PT_DOUBLE: CHECK(*(const double *)value == 1.5); break;
        case PT_STRING8: CHECK(strcmp(value, "abc") == 0); break;
        case PT_UNICODE: CHECK(strcmp(value, "\xc3\xa9") == 0); break;
        case PT_BINARY: case PT_SVREID: {
            const struct Binary_r *bin = value;
            CHECK(bin->cb == 3 && memcmp(bin->lpb, "\7\10\11", 3) == 0); break;
        }
        case PT_MV_LONG: {
            const struct LongArray_r *array = value;
            CHECK(array->cValues == 2 && array->lpl[0] == 7 && array->lpl[1] == 8); break;
        }
        case PT_MV_STRING8: {
            const struct StringArray_r *array = value;
            CHECK(array->cValues == 2 && !strcmp(array->lppszA[0], "a") && !strcmp(array->lppszA[1], "b")); break;
        }
        case PT_MV_UNICODE: {
            const struct StringArrayW_r *array = value;
            CHECK(array->cValues == 2 && !strcmp(array->lppszW[0], "a") && !strcmp(array->lppszW[1], "b")); break;
        }
        case PT_MV_BINARY: {
            const struct BinaryArray_r *array = value;
            CHECK(array->cValues == 2 && array->lpbin[0].cb == 1 && array->lpbin[0].lpb[0] == 7 &&
                array->lpbin[1].cb == 1 && array->lpbin[1].lpb[0] == 8); break;
        }
        }
        talloc_free(owner);
        blocks = talloc_total_blocks(ctx);
        for (length = 0; length < fixtures[i].length; length++) {
            blob.length = length + 1; offset = 1;
            value = pull_emsmdb_property(ctx, &offset, tag, &blob);
            if (value != NULL) fprintf(stderr, "Accepted truncated type 0x%x length %zu of %zu\n", fixtures[i].type, length, fixtures[i].length);
            CHECK(value == NULL);
            CHECK(offset == 1 && talloc_total_blocks(ctx) == blocks);
        }
        if (fixtures[i].type & 0x1000) {
            blob.length = sizeof(bytes); memset(bytes + 1, 0xff, 4); offset = 1;
            CHECK(pull_emsmdb_property(ctx, &offset, tag, &blob) == NULL && offset == 1);
            memset(bytes + 1, 0, 4); blob.length = 5;
            value = pull_emsmdb_property(ctx, &offset, tag, &blob);
            CHECK(value && offset == 5);
            talloc_free(discard_const(value));
        }
    }
    return 0;
}

static int rows(TALLOC_CTX *ctx)
{
    enum MAPITAGS columns[] = {PROP_TAG(PT_LONG, 0x3001), PROP_TAG(PT_STRING8, 0x3002)};
    struct SPropTagArray tags = { .cValues = 2, .aulPropTag = columns };
    uint8_t bytes[] = {1, 1, 0, 'b', 0}; /* Missing first column, present second column. */
    DATA_BLOB blob = { .data = bytes, .length = sizeof(bytes) };
    struct SPropValue *props = NULL;
    struct SRow output[2] = {{0}};
    struct SRowSet rowset = { .cRows = 1, .aRow = output };
    uint32_t count = 99, offset = 0;
    size_t size, blocks;
    CHECK(emsmdb_get_SPropValue_offset(ctx, &blob, &tags, &props, &count, &offset) == MAPI_E_SUCCESS);
    CHECK(count == 2 && offset == sizeof(bytes) && props[0].ulPropTag == PROP_TAG(PT_ERROR, 0x3001));
    CHECK(props[0].value.err == MAPI_E_NOT_FOUND && !strcmp(props[1].value.lpszA, "b"));
    CHECK(columns[0] == PROP_TAG(PT_LONG, 0x3001)); talloc_free(props);
    CHECK(emsmdb_get_SRowSet(ctx, &rowset, &tags, &blob) == MAPI_E_SUCCESS && rowset.cRows == 1);
    CHECK(output[0].cValues == 2 && !strcmp(output[0].lpProps[1].value.lpszA, "b")); talloc_free(output[0].lpProps);
    blocks = talloc_total_blocks(ctx);
    for (size = 0; size < sizeof(bytes); size++) {
        blob.length = size; offset = 0; count = 99; props = (void *)1;
        CHECK(emsmdb_get_SPropValue_offset(ctx, &blob, &tags, &props, &count, &offset) != MAPI_E_SUCCESS);
        CHECK(props == NULL && count == 0 && offset == 0 && talloc_total_blocks(ctx) == blocks);
    }
    blob.length = sizeof(bytes); bytes[2] = 2; offset = 0;
    CHECK(emsmdb_get_SPropValue_offset(ctx, &blob, &tags, &props, &count, &offset) != MAPI_E_SUCCESS);
    bytes[2] = 0; bytes[0] = 2;
    CHECK(emsmdb_get_SPropValue_offset(ctx, &blob, &tags, &props, &count, &offset) != MAPI_E_SUCCESS);
    bytes[0] = 1; rowset.cRows = 2; memset(output, 0, sizeof(output));
    CHECK(emsmdb_get_SRowSet(ctx, &rowset, &tags, &blob) != MAPI_E_SUCCESS && rowset.cRows == 0);
    CHECK(output[0].lpProps == NULL && talloc_total_blocks(ctx) == blocks);
    tags.cValues = UINT32_MAX; count = 99;
    CHECK(emsmdb_get_SPropValue(ctx, &blob, &tags, &props, &count, 0) != MAPI_E_SUCCESS);
    CHECK(props == NULL && count == 0);
    tags.cValues = 2;
    CHECK(emsmdb_get_SRow(ctx, &output[0], &tags, 3, &blob, 0, 1) == MAPI_E_INVALID_PARAMETER);
    return 0;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    CHECK(ctx && values(ctx) == 0 && rows(ctx) == 0);
    {
        TALLOC_CTX *limited = talloc_new(ctx);
        uint8_t bytes[] = {1, 2, 3, 4};
        DATA_BLOB blob = { .data = bytes, .length = sizeof(bytes) };
        enum MAPITAGS tag = PROP_TAG(PT_LONG, 0x3001);
        struct SPropTagArray tags = { .cValues = 1, .aulPropTag = &tag };
        struct SPropValue *props = NULL;
        uint32_t offset = 0, count = 99;
        CHECK(limited && talloc_set_memlimit(limited, 1) == 0);
        CHECK(pull_emsmdb_property(limited, &offset, tag, &blob) == NULL && offset == 0);
        CHECK(emsmdb_get_SPropValue(limited, &blob, &tags, &props, &count, 0) == MAPI_E_NOT_ENOUGH_MEMORY);
        CHECK(props == NULL && count == 0);
    }
    talloc_free(ctx);
    puts("Property scalars, arrays, truncation, count bounds, row flags and transactional ownership: OK");
    return 0;
}
