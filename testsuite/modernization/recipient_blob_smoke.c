/* Exercise the actual ModifyRecipients property parser with local wire blobs. */
#include "mapiproxy/servers/default/emsmdb/oxcmsg.c"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "Recipient blob check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    enum MAPITAGS tags[] = {PROP_TAG(PT_STRING8, 0x3001), PROP_TAG(PT_LONG, 0x3002)};
    struct ModifyRecipientRow row = {0};
    struct mapistore_message_recipient recipient = {0};
    uint8_t bytes[] = {'a', 0, 0, 0, 0};
    size_t blocks;
    CHECK(ctx);
    row.RecipientRow.prop_count = 1;
    row.RecipientRow.prop_values.data = bytes;
    row.RecipientRow.prop_values.length = 2;
    CHECK(oxcmsg_parse_ModifyRecipientRow(ctx, NULL, &row, 2, tags, &recipient) == MAPI_E_SUCCESS);
    CHECK(!strcmp(recipient.data[2], "a") && recipient.data[3] == NULL);
    talloc_free(recipient.data); recipient.data = NULL;
    blocks = talloc_total_blocks(ctx);
    row.RecipientRow.prop_count = 3;
    CHECK(oxcmsg_parse_ModifyRecipientRow(ctx, NULL, &row, 2, tags, &recipient) == MAPI_E_INVALID_PARAMETER);
    CHECK(recipient.data == NULL);
    row.RecipientRow.prop_count = 1; row.RecipientRow.layout = 1;
    row.RecipientRow.prop_values.length = 0;
    CHECK(oxcmsg_parse_ModifyRecipientRow(ctx, NULL, &row, 2, tags, &recipient) == MAPI_E_CORRUPT_DATA);
    CHECK(recipient.data == NULL && talloc_total_blocks(ctx) == blocks);
    row.RecipientRow.prop_values.length = 1; bytes[0] = PT_ERROR;
    CHECK(oxcmsg_parse_ModifyRecipientRow(ctx, NULL, &row, 2, tags, &recipient) == MAPI_E_CORRUPT_DATA);
    CHECK(recipient.data == NULL && talloc_total_blocks(ctx) == blocks);
    row.RecipientRow.prop_values.length = 5;
    CHECK(oxcmsg_parse_ModifyRecipientRow(ctx, NULL, &row, 2, tags, &recipient) == MAPI_E_SUCCESS);
    CHECK(recipient.data[2] == NULL); talloc_free(recipient.data); recipient.data = NULL;
    bytes[0] = 2;
    CHECK(oxcmsg_parse_ModifyRecipientRow(ctx, NULL, &row, 2, tags, &recipient) == MAPI_E_UNKNOWN_FLAGS);
    CHECK(recipient.data == NULL && talloc_total_blocks(ctx) == blocks);
    bytes[0] = 0; bytes[1] = 'a'; row.RecipientRow.prop_values.length = 2;
    CHECK(oxcmsg_parse_ModifyRecipientRow(ctx, NULL, &row, 2, tags, &recipient) != MAPI_E_SUCCESS);
    CHECK(recipient.data == NULL && talloc_total_blocks(ctx) == blocks);
    talloc_free(ctx);
    puts("Recipient property counts, absent/truncated flags, error payload bounds and string truncation: OK");
    return 0;
}
