/* Exercise the actual ModifyRecipients property parser with local wire blobs. */
#include "mapiproxy/servers/default/emsmdb/oxcmsg.c"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "Recipient blob check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static int directory_names(TALLOC_CTX *ctx)
{
    struct emsmdbp_context backend = {0};
    struct ldb_context *db = ldb_init(ctx, NULL);
    struct ldb_dn *base;
    struct ldb_message *message;
    static const char * const names[][2] = {
        {"/o=Test/cn=Alice", "alice"},
        {"/o=Test/cn=AliceOther", "other"},
        {"/o=Test/cn=Alice (Ops)*\\Example", "special"}
    };
    char path[] = "/tmp/openchange-recipient-XXXXXX";
    char *name;
    int fd = mkstemp(path);
    CHECK(db && fd >= 0); close(fd); unlink(path);
    CHECK(ldb_connect(db, path, 0, NULL) == LDB_SUCCESS);
    base = ldb_dn_new(db, db, "DC=test");
    CHECK(base && ldb_set_opaque(db, "defaultNamingContext", base) == LDB_SUCCESS);
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        message = ldb_msg_new(ctx); CHECK(message);
        message->dn = ldb_dn_new_fmt(message, db, "CN=user%zu,DC=test", i);
        CHECK(message->dn && ldb_msg_add_string(message, "legacyExchangeDN", names[i][0]) == LDB_SUCCESS);
        CHECK(ldb_msg_add_string(message, "sAMAccountName", names[i][1]) == LDB_SUCCESS);
        CHECK(ldb_add(db, message) == LDB_SUCCESS); talloc_free(message);
    }
    backend.samdb_ctx = db; backend.szDNPrefix = "/o=Test/";
    CHECK(oxcmsg_resolve_partial_x500name(ctx, &backend, 0, names[0][0], &name) == MAPI_E_SUCCESS);
    CHECK(!strcmp(name, "alice") && talloc_parent(name) == ctx); talloc_free(name);
    CHECK(oxcmsg_resolve_partial_x500name(ctx, &backend, 8, "cn=Alice", &name) == MAPI_E_SUCCESS);
    CHECK(!strcmp(name, "alice")); talloc_free(name);
    CHECK(oxcmsg_resolve_partial_x500name(ctx, &backend, 0, names[2][0], &name) == MAPI_E_SUCCESS);
    CHECK(!strcmp(name, "special")); talloc_free(name);
    CHECK(oxcmsg_resolve_partial_x500name(ctx, &backend, 0, "/o=Test/cn=AliceO*", &name) == MAPI_E_SUCCESS);
    CHECK(!strcmp(name, "/o=Test/cn=AliceO*")); talloc_free(name);
    CHECK(oxcmsg_resolve_partial_x500name(ctx, &backend, 9, "cn=Alice", &name) == MAPI_E_INVALID_PARAMETER && name == NULL);
    CHECK(oxcmsg_resolve_partial_x500name(ctx, &backend, 0, NULL, &name) == MAPI_E_INVALID_PARAMETER && name == NULL);
    message = ldb_msg_new(ctx); CHECK(message);
    message->dn = ldb_dn_new(message, db, "CN=duplicate,DC=test");
    CHECK(message->dn && ldb_msg_add_string(message, "legacyExchangeDN", names[0][0]) == LDB_SUCCESS);
    CHECK(ldb_msg_add_string(message, "sAMAccountName", "duplicate") == LDB_SUCCESS && ldb_add(db, message) == LDB_SUCCESS);
    talloc_free(message);
    CHECK(oxcmsg_resolve_partial_x500name(ctx, &backend, 0, names[0][0], &name) == MAPI_E_SUCCESS);
    CHECK(!strcmp(name, names[0][0])); talloc_free(name);
    talloc_free(db); unlink(path);
    return 0;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    enum MAPITAGS tags[] = {PROP_TAG(PT_STRING8, 0x3001), PROP_TAG(PT_LONG, 0x3002)};
    struct ModifyRecipientRow row = {0};
    struct mapistore_message_recipient recipient = {0};
    uint8_t bytes[] = {'a', 0, 0, 0, 0};
    size_t blocks;
    CHECK(ctx && directory_names(ctx) == 0);
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
    puts("Recipient directory filter literals, ambiguity, prefix bounds and packed property checks: OK");
    return 0;
}
