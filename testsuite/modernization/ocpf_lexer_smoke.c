/* Generate and exercise the actual Flex scanner, including string ownership. */
#include "libocpf/lex.yy.c"
int error_flag;

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "OCPF lexer check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static int scan(struct ocpf_context *ctx, const char *input, size_t length,
    int expected, const char **value)
{
    yyscan_t scanner;
    YY_BUFFER_STATE buffer;
    YYSTYPE token = {0};
    int result;
    CHECK(ocpf_yylex_init_extra(ctx, &scanner) == 0);
    buffer = ocpf_yy_scan_bytes(input, length, scanner);
    CHECK(buffer != NULL);
    result = ocpf_yylex(&token, scanner);
    CHECK(result == expected);
    if (result == STRING || result == UNICODE) *value = token.name;
    ocpf_yy_delete_buffer(buffer, scanner);
    CHECK(ocpf_yylex_destroy(scanner) == 0);
    return 0;
}

int main(void)
{
    struct ocpf_context *ctx = talloc_zero(NULL, struct ocpf_context);
    const char *first = NULL, *second = NULL;
    char *large;
    unsigned before;
    CHECK(ctx);
    ctx->filename = "lexer-test"; ctx->lineno = 1;
    CHECK(scan(ctx, "\"first\"", strlen("\"first\""), STRING, &first) == 0);
    CHECK(scan(ctx, "W\"ação\"", strlen("W\"ação\""), UNICODE, &second) == 0);
    CHECK(strcmp(first, "first") == 0 && strcmp(second, "ação") == 0);
    CHECK(talloc_parent(first) == ctx && talloc_parent(second) == ctx);
    CHECK(scan(ctx, "\"a\"\"b\" ", strlen("\"a\"\"b\" "), STRING, &second) == 0 && strcmp(second, "a\"b") == 0);
    CHECK(scan(ctx, "\"a\\\"b\" ", strlen("\"a\\\"b\" "), STRING, &second) == 0 && strcmp(second, "a\"b") == 0);
    CHECK(scan(ctx, "\"a\n  b\" ", strlen("\"a\n  b\" "), STRING, &second) == 0 && strcmp(second, "ab") == 0);
    CHECK(scan(ctx, "/* outer /* inner */ end */\"x\"", strlen("/* outer /* inner */ end */\"x\""), STRING, &second) == 0 && strcmp(second, "x") == 0);
    large = talloc_array(ctx, char, 0x4003); CHECK(large);
    large[0] = '"'; memset(large + 1, 'x', 0x3fff); large[0x4000] = '"';
    CHECK(scan(ctx, large, 0x4001, STRING, &second) == 0 && strlen(second) == 0x3fff);
    large[0x4000] = 'x'; large[0x4001] = '"'; before = error_flag;
    CHECK(scan(ctx, large, 0x4002, YYerror, &second) == 0 && error_flag == before + 1);
    before = error_flag;
    CHECK(scan(ctx, "\"unfinished", strlen("\"unfinished"), YYerror, &second) == 0 && error_flag == before + 1);
    before = error_flag;
    CHECK(scan(ctx, "/* unfinished", strlen("/* unfinished"), YYerror, &second) == 0 && error_flag == before + 1);
    CHECK(strcmp(first, "first") == 0);
    talloc_free(ctx);
    puts("OCPF scanner string ownership, limits, Unicode, quoting and truncated input: OK");
    return 0;
}
