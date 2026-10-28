/* Exercise the installed Samba AES password encoder with disposable inputs. */
#include "libmapiadmin/libmapiadmin.h"
#include <gen_ndr/samr.h>
#include <gen_ndr/ndr_samr.h>

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "Administration crypto check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)
int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    uint8_t key_bytes[16] = {1}, salt_bytes[16] = {2};
    DATA_BLOB key = { .data = key_bytes, .length = sizeof(key_bytes) };
    DATA_BLOB salt = { .data = salt_bytes, .length = sizeof(salt_bytes) };
    union samr_UserInfo first = {0}, second = {0};
    struct policy_handle handle = {0};
    struct samr_SetUserInfo request = { .in = { .user_handle = &handle, .level = 31, .info = &first } };
    struct ndr_push *push = ndr_push_init_ctx(ctx);
    CHECK(ctx && push);
    CHECK(NT_STATUS_IS_OK(init_samr_CryptPasswordAES(ctx, "Test-only-password-Á!", &salt, &key, &first.info31.password)));
    CHECK(first.info31.password.cipher && first.info31.password.cipher_len >= 514 && first.info31.password.cipher_len % 16 == 0);
    salt_bytes[0]++;
    CHECK(NT_STATUS_IS_OK(init_samr_CryptPasswordAES(ctx, "Test-only-password-Á!", &salt, &key, &second.info31.password)));
    CHECK(first.info31.password.cipher_len == second.info31.password.cipher_len);
    CHECK(memcmp(first.info31.password.cipher, second.info31.password.cipher, first.info31.password.cipher_len) != 0);
    CHECK(memcmp(first.info31.password.auth_data, second.info31.password.auth_data, sizeof(first.info31.password.auth_data)) != 0);
    CHECK(ndr_push_samr_SetUserInfo(push, NDR_IN, &request) == NDR_ERR_SUCCESS);
    CHECK(push->offset > first.info31.password.cipher_len);
    talloc_free(ctx);
    puts("Samba AES password encoding, salt separation and SAMR serialization: OK");
    return 0;
}
