/* Samba utility ABI declarations absent from its installed public headers.
 * Keep this boundary explicit; these functions remain exported by samba-util.
 * Signatures are checked against Samba 4.22.10 lib/util/util_strlist.h.
 */
#ifndef OPENCHANGE_SAMBA_COMPAT_H
#define OPENCHANGE_SAMBA_COMPAT_H

#include <talloc.h>

char **str_list_make_empty(TALLOC_CTX *mem_ctx);
char **str_list_make(TALLOC_CTX *mem_ctx, const char *string, const char *separator);
const char **str_list_add(const char **list, const char *value);
char *str_list_join(TALLOC_CTX *mem_ctx, const char **list, char separator);

/* Exported SAM database ABI absent from installed headers. Checked against
 * Samba 4.22.10 source4/dsdb/samdb/samdb.c.
 */
struct ldb_context;
struct tevent_context;
struct loadparm_context;
struct auth_session_info;
struct tsocket_address;
struct ldb_context *samdb_connect(TALLOC_CTX *, struct tevent_context *, struct loadparm_context *, struct auth_session_info *, const struct tsocket_address *, unsigned int);
int samdb_connect_url(TALLOC_CTX *, struct tevent_context *, struct loadparm_context *, struct auth_session_info *, unsigned int, const char *, const struct tsocket_address *, struct ldb_context **, char **);

#endif
