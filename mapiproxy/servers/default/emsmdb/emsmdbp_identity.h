/*
   OpenChange Server implementation

   EMSMDBP: Connect identity shared by the DCE/RPC and MAPI/HTTP paths

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef	__EMSMDBP_IDENTITY_H
#define	__EMSMDBP_IDENTITY_H

#include "dcesrv_exchange_emsmdb.h"

/* Inline so each Connect path's allocations stay in its own object (tests wrap them). */
/**
   \details Fill the session identity from a verified directory entry and
   copy the Connect reply strings onto mem_ctx.
 */
static inline enum MAPISTATUS emsmdbp_connect_identity(struct emsmdbp_context *ctx, struct ldb_message *msg,
						  const char *user_dn, uint32_t language, TALLOC_CTX *mem_ctx,
						  const char **display_name, const char **dn_prefix)
{
	const char *nickname, *legacy_dn, *last_cn, *name;

	nickname = ldb_msg_find_attr_as_string(msg, "mailNickname", NULL);
	legacy_dn = ldb_msg_find_attr_as_string(msg, "legacyExchangeDN", NULL);
	name = ldb_msg_find_attr_as_string(msg, "displayName", NULL);
	if (nickname == NULL || nickname[0] == '\0' || legacy_dn == NULL || name == NULL)
		return MAPI_E_LOGON_FAILED;
	last_cn = strrchr(legacy_dn, '/');
	if (last_cn == NULL || strncasecmp(last_cn, "/cn=", 4) != 0 ||
	    strcasecmp(last_cn + 4, nickname) != 0) return MAPI_E_LOGON_FAILED;
	ctx->szUserDN = talloc_strdup(ctx, user_dn);
	ctx->szDisplayName = talloc_strdup(ctx, name);
	ctx->szDNPrefix = talloc_strndup(ctx, legacy_dn, last_cn + 4 - legacy_dn);
	ctx->userLanguage = language;
	if (ctx->szUserDN == NULL || ctx->szDisplayName == NULL || ctx->szDNPrefix == NULL)
		return MAPI_E_NOT_ENOUGH_RESOURCES;
	/* Reply strings must remain valid when this session is disconnected. */
	*display_name = talloc_strdup(mem_ctx, ctx->szDisplayName);
	*dn_prefix = strupper_talloc(mem_ctx, ctx->szDNPrefix);
	if (*display_name == NULL || *dn_prefix == NULL) return MAPI_E_NOT_ENOUGH_RESOURCES;
	return MAPI_E_SUCCESS;
}

#endif /* __EMSMDBP_IDENTITY_H */
