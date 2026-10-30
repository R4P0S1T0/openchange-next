/*
   OpenChange Server implementation

   EMSMDBP: EMSMDB Provider implementation

   Copyright (C) Julien Kerihuel 2009-2014

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

/**
   \file emsmdbp_verify.c

   \brief Account checks bound to the authenticated DCE/RPC caller.
   Only the RPC module links this file.
 */

#include "mapiproxy/dcesrv_mapiproxy.h"
#include "dcesrv_exchange_emsmdb.h"

/**
   \details Check if the authenticated user belongs to the Exchange
   organization and is enabled

   \param dce_call pointer to the session context
   \param emsmdbp_ctx pointer to the EMSMDBP context

   \return true on success, otherwise false
 */
_PUBLIC_ bool emsmdbp_verify_user(struct dcesrv_call_state *dce_call,
				  struct emsmdbp_context *emsmdbp_ctx)
{
	int			ret;
	const char		*username = NULL;
	int			msExchUserAccountControl;
	struct ldb_result	*res = NULL;
	char *encoded;
	const char * const	recipient_attrs[] = { "msExchUserAccountControl", "objectSid", NULL };

	username = dcesrv_call_account_name(dce_call);
	if (!username || !username[0]) return false;
	encoded = ldb_binary_encode_string(emsmdbp_ctx, username);
	if (!encoded) return false;

	ret = ldb_search(emsmdbp_ctx->samdb_ctx, emsmdbp_ctx, &res,
			 ldb_get_default_basedn(emsmdbp_ctx->samdb_ctx),
			 LDB_SCOPE_SUBTREE, recipient_attrs, "sAMAccountName=%s",
			 encoded);
	talloc_free(encoded);

	/* If the search failed */
	if (ret != LDB_SUCCESS || res->count != 1) {
		return false;
	}

	/* If msExchUserAccountControl attribute is not found */
	if (!res->msgs[0]->num_elements) {
		return false;
	}

	/* If the attribute exists check its value */
	msExchUserAccountControl = ldb_msg_find_attr_as_int(res->msgs[0], "msExchUserAccountControl", 2);
	if (msExchUserAccountControl != 0) {
		return false;
	}

	if (!mapiproxy_call_owns_account(dce_call, res->msgs[0])) return false;

	/* Get a copy of the username for later use and setup missing conn_info components */
	emsmdbp_ctx->username = talloc_strdup(emsmdbp_ctx, username);
	if (emsmdbp_ctx->username == NULL || emsmdbp_ctx->mstore_ctx->conn_info == NULL) return false;
	if (openchangedb_get_MailboxReplica(emsmdbp_ctx->oc_ctx, emsmdbp_ctx->username,
		&emsmdbp_ctx->mstore_ctx->conn_info->repl_id,
		&emsmdbp_ctx->mstore_ctx->conn_info->replica_guid) != MAPI_E_SUCCESS) return false;

	return true;
}


/**
   \details Check if the user record which legacyExchangeDN points to
   belongs to the Exchange organization and is enabled

   \param dce_call pointer to the session context
   \param emsmdbp_ctx pointer to the EMSMDBP context
   \param legacyExchangeDN pointer to the userDN to lookup
   \param msg pointer on pointer to the LDB message matching the record

   \note Users can set msg to NULL if they do not intend to retrieve
   the message

   \return true on success, otherwise false
 */
_PUBLIC_ bool emsmdbp_verify_userdn(struct dcesrv_call_state *dce_call,
				    struct emsmdbp_context *emsmdbp_ctx,
				    const char *legacyExchangeDN,
				    struct ldb_message **msg)
{
	int			ret;
	int			msExchUserAccountControl;
	struct ldb_result	*res = NULL;
	char *encoded;
	const char *account, *username;
	const char * const	recipient_attrs[] = { "*", NULL };

	/* Sanity Checks */
	if (msg) *msg = NULL;
	if (!legacyExchangeDN || !legacyExchangeDN[0]) return false;
	encoded = ldb_binary_encode_string(emsmdbp_ctx, legacyExchangeDN);
	if (!encoded) return false;

	ret = ldb_search(emsmdbp_ctx->samdb_ctx, emsmdbp_ctx, &res,
			 ldb_get_default_basedn(emsmdbp_ctx->samdb_ctx),
			 LDB_SCOPE_SUBTREE, recipient_attrs, "(legacyExchangeDN=%s)",
			 encoded);
	talloc_free(encoded);

	/* If the search failed */
	if (ret != LDB_SUCCESS || res->count != 1) {
		return false;
	}

	/* Checks msExchUserAccountControl value */
	msExchUserAccountControl = ldb_msg_find_attr_as_int(res->msgs[0], "msExchUserAccountControl", 2);
	if (msExchUserAccountControl != 0) {
		return false;
	}

	/* Connect-as delegation requires an explicit policy; never infer it from a DN. */
	account = ldb_msg_find_attr_as_string(res->msgs[0], "sAMAccountName", NULL);
	username = dcesrv_call_account_name(dce_call);
	if (account == NULL || username == NULL || strcasecmp(account, username) != 0 ||
	    !mapiproxy_call_owns_account(dce_call, res->msgs[0])) return false;

	if (msg) {
		*msg = res->msgs[0];
	}

	return true;
}
