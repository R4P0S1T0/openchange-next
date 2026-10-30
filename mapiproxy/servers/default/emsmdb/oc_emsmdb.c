/*
   OpenChange EMSMDB service API for the MAPI/HTTP daemon

   OpenChange Project

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
   \file oc_emsmdb.c

   \brief The oc_emsmdb.h API over the EMSMDB provider, without DCE/RPC.
   All functions are called from one thread (the daemon's C worker).
 */

#include "mapiproxy/dcesrv_mapiproxy.h"
#include "dcesrv_exchange_emsmdb.h"
#include "oc_emsmdb.h"

struct oc_emsmdb_session {
	struct emsmdbp_context *ctx;
};

/* Process-wide state from oc_emsmdb_init; sessions are its talloc children. */
static TALLOC_CTX *oc_root;
static struct loadparm_context *oc_lp_ctx;
static void *oc_db_ctx;

/* Only the first successful call configures the process; later calls change nothing. */
uint32_t oc_emsmdb_init(const char *smb_conf_path)
{
	TALLOC_CTX *root;

	if (oc_root != NULL) return MAPI_E_SUCCESS;
	if (smb_conf_path == NULL || smb_conf_path[0] == '\0') return MAPI_E_INVALID_PARAMETER;
	root = talloc_named_const(NULL, 0, "oc_emsmdb");
	if (root == NULL) return MAPI_E_NOT_ENOUGH_RESOURCES;
	oc_lp_ctx = loadparm_init(root);
	if (oc_lp_ctx == NULL || !lpcfg_load(oc_lp_ctx, smb_conf_path)) {
		talloc_free(root);
		return MAPI_E_CALL_FAILED;
	}
	oc_db_ctx = emsmdbp_openchangedb_init(oc_lp_ctx);
	if (oc_db_ctx == NULL) {
		talloc_free(root);
		return MAPI_E_NOT_INITIALIZED;
	}
	oc_root = root;
	return MAPI_E_SUCCESS;
}

uint32_t oc_emsmdb_connect(const char *username, const char *user_dn,
			   uint32_t flags, uint32_t code_page,
			   uint32_t lcid_sort, uint32_t lcid_string,
			   oc_emsmdb_session **session,
			   const char **display_name, const char **dn_prefix)
{
	struct emsmdbp_context *ctx;

	if (session == NULL || display_name == NULL || dn_prefix == NULL) return MAPI_E_INVALID_PARAMETER;
	*session = NULL;
	*display_name = *dn_prefix = "";
	if (oc_root == NULL) return MAPI_E_NOT_INITIALIZED;
	if (username == NULL || username[0] == '\0' || user_dn == NULL || user_dn[0] == '\0') return MAPI_E_NO_ACCESS;
	ctx = emsmdbp_init(oc_lp_ctx, username, oc_db_ctx);
	if (ctx == NULL) return MAPI_E_LOGON_FAILED;
	/* Fail closed: verifying the Dovecot user against the directory (PostfixAdmin mailbox, LegacyDN) is M2; there is no Samba SID here. */
	talloc_free(ctx);
	return MAPI_E_LOGON_FAILED;
}

uint32_t oc_emsmdb_execute(oc_emsmdb_session *session, uint32_t flags,
			   const uint8_t *rop_in, size_t rop_in_len,
			   uint8_t *rop_out, size_t rop_out_cap,
			   size_t *rop_out_len)
{
	TALLOC_CTX *transaction;
	DATA_BLOB input, output;
	enum MAPISTATUS status;

	if (rop_out_len != NULL) *rop_out_len = 0;
	if (session == NULL || rop_out_len == NULL || rop_in == NULL || rop_out == NULL ||
	    rop_in_len < 8 || rop_in_len > UINT16_MAX + 8U) return ecRpcFailed;
	transaction = talloc_new(session);
	if (transaction == NULL) return MAPI_E_NOT_ENOUGH_RESOURCES;
	/* rop_in is borrowed for this call only; nothing the ROPs keep may point into it. */
	input = data_blob_talloc(transaction, rop_in, rop_in_len);
	status = MAPI_E_NOT_ENOUGH_RESOURCES;
	if (input.data == NULL) goto done;
	status = emsmdb_execute_buffer(transaction, session->ctx, &input, flags,
				       rop_out_cap > 0x40000 ? 0x40000 : (uint32_t)rop_out_cap, &output);
	if (status == MAPI_E_SUCCESS && output.length > rop_out_cap) status = ecBufferTooSmall;
	if (status != MAPI_E_SUCCESS) goto done;
	memcpy(rop_out, output.data, output.length);
	*rop_out_len = output.length;
done:
	talloc_free(transaction);
	return status;
}

void oc_emsmdb_disconnect(oc_emsmdb_session *session)
{
	talloc_free(session);
}
