/*
   MAPI Proxy - Exchange EMSMDB Server

   OpenChange Project

   Copyright (C) Julien Kerihuel 2009-2015

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
   \file dcesrv_exchange_emsmdb.c

   \brief OpenChange EMSMDB Server implementation
 */

#include <sys/time.h>

#include "mapiproxy/dcesrv_mapiproxy.h"
#include "mapiproxy/libmapiproxy/fault_util.h"
#include "mapiproxy/libmapiserver/libmapiserver.h"
#include "dcesrv_exchange_emsmdb.h"

static void *openchange_db_ctx;

static struct dcesrv_handle *dcesrv_find_emsmdb_handle(struct dcesrv_call_state *call,
                                                     const struct policy_handle *wire)
{
	/* Empty handles cause Samba to allocate rather than perform a lookup. */
	if (wire == NULL || GUID_all_zero(&wire->uuid) ||
	    !dcesrv_call_authenticated(call)) return NULL;
	return dcesrv_handle_lookup(call, wire, EXCHANGE_HANDLE_EMSMDB);
}

static struct emsmdbp_context *dcesrv_find_emsmdb_context(struct dcesrv_call_state *call,
                                                        const struct policy_handle *wire)
{
	struct dcesrv_handle *handle = dcesrv_find_emsmdb_handle(call, wire);
	return handle == NULL ? NULL : talloc_get_type(handle->data, struct emsmdbp_context);
}

static enum MAPISTATUS emsmdb_connect_context(struct dcesrv_call_state *call,
    TALLOC_CTX *mem_ctx, const char *user_dn, uint32_t language,
    struct policy_handle *wire, const char **display_name, const char **dn_prefix)
{
	struct emsmdbp_context *ctx;
	struct dcesrv_handle *handle;
	struct ldb_message *msg;
	const char *nickname, *legacy_dn, *last_cn, *name;
	enum MAPISTATUS status = MAPI_E_LOGON_FAILED;

	if (user_dn == NULL || user_dn[0] == '\0') return MAPI_E_NO_ACCESS;
	ctx = emsmdbp_init(call->conn->dce_ctx->lp_ctx,
		dcesrv_call_account_name(call), openchange_db_ctx);
	if (ctx == NULL) return MAPI_E_LOGON_FAILED;
	if (!emsmdbp_verify_user(call, ctx) ||
	    !emsmdbp_verify_userdn(call, ctx, user_dn, &msg)) goto failure;
	nickname = ldb_msg_find_attr_as_string(msg, "mailNickname", NULL);
	legacy_dn = ldb_msg_find_attr_as_string(msg, "legacyExchangeDN", NULL);
	name = ldb_msg_find_attr_as_string(msg, "displayName", NULL);
	if (nickname == NULL || nickname[0] == '\0' || legacy_dn == NULL || name == NULL) goto failure;
	last_cn = strrchr(legacy_dn, '/');
	if (last_cn == NULL || strncasecmp(last_cn, "/cn=", 4) != 0 ||
	    strcasecmp(last_cn + 4, nickname) != 0) goto failure;
	ctx->szUserDN = talloc_strdup(ctx, user_dn);
	ctx->szDisplayName = talloc_strdup(ctx, name);
	ctx->szDNPrefix = talloc_strndup(ctx, legacy_dn, last_cn + 4 - legacy_dn);
	ctx->userLanguage = language;
	status = MAPI_E_NOT_ENOUGH_RESOURCES;
	if (ctx->szUserDN == NULL || ctx->szDisplayName == NULL || ctx->szDNPrefix == NULL) goto failure;
	/* Reply strings must remain valid when this session is disconnected. */
	*display_name = talloc_strdup(mem_ctx, ctx->szDisplayName);
	*dn_prefix = strupper_talloc(mem_ctx, ctx->szDNPrefix);
	if (*display_name == NULL || *dn_prefix == NULL) goto failure;
	handle = dcesrv_handle_create(call, EXCHANGE_HANDLE_EMSMDB);
	if (handle == NULL) goto failure;
	if (!emsmdbp_set_session_uuid(ctx, handle->wire_handle.uuid)) {
		talloc_free(handle);
		goto failure;
	}
	handle->data = talloc_steal(handle, ctx);
	*wire = handle->wire_handle;
	return MAPI_E_SUCCESS;

failure:
	talloc_free(ctx);
	*display_name = *dn_prefix = "";
	return status;
}

/**
   \details exchange_emsmdb EcDoConnect (0x0) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcDoConnect request data

   \note Session linking is not supported at the moment

   \return MAPI_E_SUCCESS on success
 */
static enum MAPISTATUS dcesrv_EcDoConnect(struct dcesrv_call_state *dce_call,
                                          TALLOC_CTX *mem_ctx, struct EcDoConnect *r)
{
	ZERO_STRUCTP(r->out.handle);
	*r->out.pcmsPollsMax = *r->out.pcRetry = *r->out.pcmsRetryDelay = *r->out.picxr = 0;
	*r->out.pullTimeStamp = 0;
	*r->out.szDisplayName = *r->out.szDNPrefix = "";
	ZERO_STRUCT(r->out.rgwServerVersion);
	ZERO_STRUCT(r->out.rgwClientVersion);
	r->out.result = MAPI_E_LOGON_FAILED;
	if (!dcesrv_call_authenticated(dce_call)) return r->out.result;
	r->out.result = emsmdb_connect_context(dce_call, mem_ctx, r->in.szUserDN,
		r->in.ulLcidString, r->out.handle, r->out.szDisplayName, r->out.szDNPrefix);
	if (r->out.result != MAPI_E_SUCCESS) return r->out.result;
	*r->out.pcmsPollsMax = EMSMDB_PCMSPOLLMAX;
	*r->out.pcRetry = EMSMDB_PCRETRY;
	*r->out.pcmsRetryDelay = EMSMDB_PCRETRYDELAY;
	r->out.rgwServerVersion[0] = 0x6;
	r->out.rgwServerVersion[1] = 0x1141;
	r->out.rgwServerVersion[2] = 0x5;
	memcpy(r->out.rgwClientVersion, r->in.rgwClientVersion, sizeof(r->out.rgwClientVersion));
	*r->out.pullTimeStamp = time(NULL);
	return r->out.result;
}


/**
   \details exchange_emsmdb EcDoDisconnect (0x1) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcDoDisconnect request data

   \return MAPI_E_SUCCESS on success
 */
static enum MAPISTATUS dcesrv_EcDoDisconnect(struct dcesrv_call_state *dce_call,
                                             TALLOC_CTX *mem_ctx, struct EcDoDisconnect *r)
{
	struct dcesrv_handle *handle = dcesrv_find_emsmdb_handle(dce_call, r->in.handle);
	ZERO_STRUCTP(r->out.handle);
	if (!dcesrv_call_authenticated(dce_call)) {
		r->out.result = MAPI_E_LOGON_FAILED;
	} else if (handle == NULL) {
		r->out.result = MAPI_E_INVALID_OBJECT;
	} else {
		talloc_free(handle);
		r->out.result = MAPI_E_SUCCESS;
	}
	return r->out.result;
}

static bool emsmdb_request_valid(const struct mapi_request *request, uint32_t *op_count)
{
	uint32_t handles, i;
	size_t capacity;
	*op_count = 0;
	if (request == NULL || request->length < 2 || request->mapi_len < request->length ||
	    (request->mapi_len - request->length) % 4 != 0) return false;
	handles = (request->mapi_len - request->length) / 4;
	if (handles > 256 || (handles != 0 && (request->handles == NULL ||
	    talloc_array_length(request->handles) < handles))) return false;
	if (request->length == 2) return true;
	if (request->mapi_req == NULL) return false;
	capacity = talloc_array_length(request->mapi_req);
	for (i = 0; i < capacity && i <= (request->length - 2) / 3; i++) {
		const struct EcDoRpc_MAPI_REQ *rop = &request->mapi_req[i];
		uint32_t secondary = 0;
		if (rop->opnum == 0) { *op_count = i; return i != 0; }
		if (rop->handle_idx >= handles) return false;
		switch (rop->opnum) {
		case op_MAPI_OpenFolder: secondary = rop->u.mapi_OpenFolder.handle_idx; break;
		case op_MAPI_OpenMessage: secondary = rop->u.mapi_OpenMessage.handle_idx; break;
		case op_MAPI_GetHierarchyTable: secondary = rop->u.mapi_GetHierarchyTable.handle_idx; break;
		case op_MAPI_GetContentsTable: secondary = rop->u.mapi_GetContentsTable.handle_idx; break;
		case op_MAPI_CreateMessage: secondary = rop->u.mapi_CreateMessage.handle_idx; break;
		case op_MAPI_SaveChangesMessage: secondary = rop->u.mapi_SaveChangesMessage.handle_idx; break;
		case op_MAPI_SetMessageReadFlag: secondary = rop->u.mapi_SetMessageReadFlag.handle_idx; break;
		case op_MAPI_CreateFolder: secondary = rop->u.mapi_CreateFolder.handle_idx; break;
		case op_MAPI_GetAttachmentTable: secondary = rop->u.mapi_GetAttachmentTable.handle_idx; break;
		case op_MAPI_OpenAttach: secondary = rop->u.mapi_OpenAttach.handle_idx; break;
		case op_MAPI_CreateAttach: secondary = rop->u.mapi_CreateAttach.handle_idx; break;
		case op_MAPI_SaveChangesAttachment: secondary = rop->u.mapi_SaveChangesAttachment.handle_idx; break;
		case op_MAPI_RegisterNotification: secondary = rop->u.mapi_RegisterNotification.handle_idx; break;
		case op_MAPI_OpenStream: secondary = rop->u.mapi_OpenStream.handle_idx; break;
		case op_MAPI_MoveCopyMessages: secondary = rop->u.mapi_MoveCopyMessages.handle_idx; break;
		case op_MAPI_MoveFolder: secondary = rop->u.mapi_MoveFolder.handle_idx; break;
		case op_MAPI_CopyFolder: secondary = rop->u.mapi_CopyFolder.handle_idx; break;
		case op_MAPI_CopyTo: secondary = rop->u.mapi_CopyTo.handle_idx; break;
		case op_MAPI_CopyToStream: secondary = rop->u.mapi_CopyToStream.handle_idx; break;
		case op_MAPI_CloneStream: secondary = rop->u.mapi_CloneStream.handle_idx; break;
		case op_MAPI_GetPermissionsTable: secondary = rop->u.mapi_GetPermissionsTable.handle_idx; break;
		case op_MAPI_GetRulesTable: secondary = rop->u.mapi_GetRulesTable.handle_idx; break;
		case op_MAPI_OpenEmbeddedMessage: secondary = rop->u.mapi_OpenEmbeddedMessage.handle_idx; break;
		case op_MAPI_FastTransferSourceCopyMessages: secondary = rop->u.mapi_FastTransferSourceCopyMessages.handle_idx; break;
		case op_MAPI_FastTransferSourceCopyFolder: secondary = rop->u.mapi_FastTransferSourceCopyFolder.handle_idx; break;
		case op_MAPI_FastTransferSourceCopyTo: secondary = rop->u.mapi_FastTransferSourceCopyTo.handle_idx; break;
		case op_MAPI_FastTransferDestConfigure: secondary = rop->u.mapi_FastTransferDestinationConfigure.handle_idx; break;
		case op_MAPI_CopyProperties: secondary = rop->u.mapi_CopyProperties.handle_idx; break;
		case op_MAPI_FastTransferSourceCopyProps: secondary = rop->u.mapi_FastTransferSourceCopyProperties.handle_idx; break;
		case op_MAPI_SyncConfigure: secondary = rop->u.mapi_SyncConfigure.handle_idx; break;
		case op_MAPI_SyncImportMessageChange: secondary = rop->u.mapi_SyncImportMessageChange.handle_idx; break;
		case op_MAPI_SyncOpenCollector: secondary = rop->u.mapi_SyncOpenCollector.handle_idx; break;
		case op_MAPI_SyncGetTransferState: secondary = rop->u.mapi_SyncGetTransferState.handle_idx; break;
		case op_MAPI_SyncOpenAdvisor: secondary = rop->u.mapi_SyncOpenAdvisor.handle_idx; break;
		case op_MAPI_OpenPublicFolderByName: secondary = rop->u.mapi_OpenPublicFolderByName.handle_idx; break;
		default: break;
		}
		if (secondary >= handles) return false;
	}
	return false;
}

static enum MAPISTATUS EcDoRpc_process_transaction(TALLOC_CTX *mem_ctx,
							 struct emsmdbp_context *emsmdbp_ctx,
							 struct mapi_request *mapi_request,
							 struct mapi_response **result)
{
	enum MAPISTATUS		retval;
	struct mapi_response	*mapi_response;
	uint32_t		handles_length;
	uint16_t		size = 0;
	uint32_t		i;
	uint32_t		idx, op_count;

	*result = NULL;
	if (emsmdbp_ctx == NULL) return MAPI_E_NOT_INITIALIZED;
	if (!emsmdb_request_valid(mapi_request, &op_count)) return ecRpcFormat;
	handles_length = mapi_request->mapi_len - mapi_request->length;
	mapi_response = talloc_zero(mem_ctx, struct mapi_response);
	if (mapi_response == NULL) return MAPI_E_NOT_ENOUGH_RESOURCES;
	if (handles_length != 0) {
		mapi_response->handles = talloc_memdup(mapi_response, mapi_request->handles, handles_length);
		if (mapi_response->handles == NULL) return MAPI_E_NOT_ENOUGH_RESOURCES;
	}
	mapi_response->mapi_repl = talloc_zero_array(mapi_response, struct EcDoRpc_MAPI_REPL, op_count + 1);
	if (mapi_response->mapi_repl == NULL) return MAPI_E_NOT_ENOUGH_RESOURCES;
	idx = 0;
	if (op_count == 0) goto notif;

	/* Step 2. Process serialized MAPI requests */
	for (i = 0; i < op_count; i++) {
		uint16_t before = size;
		retval = MAPI_E_SUCCESS;
		switch (mapi_request->mapi_req[i].opnum) {
		case op_MAPI_Release: /* 0x01 */
			retval = EcDoRpc_RopRelease(mem_ctx, emsmdbp_ctx, 
						    &(mapi_request->mapi_req[i]),
						    mapi_response->handles, &size);
			break;
		case op_MAPI_OpenFolder: /* 0x02 */
			retval = EcDoRpc_RopOpenFolder(mem_ctx, emsmdbp_ctx,
						       &(mapi_request->mapi_req[i]),
						       &(mapi_response->mapi_repl[idx]),
						       mapi_response->handles, &size);
			break;
		case op_MAPI_OpenMessage: /* 0x3 */
			retval = EcDoRpc_RopOpenMessage(mem_ctx, emsmdbp_ctx,
							&(mapi_request->mapi_req[i]),
							&(mapi_response->mapi_repl[idx]),
							mapi_response->handles, &size);
			break;
		case op_MAPI_GetHierarchyTable: /* 0x04 */
			retval = EcDoRpc_RopGetHierarchyTable(mem_ctx, emsmdbp_ctx,
							      &(mapi_request->mapi_req[i]),
							      &(mapi_response->mapi_repl[idx]),
							      mapi_response->handles, &size);
			break;
		case op_MAPI_GetContentsTable: /* 0x05 */
			retval = EcDoRpc_RopGetContentsTable(mem_ctx, emsmdbp_ctx,
							     &(mapi_request->mapi_req[i]),
							     &(mapi_response->mapi_repl[idx]),
							     mapi_response->handles, &size);
			break;
		case op_MAPI_CreateMessage: /* 0x06 */
			retval = EcDoRpc_RopCreateMessage(mem_ctx, emsmdbp_ctx,
							  &(mapi_request->mapi_req[i]),
							  &(mapi_response->mapi_repl[idx]),
							  mapi_response->handles, &size);
			break;
		case op_MAPI_GetProps: /* 0x07 */
			retval = EcDoRpc_RopGetPropertiesSpecific(mem_ctx, emsmdbp_ctx,
								  &(mapi_request->mapi_req[i]),
								  &(mapi_response->mapi_repl[idx]),
								  mapi_response->handles, &size);
			break;
		case op_MAPI_GetPropsAll: /* 0x8 */
			retval = EcDoRpc_RopGetPropertiesAll(mem_ctx, emsmdbp_ctx,
							     &(mapi_request->mapi_req[i]),
							     &(mapi_response->mapi_repl[idx]),
							     mapi_response->handles, &size);
			break;
		case op_MAPI_GetPropList: /* 0x9 */
			retval = EcDoRpc_RopGetPropertiesList(mem_ctx, emsmdbp_ctx,
							      &(mapi_request->mapi_req[i]),
							      &(mapi_response->mapi_repl[idx]),	
							      mapi_response->handles, &size);
			break;
		case op_MAPI_SetProps: /* 0x0a */
			retval = EcDoRpc_RopSetProperties(mem_ctx, emsmdbp_ctx,
							  &(mapi_request->mapi_req[i]),
							  &(mapi_response->mapi_repl[idx]),
							  mapi_response->handles, &size);
			break;
		case op_MAPI_DeleteProps: /* 0xb */
			retval = EcDoRpc_RopDeleteProperties(mem_ctx, emsmdbp_ctx,
							     &(mapi_request->mapi_req[i]),
							     &(mapi_response->mapi_repl[idx]),
							     mapi_response->handles, &size);
			break;
		case op_MAPI_SaveChangesMessage: /* 0x0c */
			retval = EcDoRpc_RopSaveChangesMessage(mem_ctx, emsmdbp_ctx,
                                                               &(mapi_request->mapi_req[i]),
                                                               &(mapi_response->mapi_repl[idx]),
                                                               mapi_response->handles, &size);
			break;
		case op_MAPI_RemoveAllRecipients: /* 0xd */
			retval = EcDoRpc_RopRemoveAllRecipients(mem_ctx, emsmdbp_ctx,
								&(mapi_request->mapi_req[i]),
								&(mapi_response->mapi_repl[idx]),
								mapi_response->handles, &size);
			break;
		case op_MAPI_ModifyRecipients: /* 0xe */
			retval = EcDoRpc_RopModifyRecipients(mem_ctx, emsmdbp_ctx,
							     &(mapi_request->mapi_req[i]),
							     &(mapi_response->mapi_repl[idx]),
							     mapi_response->handles, &size);
			break;

		/* op_MAPI_ReadRecipients: 0xf */
		case op_MAPI_ReloadCachedInformation: /* 0x10 */
			retval = EcDoRpc_RopReloadCachedInformation(mem_ctx, emsmdbp_ctx,
								    &(mapi_request->mapi_req[i]),
								    &(mapi_response->mapi_repl[idx]),
								    mapi_response->handles, &size);
			break;
		case op_MAPI_SetMessageReadFlag: /* 0x11 */
			retval = EcDoRpc_RopSetMessageReadFlag(mem_ctx, emsmdbp_ctx,
							       &(mapi_request->mapi_req[i]),
							       &(mapi_response->mapi_repl[idx]),
							       mapi_response->handles, &size);
			break;
		case op_MAPI_SetColumns: /* 0x12 */
			retval = EcDoRpc_RopSetColumns(mem_ctx, emsmdbp_ctx,
						       &(mapi_request->mapi_req[i]),
						       &(mapi_response->mapi_repl[idx]),
						       mapi_response->handles, &size);
			break;
		case op_MAPI_SortTable: /* 0x13 */
			retval = EcDoRpc_RopSortTable(mem_ctx, emsmdbp_ctx,
						      &(mapi_request->mapi_req[i]),
						      &(mapi_response->mapi_repl[idx]),
						      mapi_response->handles, &size);
			break;
		case op_MAPI_Restrict: /* 0x14 */
			retval = EcDoRpc_RopRestrict(mem_ctx, emsmdbp_ctx,
						     &(mapi_request->mapi_req[i]),
						     &(mapi_response->mapi_repl[idx]),
						     mapi_response->handles, &size);
			break;
		case op_MAPI_QueryRows: /* 0x15 */
			retval = EcDoRpc_RopQueryRows(mem_ctx, emsmdbp_ctx,
						      &(mapi_request->mapi_req[i]),
						      &(mapi_response->mapi_repl[idx]),
						      mapi_response->handles, &size);
			break;
		/* op_MAPI_GetStatus: 0x16 */
		case op_MAPI_QueryPosition: /* 0x17 */
			retval = EcDoRpc_RopQueryPosition(mem_ctx, emsmdbp_ctx,
							  &(mapi_request->mapi_req[i]),
							  &(mapi_response->mapi_repl[idx]),
							  mapi_response->handles, &size);
			break;
		case op_MAPI_SeekRow: /* 0x18 */
			retval = EcDoRpc_RopSeekRow(mem_ctx, emsmdbp_ctx,
						    &(mapi_request->mapi_req[i]),
						    &(mapi_response->mapi_repl[idx]),
						    mapi_response->handles, &size);
			break;
		/* op_MAPI_SeekRowBookmark: 0x19 */
		/* op_MAPI_SeekRowApprox: 0x1a */
		/* op_MAPI_CreateBookmark: 0x1b */
		case op_MAPI_CreateFolder: /* 0x1c */
			retval = EcDoRpc_RopCreateFolder(mem_ctx, emsmdbp_ctx,
							 &(mapi_request->mapi_req[i]),
							 &(mapi_response->mapi_repl[idx]),
							 mapi_response->handles, &size);
			break;
		case op_MAPI_DeleteFolder: /* 0x1d */
			retval = EcDoRpc_RopDeleteFolder(mem_ctx, emsmdbp_ctx,
							 &(mapi_request->mapi_req[i]),
							 &(mapi_response->mapi_repl[idx]),
							 mapi_response->handles, &size);
			break;
		case op_MAPI_DeleteMessages: /* 0x1e */
			retval = EcDoRpc_RopDeleteMessages(mem_ctx, emsmdbp_ctx,
							   &(mapi_request->mapi_req[i]),
							   &(mapi_response->mapi_repl[idx]),
							   mapi_response->handles, &size);
			break;
		case op_MAPI_GetMessageStatus: /* 0x1f */
			retval = EcDoRpc_RopGetMessageStatus(mem_ctx, emsmdbp_ctx,
							     &(mapi_request->mapi_req[i]),
							     &(mapi_response->mapi_repl[idx]),
							     mapi_response->handles, &size);
			break;
		/* op_MAPI_SetMessageStatus: 0x20 */
		case op_MAPI_GetAttachmentTable: /* 0x21 */
			retval = EcDoRpc_RopGetAttachmentTable(mem_ctx, emsmdbp_ctx,
							       &(mapi_request->mapi_req[i]),
							       &(mapi_response->mapi_repl[idx]),
							       mapi_response->handles, &size);
			break;
                case op_MAPI_OpenAttach: /* 0x22 */
			retval = EcDoRpc_RopOpenAttach(mem_ctx, emsmdbp_ctx,
                                                       &(mapi_request->mapi_req[i]),
                                                       &(mapi_response->mapi_repl[idx]),
                                                       mapi_response->handles, &size);
			break;
                case op_MAPI_CreateAttach: /* 0x23 */
			retval = EcDoRpc_RopCreateAttach(mem_ctx, emsmdbp_ctx,
                                                         &(mapi_request->mapi_req[i]),
                                                         &(mapi_response->mapi_repl[idx]),
                                                         mapi_response->handles, &size);
			break;
		/* op_MAPI_DeleteAttach: 0x24 */
		case op_MAPI_SaveChangesAttachment: /* 0x25 */
			retval = EcDoRpc_RopSaveChangesAttachment(mem_ctx, emsmdbp_ctx,
                                                                  &(mapi_request->mapi_req[i]),
                                                                  &(mapi_response->mapi_repl[idx]),
                                                                  mapi_response->handles, &size);
			break;
		case op_MAPI_SetReceiveFolder: /* 0x26 */
			retval = EcDoRpc_RopSetReceiveFolder(mem_ctx, emsmdbp_ctx,
							     &(mapi_request->mapi_req[i]),
							     &(mapi_response->mapi_repl[idx]),
							     mapi_response->handles, &size);
			break;
		case op_MAPI_GetReceiveFolder: /* 0x27 */
			retval = EcDoRpc_RopGetReceiveFolder(mem_ctx, emsmdbp_ctx,
							     &(mapi_request->mapi_req[i]),
							     &(mapi_response->mapi_repl[idx]),
							     mapi_response->handles, &size);
			break;
		case op_MAPI_RegisterNotification: /* 0x29 */
			retval = EcDoRpc_RopRegisterNotification(mem_ctx, emsmdbp_ctx,
								 &(mapi_request->mapi_req[i]),
								 &(mapi_response->mapi_repl[idx]),
								 mapi_response->handles, &size);
			break;
		/* op_MAPI_Notify: 0x2a */
		case op_MAPI_OpenStream: /* 0x2b */
			retval = EcDoRpc_RopOpenStream(mem_ctx, emsmdbp_ctx,
						       &(mapi_request->mapi_req[i]),
						       &(mapi_response->mapi_repl[idx]),
						       mapi_response->handles, &size);
			break;
		case op_MAPI_ReadStream: /* 0x2c */
			retval = EcDoRpc_RopReadStream(mem_ctx, emsmdbp_ctx,
						       &(mapi_request->mapi_req[i]),
						       &(mapi_response->mapi_repl[idx]),
						       mapi_response->handles, &size);
			break;
		case op_MAPI_WriteStream: /* 0x2d */
			retval = EcDoRpc_RopWriteStream(mem_ctx, emsmdbp_ctx,
							&(mapi_request->mapi_req[i]),
							&(mapi_response->mapi_repl[idx]),
							mapi_response->handles, &size);
			break;
                case op_MAPI_SeekStream: /* 0x2e */
			retval = EcDoRpc_RopSeekStream(mem_ctx, emsmdbp_ctx,
                                                       &(mapi_request->mapi_req[i]),
                                                       &(mapi_response->mapi_repl[idx]),
                                                       mapi_response->handles, &size);
			break;
                case op_MAPI_SetStreamSize: /* 0x2f */
			retval = EcDoRpc_RopSetStreamSize(mem_ctx, emsmdbp_ctx,
                                                          &(mapi_request->mapi_req[i]),
                                                          &(mapi_response->mapi_repl[idx]),
                                                          mapi_response->handles, &size);
			break;
		case op_MAPI_SetSearchCriteria: /* 0x30 */
			retval = EcDoRpc_RopSetSearchCriteria(mem_ctx, emsmdbp_ctx,
							      &(mapi_request->mapi_req[i]),
							      &(mapi_response->mapi_repl[idx]),
							      mapi_response->handles, &size);
			break;
		case op_MAPI_GetSearchCriteria: /* 0x31 */
			retval = EcDoRpc_RopGetSearchCriteria(mem_ctx, emsmdbp_ctx,
							      &(mapi_request->mapi_req[i]),
							      &(mapi_response->mapi_repl[idx]),
							      mapi_response->handles, &size);
			break;
		case op_MAPI_SubmitMessage: /* 0x32 */
			retval = EcDoRpc_RopSubmitMessage(mem_ctx, emsmdbp_ctx,
							  &(mapi_request->mapi_req[i]),
							  &(mapi_response->mapi_repl[idx]),
							  mapi_response->handles, &size);
			break;
		case op_MAPI_MoveCopyMessages: /* 0x33 */
			retval = EcDoRpc_RopMoveCopyMessages(mem_ctx, emsmdbp_ctx,
							    &(mapi_request->mapi_req[i]),
							    &(mapi_response->mapi_repl[idx]),
							    mapi_response->handles, &size);
		        break;
		/* op_MAPI_AbortSubmit: 0x34 */
		case op_MAPI_MoveFolder: /* 0x35 */
			retval = EcDoRpc_RopMoveFolder(mem_ctx, emsmdbp_ctx,
						       &(mapi_request->mapi_req[i]),
						       &(mapi_response->mapi_repl[idx]),
						       mapi_response->handles, &size);
		        break;
		case op_MAPI_CopyFolder: /* 0x36 */
			retval = EcDoRpc_RopCopyFolder(mem_ctx, emsmdbp_ctx,
						       &(mapi_request->mapi_req[i]),
						       &(mapi_response->mapi_repl[idx]),
						       mapi_response->handles, &size);
		        break;
		/* op_MAPI_QueryColumnsAll: 0x37 */
		/* op_MAPI_Abort: 0x38 */
		case op_MAPI_CopyTo: /* 0x39 */
                        retval = EcDoRpc_RopCopyTo(mem_ctx, emsmdbp_ctx,
                                                   &(mapi_request->mapi_req[i]),
                                                   &(mapi_response->mapi_repl[idx]),
                                                   mapi_response->handles, &size);
			break;
		/* op_MAPI_CopyToStream: 0x3a */
		/* op_MAPI_CloneStream: 0x3b */
		case op_MAPI_GetPermissionsTable: /* 0x3e */
			retval = EcDoRpc_RopGetPermissionsTable(mem_ctx, emsmdbp_ctx,
								&(mapi_request->mapi_req[i]),
								&(mapi_response->mapi_repl[idx]),
								mapi_response->handles, &size);
			break;
		case op_MAPI_GetRulesTable: /* 0x3f */
			retval = EcDoRpc_RopGetRulesTable(mem_ctx, emsmdbp_ctx,
							  &(mapi_request->mapi_req[i]),
							  &(mapi_response->mapi_repl[idx]),
							  mapi_response->handles, &size);
			break;
		case op_MAPI_ModifyPermissions: /* 0x40 */
			retval = EcDoRpc_RopModifyPermissions(mem_ctx, emsmdbp_ctx,
							      &(mapi_request->mapi_req[i]),
							      &(mapi_response->mapi_repl[idx]),
							      mapi_response->handles, &size);
			break;
		case op_MAPI_ModifyRules: /* 0x41 */
			retval = EcDoRpc_RopModifyRules(mem_ctx, emsmdbp_ctx,
							&(mapi_request->mapi_req[i]),
							&(mapi_response->mapi_repl[idx]),
							mapi_response->handles, &size);
			break;
		/* op_MAPI_GetOwningServers: 0x42 */
		case op_MAPI_LongTermIdFromId: /* 0x43 */
			retval = EcDoRpc_RopLongTermIdFromId(mem_ctx, emsmdbp_ctx,
							     &(mapi_request->mapi_req[i]),
							     &(mapi_response->mapi_repl[idx]),
							     mapi_response->handles, &size);
			break;
		case op_MAPI_IdFromLongTermId: /* 0x44 */
			retval = EcDoRpc_RopIdFromLongTermId(mem_ctx, emsmdbp_ctx,
							     &(mapi_request->mapi_req[i]),
							     &(mapi_response->mapi_repl[idx]),
							     mapi_response->handles, &size);
			break;
		/* op_MAPI_PublicFolderIsGhosted: 0x45 */
		case op_MAPI_OpenEmbeddedMessage: /* 0x46 */
			retval = EcDoRpc_RopOpenEmbeddedMessage(mem_ctx, emsmdbp_ctx,
                                                                &(mapi_request->mapi_req[i]),
                                                                &(mapi_response->mapi_repl[idx]),
                                                                mapi_response->handles, &size);
                        break;
		case op_MAPI_SetSpooler: /* 0x47 */
			retval = EcDoRpc_RopSetSpooler(mem_ctx, emsmdbp_ctx,
						       &(mapi_request->mapi_req[i]),
						       &(mapi_response->mapi_repl[idx]),
						       mapi_response->handles, &size);
			break;
		/* op_MAPI_SpoolerLockMessage: 0x48 */
		case op_MAPI_AddressTypes: /*x49 */
			retval = EcDoRpc_RopGetAddressTypes(mem_ctx, emsmdbp_ctx,
							    &(mapi_request->mapi_req[i]),
							    &(mapi_response->mapi_repl[idx]),
							    mapi_response->handles, &size);
			break;
		case op_MAPI_TransportSend: /* 0x4a */
			retval = EcDoRpc_RopTransportSend(mem_ctx, emsmdbp_ctx,
							  &(mapi_request->mapi_req[i]),
							  &(mapi_response->mapi_repl[idx]),
							  mapi_response->handles, &size);
			break;
		/* op_MAPI_FastTransferSourceCopyMessages: 0x4b */
		/* op_MAPI_FastTransferSourceCopyFolder: 0x4c */
		case op_MAPI_FastTransferSourceCopyTo: /* 0x4d */
			retval = EcDoRpc_RopFastTransferSourceCopyTo(mem_ctx, emsmdbp_ctx, 
								     &(mapi_request->mapi_req[i]),
								     &(mapi_response->mapi_repl[idx]),
								     mapi_response->handles, &size);
			break;
		case op_MAPI_FastTransferSourceGetBuffer: /* 0x4e */
			retval = EcDoRpc_RopFastTransferSourceGetBuffer(mem_ctx, emsmdbp_ctx, 
									&(mapi_request->mapi_req[i]),
									&(mapi_response->mapi_repl[idx]),
									mapi_response->handles, &size);
			break;
		case op_MAPI_FindRow: /* 0x4f */
			retval = EcDoRpc_RopFindRow(mem_ctx, emsmdbp_ctx, 
						    &(mapi_request->mapi_req[i]),
						    &(mapi_response->mapi_repl[idx]),
						    mapi_response->handles, &size);
			break;
		/* op_MAPI_Progress: 0x50 */
		/* op_MAPI_TransportNewMail: 0x51 */
		/* op_MAPI_GetValidAttachments: 0x52 */
		case op_MAPI_GetNamesFromIDs: /* 0x55 */
			retval = EcDoRpc_RopGetNamesFromIDs(mem_ctx, emsmdbp_ctx,
							    &(mapi_request->mapi_req[i]),
							    &(mapi_response->mapi_repl[idx]),
							    mapi_response->handles, &size);
			break;
		case op_MAPI_GetIDsFromNames: /* 0x56 */
			retval = EcDoRpc_RopGetPropertyIdsFromNames(mem_ctx, emsmdbp_ctx,
								    &(mapi_request->mapi_req[i]),
								    &(mapi_response->mapi_repl[idx]),
								    mapi_response->handles, &size);
			break;
		/* op_MAPI_UpdateDeferredActionMessages: 0x57 */ 
		case op_MAPI_EmptyFolder: /* 0x58 */
		retval = EcDoRpc_RopEmptyFolder(mem_ctx, emsmdbp_ctx,
						&(mapi_request->mapi_req[i]),
						&(mapi_response->mapi_repl[idx]),
						mapi_response->handles, &size);
			break;
		/* op_MAPI_ExpandRow: 0x59 */
		/* op_MAPI_CollapseRow: 0x5a */
		/* op_MAPI_LockRegionStream: 0x5b */
		/* op_MAPI_UnlockRegionStream: 0x5c */
		case op_MAPI_CommitStream: /* 0x5d */
			retval = EcDoRpc_RopCommitStream(mem_ctx, emsmdbp_ctx,
							 &(mapi_request->mapi_req[i]),
							 &(mapi_response->mapi_repl[idx]),
							 mapi_response->handles, &size);
			break;
		case op_MAPI_GetStreamSize: /* 0x5e */
			retval = EcDoRpc_RopGetStreamSize(mem_ctx, emsmdbp_ctx,
							  &(mapi_request->mapi_req[i]),
							  &(mapi_response->mapi_repl[idx]),
							  mapi_response->handles, &size);
			break;
		/* op_MAPI_QueryNamedProperties: 0x5f */
		case op_MAPI_GetPerUserLongTermIds: /* 0x60 */
			retval = EcDoRpc_RopGetPerUserLongTermIds(mem_ctx, emsmdbp_ctx,
								  &(mapi_request->mapi_req[i]),
								  &(mapi_response->mapi_repl[idx]),
								  mapi_response->handles, &size);
			break;
		case op_MAPI_GetPerUserGuid: /* 0x61 */
			retval = EcDoRpc_RopGetPerUserGuid(mem_ctx, emsmdbp_ctx,
							   &(mapi_request->mapi_req[i]),
							   &(mapi_response->mapi_repl[idx]),
							   mapi_response->handles, &size);
			break;
		case op_MAPI_ReadPerUserInformation: /* 0x63 */
			retval = EcDoRpc_RopReadPerUserInformation(mem_ctx, emsmdbp_ctx,
								   &(mapi_request->mapi_req[i]),
								   &(mapi_response->mapi_repl[idx]),
								   mapi_response->handles, &size);
			break;
		/* op_MAPI_ReadPerUserInformation: 0x63 */
		/* op_MAPI_SetReadFlags: 0x66 */
		/* op_MAPI_CopyProperties: 0x67 */
		case op_MAPI_GetReceiveFolderTable: /* 0x68 */
			retval = EcDoRpc_RopGetReceiveFolderTable(mem_ctx, emsmdbp_ctx,
								  &(mapi_request->mapi_req[i]),
								  &(mapi_response->mapi_repl[idx]),
								  mapi_response->handles, &size);
			break;

		/* op_MAPI_GetCollapseState: 0x6b */
		/* op_MAPI_SetCollapseState: 0x6c */
		case op_MAPI_GetTransportFolder: /* 0x6d */
			retval = EcDoRpc_RopGetTransportFolder(mem_ctx, emsmdbp_ctx,
							       &(mapi_request->mapi_req[i]),
							       &(mapi_response->mapi_repl[idx]),
							       mapi_response->handles, &size);
			break;
		/* op_MAPI_Pending: 0x6e */
		case op_MAPI_OptionsData: /* 0x6f */
			retval = EcDoRpc_RopOptionsData(mem_ctx, emsmdbp_ctx,
							&(mapi_request->mapi_req[i]),
							&(mapi_response->mapi_repl[idx]),
							mapi_response->handles, &size);
			break;
                case op_MAPI_SyncConfigure: /* 0x70 */
			retval = EcDoRpc_RopSyncConfigure(mem_ctx, emsmdbp_ctx,
							  &(mapi_request->mapi_req[i]),
							  &(mapi_response->mapi_repl[idx]),
							  mapi_response->handles, &size);
			break;
		case op_MAPI_SyncImportMessageChange: /* 0x72 */
			retval = EcDoRpc_RopSyncImportMessageChange(mem_ctx, emsmdbp_ctx,
								    &(mapi_request->mapi_req[i]),
								    &(mapi_response->mapi_repl[idx]),
								    mapi_response->handles, &size);
			break;
		case op_MAPI_SyncImportHierarchyChange: /* 0x73 */
			retval = EcDoRpc_RopSyncImportHierarchyChange(mem_ctx, emsmdbp_ctx,
								      &(mapi_request->mapi_req[i]),
								      &(mapi_response->mapi_repl[idx]),
								      mapi_response->handles, &size);
			break;
		case op_MAPI_SyncImportDeletes: /* 0x74 */
			retval = EcDoRpc_RopSyncImportDeletes(mem_ctx, emsmdbp_ctx,
							      &(mapi_request->mapi_req[i]),
							      &(mapi_response->mapi_repl[idx]),
							      mapi_response->handles, &size);
			break;
                case op_MAPI_SyncUploadStateStreamBegin: /* 0x75 */
			retval = EcDoRpc_RopSyncUploadStateStreamBegin(mem_ctx, emsmdbp_ctx,
								       &(mapi_request->mapi_req[i]),
								       &(mapi_response->mapi_repl[idx]),
								       mapi_response->handles, &size);
			break;
                case op_MAPI_SyncUploadStateStreamContinue: /* 0x76 */
			retval = EcDoRpc_RopSyncUploadStateStreamContinue(mem_ctx, emsmdbp_ctx,
									  &(mapi_request->mapi_req[i]),
									  &(mapi_response->mapi_repl[idx]),
									  mapi_response->handles, &size);
			break;
		case op_MAPI_SyncUploadStateStreamEnd: /* 0x77 */
			retval = EcDoRpc_RopSyncUploadStateStreamEnd(mem_ctx, emsmdbp_ctx,
								     &(mapi_request->mapi_req[i]),
								     &(mapi_response->mapi_repl[idx]),
								     mapi_response->handles, &size);
			break;
		case op_MAPI_SyncImportMessageMove: /* 0x78 */
			retval = EcDoRpc_RopSyncImportMessageMove(mem_ctx, emsmdbp_ctx,
								  &(mapi_request->mapi_req[i]),
								  &(mapi_response->mapi_repl[idx]),
								  mapi_response->handles, &size);
			break;
		/* op_MAPI_SetPropertiesNoReplicate: 0x79 */
		case op_MAPI_DeletePropertiesNoReplicate: /* 0x7a */
			retval = EcDoRpc_RopDeletePropertiesNoReplicate(mem_ctx, emsmdbp_ctx,
									&(mapi_request->mapi_req[i]),
									&(mapi_response->mapi_repl[idx]),
									mapi_response->handles, &size);
			break;
		case op_MAPI_GetStoreState: /* 0x7b */
			retval = EcDoRpc_RopGetStoreState(mem_ctx, emsmdbp_ctx,
							  &(mapi_request->mapi_req[i]),
							  &(mapi_response->mapi_repl[idx]),
							  mapi_response->handles, &size);
			break;
		case op_MAPI_SyncOpenCollector: /* 0x7e */
			retval = EcDoRpc_RopSyncOpenCollector(mem_ctx, emsmdbp_ctx,
							      &(mapi_request->mapi_req[i]),
							      &(mapi_response->mapi_repl[idx]),
							      mapi_response->handles, &size);
			break;
		case op_MAPI_GetLocalReplicaIds: /* 0x7f */
			retval = EcDoRpc_RopGetLocalReplicaIds(mem_ctx, emsmdbp_ctx,
                                                               &(mapi_request->mapi_req[i]),
                                                               &(mapi_response->mapi_repl[idx]),
                                                               mapi_response->handles, &size);
			break;
		case op_MAPI_SyncImportReadStateChanges: /* 0x80 */
			retval = EcDoRpc_RopSyncImportReadStateChanges(mem_ctx, emsmdbp_ctx,
								       &(mapi_request->mapi_req[i]),
								       &(mapi_response->mapi_repl[idx]),
								       mapi_response->handles, &size);
			break;
		case op_MAPI_ResetTable: /* 0x81 */
			retval = EcDoRpc_RopResetTable(mem_ctx, emsmdbp_ctx,
						       &(mapi_request->mapi_req[i]),
						       &(mapi_response->mapi_repl[idx]),
						       mapi_response->handles, &size);
			break;
		case op_MAPI_SyncGetTransferState: /* 0x82 */
			retval = EcDoRpc_RopSyncGetTransferState(mem_ctx, emsmdbp_ctx,
								 &(mapi_request->mapi_req[i]),
								 &(mapi_response->mapi_repl[idx]),
								 mapi_response->handles, &size);
			break;
		/* op_MAPI_OpenPublicFolderByName: 0x87 */
		/* op_MAPI_SetSyncNotificationGuid: 0x88 */
		/* op_MAPI_FreeBookmark: 0x89 */
		/* op_MAPI_WriteAndCommitStream: 0x90 */
		/* op_MAPI_HardDeleteMessages: 0x91 */
		/* op_MAPI_HardDeleteMessagesAndSubfolders: 0x92 */
		case op_MAPI_SetLocalReplicaMidsetDeleted: /* 0x93 */
			retval = EcDoRpc_RopSetLocalReplicaMidsetDeleted(mem_ctx, emsmdbp_ctx,
									 &(mapi_request->mapi_req[i]),
									 &(mapi_response->mapi_repl[idx]),
									 mapi_response->handles, &size);
			break;
		case op_MAPI_Logon: /* 0xfe */
			retval = EcDoRpc_RopLogon(mem_ctx, emsmdbp_ctx,
						  &(mapi_request->mapi_req[i]),
						  &(mapi_response->mapi_repl[idx]),
						  mapi_response->handles, &size);
			break;
		default:
			mapi_response->mapi_repl[idx].opnum = mapi_request->mapi_req[i].opnum;
			mapi_response->mapi_repl[idx].handle_idx = mapi_request->mapi_req[i].handle_idx;
			mapi_response->mapi_repl[idx].error_code = MAPI_E_NO_SUPPORT;
			size += SIZE_DFLT_MAPI_RESPONSE;
			retval = MAPI_E_NO_SUPPORT;
			OC_DEBUG(1, "MAPI Rop: 0x%.2x not implemented!\n",
				  mapi_request->mapi_req[i].opnum);
		}

		if (size < before || (uint32_t)size + 2 + handles_length > UINT16_MAX) return ecBufferTooSmall;
		if (mapi_request->mapi_req[i].opnum != op_MAPI_Release) {
			idx++;
		}

		if (retval) {
			OC_DEBUG(5, "MAPI Rop: 0x%.2x [retval=0x%.8x]\n", mapi_request->mapi_req[i].opnum, retval);
		}
	}

notif:
	/* Step 3. Notifications/Pending calls should be processed here */
	/* Note: GetProps and GetRows are filled with flag NDR_REMAINING, which may hide the content of the following replies. */
	{
		DATA_BLOB		payload;
			enum mapistore_error	ret;
		struct ndr_pull		*ndr;
		enum ndr_err_code	ndr_err_code;

		ret = mapistore_notification_deliver_get(mem_ctx, emsmdbp_ctx->mstore_ctx, emsmdbp_ctx->session_uuid,
							 &payload.data, &payload.length);
		if (ret == MAPISTORE_SUCCESS) {
			ndr = ndr_pull_init_blob(&payload, mem_ctx);
			if (!ndr) {
				OC_DEBUG(0, "Unable to initialize notification ndr pull blob");
				goto end;
			}
			NDR_PULL_SET_MEM_CTX(ndr, mapi_response, 0);
			ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
			while (ndr->offset < payload.length) {
				uint32_t before = ndr->offset;
				struct EcDoRpc_MAPI_REPL *grown = talloc_realloc(mapi_response,
					mapi_response->mapi_repl, struct EcDoRpc_MAPI_REPL, idx + 2);
				if (grown == NULL) return MAPI_E_NOT_ENOUGH_RESOURCES;
				mapi_response->mapi_repl = grown;
				ZERO_STRUCT(grown[idx]); ZERO_STRUCT(grown[idx + 1]);
				ndr_err_code = ndr_pull_EcDoRpc_MAPI_REPL(ndr, NDR_SCALARS, &grown[idx]);
				if (ndr_err_code != NDR_ERR_SUCCESS || ndr->offset <= before ||
				    grown[idx].opnum != op_MAPI_Notify) return ecRpcFormat;
				if ((uint32_t)size + ndr->offset - before + 2 + handles_length > UINT16_MAX) return ecBufferTooSmall;
				size += ndr->offset - before;
				idx++;
			}

			ret = mapistore_notification_deliver_delete(emsmdbp_ctx->mstore_ctx, emsmdbp_ctx->session_uuid);
			if (ret != MAPISTORE_SUCCESS) {
				OC_DEBUG(0, "Unable to delete notification key");
			}
			talloc_free(ndr);
		}
	}

end:
	if (mapi_response->mapi_repl) {
		mapi_response->mapi_repl[idx].opnum = 0;
	}
	
	/* Step 4. Fill mapi_response structure */
	handles_length = mapi_request->mapi_len - mapi_request->length;
	mapi_response->length = size + sizeof (mapi_response->length);
	mapi_response->mapi_len = mapi_response->length + handles_length;

	*result = mapi_response;
	return MAPI_E_SUCCESS;
}

/**
   \details exchange_emsmdb EcDoRpc (0x2) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcDoRpc request data

   \return MAPI_E_SUCCESS on success
 */
static enum MAPISTATUS dcesrv_EcDoRpc(struct dcesrv_call_state *dce_call,
                                      TALLOC_CTX *mem_ctx, struct EcDoRpc *r)
{
	struct emsmdbp_context *ctx = dcesrv_find_emsmdb_context(dce_call, r->in.handle);
	struct mapi_response *response;
	r->out.size = r->in.size;
	r->out.offset = r->in.offset;
	ZERO_STRUCTP(r->out.mapi_response);
	r->out.mapi_response->length = r->out.mapi_response->mapi_len = 2;
	*r->out.length = 2;
	r->out.result = MAPI_E_LOGON_FAILED;
	if (!dcesrv_call_authenticated(dce_call)) goto failure;
	r->out.result = MAPI_E_INVALID_OBJECT;
	if (ctx == NULL) goto failure;
	r->out.result = EcDoRpc_process_transaction(mem_ctx, ctx, r->in.mapi_request, &response);
	if (r->out.result != MAPI_E_SUCCESS) goto failure;
	if (response->mapi_len > r->in.max_data) {
		r->out.result = ecBufferTooSmall;
		goto failure;
	}
	*r->out.handle = *r->in.handle;
	r->out.mapi_response = response;
	*r->out.length = response->mapi_len;
	return r->out.result;
failure:
	ZERO_STRUCTP(r->out.handle);
	return r->out.result;
}


/**
   \details exchange_emsmdb EcGetMoreRpc (0x3) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcGetMoreRpc request data

   \return MAPI_E_SUCCESS on success
 */
static void dcesrv_EcGetMoreRpc(struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx,
				struct EcGetMoreRpc *r)
{
	OC_DEBUG(3, "exchange_emsmdb: EcGetMoreRpc (0x3) not implemented\n");
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/**
   \details exchange_emsmdb EcRRegisterPushNotification (0x4) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcRRegisterPushNotification request data

   \return MAPI_E_SUCCESS on success
 */
static enum MAPISTATUS dcesrv_EcRRegisterPushNotification(struct dcesrv_call_state *dce_call,
							  TALLOC_CTX *mem_ctx,
							  struct EcRRegisterPushNotification *r)
{
	int				retval;
	struct emsmdbp_context		*emsmdbp_ctx;

	OC_DEBUG(3, "exchange_emsmdb: EcRRegisterPushNotification (0x4)\n");

	if (!dcesrv_call_authenticated(dce_call)) {
		OC_DEBUG(1, "No challenge requested by client, cannot authenticate\n");
		r->out.handle->handle_type = 0;
		r->out.handle->uuid = GUID_zero();
		r->out.result = DCERPC_FAULT_CONTEXT_MISMATCH;
		return MAPI_E_LOGON_FAILED;
	}

	/* Retrieve the emsmdbp_context from the session management system */
	emsmdbp_ctx = dcesrv_find_emsmdb_context(dce_call, r->in.handle);
	if (emsmdbp_ctx == NULL) {
		r->out.handle->handle_type = 0;
		r->out.handle->uuid = GUID_zero();
		r->out.result = DCERPC_FAULT_CONTEXT_MISMATCH;
		return MAPI_E_LOGON_FAILED;
	}

	retval = MAPI_E_SUCCESS;

	if (retval == MAPI_E_SUCCESS) {
		r->out.handle = r->in.handle;
		/* FIXME: Create a notification object and return associated handle */
		*r->out.hNotification = 244;
	} 

	return MAPI_E_SUCCESS;
}


/**
   \details exchange_emsmdb EcRUnregisterPushNotification (0x5) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcRUnregisterPushNotification request data

   \return MAPI_E_SUCCESS on success
 */
static enum MAPISTATUS dcesrv_EcRUnregisterPushNotification(struct dcesrv_call_state *dce_call,
							    TALLOC_CTX *mem_ctx,
							    struct EcRUnregisterPushNotification *r)
{
	OC_DEBUG(3, "exchange_emsmdb: EcRUnregisterPushNotification (0x5) not implemented\n");
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/**
   \details exchange_emsmdb EcDummyRpc (0x6) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcDummyRpc request data

   \return MAPI_E_SUCCESS on success
 */
static enum MAPISTATUS dcesrv_EcDummyRpc(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct EcDummyRpc *r)
{
	OC_DEBUG(3, "exchange_emsmdb: EcDummyRpc (0x6)\n");
	return MAPI_E_SUCCESS;
}


/**
   \details exchange_emsmdb EcRGetDCName (0x7) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcRGetDCName request data

   \return MAPI_E_SUCCESS on success
 */
static void dcesrv_EcRGetDCName(struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx,
				struct EcRGetDCName *r)
{
	OC_DEBUG(3, "exchange_emsmdb: EcRGetDCName (0x7) not implemented\n");
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/**
   \details exchange_emsmdb EcRNetGetDCName (0x8) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcRNetGetDCName request data

   \return MAPI_E_SUCCESS on success
 */
static void dcesrv_EcRNetGetDCName(struct dcesrv_call_state *dce_call,
				   TALLOC_CTX *mem_ctx,
				   struct EcRNetGetDCName *r)
{
	OC_DEBUG(3, "exchange_emsmdb: EcRNetGetDCName (0x8) not implemented\n");
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/**
   \details exchange_emsmdb EcDoRpcExt (0x9) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcDoRpcExt request data

   \return MAPI_E_SUCCESS on success
 */
static enum MAPISTATUS dcesrv_EcDoRpcExt(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct EcDoRpcExt *r)
{
	OC_DEBUG(3, "exchange_emsmdb: EcDoRpcExt (0x9) not implemented\n");
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/* check if a client version is too low to use */
/* TODO: this could be much more sophisticated */
static bool clientVersionIsTooLow(const uint16_t rgwClientVersion[3])
{
	if (rgwClientVersion[0] < 0x000B) {
		return true;
	} else {
		return false;
	}
}

/**
   \details exchange_emsmdb EcDoConnectEx (0xA) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcDoConnectEx request data

   \return MAPI_E_SUCCESS on success
 */
static enum MAPISTATUS dcesrv_EcDoConnectEx(struct dcesrv_call_state *dce_call,
                                            TALLOC_CTX *mem_ctx, struct EcDoConnectEx *r)
{
	ZERO_STRUCTP(r->out.handle);
	*r->out.pcmsPollsMax = *r->out.pcRetry = *r->out.pcmsRetryDelay = *r->out.picxr = 0;
	*r->out.pulTimeStamp = 0;
	*r->out.pcbAuxOut = 0;
	r->out.rgbAuxOut = NULL;
	*r->out.szDisplayName = *r->out.szDNPrefix = "";
	ZERO_STRUCT(r->out.rgwServerVersion);
	ZERO_STRUCT(r->out.rgwBestVersion);
	r->out.result = MAPI_E_LOGON_FAILED;
	if (!dcesrv_call_authenticated(dce_call)) return r->out.result;
	if (r->in.cbAuxIn < 8 || r->in.rgbAuxIn == NULL) {
		r->out.result = ecRpcFailed;
		return r->out.result;
	}
	if (clientVersionIsTooLow(r->in.rgwClientVersion)) {
		r->out.rgwBestVersion[0] = 0x000B;
		r->out.rgwBestVersion[1] = 0x8000;
		r->out.result = MAPI_E_VERSION;
		return r->out.result;
	}
	r->out.result = emsmdb_connect_context(dce_call, mem_ctx, r->in.szUserDN,
		r->in.ulLcidString, r->out.handle, r->out.szDisplayName, r->out.szDNPrefix);
	if (r->out.result != MAPI_E_SUCCESS) return r->out.result;
	*r->out.pcmsPollsMax = EMSMDB_PCMSPOLLMAX;
	*r->out.pcRetry = EMSMDB_PCRETRY;
	*r->out.pcmsRetryDelay = EMSMDB_PCRETRYDELAY;
	r->out.rgwServerVersion[0] = 0x8;
	r->out.rgwServerVersion[1] = 0x82B4;
	r->out.rgwServerVersion[2] = 0x3;
	memcpy(r->out.rgwBestVersion, r->in.rgwClientVersion, sizeof(r->out.rgwBestVersion));
	*r->out.pulTimeStamp = time(NULL);
	return r->out.result;
}

/**
   \details exchange_emsmdb EcDoRpcExt2 (0xB) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcDoRpcExt2 request data

   \return MAPI_E_SUCCESS on success
 */
static enum MAPISTATUS dcesrv_EcDoRpcExt2(struct dcesrv_call_state *dce_call,
                                          TALLOC_CTX *mem_ctx, struct EcDoRpcExt2 *r)
{
	uint32_t capacity = *r->in.pcbOut, flags = *r->in.pulFlags;
	struct emsmdbp_context *ctx = dcesrv_find_emsmdb_context(dce_call, r->in.handle);
	TALLOC_CTX *transaction = NULL;
	struct mapi2k7_request request = {0};
	struct mapi_response *response;
	struct RPC_HEADER_EXT header = {0};
	struct ndr_pull *pull;
	struct ndr_push *body, *wire;
	DATA_BLOB input = { .data = r->in.rgbIn, .length = r->in.cbIn };
	enum ndr_err_code error;

	r->out.rgbOut = r->out.rgbAuxOut = NULL;
	*r->out.pcbOut = *r->out.pcbAuxOut = *r->out.pulFlags = *r->out.pulTransTime = 0;
	r->out.result = MAPI_E_LOGON_FAILED;
	if (!dcesrv_call_authenticated(dce_call)) goto failure;
	r->out.result = MAPI_E_INVALID_OBJECT;
	if (ctx == NULL) goto failure;
	r->out.result = ecRpcFailed;
	if (capacity < 8 || capacity > 0x40000) goto done;
	r->out.result = ecRpcFormat;
	if (input.data == NULL || input.length < 8 || input.length > UINT16_MAX + 8U) goto done;
	transaction = talloc_new(mem_ctx);
	r->out.result = MAPI_E_NOT_ENOUGH_RESOURCES;
	if (transaction == NULL) goto done;
	pull = ndr_pull_init_blob(&input, transaction);
	if (pull == NULL) goto done;
	ndr_set_flags(&pull->flags, LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC);
	NDR_PULL_SET_MEM_CTX(pull, transaction, 0);
	error = ndr_pull_mapi2k7_request(pull, NDR_SCALARS | NDR_BUFFERS, &request);
	r->out.result = ecRpcFormat;
	/* Chained requests require a transaction scheduler; accept one final frame. */
	if (error != NDR_ERR_SUCCESS || pull->offset != input.length || !(request.header.Flags & RHEF_Last)) goto done;
	r->out.result = EcDoRpc_process_transaction(transaction, ctx, request.mapi_request, &response);
	if (r->out.result != MAPI_E_SUCCESS) goto done;
	r->out.result = MAPI_E_NOT_ENOUGH_RESOURCES;
	body = ndr_push_init_ctx(transaction);
	wire = ndr_push_init_ctx(transaction);
	if (body == NULL || wire == NULL) goto done;
	ndr_set_flags(&body->flags, LIBNDR_FLAG_NOALIGN);
	error = ndr_push_mapi_response(body, NDR_SCALARS | NDR_BUFFERS, response);
	r->out.result = ecRpcFormat;
	if (error != NDR_ERR_SUCCESS) goto done;
	r->out.result = ecBufferTooSmall;
	if (body->offset > UINT16_MAX || body->offset + 8U > capacity) goto done;
	header.Flags = RHEF_Last;
	if ((request.header.Flags & RHEF_XorMagic) && !(flags & pulFlags_NoXorMagic)) {
		header.Flags |= RHEF_XorMagic;
		obfuscate_data(body->data, body->offset, 0xA5);
	}
	header.Size = header.SizeActual = body->offset;
	ndr_set_flags(&wire->flags, LIBNDR_FLAG_NOALIGN);
	error = ndr_push_RPC_HEADER_EXT(wire, NDR_SCALARS, &header);
	if (error == NDR_ERR_SUCCESS) error = ndr_push_bytes(wire, body->data, body->offset);
	r->out.result = MAPI_E_NOT_ENOUGH_RESOURCES;
	if (error != NDR_ERR_SUCCESS) goto done;
	r->out.rgbOut = talloc_steal(mem_ctx, wire->data);
	*r->out.pcbOut = wire->offset;
	*r->out.handle = *r->in.handle;
	r->out.result = MAPI_E_SUCCESS;
	goto done;
failure:
	ZERO_STRUCTP(r->out.handle);
done:
	talloc_free(transaction);
	return r->out.result;
}

/**
   \details exchange_emsmdb EcUnknown0xC (0xc) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcUnknown0xC request data

   \return MAPI_E_SUCCESS on success
 */
static void dcesrv_EcUnknown0xC(struct dcesrv_call_state *dce_call,
				      TALLOC_CTX *mem_ctx,
				      struct EcUnknown0xC *r)
{
	OC_DEBUG(3, "exchange_emsmdb: EcUnknown0xC (0xc) not implemented\n");
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/**
   \details exchange_emsmdb EcUnknown0xD (0xc) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcUnknown0xD request data

   \return MAPI_E_SUCCESS on success
 */
static void dcesrv_EcUnknown0xD(struct dcesrv_call_state *dce_call,
				      TALLOC_CTX *mem_ctx,
				      struct EcUnknown0xD *r)
{
	OC_DEBUG(3, "exchange_emsmdb: EcUnknown0xC (0xd) not implemented\n");
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/**
   \details exchange_emsmdb EcGetMoreRpc (0xe) function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r pointer to the EcDoAsyncConnectExt request data

   \return MAPI_E_SUCCESS on success
 */
struct emsmdb_async_registration {
	struct mapistore_context *store;
	struct GUID uuid;
	bool registered;
};

static int emsmdb_async_registration_destructor(struct emsmdb_async_registration *reg)
{
	if (reg->registered) mapistore_notification_session_delete(reg->store, reg->uuid);
	return 0;
}

static enum MAPISTATUS dcesrv_EcDoAsyncConnectEx(struct dcesrv_call_state *dce_call,
                                                 TALLOC_CTX *mem_ctx, struct EcDoAsyncConnectEx *r)
{
	struct emsmdbp_context *ctx;
	struct dcesrv_handle *handle;
	struct dcesrv_endpoint *endpoint;
	struct dcesrv_if_list *entry;
	struct emsmdb_async_registration *reg;
	bool found = false;

	ctx = dcesrv_find_emsmdb_context(dce_call, r->in.handle);
	ZERO_STRUCTP(r->out.async_handle);
	r->out.result = MAPI_E_LOGON_FAILED;
	if (!dcesrv_call_authenticated(dce_call)) return r->out.result;
	r->out.result = MAPI_E_INVALID_OBJECT;
	if (ctx == NULL) return r->out.result;
	for (endpoint = dce_call->conn->dce_ctx->endpoint_list; endpoint; endpoint = endpoint->next) {
		for (entry = endpoint->interface_list; entry; entry = entry->next) {
			if (entry->iface && entry->iface->name && strcmp(entry->iface->name, "asyncemsmdb") == 0) {
				found = true;
				break;
			}
		}
		if (found) break;
	}
	if (!found) {
		r->out.result = ecRejected;
		return r->out.result;
	}
	r->out.result = MAPI_E_NOT_ENOUGH_RESOURCES;
	reg = talloc_zero(ctx->mstore_ctx, struct emsmdb_async_registration);
	if (reg == NULL) return r->out.result;
	reg->store = ctx->mstore_ctx;
	talloc_set_destructor(reg, emsmdb_async_registration_destructor);
	handle = dcesrv_handle_create(dce_call, EXCHANGE_HANDLE_ASYNCEMSMDB);
	if (handle == NULL) { talloc_free(reg); return r->out.result; }
	/* Both the wire handle and cache registration die with their mailbox session. */
	talloc_steal(reg, handle);
	reg->uuid = handle->wire_handle.uuid;
	if (mapistore_notification_session_add(ctx->mstore_ctx, ctx->session_uuid,
		reg->uuid, dcesrv_call_account_name(dce_call)) != MAPISTORE_SUCCESS) {
		talloc_free(reg);
		r->out.result = MAPI_E_LOGON_FAILED;
		return r->out.result;
	}
	reg->registered = true;
	*r->out.async_handle = handle->wire_handle;
	r->out.result = MAPI_E_SUCCESS;
	return r->out.result;
}


/**
   \details Dispatch incoming EMSMDB call to the correct OpenChange
   server function

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r generic pointer on EMSMDB data
   \param mapiproxy pointer to the mapiproxy structure controlling
   mapiproxy behavior

   \return NT_STATUS_OK;
 */
static NTSTATUS dcesrv_exchange_emsmdb_dispatch(struct dcesrv_call_state *dce_call,
						TALLOC_CTX *mem_ctx,
						void *r, struct mapiproxy *mapiproxy)
{
	const struct ndr_interface_table	*table;
	uint16_t				opnum;

	table = (const struct ndr_interface_table *) dce_call->context->iface->private_data;
	opnum = dce_call->pkt.u.request.opnum;

	/* Sanity checks */
	if (!dcesrv_call_authenticated(dce_call)) {
		dce_call->fault_code = DCERPC_FAULT_ACCESS_DENIED;
		return NT_STATUS_NET_WRITE_FAULT;
	}
	if (!table) return NT_STATUS_UNSUCCESSFUL;
	if (table->name && strcmp(table->name, NDR_EXCHANGE_EMSMDB_NAME)) return NT_STATUS_UNSUCCESSFUL;

	switch (opnum) {
	case NDR_ECDOCONNECT:
		dcesrv_EcDoConnect(dce_call, mem_ctx, (struct EcDoConnect *)r);
		break;
	case NDR_ECDODISCONNECT:
		dcesrv_EcDoDisconnect(dce_call, mem_ctx, (struct EcDoDisconnect *)r);
		break;
	case NDR_ECDORPC:
		dcesrv_EcDoRpc(dce_call, mem_ctx, (struct EcDoRpc *)r);
		break;
	case NDR_ECGETMORERPC:
		dcesrv_EcGetMoreRpc(dce_call, mem_ctx, (struct EcGetMoreRpc *)r);
		break;
	case NDR_ECRREGISTERPUSHNOTIFICATION:
		dcesrv_EcRRegisterPushNotification(dce_call, mem_ctx, (struct EcRRegisterPushNotification *)r);
		break;
	case NDR_ECRUNREGISTERPUSHNOTIFICATION:
		dcesrv_EcRUnregisterPushNotification(dce_call, mem_ctx, (struct EcRUnregisterPushNotification *)r);
		break;
	case NDR_ECDUMMYRPC:
		dcesrv_EcDummyRpc(dce_call, mem_ctx, (struct EcDummyRpc *)r);
		break;
	case NDR_ECRGETDCNAME:
		dcesrv_EcRGetDCName(dce_call, mem_ctx, (struct EcRGetDCName *)r);
		break;
	case NDR_ECRNETGETDCNAME:
		dcesrv_EcRNetGetDCName(dce_call, mem_ctx, (struct EcRNetGetDCName *)r);
		break;
	case NDR_ECDORPCEXT:
		dcesrv_EcDoRpcExt(dce_call, mem_ctx, (struct EcDoRpcExt *)r);
		break;
	case NDR_ECDOCONNECTEX:
		dcesrv_EcDoConnectEx(dce_call, mem_ctx, (struct EcDoConnectEx *)r);
		break;
	case NDR_ECDORPCEXT2:
		dcesrv_EcDoRpcExt2(dce_call, mem_ctx, (struct EcDoRpcExt2 *)r);
		break;
	case NDR_ECUNKNOWN0XC:
		dcesrv_EcUnknown0xC(dce_call, mem_ctx, (struct EcUnknown0xC *)r);
		break;
	case NDR_ECUNKNOWN0XD:
		dcesrv_EcUnknown0xD(dce_call, mem_ctx, (struct EcUnknown0xD *)r);
		break;
	case NDR_ECDOASYNCCONNECTEX:
		dcesrv_EcDoAsyncConnectEx(dce_call, mem_ctx, (struct EcDoAsyncConnectEx *)r);
		break;
	}

	return NT_STATUS_OK;
}


/**
   \details Initialize the EMSMDB OpenChange server

   \param dce_ctx pointer to the server context

   \return NT_STATUS_OK on success
 */
static NTSTATUS dcesrv_exchange_emsmdb_init(struct dcesrv_context *dce_ctx)
{
	/* Open read/write context on OpenChange dispatcher database */
	openchange_db_ctx = emsmdbp_openchangedb_init(dce_ctx->lp_ctx);
	if (!openchange_db_ctx) {
		OC_PANIC(false, ("[exchange_emsmdb] Unable to initialize openchangedb\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}


/**
   \details Terminate the EMSMDB connection and release the associated
   session and context if still available. This case occurs when the
   client doesn't call EcDoDisconnect but quit unexpectedly.

   \param server_id reference to the server identifier structure
   \param context_id the connection context identifier

   \return NT_STATUS_OK on success
 */

/* Policy handles are released by Samba when their association is destroyed. */
static NTSTATUS dcesrv_exchange_emsmdb_unbind(struct server_id server_id, uint32_t context_id)
{
	return NT_STATUS_OK;
}


/**
   \details Entry point for the default OpenChange EMSMDB server

   \return NT_STATUS_OK on success, otherwise NTSTATUS error
 */
NTSTATUS samba_init_module(void)
{
	struct mapiproxy_module	server = {0};
	NTSTATUS		ret;

	/* Fill in our name */
	server.name = "exchange_emsmdb";
	server.status = MAPIPROXY_DEFAULT;
	server.description = "OpenChange EMSMDB server";
	server.endpoint = "exchange_emsmdb";

	/* Fill in all the operations */
	server.init = dcesrv_exchange_emsmdb_init;
	server.unbind = dcesrv_exchange_emsmdb_unbind;
	server.dispatch = dcesrv_exchange_emsmdb_dispatch;
	server.push = NULL;
	server.pull = NULL;
	server.ndr_pull = NULL;

	/* Register ourselves with the MAPIPROXY server subsystem */
	ret = mapiproxy_server_register(&server);
	if (!NT_STATUS_IS_OK(ret)) {
		OC_DEBUG(0, "Failed to register the 'exchange_emsmdb' default mapiproxy server!\n");
		return ret;
	}

	return ret;
}
