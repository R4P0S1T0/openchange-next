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
   \file emsmdb_execute.c

   \brief ROP buffer execution shared by the RPC and MAPI/HTTP transports.
   Nothing here depends on a DCE/RPC call.
 */

#include "mapiproxy/dcesrv_mapiproxy.h"
#include "mapiproxy/libmapiproxy/fault_util.h"
#include "mapiproxy/libmapiserver/libmapiserver.h"
#include "dcesrv_exchange_emsmdb.h"

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

enum MAPISTATUS EcDoRpc_process_transaction(TALLOC_CTX *mem_ctx,
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
   \details Execute one RPC_HEADER_EXT framed ROP request buffer
   (MS-OXCRPC 3.1.4.12) and frame the response.

   \param mem_ctx owner of rop_out->data
   \param ctx the session's EMSMDB provider context
   \param rop_in the request frame; read only
   \param flags pulFlags of the request
   \param max_out the largest response the client accepts (8..0x40000)
   \param rop_out the response frame on success

   \return MAPI_E_SUCCESS on success, otherwise a MAPI status code
 */
enum MAPISTATUS emsmdb_execute_buffer(TALLOC_CTX *mem_ctx, struct emsmdbp_context *ctx,
				      const DATA_BLOB *rop_in, uint32_t flags, uint32_t max_out,
				      DATA_BLOB *rop_out)
{
	TALLOC_CTX *transaction = NULL;
	struct mapi2k7_request request = {0};
	struct mapi_response *response;
	struct RPC_HEADER_EXT header = {0};
	struct ndr_pull *pull;
	struct ndr_push *body, *wire;
	enum ndr_err_code error;
	enum MAPISTATUS result;

	*rop_out = data_blob_null;
	if (ctx == NULL) return MAPI_E_INVALID_OBJECT;
	if (max_out < 8 || max_out > 0x40000) return ecRpcFailed;
	if (rop_in == NULL || rop_in->data == NULL || rop_in->length < 8 ||
	    rop_in->length > UINT16_MAX + 8U) return ecRpcFormat;
	transaction = talloc_new(mem_ctx);
	result = MAPI_E_NOT_ENOUGH_RESOURCES;
	if (transaction == NULL) goto done;
	pull = ndr_pull_init_blob(rop_in, transaction);
	if (pull == NULL) goto done;
	ndr_set_flags(&pull->flags, LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC);
	NDR_PULL_SET_MEM_CTX(pull, transaction, 0);
	error = ndr_pull_mapi2k7_request(pull, NDR_SCALARS | NDR_BUFFERS, &request);
	result = ecRpcFormat;
	/* Chained requests require a transaction scheduler; accept one final frame. */
	if (error != NDR_ERR_SUCCESS || pull->offset != rop_in->length || !(request.header.Flags & RHEF_Last)) goto done;
	result = EcDoRpc_process_transaction(transaction, ctx, request.mapi_request, &response);
	if (result != MAPI_E_SUCCESS) goto done;
	result = MAPI_E_NOT_ENOUGH_RESOURCES;
	body = ndr_push_init_ctx(transaction);
	wire = ndr_push_init_ctx(transaction);
	if (body == NULL || wire == NULL) goto done;
	ndr_set_flags(&body->flags, LIBNDR_FLAG_NOALIGN);
	error = ndr_push_mapi_response(body, NDR_SCALARS | NDR_BUFFERS, response);
	result = ecRpcFormat;
	if (error != NDR_ERR_SUCCESS) goto done;
	result = ecBufferTooSmall;
	if (body->offset > UINT16_MAX || body->offset + 8U > max_out) goto done;
	header.Flags = RHEF_Last;
	if ((request.header.Flags & RHEF_XorMagic) && !(flags & pulFlags_NoXorMagic)) {
		header.Flags |= RHEF_XorMagic;
		obfuscate_data(body->data, body->offset, 0xA5);
	}
	header.Size = header.SizeActual = body->offset;
	ndr_set_flags(&wire->flags, LIBNDR_FLAG_NOALIGN);
	error = ndr_push_RPC_HEADER_EXT(wire, NDR_SCALARS, &header);
	if (error == NDR_ERR_SUCCESS) error = ndr_push_bytes(wire, body->data, body->offset);
	result = MAPI_E_NOT_ENOUGH_RESOURCES;
	if (error != NDR_ERR_SUCCESS) goto done;
	rop_out->data = talloc_steal(mem_ctx, wire->data);
	rop_out->length = wire->offset;
	result = MAPI_E_SUCCESS;
done:
	talloc_free(transaction);
	return result;
}
