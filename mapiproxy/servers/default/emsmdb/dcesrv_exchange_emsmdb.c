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
	DATA_BLOB input = { .data = r->in.rgbIn, .length = r->in.cbIn }, output;

	r->out.rgbOut = r->out.rgbAuxOut = NULL;
	*r->out.pcbOut = *r->out.pcbAuxOut = *r->out.pulFlags = *r->out.pulTransTime = 0;
	r->out.result = MAPI_E_LOGON_FAILED;
	if (!dcesrv_call_authenticated(dce_call)) goto failure;
	r->out.result = MAPI_E_INVALID_OBJECT;
	if (ctx == NULL) goto failure;
	r->out.result = emsmdb_execute_buffer(mem_ctx, ctx, &input, flags, capacity, &output);
	if (r->out.result != MAPI_E_SUCCESS) return r->out.result;
	r->out.rgbOut = output.data;
	*r->out.pcbOut = output.length;
	*r->out.handle = *r->in.handle;
	return r->out.result;
failure:
	ZERO_STRUCTP(r->out.handle);
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
