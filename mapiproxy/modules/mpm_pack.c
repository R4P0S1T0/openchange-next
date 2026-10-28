/*
   MAPI Proxy - Unpack/Pack Module

   OpenChange Project

   Copyright (C) Julien Kerihuel 2008

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
   \file mpm_pack.c

   \brief Pack/Unpack specified MAPI calls into/from a custom MAPI call
 */

#include "libmapi/libmapi.h"
#include "mapiproxy/dcesrv_mapiproxy.h"
#include "mapiproxy/libmapiproxy/libmapiproxy.h"

#define	MPM_NAME	"mpm_pack"
#define	MPM_PACK_ERROR	"[ERROR] mpm_pack:"

NTSTATUS samba_init_module(void);

static struct mpm_pack {
	bool mapi_calls[256];
	bool lasthop;
} *mpm = NULL;

static int pack_config_destructor(struct mpm_pack *config)
{
	if (mpm == config) mpm = NULL;
	return 0;
}

/* Decoded request arrays are talloc-owned and terminated by a zero opnum. */
static NTSTATUS request_count(const struct mapi_request *request, uint32_t *count)
{
	size_t capacity, i;

	if (request == NULL || request->length < 2 ||
	    request->mapi_len < request->length ||
	    (request->mapi_len - request->length) % sizeof(uint32_t) != 0 ||
	    request->mapi_req == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	capacity = talloc_array_length(request->mapi_req);
	for (i = 0; i < capacity && i <= UINT16_MAX / 3; i++) {
		if (request->mapi_req[i].opnum == 0) {
			*count = i;
			return NT_STATUS_OK;
		}
	}
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS replace_requests(TALLOC_CTX *mem_ctx, struct mapi_request *request,
				 struct EcDoRpc_MAPI_REQ *records, uint32_t count)
{
	struct ndr_push *ndr = ndr_push_init_ctx(records);
	uint32_t i, length, handles = request->mapi_len - request->length;

	if (ndr == NULL) return NT_STATUS_NO_MEMORY;
	for (i = 0; i < count; i++) {
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_EcDoRpc_MAPI_REQ(ndr, NDR_SCALARS, &records[i]))) {
			talloc_free(ndr);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	if (ndr->offset > UINT16_MAX - 2) {
		talloc_free(ndr);
		return NT_STATUS_INVALID_PARAMETER;
	}
	length = ndr->offset + 2;
	talloc_free(ndr);
	if (handles > UINT32_MAX - length) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	records[count].opnum = 0;
	talloc_steal(mem_ctx, records);
	/* Unchanged records can still refer to payloads owned by the old array. */
	talloc_steal(records, request->mapi_req);
	request->mapi_req = records;
	request->length = length;
	request->mapi_len = length + handles;
	return NT_STATUS_OK;
}

static NTSTATUS unpack(TALLOC_CTX *mem_ctx, struct EcDoRpc *rpc)
{
	struct mapi_request *request = rpc->in.mapi_request;
	struct EcDoRpc_MAPI_REQ *records, *input;
	struct ndr_pull *ndr;
	DATA_BLOB blob;
	TALLOC_CTX *tmp;
	NTSTATUS status;
	uint32_t count, i, wrapper = UINT32_MAX, next = 0, output = 0, capacity;
	uint8_t pos;

	status = request_count(request, &count);
	if (!NT_STATUS_IS_OK(status)) return status;
	input = request->mapi_req;
	for (i = 0; i < count; i++) {
		if (input[i].opnum != op_MAPI_proxypack) continue;
		if (wrapper != UINT32_MAX) return NT_STATUS_INVALID_PARAMETER;
		wrapper = i;
	}
	if (wrapper == UINT32_MAX) return NT_STATUS_NOT_FOUND;
	blob.data = input[wrapper].u.mapi_proxypack.bin.lpb;
	blob.length = input[wrapper].u.mapi_proxypack.bin.cb;
	if (blob.length == 0 || blob.data == NULL) return NT_STATUS_INVALID_PARAMETER;

	tmp = talloc_new(mem_ctx);
	if (tmp == NULL) return NT_STATUS_NO_MEMORY;
	/* A packed entry needs at least one position byte and three ROP bytes. */
	capacity = blob.length / 4;
	if (capacity > UINT8_MAX + 1) capacity = UINT8_MAX + 1;
	capacity += count;
	records = talloc_zero_array(tmp, struct EcDoRpc_MAPI_REQ, capacity);
	ndr = ndr_pull_init_blob(&blob, tmp);
	status = NT_STATUS_NO_MEMORY;
	if (records == NULL || ndr == NULL) goto done;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN | LIBNDR_FLAG_REF_ALLOC);
	ndr->current_mem_ctx = records;
	status = NT_STATUS_INVALID_PARAMETER;
	while (ndr->offset < ndr->data_size) {
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_uint8(ndr, NDR_SCALARS, &pos))) goto done;
		if (pos < output) goto done;
		while (output < pos) {
			if (next == wrapper) next++;
			if (next >= count || output + 1 >= capacity) goto done;
			records[output++] = input[next++];
		}
		if (output + 1 >= capacity ||
		    !NDR_ERR_CODE_IS_SUCCESS(ndr_pull_EcDoRpc_MAPI_REQ(ndr, NDR_SCALARS, &records[output])) ||
		    records[output].opnum == 0 || records[output].opnum == op_MAPI_proxypack) goto done;
		output++;
	}
	while (next < count) {
		if (next == wrapper) { next++; continue; }
		if (output + 1 >= capacity) goto done;
		records[output++] = input[next++];
	}
	status = replace_requests(mem_ctx, request, records, output);

done:
	talloc_free(tmp);
	return status;
}

static NTSTATUS pack(TALLOC_CTX *mem_ctx, struct EcDoRpc *rpc)
{
	struct mapi_request *request = rpc->in.mapi_request;
	struct EcDoRpc_MAPI_REQ *records;
	struct ndr_push *ndr;
	TALLOC_CTX *tmp;
	NTSTATUS status;
	uint32_t count, i, output = 0;

	status = request_count(request, &count);
	if (!NT_STATUS_IS_OK(status)) return status;
	tmp = talloc_new(mem_ctx);
	if (tmp == NULL) return NT_STATUS_NO_MEMORY;
	records = talloc_zero_array(tmp, struct EcDoRpc_MAPI_REQ, count + 2);
	ndr = ndr_push_init_ctx(tmp);
	status = NT_STATUS_NO_MEMORY;
	if (records == NULL || ndr == NULL) goto done;
	status = NT_STATUS_INVALID_PARAMETER;
	for (i = 0; i < count; i++) {
		/* The custom wire format has only one byte for a packed position. */
		if (i <= UINT8_MAX && mpm->mapi_calls[request->mapi_req[i].opnum]) {
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_uint8(ndr, NDR_SCALARS, i)) ||
			    !NDR_ERR_CODE_IS_SUCCESS(ndr_push_EcDoRpc_MAPI_REQ(ndr, NDR_SCALARS, &request->mapi_req[i]))) goto done;
		} else {
			records[output++] = request->mapi_req[i];
		}
	}
	status = NT_STATUS_NOT_FOUND;
	if (ndr->offset == 0) goto done;
	status = NT_STATUS_INVALID_PARAMETER;
	if (ndr->offset > UINT16_MAX) goto done;
	records[output].opnum = op_MAPI_proxypack;
	records[output].u.mapi_proxypack.bin.cb = ndr->offset;
	records[output].u.mapi_proxypack.bin.lpb = talloc_memdup(records, ndr->data, ndr->offset);
	if (records[output].u.mapi_proxypack.bin.lpb == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	status = replace_requests(mem_ctx, request, records, output + 1);

done:
	talloc_free(tmp);
	return status;
}

static NTSTATUS pack_push(struct dcesrv_call_state *dce_call,
			  TALLOC_CTX *mem_ctx, void *r)
{
	return NT_STATUS_OK;
}


static NTSTATUS pack_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull)
{
	return NT_STATUS_OK;
}


/**
   \details pack EcDoRpc MAPI requests

   This function searches for MAPI opnums to pack in the requests,
   add this opnums to the mapiproxy opnum DATA blob and refactor the
   request to remove references to these calls in the original
   request.
 */
static NTSTATUS pack_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	struct EcDoRpc *rpc = r;
	NTSTATUS status;

	if (dce_call->pkt.u.request.opnum != NDR_ECDORPC) return NT_STATUS_OK;
	if (rpc == NULL || rpc->in.mapi_request == NULL || mpm == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (!mpm->lasthop || rpc->in.mapi_request->length == 2) return NT_STATUS_OK;
	status = unpack(mem_ctx, rpc);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) status = pack(mem_ctx, rpc);
	return NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND) ? NT_STATUS_OK : status;
}


/**
   \details Initialize the pack module and retrieve configuration from
   smb.conf.

   Possible parameters:
   * mpm_pack:opnums = 0x1, 0x2, 0x3
   * mpm_pack:lasthop = true|false
   
 */
static NTSTATUS pack_init(struct dcesrv_context *dce_ctx)
{
	struct mpm_pack *config;
	const char **calls;
	char *end;
	unsigned long opnum;
	uint32_t i;

	config = talloc_zero(dce_ctx, struct mpm_pack);
	if (config == NULL) return NT_STATUS_NO_MEMORY;
	talloc_set_destructor(config, pack_config_destructor);
	calls = lpcfg_parm_string_list(config, dce_ctx->lp_ctx, NULL, MPM_NAME, "opnums", NULL);
	if (calls == NULL || calls[0] == NULL) {
		talloc_free(config);
		return NT_STATUS_INVALID_PARAMETER;
	}
	for (i = 0; calls[i]; i++) {
		errno = 0;
		opnum = strtoul(calls[i], &end, 16);
		if (errno != 0 || end == calls[i] || *end != '\0' || opnum == 0 ||
		    opnum >= UINT8_MAX || opnum == op_MAPI_proxypack || config->mapi_calls[opnum]) {
			talloc_free(config);
			return NT_STATUS_INVALID_PARAMETER;
		}
		config->mapi_calls[opnum] = true;
	}
	config->lasthop = lpcfg_parm_bool(dce_ctx->lp_ctx, NULL, MPM_NAME, "lasthop", true);
	talloc_free(mpm);
	mpm = config;
	return NT_STATUS_OK;
}


/**
   \details Entry point for the pack mapiproxy module

   \return NT_STATUS_OK on success, otherwise NTSTATUS error
 */
NTSTATUS samba_init_module(void)
{
	struct mapiproxy_module	module = {0};
	NTSTATUS		ret;

	/* Fill in our name */
	module.name = "pack";
	module.description = "Pack specified MAPI calls into a custom MAPI call";
	module.endpoint = "exchange_emsmdb";

	/* Fill in all the operations */
	module.init = pack_init;
	module.unbind = NULL;
	module.push = pack_push;
	module.ndr_pull = pack_ndr_pull;
	module.pull = pack_pull;
	module.dispatch = NULL;

	/* Register ourselves with the MAPIPROXY subsystem */
	ret = mapiproxy_module_register(&module);
	if (!NT_STATUS_IS_OK(ret)) {
		OC_DEBUG(0, "Failed to register the 'pack' mapiproxy module!");
		return ret;
	}

	return ret;
}
