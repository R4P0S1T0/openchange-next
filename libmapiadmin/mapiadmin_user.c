/*
   OpenChange Exchange Administration library.

   Based on the work by Andrew Tridgell, 2004

   Original source code available in SAMBA_4_0:
   source/torture/rpc/testjoin.c

   Copyright (C) Julien Kerihuel 2007-2010.

   SAMR related code

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

#include "libmapiadmin/libmapiadmin.h"
#include "libmapi/libmapi_private.h"

#include <param.h>
#include <credentials.h>
#include <ldb_errors.h>
#include <ldb_wrap.h>

#include <gen_ndr/ndr_samr.h>

#include <time.h>

/**
	\file
	User management functions for mapiadmin
*/

/**
 * open connection so SAMR + Join Domain
 * common code needed when adding or removing users
 */
static enum MAPISTATUS mapiadmin_samr_connect(struct mapiadmin_ctx *admin, TALLOC_CTX *mem_ctx)
{
	struct mapi_context *mapi;
	struct mapi_profile *profile;
	struct test_join *user;
	struct tevent_context *ev;
	struct samr_Connect connect = {0};
	struct samr_LookupDomain lookup = {0};
	struct samr_OpenDomain open = {0};
	struct policy_handle connect_handle = {0}, domain_handle = {0};
	struct dom_sid *sid = NULL;
	struct lsa_String domain = {0};
	NTSTATUS status;

	OPENCHANGE_RETVAL_IF(!admin || !admin->session || !admin->session->profile ||
		!admin->session->profile->credentials || !admin->username ||
		!admin->session->mapi_ctx, MAPI_E_NOT_INITIALIZED, NULL);
	if (admin->user_ctx != NULL && admin->handle != NULL) return MAPI_E_SUCCESS;
	mapi = admin->session->mapi_ctx;
	profile = admin->session->profile;
	OPENCHANGE_RETVAL_IF(profile->domain == NULL, MAPI_E_NOT_INITIALIZED, NULL);
	user = talloc_zero(admin, struct test_join);
	OPENCHANGE_RETVAL_IF(user == NULL, MAPI_E_NOT_ENOUGH_RESOURCES, NULL);
	ev = tevent_context_init(user);
	if (ev == NULL) goto no_memory;
	status = dcerpc_pipe_connect(user, &user->p, admin->dc_binding ? admin->dc_binding : admin->binding,
		&ndr_table_samr, profile->credentials, ev, mapi->lp_ctx);
	if (!NT_STATUS_IS_OK(status)) goto failure;
	connect.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	connect.out.connect_handle = &connect_handle;
	status = dcerpc_binding_handle_call(user->p->binding_handle, NULL, &ndr_table_samr, NDR_SAMR_CONNECT, user, &connect);
	if (!NT_STATUS_IS_OK(status) || !NT_STATUS_IS_OK(connect.out.result)) goto failure;
	domain.string = profile->domain;
	lookup.in.connect_handle = &connect_handle;
	lookup.in.domain_name = &domain;
	lookup.out.sid = &sid;
	status = dcerpc_binding_handle_call(user->p->binding_handle, NULL, &ndr_table_samr, NDR_SAMR_LOOKUPDOMAIN, user, &lookup);
	if (!NT_STATUS_IS_OK(status) || !NT_STATUS_IS_OK(lookup.out.result) || sid == NULL) goto failure;
	user->dom_sid = sid;
	user->dom_netbios_name = talloc_strdup(user, profile->domain);
	if (user->dom_netbios_name == NULL) goto no_memory;
	open.in.connect_handle = &connect_handle;
	open.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	open.in.sid = sid;
	open.out.domain_handle = &domain_handle;
	status = dcerpc_binding_handle_call(user->p->binding_handle, NULL, &ndr_table_samr, NDR_SAMR_OPENDOMAIN, user, &open);
	if (!NT_STATUS_IS_OK(status) || !NT_STATUS_IS_OK(open.out.result)) goto failure;
	admin->handle = talloc_memdup(user, &domain_handle, sizeof(domain_handle));
	if (admin->handle == NULL) goto no_memory;
	admin->user_ctx = user;
	errno = 0;
	return MAPI_E_SUCCESS;
no_memory:
	talloc_free(user);
	return MAPI_E_NOT_ENOUGH_RESOURCES;
failure:
	talloc_free(user);
	return MAPI_E_CALL_FAILED;
}


struct tce_async_context {
	int	found;
};

static int tce_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct tce_async_context	*actx = talloc_get_type(req->context, struct tce_async_context);

	switch (ares->type) {

	case LDB_REPLY_ENTRY:
		if (ldb_msg_find_element(ares->message, "msExchMailboxGuid") != NULL) {
			OC_DEBUG(3, "msExchMailboxGuid found!");
			actx->found = 1;
			talloc_free(ares);
			return ldb_request_done(req, LDB_SUCCESS);
		}
		break;
	case LDB_REPLY_DONE:
		break;
	default:
		OC_DEBUG(3, "unknown Reply Type ignore it");
		talloc_free(ares);
		return LDB_ERR_OTHER;
	}

	if (talloc_free(ares) == -1) {
		OC_DEBUG(3, "talloc_free failed");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

/**
 * Extend user attributes to be Exchange user
 */
_PUBLIC_ enum MAPISTATUS mapiadmin_user_extend(struct mapiadmin_ctx *mapiadmin_ctx)
{
	TALLOC_CTX			*mem_ctx;
	enum MAPISTATUS			retval;
	struct tevent_context		*ev = NULL;
	struct mapi_context		*mapi_ctx;
	struct mapi_profile		*profile;
	struct ldb_context		*remote_ldb;
	struct ldb_request		*req;
	struct ldb_message		*msg;
	struct ldb_result		*res;
	struct ldb_control		**controls;
	const char			*control_strings[2] = { "notification:0", NULL };
	struct tce_async_context	*tce_ctx;
	const struct dom_sid		*dom_sid;
	char				*remote_ldb_url;
	const char * const		dom_attrs[] = { "*", NULL };
	int				ret;
	uint32_t			count;
	char				**values;
	const char			*exch_attrs[7];
	uint32_t			i;
	char				*realm = NULL;
	char				*org = NULL;
	const char			*UserAccountControl;
	struct ldb_dn			*account_dn;

	/* Sanity checks */
	OPENCHANGE_RETVAL_IF(!mapiadmin_ctx, MAPI_E_NOT_INITIALIZED, NULL);
	OPENCHANGE_RETVAL_IF(!mapiadmin_ctx->session, MAPI_E_NOT_INITIALIZED, NULL);
	OPENCHANGE_RETVAL_IF(!mapiadmin_ctx->session->profile, MAPI_E_NOT_INITIALIZED, NULL);
	OPENCHANGE_RETVAL_IF(!mapiadmin_ctx->session->profile->credentials, MAPI_E_NOT_INITIALIZED, NULL);
	OPENCHANGE_RETVAL_IF(!mapiadmin_ctx->user_ctx, MAPI_E_NOT_INITIALIZED, NULL);

	mapi_ctx = mapiadmin_ctx->session->mapi_ctx;
	OPENCHANGE_RETVAL_IF(!mapi_ctx, MAPI_E_NOT_INITIALIZED, NULL);

	profile = mapiadmin_ctx->session->profile;
	dom_sid = mapiadmin_ctx->user_ctx->user_sid;

	/* initialize memory context */
	mem_ctx = talloc_named((TALLOC_CTX *)mapiadmin_ctx, 0, "mapiadmin_user_extend");

	/* open LDAP connection */
	ev = tevent_context_init(mem_ctx);
	remote_ldb_url = talloc_asprintf(mem_ctx, "ldap://%s", profile->server);
	OPENCHANGE_RETVAL_IF(!remote_ldb_url, MAPI_E_CORRUPT_DATA, mem_ctx);
	remote_ldb = ldb_wrap_connect(mem_ctx, ev, mapi_ctx->lp_ctx, remote_ldb_url, 
				      NULL, mapiadmin_ctx->session->profile->credentials, 0);
	OPENCHANGE_RETVAL_IF(!remote_ldb, ecRpcFailed, mem_ctx);

	/* Search the user_dn */
	account_dn = samdb_search_dn(remote_ldb, mem_ctx, NULL, 
				     "(&(objectSid=%s)(objectClass=user))", 
				     ldap_encode_ndr_dom_sid(mem_ctx, dom_sid));

	ret = ldb_search(remote_ldb, mem_ctx, &res, account_dn, LDB_SCOPE_SUBTREE, dom_attrs, "(objectSid=%s)",
			 ldap_encode_ndr_dom_sid(mem_ctx, dom_sid));
	OPENCHANGE_RETVAL_IF(ret != LDB_SUCCESS, MAPI_E_NOT_FOUND, mem_ctx);
	OPENCHANGE_RETVAL_IF(res->count != 1, MAPI_E_NOT_FOUND, mem_ctx);

	/* Prepare a new message for modify */
	msg = ldb_msg_new(mem_ctx);
	OPENCHANGE_RETVAL_IF(!msg, MAPI_E_NOT_ENOUGH_RESOURCES, mem_ctx);

	msg->dn = res->msgs[0]->dn;

	/* message: givenName */
	exch_attrs[0] = talloc_strdup(mem_ctx, mapiadmin_ctx->username);
	ret = ldb_msg_add_string(msg, "givenName", exch_attrs[0]);
	OPENCHANGE_RETVAL_IF((ret == -1), MAPI_E_NOT_ENOUGH_RESOURCES, mem_ctx);

	/* message: userAccountControl */
	exch_attrs[1] = talloc_asprintf(mem_ctx, "513");
	ret = ldb_msg_add_string(msg, "userAccountControl", exch_attrs[1]);
	OPENCHANGE_RETVAL_IF((ret == -1), MAPI_E_NOT_ENOUGH_RESOURCES, mem_ctx);
	msg->elements[1].flags = LDB_FLAG_MOD_REPLACE;

	/* message: mail */
	retval = GetProfileAttr(profile, "ProxyAddress", &count, &values);
	OPENCHANGE_RETVAL_IF(retval, retval, mem_ctx);

	for (i = 0; i < count; i++) {
		if (values[i] && !strncasecmp("smtp", values[i], 4)) {
			realm = strchr(values[i], '@');
			realm += 1;
		}
	}
	OPENCHANGE_RETVAL_IF(!realm, MAPI_E_NOT_FOUND, mem_ctx);

	exch_attrs[2] = talloc_asprintf(mem_ctx, "%s@%s", mapiadmin_ctx->username, realm);
	ret = ldb_msg_add_string(msg, "mail", exch_attrs[2]);
	OPENCHANGE_RETVAL_IF((ret == -1), MAPI_E_NOT_ENOUGH_RESOURCES, mem_ctx);

	/* message: mailNickname */
	exch_attrs[3] = talloc_strdup(mem_ctx, mapiadmin_ctx->username);
	ret = ldb_msg_add_string(msg, "mailNickname", exch_attrs[3]);
	OPENCHANGE_RETVAL_IF((ret == -1), MAPI_E_NOT_ENOUGH_RESOURCES, mem_ctx);

	/* message: mDBUseDefaults */
	exch_attrs[4] = talloc_asprintf(mem_ctx, "TRUE");
	ret = ldb_msg_add_string(msg, "mDBUseDefaults", exch_attrs[4]);
	OPENCHANGE_RETVAL_IF((ret == -1), MAPI_E_NOT_ENOUGH_RESOURCES, mem_ctx);

	/* message: legacyExchangeDN */
	org = talloc_strndup(mem_ctx, profile->mailbox,
			     strlen(profile->mailbox) - strlen(profile->username));
	exch_attrs[5] = talloc_asprintf(mem_ctx, "%s%s", org, mapiadmin_ctx->username);
	talloc_free(org);
	ret = ldb_msg_add_string(msg, "legacyExchangeDN", exch_attrs[5]);
	OPENCHANGE_RETVAL_IF((ret == -1), MAPI_E_NOT_ENOUGH_RESOURCES, mem_ctx);

	/* message: msExchHomeServerName */
	exch_attrs[6] = talloc_strdup(mem_ctx, profile->homemdb);
	ret = ldb_msg_add_string(msg, "msExchHomeServerName", exch_attrs[6]);
	OPENCHANGE_RETVAL_IF((ret == -1), MAPI_E_NOT_ENOUGH_RESOURCES, mem_ctx);

	/* Prior we call ldb_modify, set up async ldb request on
	 * msExchMailboxGuid 
	 */
	req = talloc_zero(mem_ctx, struct ldb_request);
	tce_ctx = talloc_zero(mem_ctx, struct tce_async_context);
	controls = ldb_parse_control_strings(remote_ldb, mem_ctx, control_strings);

	ret = ldb_build_search_req(&req, remote_ldb, mem_ctx, 
				   msg->dn,
				   LDB_SCOPE_BASE,
				   "(objectclass=*)",
				   NULL,
				   controls, 
				   (void *)tce_ctx, 
				   tce_search_callback, 
				   NULL);
	OC_DEBUG(3, "ldb_build_search_req: %s", ldb_strerror(ret));
	OPENCHANGE_RETVAL_IF((ret != LDB_SUCCESS), MAPI_E_CALL_FAILED, mem_ctx);

	ldb_set_timeout(mem_ctx, req, 60);

	ret = ldb_request(remote_ldb, req);
	OC_DEBUG(3, "ldb_request: %s", ldb_strerror(ret));
	OPENCHANGE_RETVAL_IF((ret != LDB_SUCCESS), MAPI_E_CALL_FAILED, mem_ctx);

	ret = ldb_modify(remote_ldb, msg);
	OC_DEBUG(3, "ldb_modify: %s", ldb_strerror(ret));
	OPENCHANGE_RETVAL_IF((ret != LDB_SUCCESS), MAPI_E_CORRUPT_DATA, mem_ctx);

	/* async search */
	ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	OC_DEBUG(3, "ldb_wait: %s", ldb_strerror(ret));
	OPENCHANGE_RETVAL_IF((ret != LDB_SUCCESS), MAPI_E_CALL_FAILED, mem_ctx);
	OPENCHANGE_RETVAL_IF(!tce_ctx->found, MAPI_E_CALL_FAILED, mem_ctx);
	
	/* When successful replace UserAccountControl attr in the user
	 * record 
	 */
	talloc_free(msg);
	msg = ldb_msg_new(mem_ctx);
	OPENCHANGE_RETVAL_IF(!msg, MAPI_E_NOT_ENOUGH_RESOURCES, mem_ctx);
	msg->dn = res->msgs[0]->dn;

	UserAccountControl = talloc_asprintf(mem_ctx, "66048");
	ret = ldb_msg_add_string(msg, "UserAccountControl", UserAccountControl);
	OPENCHANGE_RETVAL_IF((ret == -1), MAPI_E_NOT_ENOUGH_RESOURCES, mem_ctx);
	msg->elements[0].flags = LDB_FLAG_MOD_REPLACE;

	ret = ldb_modify(remote_ldb, msg);
	OC_DEBUG(3, "ldb_modify: %s", ldb_strerror(ret));
	OPENCHANGE_RETVAL_IF((ret != LDB_SUCCESS), MAPI_E_CORRUPT_DATA, mem_ctx);

	/* reset errno before leaving */
	errno = 0;
	talloc_free(mem_ctx);
	return MAPI_E_SUCCESS;
}

/**
 * Add a user to Active Directory 
 */
_PUBLIC_ enum MAPISTATUS mapiadmin_user_add(struct mapiadmin_ctx *admin)
{
	TALLOC_CTX *ctx = talloc_new(NULL);
	struct samr_CreateUser2 create = {0};
	struct samr_GetUserPwInfo policy = {0};
	struct samr_SetUserInfo set = {0};
	struct samr_DeleteUser remove = {0};
	union samr_UserInfo info = {0};
	struct samr_PwInfo password_policy = {0};
	struct lsa_String name = {0};
	uint32_t access = 0, rid = 0;
	uint8_t salt_data[16];
	DATA_BLOB key = {0}, salt = { .data = salt_data, .length = sizeof(salt_data) };
	NTSTATUS status;
	enum MAPISTATUS result;
	bool created = false;

	OPENCHANGE_RETVAL_IF(ctx == NULL, MAPI_E_NOT_ENOUGH_RESOURCES, NULL);
	result = mapiadmin_samr_connect(admin, ctx);
	if (result != MAPI_E_SUCCESS) goto done;
	name.string = admin->username;
	create.in.domain_handle = admin->handle;
	create.in.account_name = &name;
	create.in.acct_flags = ACB_NORMAL;
	create.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	create.out.user_handle = &admin->user_ctx->user_handle;
	create.out.access_granted = &access;
	create.out.rid = &rid;
	status = dcerpc_binding_handle_call(admin->user_ctx->p->binding_handle, NULL,
		&ndr_table_samr, NDR_SAMR_CREATEUSER2, ctx, &create);
	if (NT_STATUS_IS_OK(status)) status = create.out.result;
	result = MAPI_E_COLLISION;
	if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) goto done;
	result = MAPI_E_CALL_FAILED;
	if (!NT_STATUS_IS_OK(status)) goto done;
	created = true;
	admin->user_ctx->user_sid = dom_sid_add_rid(admin->user_ctx, admin->user_ctx->dom_sid, rid);
	result = MAPI_E_NOT_ENOUGH_RESOURCES;
	if (admin->user_ctx->user_sid == NULL) goto done;
	policy.in.user_handle = &admin->user_ctx->user_handle;
	policy.out.info = &password_policy;
	status = dcerpc_binding_handle_call(admin->user_ctx->p->binding_handle, NULL,
		&ndr_table_samr, NDR_SAMR_GETUSERPWINFO, ctx, &policy);
	if (NT_STATUS_IS_OK(status)) status = policy.out.result;
	result = MAPI_E_CALL_FAILED;
	if (!NT_STATUS_IS_OK(status)) goto done;
	if (admin->password == NULL) {
		if (password_policy.min_password_length > 256) { result = MAPI_E_BAD_VALUE; goto done; }
		admin->password = generate_random_str(admin->user_ctx, MAX(32, password_policy.min_password_length));
	}
	result = MAPI_E_NOT_ENOUGH_RESOURCES;
	if (admin->password == NULL) goto done;
	status = dcerpc_binding_handle_transport_session_key(admin->user_ctx->p->binding_handle, ctx, &key);
	result = MAPI_E_CALL_FAILED;
	if (!NT_STATUS_IS_OK(status) || key.data == NULL || key.length < 16) goto done;
	if (getentropy(salt_data, sizeof(salt_data)) != 0) goto done;
	status = init_samr_CryptPasswordAES(ctx, admin->password, &salt, &key, &info.info31.password);
	result = MAPI_E_NO_SUPPORT;
	if (!NT_STATUS_IS_OK(status)) goto done;
	set.in.user_handle = &admin->user_ctx->user_handle;
	set.in.level = 31;
	set.in.info = &info;
	status = dcerpc_binding_handle_call(admin->user_ctx->p->binding_handle, NULL,
		&ndr_table_samr, NDR_SAMR_SETUSERINFO, ctx, &set);
	if (NT_STATUS_IS_OK(status)) status = set.out.result;
	result = NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION) ? MAPI_E_BAD_VALUE : MAPI_E_CALL_FAILED;
	if (!NT_STATUS_IS_OK(status)) goto done;
	ZERO_STRUCT(info);
	set.in.level = 21;
	info.info21.acct_flags = ACB_NORMAL;
	info.info21.fields_present = SAMR_FIELD_ACCT_FLAGS | SAMR_FIELD_DESCRIPTION | SAMR_FIELD_COMMENT | SAMR_FIELD_FULL_NAME;
	info.info21.comment.string = talloc_strdup(ctx, admin->comment ? admin->comment : "Created by OpenChange-next");
	info.info21.full_name.string = talloc_strdup(ctx, admin->fullname ? admin->fullname : admin->username);
	info.info21.description.string = talloc_strdup(ctx, admin->description ? admin->description : "OpenChange account");
	result = MAPI_E_NOT_ENOUGH_RESOURCES;
	if (info.info21.comment.string == NULL || info.info21.full_name.string == NULL ||
	    info.info21.description.string == NULL) goto done;
	status = dcerpc_binding_handle_call(admin->user_ctx->p->binding_handle, NULL,
		&ndr_table_samr, NDR_SAMR_SETUSERINFO, ctx, &set);
	if (NT_STATUS_IS_OK(status)) status = set.out.result;
	result = MAPI_E_CALL_FAILED;
	if (!NT_STATUS_IS_OK(status)) goto done;
	result = mapiadmin_user_extend(admin);

done:
	/* Roll back only the exact account created here, never a lookup by name. */
	if (created && result != MAPI_E_SUCCESS) {
		remove.in.user_handle = remove.out.user_handle = &admin->user_ctx->user_handle;
		status = dcerpc_binding_handle_call(admin->user_ctx->p->binding_handle, NULL,
			&ndr_table_samr, NDR_SAMR_DELETEUSER, ctx, &remove);
		if (!NT_STATUS_IS_OK(status) || !NT_STATUS_IS_OK(remove.out.result)) {
			OC_DEBUG(0, "Unable to roll back newly created account %s", admin->username);
		}
	}
	data_blob_clear_free(&key);
	talloc_free(ctx);
	errno = result;
	return result;
}

/**
 * Delete a user from Active Directory 
 */
_PUBLIC_ enum MAPISTATUS mapiadmin_user_del(struct mapiadmin_ctx *mapiadmin_ctx)
{
	TALLOC_CTX		*mem_ctx;
	enum MAPISTATUS		retval;
	NTSTATUS		status;
	struct samr_DeleteUser	d = {0};
	struct policy_handle	user_handle;
	uint32_t		rid;
	struct samr_LookupNames	n = {0};
	struct lsa_String	sname;
	struct samr_OpenUser	r = {0};

	OPENCHANGE_RETVAL_IF(!mapiadmin_ctx, MAPI_E_NOT_INITIALIZED, NULL);
	OPENCHANGE_RETVAL_IF(!mapiadmin_ctx->username, MAPI_E_NOT_INITIALIZED, NULL);

	mem_ctx = talloc_named(NULL, 0, "mapiadmin_user_del");
	OPENCHANGE_RETVAL_IF(mem_ctx == NULL, MAPI_E_NOT_ENOUGH_RESOURCES, NULL);

 	/* Initiate SAMR connection if not already done */
	if (!mapiadmin_ctx->user_ctx) {
		retval = mapiadmin_samr_connect(mapiadmin_ctx, mem_ctx);
		OPENCHANGE_RETVAL_IF(retval, retval, mem_ctx);
	}

	sname.string = mapiadmin_ctx->username;

	n.in.domain_handle = mapiadmin_ctx->handle;
	n.in.num_names = 1;
	n.in.names = &sname;

	n.out.rids = talloc_zero(mem_ctx, struct samr_Ids);
	n.out.types = talloc_zero(mem_ctx, struct samr_Ids);
	OPENCHANGE_RETVAL_IF(n.out.rids == NULL || n.out.types == NULL, MAPI_E_NOT_ENOUGH_RESOURCES, mem_ctx);

	status = dcerpc_binding_handle_call(mapiadmin_ctx->user_ctx->p->binding_handle, NULL, &ndr_table_samr, NDR_SAMR_LOOKUPNAMES, mem_ctx, &n);
	if (NT_STATUS_IS_OK(status)) status = n.out.result;
	if (NT_STATUS_IS_OK(status) && n.out.rids->count == 1 && n.out.rids->ids != NULL) {
		rid = n.out.rids->ids[0];
	} else {
		OPENCHANGE_RETVAL_IF(true, MAPI_E_NOT_FOUND, mem_ctx);
	}

	r.in.domain_handle = mapiadmin_ctx->handle;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.user_handle = &user_handle;

	status = dcerpc_binding_handle_call(mapiadmin_ctx->user_ctx->p->binding_handle, NULL, &ndr_table_samr, NDR_SAMR_OPENUSER, mem_ctx, &r);
	if (NT_STATUS_IS_OK(status)) status = r.out.result;
	if (!NT_STATUS_IS_OK(status)) {
		OC_DEBUG(3, "OpenUser(%s) failed - %s", mapiadmin_ctx->username, nt_errstr(status));
		OPENCHANGE_RETVAL_IF(!NT_STATUS_IS_OK(status), MAPI_E_NOT_FOUND, mem_ctx);
	}

	d.in.user_handle = &user_handle;
	d.out.user_handle = &user_handle;
	status = dcerpc_binding_handle_call(mapiadmin_ctx->user_ctx->p->binding_handle, NULL, &ndr_table_samr, NDR_SAMR_DELETEUSER, mem_ctx, &d);
	if (NT_STATUS_IS_OK(status)) status = d.out.result;
	OPENCHANGE_RETVAL_IF(!NT_STATUS_IS_OK(status), MAPI_E_CALL_FAILED, mem_ctx);

	talloc_free(mem_ctx);
	return MAPI_E_SUCCESS;
}

_PUBLIC_ enum MAPISTATUS mapiadmin_user_mod(struct mapiadmin_ctx *mapiadmin)
{
	return MAPI_E_NO_SUPPORT;
}
