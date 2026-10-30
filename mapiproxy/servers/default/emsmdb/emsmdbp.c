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
   \file emsmdbp.c

   \brief EMSMDB Provider implementation
 */

#define TEVENT_DEPRECATED
#include "mapiproxy/dcesrv_mapiproxy.h"
#include "dcesrv_exchange_emsmdb.h"
#include "mapiproxy/libmapiserver/libmapiserver.h"
#include "mapiproxy/libmapiproxy/fault_util.h"

static struct GUID MagicGUID = {
	.time_low = 0xbeefface,
	.time_mid = 0xcafe,
	.time_hi_and_version = 0xbabe,
	.clock_seq = { 0x12, 0x34 },
	.node = { 0xde, 0xad, 0xfa, 0xce, 0xca, 0xfe }
};
const struct GUID *const MagicGUIDp = &MagicGUID;

/* Directory state is owned by one EMSMDB session. */
static struct ldb_context *samdb_init(TALLOC_CTX *owner, struct loadparm_context *lp_ctx)
{
	struct tevent_context *ev = tevent_context_init(owner);
	struct ldb_context *samdb_ctx = NULL;
	const char *url;
	char *error = NULL;
	if (ev == NULL) return NULL;
	url = lpcfg_parm_string(lp_ctx, NULL, "dcerpc_mapiproxy", "samdb_url");
	if (url == NULL) return samdb_connect(owner, ev, lp_ctx, system_session(lp_ctx), NULL, 0);
	if (samdb_connect_url(owner, ev, lp_ctx, system_session(lp_ctx),
		LDB_FLG_RECONNECT, url, NULL, &samdb_ctx, &error) != LDB_SUCCESS) return NULL;
	return samdb_ctx;
}

/**
   \details Release the MAPISTORE context used by EMSMDB provider
   context

   \param data pointer on data to destroy

   \return 0 on success, otherwise -1
 */
static int emsmdbp_mapi_store_destructor(void *data)
{
	struct mapistore_context *mstore_ctx = (struct mapistore_context *) data;

	mapistore_release(mstore_ctx);
	OC_DEBUG(6, "MAPISTORE context released\n");
	return 0;
}

/**
   \details Initialize the EMSMDBP context and open connections to
   Samba databases.

   \param lp_ctx pointer to the loadparm_context
   \param username account name for current session
   \param ldb_ctx pointer to the openchange dispatcher ldb database

   \return Allocated emsmdbp_context pointer on success, otherwise
   NULL
 */
_PUBLIC_ struct emsmdbp_context *emsmdbp_init(struct loadparm_context *lp_ctx,
					      const char *username,
					      void *oc_ctx)
{
	TALLOC_CTX		*mem_ctx = NULL;
	struct emsmdbp_context	*emsmdbp_ctx;
	enum mapistore_error	ret;

	/* Sanity Checks */
	if (!lp_ctx || !username || !username[0]) return NULL;

	emsmdbp_ctx = talloc_zero(NULL, struct emsmdbp_context);
	if (!emsmdbp_ctx) {
		talloc_free(mem_ctx);
		return NULL;
	}

	mem_ctx = emsmdbp_ctx;
	emsmdbp_ctx->mem_ctx = emsmdbp_ctx;

	/* Save a pointer to the loadparm context */
	emsmdbp_ctx->lp_ctx = lp_ctx;

	emsmdbp_ctx->samdb_ctx = samdb_init(emsmdbp_ctx, lp_ctx);
	if (!emsmdbp_ctx->samdb_ctx) {
		talloc_free(mem_ctx);
		OC_DEBUG(0, "Connection to \"sam.ldb\" failed\n");
		return NULL;
	}

	/* Reference global OpenChange dispatcher database pointer within current context */
	emsmdbp_ctx->oc_ctx = oc_ctx;

	/* Initialize the mapistore context */
	emsmdbp_ctx->mstore_ctx = mapistore_init(mem_ctx, lp_ctx, NULL);
	if (!emsmdbp_ctx->mstore_ctx) {
		OC_DEBUG(0, "MAPISTORE initialization failed\n");
		talloc_free(mem_ctx);
		return NULL;
	}

	talloc_set_destructor((void *)emsmdbp_ctx->mstore_ctx, (int (*)(void *))emsmdbp_mapi_store_destructor);

	ret = mapistore_set_connection_info(emsmdbp_ctx->mstore_ctx, emsmdbp_ctx->samdb_ctx, emsmdbp_ctx->oc_ctx, username);
	if (ret != MAPISTORE_SUCCESS) {
		OC_DEBUG(0, "MAPISTORE connection info initialization failed\n");
		talloc_free(mem_ctx);
		return NULL;
	}
	/* Initialize MAPI handles context */
	emsmdbp_ctx->handles_ctx = mapi_handles_init(mem_ctx);
	if (!emsmdbp_ctx->handles_ctx) {
		OC_DEBUG(0, "MAPI handles context initialization failed\n");
		talloc_free(mem_ctx);
		return NULL;
	}

	return emsmdbp_ctx;
}


/**
   \details Associate the session uuid to the emsmdb context

   \param emsmdbp_ctx pointer to the emsmdb context
   \param uuid the uuid to associate

   \return true on success, otherwise false
 */
_PUBLIC_ bool emsmdbp_set_session_uuid(struct emsmdbp_context *emsmdbp_ctx, struct GUID uuid)
{
	if (!emsmdbp_ctx) return false;

  emsmdbp_ctx->session_uuid = uuid;
  return true;
}

/**
   \details Open openchange.ldb database

   \param lp_ctx pointer on the loadparm_context

   \note This function is just a wrapper over
   mapiproxy_server_openchange_ldb_init

   \return Allocated openchangedb context on success, otherwise NULL
 */
_PUBLIC_ void *emsmdbp_openchangedb_init(struct loadparm_context *lp_ctx)
{
	/* Sanity checks */
	if (!lp_ctx) return NULL;

	return mapiproxy_server_openchangedb_init(lp_ctx);
}


_PUBLIC_ bool emsmdbp_destructor(void *data)
{
	return data != NULL && talloc_free(data) == 0;
}


/**
   \details Resolve a recipient and build the associated RecipientRow
   structure

   \param mem_ctx pointer to the memory context
   \param emsmdbp_ctx pointer to the EMSMDBP context
   \param recipient pointer to the recipient string
   \param properties array of properties to lookup for a recipient
   \param row the RecipientRow to fill in

   \note This is a very preliminary implementation with a lot of
   pseudo-hardcoded things. Lot of work is required to make this
   function generic and to cover all different cases

   \return Allocated RecipientRow on success, otherwise NULL
 */
_PUBLIC_ enum MAPISTATUS emsmdbp_resolve_recipient(TALLOC_CTX *mem_ctx,
						   struct emsmdbp_context *emsmdbp_ctx,
						   char *recipient,
						   struct mapi_SPropTagArray *properties,
						   struct RecipientRow *row)
{
	enum MAPISTATUS		retval;
	struct ldb_result	*res = NULL;
	const char * const	recipient_attrs[] = { "*", NULL };
	int			ret;
	uint32_t		i;
	uint32_t		property = 0;
	void			*data;
	char			*str;
	char			*username;
	char			*legacyExchangeDN;
	uint32_t		org_length;
	uint32_t		l;

	/* Sanity checks */
	OPENCHANGE_RETVAL_IF(!mem_ctx, MAPI_E_NOT_INITIALIZED, NULL);
	OPENCHANGE_RETVAL_IF(!emsmdbp_ctx, MAPI_E_NOT_INITIALIZED, NULL);
	OPENCHANGE_RETVAL_IF(!emsmdbp_ctx->samdb_ctx, MAPI_E_NOT_INITIALIZED, NULL);
	OPENCHANGE_RETVAL_IF(!properties, MAPI_E_INVALID_PARAMETER, NULL);
	OPENCHANGE_RETVAL_IF(!recipient, MAPI_E_INVALID_PARAMETER, NULL);
	OPENCHANGE_RETVAL_IF(!row, MAPI_E_INVALID_PARAMETER, NULL);

	ret = ldb_search(emsmdbp_ctx->samdb_ctx, emsmdbp_ctx, &res,
			 ldb_get_default_basedn(emsmdbp_ctx->samdb_ctx),
			 LDB_SCOPE_SUBTREE, recipient_attrs,
			 "(&(objectClass=user)(sAMAccountName=*%s*)(!(objectClass=computer)))",
			 ldb_binary_encode_string(mem_ctx, recipient));

	/* If the search failed, build an external recipient: very basic for the moment */
	if (ret != LDB_SUCCESS || !res->count) {
	failure:
		row->RecipientFlags = 0x07db;
		row->EmailAddress.lpszW = talloc_strdup(mem_ctx, recipient);
		row->DisplayName.lpszW = talloc_strdup(mem_ctx, recipient);
		row->SimpleDisplayName.lpszW = talloc_strdup(mem_ctx, recipient);
		row->prop_count = properties->cValues;
		row->layout = 0x1;
		row->prop_values.length = 0;
		for (i = 0; i < properties->cValues; i++) {
			switch (properties->aulPropTag[i]) {
			case PidTagSmtpAddress:
				property = properties->aulPropTag[i];
				data = (void *) recipient;
				break;
			default:
				retval = MAPI_E_NOT_FOUND;
				property = (properties->aulPropTag[i] & 0xFFFF0000) + PT_ERROR;
				data = (void *)&retval;
				break;
			}

			libmapiserver_push_property(mem_ctx,
						    property, (const void *)data, &row->prop_values, 
						    row->layout, 0, 0);
		}

		return MAPI_E_SUCCESS;
	}

	/* Otherwise build a RecipientRow for resolved username */

	username = (char *) ldb_msg_find_attr_as_string(res->msgs[0], "mailNickname", NULL);
	legacyExchangeDN = (char *) ldb_msg_find_attr_as_string(res->msgs[0], "legacyExchangeDN", NULL);
	if (!username || !legacyExchangeDN) {
		OC_DEBUG(0, "record found but mailNickname or legacyExchangeDN is missing for %s\n", recipient);
		goto failure;
	}
	org_length = strlen(legacyExchangeDN) - strlen(username);

	/* Check if we need a flagged blob */
	row->layout = 0;
	for (i = 0; i < properties->cValues; i++) {
		switch (properties->aulPropTag[i]) {
		case PR_DISPLAY_TYPE:
		case PR_OBJECT_TYPE:
		case PidTagAddressBookDisplayNamePrintable:
		case PidTagSmtpAddress:
			break;
		default:
			row->layout = 1;
			break;
		}
	}

	row->RecipientFlags = 0x06d1;
	row->AddressPrefixUsed.prefix_size = org_length;
	row->DisplayType.display_type = SINGLE_RECIPIENT;
	row->X500DN.recipient_x500name = talloc_strdup(mem_ctx, username);

	row->DisplayName.lpszW = talloc_strdup(mem_ctx, username);
	row->SimpleDisplayName.lpszW = talloc_strdup(mem_ctx, username);
	row->prop_count = properties->cValues;
	row->prop_values.length = 0;

	/* Add this very small set of properties */
	for (i = 0; i < properties->cValues; i++) {
		switch (properties->aulPropTag[i]) {
		case PR_DISPLAY_TYPE:
			property = properties->aulPropTag[i];
			l = 0x0;
			data = (void *)&l;
			break;
		case PR_OBJECT_TYPE:
			property = properties->aulPropTag[i];
			l = MAPI_MAILUSER;
			data = (void *)&l;
			break;
		case PidTagAddressBookDisplayNamePrintable:
			property = properties->aulPropTag[i];
			str = (char *) ldb_msg_find_attr_as_string(res->msgs[0], "mailNickname", NULL);
			data = (void *) str;
			break;
		case PidTagSmtpAddress:
			property = properties->aulPropTag[i];
			str = (char *) ldb_msg_find_attr_as_string(res->msgs[0], "legacyExchangeDN", NULL);
			data = (void *) str;
			break;
		default:
			retval = MAPI_E_NOT_FOUND;
			property = (properties->aulPropTag[i] & 0xFFFF0000) + PT_ERROR;
			data = (void *)&retval;
			break;
		}
		libmapiserver_push_property(mem_ctx,
					    property, (const void *)data, &row->prop_values, 
					    row->layout, 0, 0);
	}

	return MAPI_E_SUCCESS;
}

_PUBLIC_ int emsmdbp_guid_to_replid(struct emsmdbp_context *emsmdbp_ctx, const char *username, const struct GUID *guidP, uint16_t *replidP)
{
	uint16_t	replid;
	struct GUID	guid;

	if (GUID_equal(guidP, MagicGUIDp)) {
		*replidP = 2;
		return MAPI_E_SUCCESS;
	}

	openchangedb_get_MailboxReplica(emsmdbp_ctx->oc_ctx, username, &replid, &guid);
	if (GUID_equal(guidP, &guid)) {
		*replidP = replid;
		return MAPI_E_SUCCESS;
	}

	if (mapistore_replica_mapping_guid_to_replid(emsmdbp_ctx->mstore_ctx, username, guidP, &replid) == MAPISTORE_SUCCESS) {
		*replidP = replid;
		return MAPI_E_SUCCESS;
	}

	return MAPI_E_NOT_FOUND;
}

_PUBLIC_ int emsmdbp_replid_to_guid(struct emsmdbp_context *emsmdbp_ctx, const char *username, const uint16_t replid, struct GUID *guidP)
{
	uint16_t	db_replid;
	struct GUID	guid;

	if (replid == 2) {
		*guidP = MagicGUID;
		return MAPI_E_SUCCESS;
	}

	openchangedb_get_MailboxReplica(emsmdbp_ctx->oc_ctx, username, &db_replid, &guid);
	if (replid == db_replid) {
		*guidP = guid;
		return MAPI_E_SUCCESS;
	}

	if (mapistore_replica_mapping_replid_to_guid(emsmdbp_ctx->mstore_ctx, username, replid, &guid) == MAPISTORE_SUCCESS) {
		*guidP = guid;
		return MAPI_E_SUCCESS;
	}

	return MAPI_E_NOT_FOUND;
}

_PUBLIC_ int emsmdbp_source_key_from_fmid(TALLOC_CTX *mem_ctx, struct emsmdbp_context *emsmdbp_ctx, const char *username, uint64_t fmid, struct Binary_r **source_keyP)
{
	struct Binary_r	*source_key;
	uint64_t	gc;
	uint16_t	replid;
	uint8_t		*bytes;
	int		i;

	replid = fmid & 0xffff;
	source_key = talloc_zero(NULL, struct Binary_r);
	source_key->cb = 22;
	source_key->lpb = talloc_array(source_key, uint8_t, source_key->cb);
	if (emsmdbp_replid_to_guid(emsmdbp_ctx, username, replid, (struct GUID *) source_key->lpb)) {
		talloc_free(source_key);
		return MAPISTORE_ERROR;
	}

	(void) talloc_reference(mem_ctx, source_key);
	talloc_unlink(NULL, source_key);

	gc = fmid >> 16;

	bytes = source_key->lpb + 16;
	for (i = 0; i < 6; i++) {
		bytes[i] = gc & 0xff;
		gc >>= 8;
	}

	*source_keyP = source_key;

	return MAPISTORE_SUCCESS;
}

/**
   \details Extract organization name and group name from the legacy exchange
   dn of the current logged user.

   \param mem_ctx memory context used for returned values
   \param emsmdbp_ctx pointer to the EMSMDBP context
   \param organization_name pointer to the returned organization name
   \param group_name pointer to the returned group name

   \note You can set organization_name or group_name to NULL if you don't want
   this values

   \return MAPI_E_SUCCESS or an error if something happens
 */
_PUBLIC_ enum MAPISTATUS emsmdbp_fetch_organizational_units(TALLOC_CTX *mem_ctx,
	struct emsmdbp_context *emsmdbp_ctx, char **organization_name, char **group_name)
{
	const char *dn, *group, *recipient;
	char *organization = NULL, *unit = NULL;

	if (organization_name) *organization_name = NULL;
	if (group_name) *group_name = NULL;
	OPENCHANGE_RETVAL_IF(!emsmdbp_ctx || !emsmdbp_ctx->szUserDN, MAPI_E_NOT_INITIALIZED, NULL);
	if (!organization_name && !group_name) return MAPI_E_SUCCESS;
	dn = emsmdbp_ctx->szUserDN;
	OPENCHANGE_RETVAL_IF(strncmp(dn, "/o=", 3) != 0, MAPI_E_BAD_VALUE, NULL);
	group = strstr(dn + 3, "/ou=");
	OPENCHANGE_RETVAL_IF(group == NULL || group == dn + 3, MAPI_E_BAD_VALUE, NULL);
	recipient = strstr(group + 4, "/cn=");
	OPENCHANGE_RETVAL_IF(group_name && (recipient == NULL || recipient == group + 4), MAPI_E_BAD_VALUE, NULL);
	if (organization_name) {
		organization = talloc_strndup(mem_ctx, dn + 3, group - dn - 3);
		OPENCHANGE_RETVAL_IF(organization == NULL, MAPI_E_NOT_ENOUGH_MEMORY, NULL);
	}
	if (group_name) {
		unit = talloc_strndup(mem_ctx, group + 4, recipient - group - 4);
		if (unit == NULL) {
			talloc_free(organization);
			OPENCHANGE_RETVAL_ERR(MAPI_E_NOT_ENOUGH_MEMORY, NULL);
		}
	}
	if (organization_name) *organization_name = organization;
	if (group_name) *group_name = unit;
	return MAPI_E_SUCCESS;
}

/**
   \details Get the organization name (like "First Organization") as a DN.

   \param emsmdbp_ctx pointer to the EMSMDBP context
   \param basedn pointer to the returned struct ldb_dn

   \return MAPI_E_SUCCESS or an error if something happens
 */
_PUBLIC_ enum MAPISTATUS emsmdbp_get_org_dn(struct emsmdbp_context *emsmdbp_ctx, struct ldb_dn **basedn)
{
	enum MAPISTATUS retval;
	struct ldb_result *res = NULL;
	struct ldb_dn *config;
	char *org_name, *encoded;
	int ret;

	OPENCHANGE_RETVAL_IF(!basedn, MAPI_E_INVALID_PARAMETER, NULL);
	*basedn = NULL;
	OPENCHANGE_RETVAL_IF(!emsmdbp_ctx || !emsmdbp_ctx->samdb_ctx, MAPI_E_NOT_INITIALIZED, NULL);
	config = ldb_get_config_basedn(emsmdbp_ctx->samdb_ctx);
	OPENCHANGE_RETVAL_IF(config == NULL, MAPI_E_NOT_FOUND, NULL);
	retval = emsmdbp_fetch_organizational_units(emsmdbp_ctx, emsmdbp_ctx, &org_name, NULL);
	OPENCHANGE_RETVAL_IF(retval != MAPI_E_SUCCESS, retval, NULL);
	encoded = ldb_binary_encode_string(emsmdbp_ctx, org_name);
	talloc_free(org_name);
	OPENCHANGE_RETVAL_IF(encoded == NULL, MAPI_E_NOT_ENOUGH_MEMORY, NULL);
	ret = ldb_search(emsmdbp_ctx->samdb_ctx, emsmdbp_ctx, &res,
		config, LDB_SCOPE_SUBTREE, NULL,
		"(&(objectClass=msExchOrganizationContainer)(cn=%s))", encoded);
	talloc_free(encoded);
	if (ret != LDB_SUCCESS || res->count != 1) {
		talloc_free(res);
		OPENCHANGE_RETVAL_ERR(MAPI_E_NOT_FOUND, NULL);
	}
	*basedn = ldb_dn_copy(emsmdbp_ctx, res->msgs[0]->dn);
	talloc_free(res);
	OPENCHANGE_RETVAL_IF(*basedn == NULL, MAPI_E_NOT_ENOUGH_MEMORY, NULL);
	return MAPI_E_SUCCESS;
}
