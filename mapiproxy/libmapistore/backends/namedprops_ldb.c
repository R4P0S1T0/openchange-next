/*
   MAPI Proxy - Named properties backend LDB implementation

   OpenChange Project

   Copyright (C) Julien Kerihuel 2010-2013

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

#include "libmapi/libmapi.h"
#include "libmapi/libmapi_private.h"
#include "namedprops_ldb.h"
#include "../mapistore.h"
#include "../mapistore_private.h"


struct ldb_wrap {
	struct ldb_wrap *next;
	struct ldb_wrap *prev;
	struct ldb_wrap_context {
		const char *url;
		struct tevent_context *ev;
		unsigned int flags;
	} context;
	struct ldb_context *ldb;
};

static struct ldb_wrap *ldb_wrap_list;


/*
  see if two database opens are equivalent
 */
static bool mapistore_ldb_wrap_same_context(const struct ldb_wrap_context *c1,
					    const struct ldb_wrap_context *c2)
{
	return (c1->ev == c2->ev &&
		c1->flags == c2->flags &&
		(c1->url == c2->url || strcmp(c1->url, c2->url) == 0));
}

/* 
   free a ldb_wrap structure
 */
static int mapistore_ldb_wrap_destructor(struct ldb_wrap *w)
{
	DLIST_REMOVE(ldb_wrap_list, w);
	return 0;
}

/*
  wrapped connection to a ldb database
  to close just talloc_free() the returned ldb_context

  TODO:  We need an error_string parameter
 */
static struct ldb_context *mapistore_ldb_wrap_connect(TALLOC_CTX *mem_ctx,
						      struct tevent_context *ev,
						      const char *url,
						      unsigned int flags)
{
	struct ldb_context	*ldb;
	int			ret;
	struct ldb_wrap		*w;
	struct ldb_wrap_context c;

	c.url          = url;
	c.ev           = ev;
	c.flags        = flags;

	/* see if we can re-use an existing ldb */
	for (w = ldb_wrap_list; w; w = w->next) {
		if (mapistore_ldb_wrap_same_context(&c, &w->context)) {
			return talloc_reference(mem_ctx, w->ldb);
		}
	}

	/* we want to use the existing event context if possible. This
	   relies on the fact that in smbd, everything is a child of
	   the main event_context */
	if (ev == NULL) {
		return NULL;
	}

	ldb = ldb_init(mem_ctx, ev);
	if (ldb == NULL) {
		return NULL;
	}

	ldb_set_create_perms(ldb, 0600);
	
	ret = ldb_connect(ldb, url, flags, NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(ldb);
		return NULL;
	}

	/* add to the list of open ldb contexts */
	w = talloc(ldb, struct ldb_wrap);
	if (w == NULL) {
		talloc_free(ldb);
		return NULL;
	}

	w->context = c;
	w->context.url = talloc_strdup(w, url);
	if (w->context.url == NULL) {
		talloc_free(ldb);
		return NULL;
	}

	w->ldb = ldb;

	DLIST_ADD(ldb_wrap_list, w);

	OC_DEBUG(3, "ldb_wrap open of %s\n", url);

	talloc_set_destructor(w, mapistore_ldb_wrap_destructor);

	return ldb;
}

static enum mapistore_error get_mapped_id(struct namedprops_context *self,
					  struct MAPINAMEID nameid,
					  uint16_t *propID)
{
	TALLOC_CTX *mem_ctx;
	struct ldb_result *res = NULL;
	const char * const attrs[] = { "mappedId", NULL };
	char *filter = NULL, *guid, *name;
	unsigned id;
	int ret;

	MAPISTORE_RETVAL_IF(!self || !self->data || !propID, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	mem_ctx = talloc_new(NULL);
	MAPISTORE_RETVAL_IF(!mem_ctx, MAPISTORE_ERR_NO_MEMORY, NULL);
	guid = GUID_string(mem_ctx, &nameid.lpguid);
	MAPISTORE_RETVAL_IF(!guid, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	switch (nameid.ulKind) {
	case MNID_ID:
		filter = talloc_asprintf(mem_ctx,
			"(&(objectClass=MNID_ID)(oleguid=%s)(cn=0x%.4x))", guid, nameid.kind.lid);
		break;
	case MNID_STRING:
		MAPISTORE_RETVAL_IF(!nameid.kind.lpwstr.Name, MAPISTORE_ERR_INVALID_PARAMETER, mem_ctx);
		name = ldb_binary_encode_string(mem_ctx, nameid.kind.lpwstr.Name);
		MAPISTORE_RETVAL_IF(!name, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
		filter = talloc_asprintf(mem_ctx,
			"(&(objectClass=MNID_STRING)(oleguid=%s)(cn=%s))", guid, name);
		break;
	default:
		MAPISTORE_RETVAL_ERR(MAPISTORE_ERR_INVALID_PARAMETER, mem_ctx);
	}
	MAPISTORE_RETVAL_IF(!filter, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	ret = ldb_search(self->data, mem_ctx, &res, ldb_get_default_basedn(self->data),
		LDB_SCOPE_SUBTREE, attrs, "%s", filter);
	MAPISTORE_RETVAL_IF(ret != LDB_SUCCESS, MAPISTORE_ERR_DATABASE_OPS, mem_ctx);
	MAPISTORE_RETVAL_IF(!res->count, MAPISTORE_ERR_NOT_FOUND, mem_ctx);
	MAPISTORE_RETVAL_IF(res->count != 1, MAPISTORE_ERR_INVALID_DATA, mem_ctx);
	id = ldb_msg_find_attr_as_uint(res->msgs[0], "mappedId", 0);
	MAPISTORE_RETVAL_IF(!id || id > UINT16_MAX, MAPISTORE_ERR_INVALID_DATA, mem_ctx);
	*propID = id;
	talloc_free(mem_ctx);
	return MAPISTORE_SUCCESS;
}

/**
   \details Return the next unused namedprops ID

   \param nprops pointer to the namedprops context
   \param highest_id pointer to the next ID to return

   \return MAPISTORE_SUCCESS on success, otherwise MAPISTORE error
 */
static enum mapistore_error next_unused_id(struct namedprops_context *nprops, uint16_t *highest_id)
{
	TALLOC_CTX		*mem_ctx = NULL;
	struct ldb_context	*ldb_ctx;
	struct ldb_result	*res = NULL;
	const char * const	attrs[] = { "mappedId", NULL };
	int			ret;
	int			i;
	unsigned		current_id, highest = 0x8000;

	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!nprops, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	MAPISTORE_RETVAL_IF(!highest_id, MAPISTORE_ERR_INVALID_PARAMETER, NULL);

	ldb_ctx = (struct ldb_context *) nprops->data;
	MAPISTORE_RETVAL_IF(!ldb_ctx, MAPISTORE_ERR_INVALID_PARAMETER, NULL);

	mem_ctx = talloc_named(NULL, 0, "next_unused_id");
	MAPISTORE_RETVAL_IF(!mem_ctx, MAPISTORE_ERR_NO_MEMORY, NULL);

	ret = ldb_search(ldb_ctx, mem_ctx, &res, ldb_get_default_basedn(ldb_ctx),
			 LDB_SCOPE_SUBTREE, attrs, "(cn=*)");
	MAPISTORE_RETVAL_IF(ret != LDB_SUCCESS, MAPISTORE_ERR_DATABASE_OPS, mem_ctx);

	for (i = 0; i < res->count; i++) {
		current_id = ldb_msg_find_attr_as_uint(res->msgs[i], "mappedId", 0);
		if (highest < current_id) highest = current_id;
	}

	MAPISTORE_RETVAL_IF(highest >= 0xfffe, MAPISTORE_ERR_NOT_AVAILABLE, mem_ctx);
	*highest_id = highest + 1;

	talloc_free(mem_ctx);
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error create_id(struct namedprops_context *self,
				      struct MAPINAMEID nameid,
				      uint16_t mapped_id)
{
	TALLOC_CTX *mem_ctx;
	struct ldb_message *msg;
	char *guid, *escaped, *mapped, *lid = NULL;
	const char *cn;
	int ret;

	MAPISTORE_RETVAL_IF(!self || !self->data, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	MAPISTORE_RETVAL_IF(nameid.ulKind != MNID_ID && nameid.ulKind != MNID_STRING,
		MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	MAPISTORE_RETVAL_IF(nameid.ulKind == MNID_STRING && !nameid.kind.lpwstr.Name,
		MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	mem_ctx = talloc_new(NULL);
	MAPISTORE_RETVAL_IF(!mem_ctx, MAPISTORE_ERR_NO_MEMORY, NULL);
	msg = ldb_msg_new(mem_ctx);
	guid = GUID_string(mem_ctx, &nameid.lpguid);
	mapped = talloc_asprintf(mem_ctx, "%u", mapped_id);
	cn = nameid.ulKind == MNID_ID
		? talloc_asprintf(mem_ctx, "0x%.4x", nameid.kind.lid) : nameid.kind.lpwstr.Name;
	MAPISTORE_RETVAL_IF(!msg || !guid || !mapped || !cn, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	msg->dn = ldb_dn_new_fmt(msg, self->data, "CN=%s,CN=default", guid);
	MAPISTORE_RETVAL_IF(!msg->dn, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	/* Let LDB escape the RDN and store names as literal attribute values. */
	escaped = ldb_dn_escape_value(mem_ctx, (struct ldb_val){(uint8_t *)cn, strlen(cn)});
	MAPISTORE_RETVAL_IF(!escaped, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	MAPISTORE_RETVAL_IF(!ldb_dn_add_child_fmt(msg->dn, "CN=%s", escaped),
		MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	ret = ldb_msg_add_string(msg, "objectClass", nameid.ulKind == MNID_ID ? "MNID_ID" : "MNID_STRING");
	if (ret == LDB_SUCCESS) ret = ldb_msg_add_string(msg, "cn", cn);
	if (ret == LDB_SUCCESS) ret = ldb_msg_add_string(msg, "propType", "PT_NULL");
	if (ret == LDB_SUCCESS) ret = ldb_msg_add_string(msg, "oleguid", guid);
	if (ret == LDB_SUCCESS) ret = ldb_msg_add_string(msg, "mappedId", mapped);
	if (nameid.ulKind == MNID_ID) {
		lid = talloc_asprintf(mem_ctx, "%u", nameid.kind.lid);
		MAPISTORE_RETVAL_IF(!lid, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	}
	if (ret == LDB_SUCCESS) ret = ldb_msg_add_string(msg,
		nameid.ulKind == MNID_ID ? "propId" : "propName", lid ? lid : cn);
	MAPISTORE_RETVAL_IF(ret != LDB_SUCCESS, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	ret = ldb_add(self->data, msg);
	MAPISTORE_RETVAL_IF(ret != LDB_SUCCESS, MAPISTORE_ERR_DATABASE_OPS, mem_ctx);
	talloc_free(mem_ctx);
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error get_nameid(struct namedprops_context *self,
				       uint16_t propID,
				       TALLOC_CTX *mem_ctx,
				       struct MAPINAMEID **nameidp)
{
	TALLOC_CTX *local_mem_ctx;
	struct ldb_result *res = NULL;
	const char * const attrs[] = { "*", NULL };
	const char *guid, *oClass, *cn;
	char *end;
	struct MAPINAMEID *nameid = NULL;
	unsigned long long lid;
	size_t name_size;
	int ret;
	enum mapistore_error status = MAPISTORE_ERR_INVALID_DATA;

	MAPISTORE_RETVAL_IF(!nameidp, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	*nameidp = NULL;
	MAPISTORE_RETVAL_IF(!self || !self->data, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	local_mem_ctx = talloc_new(NULL);
	MAPISTORE_RETVAL_IF(!local_mem_ctx, MAPISTORE_ERR_NO_MEMORY, NULL);
	ret = ldb_search(self->data, local_mem_ctx, &res, ldb_get_default_basedn(self->data),
		LDB_SCOPE_SUBTREE, attrs, "(mappedId=%u)", propID);
	MAPISTORE_RETVAL_IF(ret != LDB_SUCCESS || !res->count, MAPISTORE_ERROR, local_mem_ctx);
	MAPISTORE_RETVAL_IF(res->count != 1, MAPISTORE_ERR_INVALID_DATA, local_mem_ctx);

	guid = ldb_msg_find_attr_as_string(res->msgs[0], "oleguid", NULL);
	cn = ldb_msg_find_attr_as_string(res->msgs[0], "cn", NULL);
	oClass = ldb_msg_find_attr_as_string(res->msgs[0], "objectClass", NULL);
	MAPISTORE_RETVAL_IF(!guid || !cn || !oClass, MAPISTORE_ERR_INVALID_DATA, local_mem_ctx);

	nameid = talloc_zero(mem_ctx, struct MAPINAMEID);
	if (!nameid) { status = MAPISTORE_ERR_NO_MEMORY; goto end; }
	if (!NT_STATUS_IS_OK(GUID_from_string(guid, &nameid->lpguid))) goto end;
	if (strcmp(oClass, "MNID_ID") == 0) {
		errno = 0;
		lid = strtoull(cn, &end, 16);
		if (errno || end == cn || *end || strchr(cn, '-') || lid > UINT32_MAX) goto end;
		nameid->ulKind = MNID_ID;
		nameid->kind.lid = lid;
	} else if (strcmp(oClass, "MNID_STRING") == 0) {
		name_size = get_utf8_utf16_conv_length(cn);
		if (name_size > UINT8_MAX) goto end;
		nameid->ulKind = MNID_STRING;
		nameid->kind.lpwstr.NameSize = name_size;
		nameid->kind.lpwstr.Name = talloc_strdup(nameid, cn);
		if (!nameid->kind.lpwstr.Name) { status = MAPISTORE_ERR_NO_MEMORY; goto end; }
	} else {
		goto end;
	}
	*nameidp = nameid;
	nameid = NULL;
	status = MAPISTORE_SUCCESS;
end:
	talloc_free(nameid);
	talloc_free(local_mem_ctx);
	if (status != MAPISTORE_SUCCESS) mapistore_set_errno(status);
	return status;
}

static enum mapistore_error get_nameid_type(struct namedprops_context *self,
					    uint16_t propID,
					    uint16_t *propTypeP)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	const char * const attrs[] = { "propType", NULL };
	struct ldb_result *res = NULL;
	struct ldb_context *ldb_ctx = self->data;
	int ret = ldb_search(ldb_ctx, mem_ctx, &res, ldb_get_default_basedn(ldb_ctx),
			     LDB_SCOPE_SUBTREE, attrs, "(mappedId=%d)", propID);
	MAPISTORE_RETVAL_IF(ret != LDB_SUCCESS || !res->count, MAPISTORE_ERROR, mem_ctx);

	int propType = ldb_msg_find_attr_as_int(res->msgs[0], "propType", 0);
	if (!propType) {
		const char *val = ldb_msg_find_attr_as_string(res->msgs[0], "propType", "");
		propType = mapistore_namedprops_prop_type_from_string(val);
		MAPISTORE_RETVAL_IF(propType == -1, MAPISTORE_ERROR, mem_ctx);
	}
	MAPISTORE_RETVAL_IF(!propType, MAPISTORE_ERROR, mem_ctx);
	*propTypeP = propType;
	talloc_free(mem_ctx);

	return MAPISTORE_SUCCESS;
}

static enum mapistore_error transaction_start(struct namedprops_context *self)
{
	struct ldb_context *ldb_ctx = self->data;
	int ret = ldb_transaction_start(ldb_ctx);
	MAPISTORE_RETVAL_IF(ret != LDB_SUCCESS, MAPISTORE_ERROR, NULL);
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error transaction_commit(struct namedprops_context *self)
{
	struct ldb_context *ldb_ctx = self->data;
	int ret = ldb_transaction_commit(ldb_ctx);
	MAPISTORE_RETVAL_IF(ret != LDB_SUCCESS, MAPISTORE_ERROR, NULL);
	return MAPISTORE_SUCCESS;
}
static enum mapistore_error transaction_cancel(struct namedprops_context *self)
{
	int ret;
	MAPISTORE_RETVAL_IF(!self || !self->data, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	ret = ldb_transaction_cancel(self->data);
	MAPISTORE_RETVAL_IF(ret != LDB_SUCCESS, MAPISTORE_ERR_DATABASE_OPS, NULL);
	return MAPISTORE_SUCCESS;
}



/**
   \details Initialize mapistore named properties LDB backend

   \param mem_ctx pointer to the memory context
   \param lp_ctx pointer to the loadparm context
   \param nprops_ctx pointer on pointer ot the namedprops context to
   return

   \return MAPISTORE_SUCCESS on success, otherwise MAPISTORE error
 */
enum mapistore_error mapistore_namedprops_ldb_init(TALLOC_CTX *mem_ctx,
						   struct loadparm_context *lp_ctx,
						   struct namedprops_context **nprops_ctx)
{
	int				ret;
	struct namedprops_context	*nprops = NULL;
	const char			*database;
	const char			*data_path;
	struct stat			sb;
	struct ldb_context		*ldb_ctx = NULL;
	struct ldb_ldif			*ldif;
	struct ldb_message		*msg;
	char				*filename;
	FILE				*f;
	struct tevent_context		*ev;

	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!lp_ctx, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	MAPISTORE_RETVAL_IF(!nprops_ctx, MAPISTORE_ERR_INVALID_PARAMETER, NULL);

	/* Retrieve smb.conf argument */
	database = lpcfg_parm_string(lp_ctx, NULL, "namedproperties", "ldb_url");
	MAPISTORE_RETVAL_IF(!database, MAPISTORE_ERR_BACKEND_INIT, NULL);

	ev = tevent_context_init(mem_ctx);
	MAPISTORE_RETVAL_IF(!ev, MAPISTORE_ERR_NO_MEMORY, NULL);

	/* Stat the database and populate it if it doesn't exist */
	if (stat(database, &sb) == -1) {
		ldb_ctx = mapistore_ldb_wrap_connect(mem_ctx, ev, database, 0);
		MAPISTORE_RETVAL_IF(!ldb_ctx, MAPISTORE_ERR_DATABASE_INIT, NULL);

		data_path = lpcfg_parm_string(lp_ctx, NULL, "namedproperties", "ldb_data");
		filename = talloc_asprintf(mem_ctx, "%s/mapistore_namedprops.ldif",
					   data_path ? data_path :
					   mapistore_namedprops_get_ldif_path());
		f = fopen(filename, "r");
		talloc_free(filename);
		MAPISTORE_RETVAL_IF(!f, MAPISTORE_ERROR, NULL);

		ldb_transaction_start(ldb_ctx);

		msg = ldb_msg_new(mem_ctx);
		MAPISTORE_RETVAL_IF(!msg, MAPISTORE_ERR_NO_MEMORY, NULL);
		msg->dn = ldb_dn_new(msg, ldb_ctx, "@INDEXLIST");
		ldb_msg_add_string(msg, "@IDXATTR", "cn");
		ldb_msg_add_string(msg, "@IDXATTR", "oleguid");
		ldb_msg_add_string(msg, "@IDXATTR", "mappedId");
		msg->elements[0].flags = LDB_FLAG_MOD_ADD;
		ret = ldb_add(ldb_ctx, msg);
		talloc_free(msg);
		if (ret != LDB_SUCCESS) {
			fclose(f);
			return MAPISTORE_ERR_DATABASE_INIT;
		}

		while ((ldif = ldb_ldif_read_file(ldb_ctx, f))) {
			struct ldb_message	*normalized_msg;

			ret = ldb_msg_normalize(ldb_ctx, mem_ctx, ldif->msg, &normalized_msg);
			MAPISTORE_RETVAL_IF(ret, MAPISTORE_ERR_DATABASE_INIT, NULL);
			ret = ldb_add(ldb_ctx, normalized_msg);
			talloc_free(normalized_msg);
			if (ret != LDB_SUCCESS) {
				fclose(f);
				return MAPISTORE_ERR_DATABASE_INIT;
			}
			ldb_ldif_read_free(ldb_ctx, ldif);
		}

		ldb_transaction_commit(ldb_ctx);
		fclose(f);
	} else {
		ldb_ctx = mapistore_ldb_wrap_connect(mem_ctx, ev, database, 0);
		MAPISTORE_RETVAL_IF(!ldb_ctx, MAPISTORE_ERR_DATABASE_INIT, NULL);
	}

	nprops = talloc_zero(mem_ctx, struct namedprops_context);
	MAPISTORE_RETVAL_IF(!nprops, MAPISTORE_ERR_NO_MEMORY, NULL);

	nprops->backend_type = NAMEDPROPS_BACKEND_LDB;
	nprops->create_id = create_id;
	nprops->get_mapped_id = get_mapped_id;
	nprops->get_nameid = get_nameid;
	nprops->get_nameid_type = get_nameid_type;
	nprops->next_unused_id = next_unused_id;
	nprops->transaction_commit = transaction_commit;
	nprops->transaction_cancel = transaction_cancel;
	nprops->transaction_start = transaction_start;
	nprops->data = ldb_ctx;

	*nprops_ctx = nprops;

	return MAPISTORE_SUCCESS;
}
