/*
   MAPI Proxy - Named properties backend MySQL implementation

   OpenChange Project

   Copyright (C) Jesús García Sáez 2014

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

#include "namedprops_mysql.h"
#include "../mapistore.h"
#include "../mapistore_private.h"
#include "mapiproxy/util/mysql.h"
#include "mapiproxy/util/schema_migration.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <mysql/mysql.h>
#include <mysql/mysqld_error.h>
#include <ldb.h>
#include "libmapi/libmapi_private.h"


static enum mapistore_error get_mapped_id(struct namedprops_context *self,
					  struct MAPINAMEID nameid,
					  uint16_t *mapped_id)
{
	TALLOC_CTX *mem_ctx;
	char *guid, *sql;
	const char *name;
	uint64_t id;
	enum MYSQLRESULT result;

	MAPISTORE_RETVAL_IF(!self || !self->data || !mapped_id,
		MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	MAPISTORE_RETVAL_IF(nameid.ulKind != MNID_ID && nameid.ulKind != MNID_STRING,
		MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	mem_ctx = talloc_new(NULL);
	MAPISTORE_RETVAL_IF(!mem_ctx, MAPISTORE_ERR_NO_MEMORY, NULL);
	guid = GUID_string(mem_ctx, &nameid.lpguid);
	MAPISTORE_RETVAL_IF(!guid, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	if (nameid.ulKind == MNID_ID) {
		sql = talloc_asprintf(mem_ctx,
			"SELECT mappedId FROM "NAMEDPROPS_MYSQL_TABLE" "
			"WHERE `type`=%u AND `oleguid`='%s' AND `propId`=%u FOR UPDATE",
			nameid.ulKind, guid, nameid.kind.lid);
	} else {
		MAPISTORE_RETVAL_IF(!nameid.kind.lpwstr.Name, MAPISTORE_ERR_INVALID_PARAMETER, mem_ctx);
		name = _sql(mem_ctx, nameid.kind.lpwstr.Name);
		MAPISTORE_RETVAL_IF(!name, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
		sql = talloc_asprintf(mem_ctx,
			"SELECT mappedId FROM "NAMEDPROPS_MYSQL_TABLE" "
			"WHERE `type`=%u AND `oleguid`='%s' AND `propName`='%s' FOR UPDATE",
			nameid.ulKind, guid, name);
	}
	MAPISTORE_RETVAL_IF(!sql, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	/* A locking read sees a concurrent insert even after an older transaction snapshot. */
	result = select_first_uint(self->data, sql, &id);
	MAPISTORE_RETVAL_IF(result == MYSQL_NOT_FOUND, MAPISTORE_ERR_NOT_FOUND, mem_ctx);
	MAPISTORE_RETVAL_IF(result != MYSQL_SUCCESS || id > UINT16_MAX,
		MAPISTORE_ERR_DATABASE_OPS, mem_ctx);
	*mapped_id = id;
	talloc_free(mem_ctx);
	return MAPISTORE_SUCCESS;
}

/**
   \details Return the next unused namedprops ID

   \param nprops pointer to the namedprops creontext
   \param highest_id pointer to the next ID to return

   \return MAPISTORE_SUCCESS on success, otherwise MAPISTORE error
 */
static enum mapistore_error next_unused_id(struct namedprops_context *nprops,
					   uint16_t *highest_id)
{
	uint64_t id;
	enum MYSQLRESULT ret;
	MAPISTORE_RETVAL_IF(!nprops || !nprops->data || !highest_id,
		MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	ret = select_first_uint(nprops->data,
		"SELECT COALESCE(MAX(mappedId),32768) FROM "NAMEDPROPS_MYSQL_TABLE, &id);
	MAPISTORE_RETVAL_IF(ret != MYSQL_SUCCESS, MAPISTORE_ERR_DATABASE_OPS, NULL);
	MAPISTORE_RETVAL_IF(id >= 0xfffe, MAPISTORE_ERR_NOT_AVAILABLE, NULL);
	if (id < 0x8000) id = 0x8000;
	*highest_id = id + 1;
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error create_id(struct namedprops_context *self,
				      struct MAPINAMEID nameid,
				      uint16_t mapped_id)
{
	TALLOC_CTX *mem_ctx;
	char *guid, *key, *sql;
	const char *name;
	enum MYSQLRESULT result;

	MAPISTORE_RETVAL_IF(!self || !self->data, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	MAPISTORE_RETVAL_IF(nameid.ulKind != MNID_ID && nameid.ulKind != MNID_STRING,
		MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	mem_ctx = talloc_new(NULL);
	MAPISTORE_RETVAL_IF(!mem_ctx, MAPISTORE_ERR_NO_MEMORY, NULL);
	guid = GUID_string(mem_ctx, &nameid.lpguid);
	MAPISTORE_RETVAL_IF(!guid, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	if (nameid.ulKind == MNID_ID) {
		key = talloc_asprintf(mem_ctx, "propId=%u", nameid.kind.lid);
	} else {
		MAPISTORE_RETVAL_IF(!nameid.kind.lpwstr.Name, MAPISTORE_ERR_INVALID_PARAMETER, mem_ctx);
		name = _sql(mem_ctx, nameid.kind.lpwstr.Name);
		MAPISTORE_RETVAL_IF(!name, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
		key = talloc_asprintf(mem_ctx, "propName='%s'", name);
	}
	MAPISTORE_RETVAL_IF(!key, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	sql = talloc_asprintf(mem_ctx,
		"INSERT INTO "NAMEDPROPS_MYSQL_TABLE" SET type=%u, propType=%u, "
		"oleguid='%s', mappedId=%u, %s",
		nameid.ulKind, PT_NULL, guid, mapped_id, key);
	MAPISTORE_RETVAL_IF(!sql, MAPISTORE_ERR_NO_MEMORY, mem_ctx);
	result = execute_query(self->data, sql);
	talloc_free(mem_ctx);
	MAPISTORE_RETVAL_IF(result != MYSQL_SUCCESS && mysql_errno(self->data) == ER_DUP_ENTRY,
		MAPISTORE_ERR_EXIST, NULL);
	MAPISTORE_RETVAL_IF(result != MYSQL_SUCCESS, MAPISTORE_ERR_DATABASE_OPS, NULL);
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error get_nameid(struct namedprops_context *self,
				       uint16_t mapped_id,
				       TALLOC_CTX *mem_ctx,
				       struct MAPINAMEID **nameidp)
{
	TALLOC_CTX *tmp;
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	struct MAPINAMEID *nameid = NULL;
	char *sql;
	uint64_t type, id;
	size_t name_size;
	enum MYSQLRESULT result;
	enum mapistore_error status = MAPISTORE_ERR_DATABASE_OPS;

	MAPISTORE_RETVAL_IF(!nameidp, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	*nameidp = NULL;
	MAPISTORE_RETVAL_IF(!self || !self->data, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	tmp = talloc_new(NULL);
	MAPISTORE_RETVAL_IF(!tmp, MAPISTORE_ERR_NO_MEMORY, NULL);
	sql = talloc_asprintf(tmp,
		"SELECT type, oleguid, propName, propId FROM "NAMEDPROPS_MYSQL_TABLE" "
		"WHERE mappedId=%u", mapped_id);
	if (!sql) { status = MAPISTORE_ERR_NO_MEMORY; goto end; }
	result = select_without_fetch(self->data, sql, &res);
	if (result == MYSQL_NOT_FOUND) { status = MAPISTORE_ERR_NOT_FOUND; goto end; }
	if (result != MYSQL_SUCCESS || mysql_field_count(self->data) != 4) goto end;
	row = mysql_fetch_row(res);
	if (!row) goto end;
	status = MAPISTORE_ERR_INVALID_DATA;
	if (!convert_string_to_ull(row[0], &type) || type > MNID_STRING || !row[1]) goto end;
	nameid = talloc_zero(mem_ctx, struct MAPINAMEID);
	if (!nameid) { status = MAPISTORE_ERR_NO_MEMORY; goto end; }
	if (!NT_STATUS_IS_OK(GUID_from_string(row[1], &nameid->lpguid))) goto end;
	nameid->ulKind = type;
	if (type == MNID_ID) {
		if (!convert_string_to_ull(row[3], &id) || id > UINT32_MAX) goto end;
		nameid->kind.lid = id;
	} else {
		if (!row[2]) goto end;
		name_size = get_utf8_utf16_conv_length(row[2]);
		if (name_size > UINT8_MAX) goto end;
		nameid->kind.lpwstr.NameSize = name_size;
		nameid->kind.lpwstr.Name = talloc_strdup(nameid, row[2]);
		if (!nameid->kind.lpwstr.Name) { status = MAPISTORE_ERR_NO_MEMORY; goto end; }
	}
	*nameidp = nameid;
	nameid = NULL;
	status = MAPISTORE_SUCCESS;
end:
	if (res) mysql_free_result(res);
	talloc_free(nameid);
	talloc_free(tmp);
	if (status != MAPISTORE_SUCCESS) mapistore_set_errno(status);
	return status;
}

static enum mapistore_error get_nameid_type(struct namedprops_context *self,
					    uint16_t mapped_id,
					    uint16_t *prop_type)
{
	TALLOC_CTX *tmp;
	char *sql;
	uint64_t type;
	enum MYSQLRESULT result;

	MAPISTORE_RETVAL_IF(!self || !self->data || !prop_type,
		MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	tmp = talloc_new(NULL);
	MAPISTORE_RETVAL_IF(!tmp, MAPISTORE_ERR_NO_MEMORY, NULL);
	sql = talloc_asprintf(tmp,
		"SELECT propType FROM "NAMEDPROPS_MYSQL_TABLE" WHERE mappedId=%u", mapped_id);
	MAPISTORE_RETVAL_IF(!sql, MAPISTORE_ERR_NO_MEMORY, tmp);
	result = select_first_uint(self->data, sql, &type);
	talloc_free(tmp);
	MAPISTORE_RETVAL_IF(result == MYSQL_NOT_FOUND, MAPISTORE_ERR_NOT_FOUND, NULL);
	MAPISTORE_RETVAL_IF(result != MYSQL_SUCCESS || type > UINT16_MAX,
		MAPISTORE_ERR_DATABASE_OPS, NULL);
	*prop_type = type;
	return MAPISTORE_SUCCESS;
}

/* Advisory locks are connection-scoped and must outlive COMMIT/ROLLBACK. */
#define NAMEDPROPS_LOCK "CONCAT('openchange:namedprops:',MD5(DATABASE()))"

static enum mapistore_error transaction_unlock(struct namedprops_context *self)
{
	uint64_t released;
	my_bool reconnect = true;
	enum MYSQLRESULT ret;
	int option_error;

	ret = select_first_uint(self->data, "SELECT RELEASE_LOCK("NAMEDPROPS_LOCK")", &released);
	option_error = mysql_options(self->data, MYSQL_OPT_RECONNECT, &reconnect);
	MAPISTORE_RETVAL_IF(ret != MYSQL_SUCCESS || released != 1 || option_error,
		MAPISTORE_ERR_DATABASE_OPS, NULL);
	return MAPISTORE_SUCCESS;
}

static bool disconnect_failed_transaction(MYSQL *conn)
{
	my_bool reconnect = false;
	uint64_t id;
	char sql[64];

	/* Never reconnect while identifying the session whose cleanup failed. */
	if (mysql_options(conn, MYSQL_OPT_RECONNECT, &reconnect) ||
	    select_first_uint(conn, "SELECT CONNECTION_ID()", &id) != MYSQL_SUCCESS) {
		return false;
	}
	/* Keep borrowed MYSQL pointers valid; terminate only their server session. */
	snprintf(sql, sizeof(sql), "KILL CONNECTION %"PRIu64, id);
	return mysql_query(conn, sql) == 0;
}

static enum mapistore_error transaction_start(struct namedprops_context *self)
{
	uint64_t locked;
	my_bool reconnect = false;
	enum MYSQLRESULT ret;

	MAPISTORE_RETVAL_IF(!self || !self->data, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	/* A pooled connection must not enter a second transaction recursively. */
	ret = select_first_uint(self->data,
		"SELECT COALESCE(IS_USED_LOCK("NAMEDPROPS_LOCK")=CONNECTION_ID(),0)", &locked);
	MAPISTORE_RETVAL_IF(ret != MYSQL_SUCCESS || locked, MAPISTORE_ERR_DATABASE_OPS, NULL);
	MAPISTORE_RETVAL_IF(mysql_options(self->data, MYSQL_OPT_RECONNECT, &reconnect),
		MAPISTORE_ERR_DATABASE_OPS, NULL);
	ret = select_first_uint(self->data, "SELECT GET_LOCK("NAMEDPROPS_LOCK",5)", &locked);
	if (ret != MYSQL_SUCCESS || locked != 1) {
		/* A result-read failure may occur after the server acquired the lock. */
		if (ret != MYSQL_SUCCESS) goto unlock;
		goto error;
	}
	if (mysql_query(self->data, "START TRANSACTION") != 0) goto unlock;
	return MAPISTORE_SUCCESS;
unlock:
	if (transaction_unlock(self) != MAPISTORE_SUCCESS) {
		OC_DEBUG(0, "Named-property start cleanup failed (error %u, SQLSTATE %.5s)",
			mysql_errno(self->data), mysql_sqlstate(self->data));
		if (disconnect_failed_transaction(self->data)) {
			OC_DEBUG(0, "Terminated failed named-property SQL session; retry can reconnect");
		} else {
			OC_DEBUG(0, "Cannot terminate failed named-property SQL session; "
				"a surviving session retains its lock and requires connection recovery");
		}
	}
error:
	reconnect = true;
	if (mysql_options(self->data, MYSQL_OPT_RECONNECT, &reconnect)) {
		OC_DEBUG(0, "Cannot restore named-property SQL reconnect policy after failed start");
	}
	MAPISTORE_RETVAL_ERR(MAPISTORE_ERR_DATABASE_OPS, NULL);
}

static enum mapistore_error transaction_commit(struct namedprops_context *self)
{
	MAPISTORE_RETVAL_IF(!self || !self->data, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	MAPISTORE_RETVAL_IF(mysql_query(self->data, "COMMIT"), MAPISTORE_ERR_DATABASE_OPS, NULL);
	return transaction_unlock(self);
}

static enum mapistore_error transaction_cancel(struct namedprops_context *self)
{
	my_bool reconnect = true;
	MAPISTORE_RETVAL_IF(!self || !self->data, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	if (mysql_query(self->data, "ROLLBACK") != 0) {
		OC_DEBUG(0, "Named-property rollback failed (error %u, SQLSTATE %.5s)",
			mysql_errno(self->data), mysql_sqlstate(self->data));
		if (disconnect_failed_transaction(self->data)) {
			OC_DEBUG(0, "Terminated failed named-property SQL session; retry can reconnect");
		} else {
			OC_DEBUG(0, "Cannot terminate failed named-property SQL session; "
				"a surviving session retains its lock and requires connection recovery");
		}
		mysql_options(self->data, MYSQL_OPT_RECONNECT, &reconnect);
		MAPISTORE_RETVAL_ERR(MAPISTORE_ERR_DATABASE_OPS, NULL);
	}
	return transaction_unlock(self);
}


static int mapistore_namedprops_mysql_destructor(struct namedprops_context *self)
{
	OC_DEBUG(5, "Destroying namedprops mysql context\n");
	if (self && self->data) {
		MYSQL *conn = self->data;
		release_connection(conn);
	} else {
		OC_DEBUG(0, "Error: tried to destroy corrupted namedprops mysql context\n");
	}
	return 0;
}

/**
   \details Retrieve MySQL backend parametric options from
   configuration file and store them into a data structure.

   \param lp_ctx Pointer to the loadparm context
   \param p pointer to the structure with individual
   parameters to return

   \return MAPISTORE_SUCCES on success, otherwise MAPISTORE error
 */
enum mapistore_error mapistore_namedprops_mysql_parameters(struct loadparm_context *lp_ctx,
							   struct namedprops_mysql_params *p)
{
	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!lp_ctx, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	MAPISTORE_RETVAL_IF(!p, MAPISTORE_ERR_INVALID_PARAMETER, NULL);

	/* Retrieve parametric options */
	p->data = lpcfg_parm_string(lp_ctx, NULL, "namedproperties", "mysql_data");
	p->sock = lpcfg_parm_string(lp_ctx, NULL, "namedproperties", "mysql_sock");
	p->user = lpcfg_parm_string(lp_ctx, NULL, "namedproperties", "mysql_user");
	p->pass = lpcfg_parm_string(lp_ctx, NULL, "namedproperties", "mysql_pass");
	p->host = lpcfg_parm_string(lp_ctx, NULL, "namedproperties", "mysql_host");
	p->port = lpcfg_parm_int(lp_ctx, NULL, "namedproperties", "mysql_port", 3306);
	p->db = lpcfg_parm_string(lp_ctx, NULL, "namedproperties", "mysql_db");

	/* Enforce the logic */
	MAPISTORE_RETVAL_IF(!p->user, MAPISTORE_ERR_BACKEND_INIT, NULL);
	MAPISTORE_RETVAL_IF(!p->db, MAPISTORE_ERR_BACKEND_INIT, NULL);
	MAPISTORE_RETVAL_IF(!p->host && !p->sock, MAPISTORE_ERR_BACKEND_INIT, NULL);

	return MAPISTORE_SUCCESS;
}

static char *connection_string_from_parameters(TALLOC_CTX *mem_ctx, struct namedprops_mysql_params *parms)
{
	char *connection_string;

	connection_string = talloc_asprintf(mem_ctx, "mysql://%s", parms->user);
	if (!connection_string) return NULL;
	if (parms->pass && parms->pass[0]) {
		connection_string = talloc_asprintf_append(connection_string, ":%s", parms->pass);
		if (!connection_string) return NULL;
	}
	connection_string = talloc_asprintf_append(connection_string, "@%s", parms->host);
	if (!connection_string) return NULL;
	if (parms->port) {
		connection_string = talloc_asprintf_append(connection_string, ":%d", parms->port);
		if (!connection_string) return NULL;
	}
	return talloc_asprintf_append(connection_string, "/%s", parms->db);
}

static enum mapistore_error validate_namedprops_schema(MYSQL *conn)
{
	uint64_t version;

	if (select_first_uint(conn,
		"SELECT MAX(version) FROM migrations WHERE app='named_properties'",
		&version) != MYSQL_SUCCESS || version != 3) {
		OC_DEBUG(0, "Named-property SQL schema requires migration version 3; "
			"follow the named-property upgrade procedure before retrying");
		return MAPISTORE_ERR_DATABASE_INIT;
	}
	return MAPISTORE_SUCCESS;
}

/**
   \details Initialize mapistore named properties MySQL backend

   \param mem_ctx pointer to the memory context
   \param lp_ctx pointer to the loadparm context
   \param nprops_ctx pointer on pointer to the namedprops context to
   return

   \return MAPISTORE_SUCCESS on success, otherwise MAPISTORE error
 */
enum mapistore_error mapistore_namedprops_mysql_init(TALLOC_CTX *mem_ctx,
						     struct loadparm_context *lp_ctx,
						     struct namedprops_context **nprops_ctx)
{
	enum mapistore_error		retval;
	struct namedprops_context	*nprops = NULL;
	struct namedprops_mysql_params	parms;
	MYSQL				*conn = NULL;
	char				*connection_string = NULL;
	int				schema_created_ret;
	uint64_t			table_count;

	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!nprops_ctx, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	*nprops_ctx = NULL;
	MAPISTORE_RETVAL_IF(!lp_ctx, MAPISTORE_ERR_INVALID_PARAMETER, NULL);

	/* Retrieve smb.conf arguments */
	retval = mapistore_namedprops_mysql_parameters(lp_ctx, &parms);
	if (retval != MAPISTORE_SUCCESS) {
		OC_DEBUG(0, "ERROR: parsing MySQL named properties "
			    "parametric option failed with %s\n",
			    mapistore_errstr(retval));
		MAPISTORE_RETVAL_ERR(retval, NULL);
	}

	/* Establish MySQL connection */
	connection_string = connection_string_from_parameters(mem_ctx, &parms);
	MAPISTORE_RETVAL_IF(!connection_string, MAPISTORE_ERR_NOT_INITIALIZED, NULL);
	if (parms.sock) {
		// FIXME
		OC_DEBUG(0, "Not implemented connect through unix socket to mysql");
		MAPISTORE_RETVAL_ERR(MAPISTORE_ERR_DATABASE_INIT, connection_string);
	} else {
		create_connection(connection_string, &conn);
	}
	MAPISTORE_RETVAL_IF(!conn, MAPISTORE_ERR_NOT_INITIALIZED, connection_string);

	/* Initialize the database */
	if (select_first_uint(conn,
		"SELECT COUNT(*) FROM information_schema.tables WHERE "
		"BINARY table_schema=BINARY DATABASE() AND BINARY table_name='named_properties'",
		&table_count) != MYSQL_SUCCESS) {
		OC_DEBUG(0, "Failed to read named-property SQL table existence");
		MAPISTORE_RETVAL_ERR(MAPISTORE_ERR_DATABASE_INIT, connection_string);
	}
	if (table_count == 0) {
		OC_DEBUG(3, "Creating schema for named_properties on MySQL");
		schema_created_ret = migrate_named_properties_schema(connection_string);
		if (schema_created_ret) {
			OC_DEBUG(1, "Failed named properties schema creation using "
				 "migration framework: %d\n", schema_created_ret);
			MAPISTORE_RETVAL_ERR(MAPISTORE_ERR_DATABASE_INIT, connection_string);
		}
	}

	retval = validate_namedprops_schema(conn);
	MAPISTORE_RETVAL_IF(retval != MAPISTORE_SUCCESS, retval, connection_string);
	talloc_free(connection_string);

	/* Create context */
	nprops = talloc_zero(mem_ctx, struct namedprops_context);
	MAPISTORE_RETVAL_IF(!nprops, MAPISTORE_ERR_NO_MEMORY, NULL);

	nprops->backend_type = NAMEDPROPS_BACKEND_MYSQL;

	nprops->create_id = create_id;
	nprops->get_mapped_id = get_mapped_id;
	nprops->get_nameid = get_nameid;
	nprops->get_nameid_type = get_nameid_type;
	nprops->next_unused_id = next_unused_id;
	nprops->transaction_commit = transaction_commit;
	nprops->transaction_cancel = transaction_cancel;
	nprops->transaction_start = transaction_start;

	nprops->data = conn;
	talloc_set_destructor(nprops, mapistore_namedprops_mysql_destructor);

	*nprops_ctx = nprops;
	return MAPISTORE_SUCCESS;
}
