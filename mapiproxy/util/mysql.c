/*
   MySQL util functions

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

#include "mysql.h"
#include <sys/stat.h>

#include <time.h>
#include "ccan/htable/htable.h"
#include "ccan/hash/hash.h"
#include "libmapi/mapicode.h"
#include "libmapi/libmapi.h"
#include "libmapi/libmapi_private.h"


/* Items stored on ht table */
struct conn_v {
	MYSQL		*conn;
	const char	*connection_string;
};

/* Rehash function for ht table */
static size_t _ht_rehash(const void *e, void *unused)
{
	return hash_string(((struct conn_v *)e)->connection_string);
}

/* Comparison function to get items from ht table */
static bool _ht_cmp(const void *e, void *string)
{
	return strcmp(((struct conn_v *)e)->connection_string, (const char *)string) == 0;
}

/* This is a dictionary [connection_string] -> [MYSQL *] (actually struct conn_v) */
static struct htable ht = HTABLE_INITIALIZER(ht, _ht_rehash, NULL);


static float timespec_diff_in_seconds(struct timespec *end, struct timespec *start)
{
	return ((float)((end->tv_sec * 1000000000 + end->tv_nsec) -
			(start->tv_sec * 1000000000 + start->tv_nsec)))
		/ 1000000000;
}

/**
    \details Close and delete all mysql connections already open
 */
void close_all_connections(void)
{
	struct htable_iter i;
	struct conn_v *entry, *next;
	entry = htable_first(&ht, &i);
	while (entry) {
		next = htable_next(&ht, &i);
		OC_DEBUG(3, "Closing pooled MySQL connection");
		mysql_close(entry->conn);
		talloc_free(entry);
		entry = next;
	}
	htable_clear(&ht);
}

/**
   \details Parse mysql connection string with format like:
		mysql://user[:pass]@host[:port]/database

   \param mem_ctx pointer to the memory context
   \param connection_string pointer to conenction string
   \param host out parameter to store host into
   \param port out parameter to store connection port - optional
   \param user out parameter to store user name into
   \param passwd out parameter to store password into - optional
   \param db out parameter to store database name into

   \return true on success, false if invalid connection string
 */
static bool parse_connection_string(TALLOC_CTX *mem_ctx,
				    const char *connection_string,
				    char **host, int *port, char **user,
				    char **passwd, char **db)
{
	const char	*user_p, *pass_p, *host_p, *port_p, *db_p;
	TALLOC_CTX *tmp;
	char *parsed_user, *parsed_passwd = NULL, *parsed_host, *parsed_db;
	size_t i;
	size_t		user_len, pass_len, host_len, port_len;
	uint64_t	port_number;

	/* Sanity check on input parameters */
	if (!host || !port || !user || !passwd || !db) return false;
	*host = *user = *passwd = *db = NULL;
	*port = 0;
	if (!connection_string || !connection_string[0]) return false;

	/* check for prefix - len(mysql://) = 8 */
	if (strncasecmp(connection_string, "mysql://", 8)) {
		return false;
	}

	/* skip prefix */
	user_p = connection_string + 8;
	/* find out host offset */
	host_p = strchr(user_p, '@');
	if (!host_p) {
		return false;
	}
	host_p++;
	/* find out db name offset */
	db_p = strchr(host_p, '/');
	if (!db_p) {
		return false;
	}
	db_p++;

	if (!db_p[0]) {
		/* empty database name */
		return false;
	}

	/* check for password - it is optional */
	pass_p = strchr(user_p, ':');
	if (pass_p) {
		pass_p++;
		if (pass_p > host_p) {
			/* : found after host offset! no password */
			user_len = host_p - user_p - 1;
			pass_len = 0;
			pass_p = NULL;
		} else if (pass_p == user_p) {
			/* username is empty */
			return false;
		} else {
			user_len = pass_p - user_p - 1;
			pass_len = host_p  - pass_p - 1;
		}
	} else {
		user_len = host_p - user_p - 1;
		pass_len = 0;
	}

	if (!user_len) {
		/* username is empty */
		return false;
	}

	/* check for port - it is optional */
	port_p = strchr(host_p, ':');
	if (port_p) {
		port_p++;
		if (port_p > db_p) {
			/* : found after db offset and db cannot have ':' */
			return false;
		}
		if (port_p == host_p) {
			/* host is empty */
			return false;
		}
		host_len = port_p - host_p -1;
		port_len = db_p - port_p - 1;
	} else {
		host_len = db_p - host_p - 1;
		port_len = 0;
	}

	if (!host_len) {
		/* no hostname in connection string */
		return false;
	}

	port_number = 0;
	if (port_p != NULL && port_len == 0) return false;
	for (i = 0; i < port_len; i++) {
		if (port_p[i] < '0' || port_p[i] > '9') return false;
		port_number = port_number * 10 + (port_p[i] - '0');
		if (port_number > UINT16_MAX) return false;
	}
	tmp = talloc_new(mem_ctx);
	if (tmp == NULL) return false;
	parsed_user = talloc_strndup(tmp, user_p, user_len);
	if (pass_p != NULL) parsed_passwd = talloc_strndup(tmp, pass_p, pass_len);
	parsed_host = talloc_strndup(tmp, host_p, host_len);
	parsed_db = talloc_strdup(tmp, db_p);
	if (parsed_user == NULL || parsed_host == NULL || parsed_db == NULL ||
	    (pass_p != NULL && parsed_passwd == NULL)) {
		talloc_free(tmp);
		return false;
	}
	*user = talloc_steal(mem_ctx, parsed_user);
	*passwd = talloc_steal(mem_ctx, parsed_passwd);
	*host = talloc_steal(mem_ctx, parsed_host);
	*db = talloc_steal(mem_ctx, parsed_db);
	*port = port_number;
	talloc_free(tmp);

	return true;
}


static char *mysql_quote_dbname(TALLOC_CTX *ctx, const char *name)
{
	size_t length = strlen(name), i, used = 0;
	char *quoted;
	if (length > (SIZE_MAX - 3) / 2) return NULL;
	quoted = talloc_array(ctx, char, 2 * length + 3);
	if (quoted == NULL) return NULL;
	quoted[used++] = '`';
	for (i = 0; i < length; i++) {
		if (name[i] == '`') quoted[used++] = '`';
		quoted[used++] = name[i];
	}
	quoted[used++] = '`';
	quoted[used] = '\0';
	return quoted;
}

MYSQL *create_connection(const char *connection_string, MYSQL **conn)
{
	TALLOC_CTX *mem_ctx;
	my_bool reconnect = true;
	char *host, *user, *passwd, *db, *quoted, *sql;
	int port;
	struct conn_v *entry = NULL, *cached;
	MYSQL *candidate = NULL;

	if (conn == NULL) return NULL;
	*conn = NULL;
	if (connection_string == NULL || connection_string[0] == '\0') return NULL;
	cached = htable_get(&ht, hash_string(connection_string), _ht_cmp, connection_string);
	if (cached) {
		OC_DEBUG(5, "[MYSQL] Reusing pooled connection");
		*conn = cached->conn;
		return *conn;
	}
	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) return NULL;
	if (!parse_connection_string(mem_ctx, connection_string, &host, &port, &user, &passwd, &db)) {
		OC_DEBUG(1, "[MYSQL] Invalid connection string");
		goto end;
	}
	candidate = mysql_init(NULL);
	if (candidate == NULL) goto end;
	if (mysql_options(candidate, MYSQL_OPT_RECONNECT, &reconnect))
		OC_DEBUG(1, "[MYSQL] Cannot set MYSQL_OPT_RECONNECT option");
	/* Legacy literal escaping requires UTF-8 and backslash escapes on every reconnect. */
	if (mysql_options(candidate, MYSQL_SET_CHARSET_NAME, "utf8mb4") ||
	    mysql_options(candidate, MYSQL_INIT_COMMAND,
		"SET SESSION sql_mode=TRIM(BOTH ',' FROM REPLACE(CONCAT(',',@@SESSION.sql_mode,','),"
		"',NO_BACKSLASH_ESCAPES,',','))")) {
		OC_DEBUG(1, "[MYSQL] Cannot configure SQL string encoding");
		goto end;
	}

	if (!mysql_real_connect(candidate, host, user, passwd, NULL, port, NULL, 0)) {
		OC_DEBUG(1, "[MYSQL] Cannot connect: %s", mysql_error(candidate));
		goto end;
	}
	if (mysql_select_db(candidate, db) != 0) {
		quoted = mysql_quote_dbname(mem_ctx, db);
		if (quoted == NULL) goto end;
		sql = talloc_asprintf(mem_ctx, "CREATE DATABASE %s", quoted);
		if (sql == NULL) goto end;
		if (mysql_query(candidate, sql) != 0 || mysql_select_db(candidate, db) != 0) {
			OC_DEBUG(1, "[MYSQL] Cannot create/select database: %s", mysql_error(candidate));
			goto end;
		}
	}
	entry = talloc_zero(talloc_autofree_context(), struct conn_v);
	if (entry == NULL) goto end;
	entry->connection_string = talloc_strdup(entry, connection_string);
	if (entry->connection_string == NULL) goto end;
	entry->conn = candidate;
	if (!htable_add(&ht, hash_string(connection_string), entry)) {
		OC_DEBUG(1, "[MYSQL] Cannot add connection to pool");
		goto end;
	}
	*conn = candidate;
	candidate = NULL;
	entry = NULL;
	OC_DEBUG(5, "[MYSQL] Connection added to pool");
end:
	if (candidate) mysql_close(candidate);
	talloc_free(entry);
	talloc_free(mem_ctx);
	return *conn;
}

void release_connection(MYSQL *conn)
{
	// Do nothing
}

enum MYSQLRESULT execute_query(MYSQL *conn, const char *sql)
{
	struct timespec start, end;
	float seconds_spent;

	if (conn == NULL || sql == NULL) return MYSQL_ERROR;

	clock_gettime(CLOCK_MONOTONIC, &start);
	if (mysql_query(conn, sql) != 0) {
		OC_DEBUG(3, "Error on query `%s`: %s", sql, mysql_error(conn));
		return MYSQL_ERROR;
	}
	clock_gettime(CLOCK_MONOTONIC, &end);

	seconds_spent = timespec_diff_in_seconds(&end, &start);
	if (seconds_spent > THRESHOLD_SLOW_QUERIES) {
		printf("MySQL slow query!\n"
		       "\tQuery: `%s`\n\tTime: %.3f\n", sql, seconds_spent);
		OC_DEBUG(5, "MySQL slow query!"
			  "\tQuery: `%s`\n\tTime: %.3f\n", sql, seconds_spent);
	}
	return MYSQL_SUCCESS;
}


enum MYSQLRESULT select_without_fetch(MYSQL *conn, const char *sql,
					    MYSQL_RES **res)
{
	enum MYSQLRESULT ret;

	if (res == NULL) {
		OC_DEBUG(0, "Bad parameters when calling select_without_fetch");
		return MYSQL_ERROR;
	}

	ret = execute_query(conn, sql);
	if (ret != MYSQL_SUCCESS) {
		*res = NULL;
		return ret;
	}

	*res = mysql_store_result(conn);
	if (*res == NULL) {
		OC_DEBUG(0, "Error getting results of `%s`: %s", sql,
			  mysql_error(conn));
		return MYSQL_ERROR;
	}

	if (mysql_num_rows(*res) == 0) {
		mysql_free_result(*res);
		*res = NULL;
		return MYSQL_NOT_FOUND;
	}

	return MYSQL_SUCCESS;
}


enum MYSQLRESULT select_all_strings(TALLOC_CTX *mem_ctx, MYSQL *conn,
				   const char *sql,
				   struct StringArrayW_r **_results)
{
	MYSQL_RES *res;
	struct StringArrayW_r *results;
	uint32_t i, num_rows = 0;
	enum MYSQLRESULT ret;

	ret = select_without_fetch(conn, sql, &res);
	if (ret == MYSQL_NOT_FOUND) {
		results = talloc_zero(mem_ctx, struct StringArrayW_r);
		results->cValues = 0;
	} else if (ret == MYSQL_SUCCESS) {
		results = talloc_zero(mem_ctx, struct StringArrayW_r);
		num_rows = mysql_num_rows(res);
		results->cValues = num_rows;
		if (results->cValues == 1) {
			results->cValues  = mysql_field_count(conn) - 1;
		}
	} else {
		// Unexpected error on sql query
		return ret;
	}

	results->lppszW = talloc_zero_array(results, const char *,
					    results->cValues);
	if (num_rows == 1 && results->cValues != 1) {
		// Getting 1 row with n strings
		MYSQL_ROW row = mysql_fetch_row(res);
		for (i = 0; i < results->cValues; i++) {
			results->lppszW[i] = talloc_strdup(results, row[i+1]);
		}
	} else {
		// Getting n rows with 1 string
		for (i = 0; i < results->cValues; i++) {
			MYSQL_ROW row = mysql_fetch_row(res);
			if (row == NULL) {
				OC_DEBUG(0, "Error getting row %d of `%s`: %s", i, sql,
					  mysql_error(conn));
				mysql_free_result(res);
				return MYSQL_ERROR;
			}
			results->lppszW[i] = talloc_strdup(results, row[0]);
		}
	}

	if (ret == MYSQL_SUCCESS) {
		mysql_free_result(res);
	}
	*_results = results;

	return MYSQL_SUCCESS;
}


enum MYSQLRESULT select_first_string(TALLOC_CTX *mem_ctx, MYSQL *conn,
				    const char *sql, const char **s)
{
	MYSQL_RES *res;
	enum MYSQLRESULT ret;

	ret = select_without_fetch(conn, sql, &res);
	if (ret != MYSQL_SUCCESS) {
		return ret;
	}

	MYSQL_ROW row = mysql_fetch_row(res);
	if (row == NULL) {
		OC_DEBUG(0, "Error getting row of `%s`: %s", sql,
			  mysql_error(conn));
		return MYSQL_ERROR;
	}

	*s = talloc_strdup(mem_ctx, row[0]);
	mysql_free_result(res);

	return MYSQL_SUCCESS;
}


enum MYSQLRESULT select_first_uint(MYSQL *conn, const char *sql,
				  uint64_t *n)
{
	TALLOC_CTX *mem_ctx = talloc_named(NULL, 0, "select_first_uint");
	const char *result;
	enum MYSQLRESULT ret;

	ret = select_first_string(mem_ctx, conn, sql, &result);
	if (ret != MYSQL_SUCCESS) {
		talloc_free(mem_ctx);
		return ret;
	}

	ret = MYSQL_ERROR;
	if (convert_string_to_ull(result, n)) {
		ret = MYSQL_SUCCESS;
	}

	talloc_free(mem_ctx);

	return ret;
}


bool table_exists(MYSQL *conn, char *table_name)
{
	MYSQL_RES *res;
	bool created;

	res = mysql_list_tables(conn, table_name);
	if (res == NULL) return false;
	created = mysql_num_rows(res) == 1;
	mysql_free_result(res);

	return created;
}

/**
   \details Create the existing sql schema in filename

   \param conn pointer to the MySQL connection
   \param filename path to the schema file

   \fixme find a better approach than allocating buffer of the file size

   \return bool indicating success
 */
bool create_schema(MYSQL *conn, const char *filename)
{
	TALLOC_CTX	*mem_ctx = NULL;
	struct stat	sb;
	FILE		*f = NULL;
	int		ret;
	int		len;
	char		*query, *schema;
	bool		queries_to_execute;
	bool		schema_created = false;

	/* Sanity checks */
	if (!conn || !filename) return false;

	mem_ctx = talloc_named(NULL, 0, "create_schema");
	if (!mem_ctx) goto end;

	ret = stat(filename, &sb);
	if (ret == -1 || sb.st_size == 0) goto end;

	schema = talloc_zero_array(mem_ctx, char, sb.st_size + 1);
	if (!schema) goto end;

	f = fopen(filename, "r");
	if (!f) goto end;

	len = fread(schema, sizeof(char), sb.st_size, f);
	if (len != sb.st_size) goto end;

	query = strtok(schema, ";");
	queries_to_execute = query != NULL;
	while (queries_to_execute) {
		ret = mysql_query(conn, query);
		if (ret) goto end;
		query = strtok(NULL, ";");
		queries_to_execute = query && strlen(query) > 10;
	}
	schema_created = true;
end:
	if (mem_ctx) talloc_free(mem_ctx);
	if (f) fclose(f);

	return schema_created;
}

const char* _sql_escape(TALLOC_CTX *mem_ctx, const char *s, char c)
{
	size_t len, c_count, i, j;
	char *ret;

	if (!s) return "";

	len = strlen(s);
	c_count = 0;
	for (i = 0; i < len; i++) {
		if (s[i] == c || s[i] == '\\') c_count++;
	}

	if (c_count == 0) return s;

	if (c_count > SIZE_MAX - len - 1) return NULL;
	ret = talloc_zero_size(mem_ctx, len + c_count + 1);
	if (ret == NULL) return NULL;
	for (i = 0, j = 0; i < len; i++) {
		if (s[i] == c || s[i] == '\\') ret[i + j++] = '\\';
		ret[i + j] = s[i];
	}

	return ret;
}

// FIXME use this function instead of strtoull(*, NULL, *) in openchangedb_mysql.c
bool convert_string_to_ull(const char *str, uint64_t *ret)
{
	bool retval = false;
	char *aux = NULL;

	if (ret != NULL && str != NULL) {
		*ret = strtoull(str, &aux, 10);
		if (aux != NULL && *aux == '\0') {
			retval = true;
		} else {
			OC_DEBUG(1, "ERROR converting %s into ull", str);
		}
	}

	return retval;
}
