/*
   CardDAV mapistore backend: field fingerprints of the version Outlook and SOGo last agreed on

   Only keyed hashes and the ETag are stored, never contact data: in the indexing MySQL
   database when there is one (table dav_fingerprints), else in process memory.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <string.h>
#include <stdlib.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "mapiproxy/util/mysql.h"
#include "utils/dlinklist.h"
#include "dav_fpstore.h"

#define FP_TABLE "dav_fingerprints"
#define FP_BYTES (DAV_F_COUNT * 8)

struct fp_row {
	struct fp_row	*prev, *next;
	char		*user, *href, *etag;
	uint64_t	fp[DAV_F_COUNT];
};

struct dav_fpstore {
	MYSQL		*conn;		/* NULL: rows in memory */
	struct fp_row	*rows;
};

uint64_t dav_fp(const uint8_t *key, size_t key_len, enum dav_field f, const char *value)
{
	size_t		len = value ? strlen(value) : 0;
	uint8_t		*msg = malloc(len + 2), digest[32];
	uint64_t	fp = 0;
	int		i;

	if (!msg) return 0;
	msg[0] = (uint8_t) f;
	msg[1] = value ? 0x00 : 0x01;
	if (len) memcpy(msg + 2, value, len);
	if (gnutls_hmac_fast(GNUTLS_MAC_SHA256, key, key_len, msg, len + 2, digest) == 0) {
		for (i = 0; i < 8; i++) fp = (fp << 8) | digest[i];
	}
	explicit_bzero(msg, len + 2);
	free(msg);
	return fp;
}

static const char *create_table_sql =
	"CREATE TABLE IF NOT EXISTS " FP_TABLE " (user VARCHAR(320), href VARCHAR(1024), etag VARCHAR(255), fp BLOB, "
	"PRIMARY KEY(user, href(255))) CHARSET utf8mb4 COLLATE utf8mb4_bin";

struct dav_fpstore *dav_fpstore_open(TALLOC_CTX *mem_ctx, const char *indexing_url)
{
	struct dav_fpstore *s = talloc_zero(mem_ctx, struct dav_fpstore);

	if (!s || !indexing_url || strncmp(indexing_url, "mysql://", 8) != 0) {
		return s;
	}
	if (!create_connection(indexing_url, &s->conn) || execute_query(s->conn, create_table_sql) != MYSQL_SUCCESS) {
		/* The URL may carry a password: not logged. */
		OC_DEBUG(0, "DAV backend: fingerprint table unavailable; fingerprints kept in memory\n");
		s->conn = NULL;
	}
	return s;
}

static struct fp_row *row_find(struct dav_fpstore *s, const char *user, const char *href)
{
	struct fp_row *r;

	for (r = s->rows; r && (strcmp(r->user, user) || strcmp(r->href, href)); r = r->next);
	return r;
}

static bool parse_hex(const char *hex, uint64_t fp[DAV_F_COUNT])
{
	int i, j, v;

	if (!hex || strlen(hex) != FP_BYTES * 2) return false;
	for (i = 0; i < DAV_F_COUNT; i++) {
		fp[i] = 0;
		for (j = 0; j < 16; j++) {
			char c = hex[i * 16 + j];
			v = c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
			if (v < 0) return false;
			fp[i] = (fp[i] << 4) | v;
		}
	}
	return true;
}

enum mapistore_error dav_fp_get(struct dav_fpstore *s, TALLOC_CTX *mem_ctx, const char *user, const char *href,
				uint64_t fp[DAV_F_COUNT], char **etag)
{
	TALLOC_CTX		*tmp;
	const char		*eu, *eh;
	char			*sql;
	MYSQL_RES		*res = NULL;
	MYSQL_ROW		row;
	enum mapistore_error	ret = MAPISTORE_ERR_NOT_FOUND;
	struct fp_row		*r;

	if (!s || !user || !href || !etag) return MAPISTORE_ERR_INVALID_PARAMETER;
	*etag = NULL;
	if (!s->conn) {
		if (!(r = row_find(s, user, href))) return MAPISTORE_ERR_NOT_FOUND;
		memcpy(fp, r->fp, sizeof r->fp);
		*etag = talloc_strdup(mem_ctx, r->etag);
		return *etag ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
	}
	tmp = talloc_new(NULL);
	eu = tmp ? _sql(tmp, user) : NULL;
	eh = tmp ? _sql(tmp, href) : NULL;
	sql = eu && eh ? talloc_asprintf(tmp, "SELECT etag, HEX(fp) FROM " FP_TABLE " WHERE user = '%s' AND href = '%s'", eu, eh) : NULL;
	if (!sql) {
		talloc_free(tmp);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	switch (select_without_fetch(s->conn, sql, &res)) {
	case MYSQL_SUCCESS:
		row = mysql_fetch_row(res);
		if (row && row[0] && parse_hex(row[1], fp)) {
			*etag = talloc_strdup(mem_ctx, row[0]);
			ret = *etag ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
		}
		mysql_free_result(res);
		break;
	case MYSQL_NOT_FOUND:
		break;
	default:
		ret = MAPISTORE_ERR_DATABASE_OPS;
	}
	talloc_free(tmp);
	return ret;
}

enum mapistore_error dav_fp_put(struct dav_fpstore *s, const char *user, const char *href,
				const uint64_t fp[DAV_F_COUNT], const char *etag)
{
	TALLOC_CTX		*tmp;
	const char		*eu, *eh, *ee;
	char			*sql;
	struct fp_row		*r;
	enum mapistore_error	ret;
	int			i;

	if (!s || !user || !href || !etag) return MAPISTORE_ERR_INVALID_PARAMETER;
	if (!s->conn) {
		if (!(r = row_find(s, user, href))) {
			r = talloc_zero(s, struct fp_row);
			if (!r || !(r->user = talloc_strdup(r, user)) || !(r->href = talloc_strdup(r, href))) {
				talloc_free(r);
				return MAPISTORE_ERR_NO_MEMORY;
			}
			DLIST_ADD(s->rows, r);
		}
		talloc_free(r->etag);
		memcpy(r->fp, fp, sizeof r->fp);
		return (r->etag = talloc_strdup(r, etag)) ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
	}
	tmp = talloc_new(NULL);
	eu = tmp ? _sql(tmp, user) : NULL;
	eh = tmp ? _sql(tmp, href) : NULL;
	ee = tmp ? _sql(tmp, etag) : NULL;
	sql = eu && eh && ee ? talloc_asprintf(tmp, "REPLACE INTO " FP_TABLE " (user, href, etag, fp) VALUES ('%s', '%s', '%s', 0x",
					       eu, eh, ee) : NULL;
	for (i = 0; sql && i < DAV_F_COUNT; i++) {
		sql = talloc_asprintf_append_buffer(sql, "%016llX", (unsigned long long) fp[i]);
	}
	sql = sql ? talloc_strdup_append_buffer(sql, ")") : NULL;
	ret = !sql ? MAPISTORE_ERR_NO_MEMORY : execute_query(s->conn, sql) == MYSQL_SUCCESS ? MAPISTORE_SUCCESS : MAPISTORE_ERR_DATABASE_OPS;
	talloc_free(tmp);
	return ret;
}

enum mapistore_error dav_fp_delete(struct dav_fpstore *s, const char *user, const char *href)
{
	TALLOC_CTX		*tmp;
	const char		*eu, *eh;
	char			*sql;
	struct fp_row		*r;
	enum mapistore_error	ret;

	if (!s || !user || !href) return MAPISTORE_ERR_INVALID_PARAMETER;
	if (!s->conn) {
		if ((r = row_find(s, user, href))) {
			DLIST_REMOVE(s->rows, r);
			talloc_free(r);
		}
		return MAPISTORE_SUCCESS;
	}
	tmp = talloc_new(NULL);
	eu = tmp ? _sql(tmp, user) : NULL;
	eh = tmp ? _sql(tmp, href) : NULL;
	sql = eu && eh ? talloc_asprintf(tmp, "DELETE FROM " FP_TABLE " WHERE user = '%s' AND href = '%s'", eu, eh) : NULL;
	ret = !sql ? MAPISTORE_ERR_NO_MEMORY : execute_query(s->conn, sql) == MYSQL_SUCCESS ? MAPISTORE_SUCCESS : MAPISTORE_ERR_DATABASE_OPS;
	talloc_free(tmp);
	return ret;
}

/* href is a member of book (normalized, no trailing '/') and not one of live. */
static bool is_gone(const char *book, const char *href, char **live, size_t n)
{
	size_t bl = strlen(book), i;

	if (strncmp(href, book, bl) != 0 || href[bl] != '/') return false;
	for (i = 0; i < n; i++) {
		if (strcmp(live[i], href) == 0) return false;
	}
	return true;
}

enum mapistore_error dav_fp_prune(struct dav_fpstore *s, const char *user, const char *book_href, char **live, size_t n,
				  TALLOC_CTX *mem_ctx, char ***gonep, size_t *ngonep)
{
	TALLOC_CTX		*tmp;
	const char		*eu;
	char			*sql, **gone;
	MYSQL_RES		*res = NULL;
	MYSQL_ROW		row;
	struct fp_row		*r;
	size_t			k = 0, i;
	enum mapistore_error	ret = MAPISTORE_SUCCESS;

	if (!s || !user || !book_href || !gonep || !ngonep) return MAPISTORE_ERR_INVALID_PARAMETER;
	*gonep = NULL;
	*ngonep = 0;
	gone = talloc_array(mem_ctx, char *, 1);
	if (!gone) return MAPISTORE_ERR_NO_MEMORY;
	if (!s->conn) {
		for (r = s->rows; r; r = r->next) {
			if (strcmp(r->user, user) || !is_gone(book_href, r->href, live, n)) continue;
			gone = talloc_realloc(mem_ctx, gone, char *, k + 1);
			if (!gone || !(gone[k++] = talloc_strdup(gone, r->href))) return MAPISTORE_ERR_NO_MEMORY;
		}
		for (i = 0; i < k; i++) dav_fp_delete(s, user, gone[i]);
		*gonep = gone;
		*ngonep = k;
		return MAPISTORE_SUCCESS;
	}
	tmp = talloc_new(NULL);
	eu = tmp ? _sql(tmp, user) : NULL;
	sql = eu ? talloc_asprintf(tmp, "SELECT href FROM " FP_TABLE " WHERE user = '%s'", eu) : NULL;
	if (!sql) {
		talloc_free(tmp);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	switch (select_without_fetch(s->conn, sql, &res)) {
	case MYSQL_SUCCESS:
		while ((row = mysql_fetch_row(res))) {
			if (!row[0] || !is_gone(book_href, row[0], live, n)) continue;
			gone = talloc_realloc(mem_ctx, gone, char *, k + 1);
			if (!gone || !(gone[k++] = talloc_strdup(gone, row[0]))) {
				ret = MAPISTORE_ERR_NO_MEMORY;
				break;
			}
		}
		mysql_free_result(res);
		break;
	case MYSQL_NOT_FOUND:
		break;
	default:
		ret = MAPISTORE_ERR_DATABASE_OPS;
	}
	talloc_free(tmp);
	for (i = 0; ret == MAPISTORE_SUCCESS && i < k; i++) {
		ret = dav_fp_delete(s, user, gone[i]);
	}
	if (ret != MAPISTORE_SUCCESS) {
		talloc_free(gone);
		return ret;
	}
	*gonep = gone;
	*ngonep = k;
	return MAPISTORE_SUCCESS;
}
