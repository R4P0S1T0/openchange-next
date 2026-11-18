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
#include <stdio.h>
#include <sys/time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "mapiproxy/util/mysql.h"
#include "utils/dlinklist.h"
#include "dav_fpstore.h"

#define FP_TABLE "dav_fingerprints"
#define FP_VERSIONS_TABLE "dav_fingerprint_versions"
#define FP_BYTES (DAV_F_COUNT * 8)

struct fp_row {
	struct fp_row	*prev, *next;
	char		*user, *href, *etag;
	uint64_t	fp[DAV_F_COUNT];
};

struct fp_version {
	struct fp_version	*prev, *next;	/* newest first */
	char			*user, *href, *etag;
	struct Binary_r		*ck;
	uint64_t		fp[DAV_F_COUNT];
};

struct dav_fpstore {
	MYSQL			*conn;		/* NULL: rows in memory */
	struct fp_row		*rows;
	struct fp_version	*versions;
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

static const char *create_versions_sql =
	"CREATE TABLE IF NOT EXISTS " FP_VERSIONS_TABLE " (user VARCHAR(320), href VARCHAR(1024), ck VARBINARY(64), seq BIGINT, "
	"etag VARCHAR(255), fp BLOB, PRIMARY KEY(user, href(255), ck)) CHARSET utf8mb4 COLLATE utf8mb4_bin";

struct dav_fpstore *dav_fpstore_open(TALLOC_CTX *mem_ctx, const char *indexing_url)
{
	struct dav_fpstore *s = talloc_zero(mem_ctx, struct dav_fpstore);

	if (!s || !indexing_url || strncmp(indexing_url, "mysql://", 8) != 0) {
		return s;
	}
	if (!create_connection(indexing_url, &s->conn) || execute_query(s->conn, create_table_sql) != MYSQL_SUCCESS ||
	    execute_query(s->conn, create_versions_sql) != MYSQL_SUCCESS) {
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

static int hexval(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* Whether pcl (SizedXids, MS-OXCFXICS 2.2.2.3) lists the XID ck. */
static bool pcl_has(const struct Binary_r *pcl, const uint8_t *ck, size_t len)
{
	uint32_t i = 0, n;

	while (i < pcl->cb && (n = pcl->lpb[i]) && i + 1 + n <= pcl->cb) {
		if (n == len && memcmp(pcl->lpb + i + 1, ck, len) == 0) return true;
		i += 1 + n;
	}
	return false;
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
		if (!(r = row_find(s, user, href)) || !r->etag) return MAPISTORE_ERR_NOT_FOUND;
		memcpy(fp, r->fp, sizeof r->fp);
		*etag = talloc_strdup(mem_ctx, r->etag);
		return *etag ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
	}
	tmp = talloc_new(NULL);
	eu = tmp ? _sql(tmp, user) : NULL;
	eh = tmp ? _sql(tmp, href) : NULL;
	sql = eu && eh ? talloc_asprintf(tmp, "SELECT etag, HEX(fp) FROM " FP_TABLE " WHERE user = '%s' AND href = '%s' AND etag IS NOT NULL", eu, eh) : NULL;
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

	struct fp_version	*v, *next;

	if (!s || !user || !href) return MAPISTORE_ERR_INVALID_PARAMETER;
	if (!s->conn) {
		if ((r = row_find(s, user, href))) {
			DLIST_REMOVE(s->rows, r);
			talloc_free(r);
		}
		for (v = s->versions; v; v = next) {
			next = v->next;
			if (strcmp(v->user, user) || strcmp(v->href, href)) continue;
			DLIST_REMOVE(s->versions, v);
			talloc_free(v);
		}
		return MAPISTORE_SUCCESS;
	}
	tmp = talloc_new(NULL);
	eu = tmp ? _sql(tmp, user) : NULL;
	eh = tmp ? _sql(tmp, href) : NULL;
	sql = eu && eh ? talloc_asprintf(tmp, "DELETE FROM " FP_VERSIONS_TABLE " WHERE user = '%s' AND href = '%s'", eu, eh) : NULL;
	ret = !sql ? MAPISTORE_ERR_NO_MEMORY : execute_query(s->conn, sql) == MYSQL_SUCCESS ? MAPISTORE_SUCCESS : MAPISTORE_ERR_DATABASE_OPS;
	sql = ret == MAPISTORE_SUCCESS ? talloc_asprintf(tmp, "DELETE FROM " FP_TABLE " WHERE user = '%s' AND href = '%s'", eu, eh) : NULL;
	if (ret == MAPISTORE_SUCCESS) {
		ret = !sql ? MAPISTORE_ERR_NO_MEMORY : execute_query(s->conn, sql) == MYSQL_SUCCESS ? MAPISTORE_SUCCESS : MAPISTORE_ERR_DATABASE_OPS;
	}
	talloc_free(tmp);
	return ret;
}

enum { NOT_MEMBER, LIVE, GONE };

/* Where href (normalized) stands for book (normalized, no trailing '/') and its live hrefs. */
static int classify(const char *book, const char *href, char **live, size_t n)
{
	size_t bl = strlen(book), i;

	if (strncmp(href, book, bl) != 0 || href[bl] != '/') return NOT_MEMBER;
	for (i = 0; i < n; i++) {
		if (strcmp(live[i], href) == 0) return LIVE;
	}
	return GONE;
}

static bool href_add(TALLOC_CTX *mem_ctx, char ***list, size_t *k, const char *href)
{
	char **l = talloc_realloc(mem_ctx, *list, char *, *k + 1);

	if (!l) return false;
	*list = l;
	return (l[(*k)++] = talloc_strdup(l, href)) != NULL;
}

/* A gone item's row stays as a tombstone (no ETag) so every client of the user learns the deletion
   (emsmdb drops the ones a client already knows); it goes when the href is listed again. */
static enum mapistore_error tombstone(struct dav_fpstore *s, const char *user, const char *href)
{
	TALLOC_CTX		*tmp = talloc_new(NULL);
	const char		*eu = tmp ? _sql(tmp, user) : NULL, *eh = tmp ? _sql(tmp, href) : NULL;
	char			*sql = eu && eh ? talloc_asprintf(tmp, "UPDATE " FP_TABLE " SET etag = NULL WHERE user = '%s' AND href = '%s'", eu, eh) : NULL;
	enum mapistore_error	ret = !sql ? MAPISTORE_ERR_NO_MEMORY : execute_query(s->conn, sql) == MYSQL_SUCCESS ? MAPISTORE_SUCCESS : MAPISTORE_ERR_DATABASE_OPS;

	talloc_free(tmp);
	return ret;
}

enum mapistore_error dav_fp_tombstone(struct dav_fpstore *s, const char *user, const char *href)
{
	struct fp_row *r;

	if (!s || !user || !href) return MAPISTORE_ERR_INVALID_PARAMETER;
	if (!s->conn) {
		if ((r = row_find(s, user, href))) TALLOC_FREE(r->etag);
		return MAPISTORE_SUCCESS;
	}
	return tombstone(s, user, href);
}

static char *hex_of(TALLOC_CTX *mem_ctx, const uint8_t *b, size_t n)
{
	char	*o = talloc_array(mem_ctx, char, 2 * n + 1);
	size_t	i;

	for (i = 0; o && i < n; i++) snprintf(o + 2 * i, 3, "%02X", b[i]);
	if (o) o[2 * n] = '\0';
	return o;
}

enum mapistore_error dav_fp_version_put(struct dav_fpstore *s, const char *user, const char *href, const struct Binary_r *ck,
					const uint64_t fp[DAV_F_COUNT], const char *etag)
{
	static uint64_t		last_seq;
	TALLOC_CTX		*tmp;
	struct fp_version	*v, *next;
	struct timeval		tv;
	const char		*eu, *eh, *ee;
	char			*sql, *k;
	uint64_t		seq;
	unsigned		kept = 0;
	enum mapistore_error	ret;
	int			i;

	if (!s || !user || !href || !ck || !ck->cb || ck->cb > 64 || !etag) return MAPISTORE_ERR_INVALID_PARAMETER;
	if (!s->conn) {
		for (v = s->versions; v; v = next) {
			next = v->next;
			if (strcmp(v->user, user) || strcmp(v->href, href)) continue;
			/* the same version again, or one beyond the kept ones (the list is newest first) */
			if ((v->ck->cb == ck->cb && !memcmp(v->ck->lpb, ck->lpb, ck->cb)) || ++kept >= DAV_FP_VERSIONS) {
				DLIST_REMOVE(s->versions, v);
				talloc_free(v);
			}
		}
		v = talloc_zero(s, struct fp_version);
		if (!v || !(v->user = talloc_strdup(v, user)) || !(v->href = talloc_strdup(v, href)) ||
		    !(v->etag = talloc_strdup(v, etag)) || !(v->ck = talloc_zero(v, struct Binary_r)) ||
		    !(v->ck->lpb = talloc_memdup(v->ck, ck->lpb, ck->cb))) {
			talloc_free(v);
			return MAPISTORE_ERR_NO_MEMORY;
		}
		v->ck->cb = ck->cb;
		memcpy(v->fp, fp, sizeof v->fp);
		DLIST_ADD(s->versions, v);
		return MAPISTORE_SUCCESS;
	}
	/* newest = highest seq: microseconds, strictly increasing in this process */
	gettimeofday(&tv, NULL);
	seq = (uint64_t) tv.tv_sec * 1000000 + tv.tv_usec;
	seq = last_seq = seq > last_seq ? seq : last_seq + 1;
	tmp = talloc_new(NULL);
	eu = tmp ? _sql(tmp, user) : NULL;
	eh = tmp ? _sql(tmp, href) : NULL;
	ee = tmp ? _sql(tmp, etag) : NULL;
	k = tmp ? hex_of(tmp, ck->lpb, ck->cb) : NULL;
	sql = eu && eh && ee && k ? talloc_asprintf(tmp, "REPLACE INTO " FP_VERSIONS_TABLE " (user, href, ck, seq, etag, fp) VALUES "
						     "('%s', '%s', 0x%s, %llu, '%s', 0x", eu, eh, k, (unsigned long long) seq, ee) : NULL;
	for (i = 0; sql && i < DAV_F_COUNT; i++) sql = talloc_asprintf_append_buffer(sql, "%016llX", (unsigned long long) fp[i]);
	sql = sql ? talloc_strdup_append_buffer(sql, ")") : NULL;
	ret = !sql ? MAPISTORE_ERR_NO_MEMORY : execute_query(s->conn, sql) == MYSQL_SUCCESS ? MAPISTORE_SUCCESS : MAPISTORE_ERR_DATABASE_OPS;
	if (ret == MAPISTORE_SUCCESS) {
		sql = talloc_asprintf(tmp, "DELETE FROM " FP_VERSIONS_TABLE " WHERE user = '%s' AND href = '%s' AND seq < (SELECT seq FROM "
				      "(SELECT seq FROM " FP_VERSIONS_TABLE " WHERE user = '%s' AND href = '%s' ORDER BY seq DESC LIMIT 1 OFFSET %d) AS k)",
				      eu, eh, eu, eh, DAV_FP_VERSIONS - 1);
		ret = !sql ? MAPISTORE_ERR_NO_MEMORY : execute_query(s->conn, sql) == MYSQL_SUCCESS ? MAPISTORE_SUCCESS : MAPISTORE_ERR_DATABASE_OPS;
	}
	talloc_free(tmp);
	return ret;
}

enum mapistore_error dav_fp_version_get(struct dav_fpstore *s, TALLOC_CTX *mem_ctx, const char *user, const char *href,
					const struct Binary_r *pcl, uint64_t fp[DAV_F_COUNT], char **etag)
{
	TALLOC_CTX		*tmp;
	struct fp_version	*v;
	const char		*eu, *eh;
	char			*sql;
	MYSQL_RES		*res = NULL;
	MYSQL_ROW		row;
	uint8_t			ck[64];
	size_t			n, i;
	enum mapistore_error	ret = MAPISTORE_ERR_NOT_FOUND;

	if (!s || !user || !href || !pcl || !etag) return MAPISTORE_ERR_INVALID_PARAMETER;
	*etag = NULL;
	if (!s->conn) {
		for (v = s->versions; v; v = v->next) {
			if (strcmp(v->user, user) || strcmp(v->href, href) || !pcl_has(pcl, v->ck->lpb, v->ck->cb)) continue;
			memcpy(fp, v->fp, sizeof v->fp);
			*etag = talloc_strdup(mem_ctx, v->etag);
			return *etag ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
		}
		return MAPISTORE_ERR_NOT_FOUND;
	}
	tmp = talloc_new(NULL);
	eu = tmp ? _sql(tmp, user) : NULL;
	eh = tmp ? _sql(tmp, href) : NULL;
	sql = eu && eh ? talloc_asprintf(tmp, "SELECT HEX(ck), etag, HEX(fp) FROM " FP_VERSIONS_TABLE " WHERE user = '%s' AND href = '%s' "
					 "ORDER BY seq DESC", eu, eh) : NULL;
	if (!sql) {
		talloc_free(tmp);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	switch (select_without_fetch(s->conn, sql, &res)) {
	case MYSQL_SUCCESS:
		while (ret == MAPISTORE_ERR_NOT_FOUND && (row = mysql_fetch_row(res))) {
			n = row[0] ? strlen(row[0]) / 2 : 0;
			if (!n || n > sizeof ck || !row[1]) continue;
			for (i = 0; i < n && hexval(row[0][2 * i]) >= 0 && hexval(row[0][2 * i + 1]) >= 0; i++) {
				ck[i] = hexval(row[0][2 * i]) << 4 | hexval(row[0][2 * i + 1]);
			}
			if (i < n || !pcl_has(pcl, ck, n) || !parse_hex(row[2], fp)) continue;
			*etag = talloc_strdup(mem_ctx, row[1]);
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

enum mapistore_error dav_fp_prune(struct dav_fpstore *s, const char *user, const char *book_href, char **live, size_t n,
				  TALLOC_CTX *mem_ctx, char ***gonep, size_t *ngonep)
{
	TALLOC_CTX		*tmp;
	const char		*eu;
	char			*sql, **gone = NULL, **mark = NULL, **drop = NULL;
	MYSQL_RES		*res = NULL;
	MYSQL_ROW		row;
	struct fp_row		*r;
	size_t			k = 0, nmark = 0, ndrop = 0, i;
	enum mapistore_error	ret = MAPISTORE_SUCCESS;
	int			where;

	if (!s || !user || !book_href || !gonep || !ngonep) return MAPISTORE_ERR_INVALID_PARAMETER;
	*gonep = NULL;
	*ngonep = 0;
	tmp = talloc_new(NULL);
	if (!tmp) return MAPISTORE_ERR_NO_MEMORY;
	if (!s->conn) {
		for (r = s->rows; r && ret == MAPISTORE_SUCCESS; r = r->next) {
			if (strcmp(r->user, user)) continue;
			where = classify(book_href, r->href, live, n);
			if (where == GONE) {
				TALLOC_FREE(r->etag);
				if (!href_add(mem_ctx, &gone, &k, r->href)) ret = MAPISTORE_ERR_NO_MEMORY;
			} else if (where == LIVE && !r->etag && !href_add(tmp, &drop, &ndrop, r->href)) {
				ret = MAPISTORE_ERR_NO_MEMORY;
			}
		}
	} else {
		eu = _sql(tmp, user);
		sql = eu ? talloc_asprintf(tmp, "SELECT href, etag IS NULL FROM " FP_TABLE " WHERE user = '%s'", eu) : NULL;
		switch (sql ? select_without_fetch(s->conn, sql, &res) : MYSQL_ERROR) {
		case MYSQL_SUCCESS:
			while (ret == MAPISTORE_SUCCESS && (row = mysql_fetch_row(res))) {
				bool dead = row[1] && strcmp(row[1], "0") != 0;

				if (!row[0]) continue;
				where = classify(book_href, row[0], live, n);
				if ((where == GONE && (!href_add(mem_ctx, &gone, &k, row[0]) || (!dead && !href_add(tmp, &mark, &nmark, row[0])))) ||
				    (where == LIVE && dead && !href_add(tmp, &drop, &ndrop, row[0]))) {
					ret = MAPISTORE_ERR_NO_MEMORY;
				}
			}
			mysql_free_result(res);
			break;
		case MYSQL_NOT_FOUND:
			break;
		default:
			ret = sql ? MAPISTORE_ERR_DATABASE_OPS : MAPISTORE_ERR_NO_MEMORY;
		}
		for (i = 0; ret == MAPISTORE_SUCCESS && i < nmark; i++) ret = tombstone(s, user, mark[i]);
	}
	for (i = 0; ret == MAPISTORE_SUCCESS && i < ndrop; i++) ret = dav_fp_delete(s, user, drop[i]);
	talloc_free(tmp);
	if (ret != MAPISTORE_SUCCESS) {
		talloc_free(gone);
		return ret;
	}
	*gonep = gone;
	*ngonep = k;
	return MAPISTORE_SUCCESS;
}
