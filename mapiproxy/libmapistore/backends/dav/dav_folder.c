/*
   CardDAV mapistore backend: address books as Outlook contacts folders, item list and ICS

   Each address book of the user is one context whose root folder is the book. The list of
   cards (href, ETag, MID) and the sync token live in session memory; a new session starts
   from a full listing.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <string.h>
#include <strings.h>
#include <inttypes.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "utils/dlinklist.h"
#include "mapiproxy/libmapiproxy/libmapiproxy.h"
#include "dav_backend.h"
#include "dav_http.h"
#include "dav_fpstore.h"

#define DAV_MULTIGET_BATCH 100
#define N(a) (sizeof (a) / sizeof (a)[0])

/* Process-wide, so fingerprints outlive sessions (in memory when the indexing is not MySQL). */
static struct dav_fpstore *fpstore;

/* R14: reads reuse a context's last sync and book listing for sync_window seconds. A poll that sees a change,
   or a book written here, bumps generation and so ends every reuse at once. */
static int sync_window = 10;
static unsigned generation;

void dav_backend_set_sync_window(int seconds)
{
	sync_window = seconds;
}

static bool fresh(time_t at, unsigned gen)
{
	return at && gen == generation && time(NULL) - at < sync_window;
}

uint64_t *dav_i8(TALLOC_CTX *mem_ctx, uint64_t v)
{
	uint64_t *p = talloc(mem_ctx, uint64_t);

	if (p) *p = v;
	return p;
}

uint32_t *dav_long(TALLOC_CTX *mem_ctx, uint32_t v)
{
	uint32_t *p = talloc(mem_ctx, uint32_t);

	if (p) *p = v;
	return p;
}

uint8_t *dav_bool(TALLOC_CTX *mem_ctx, bool v)
{
	uint8_t *p = talloc(mem_ctx, uint8_t);

	if (p) *p = v ? 1 : 0;
	return p;
}

/* One URL path segment: unreserved characters, sub-delims, ':' and '@' as they are, the rest
   %-encoded; '%' is kept only for segments that are already normalized (their %2F and %25). */
static char *escape_segment(TALLOC_CTX *mem_ctx, const char *s, bool keep_pct)
{
	static const char plain[] = "-._~!$&'()*+,;=:@";
	char *o = talloc_strdup(mem_ctx, "");

	for (; o && *s; s++) {
		unsigned char c = *s;

		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strchr(plain, c) ||
		    (keep_pct && c == '%')) {
			o = talloc_asprintf_append_buffer(o, "%c", c);
		} else {
			o = talloc_asprintf_append_buffer(o, "%%%02X", c);
		}
	}
	return o;
}

/* dav_url with every %u replaced by the user's name. */
static char *home_url(TALLOC_CTX *mem_ctx, const char *username)
{
	const struct dav_settings	*settings = dav_backend_settings();
	const char			*t = settings->url_template, *u;
	char				*user = escape_segment(mem_ctx, username, false), *o = talloc_strdup(mem_ctx, "");

	while (o && user && (u = strstr(t, "%u"))) {
		o = talloc_asprintf_append_buffer(o, "%.*s%s", (int) (u - t), t, user);
		t = u + 2;
	}
	return o && user ? talloc_strdup_append_buffer(o, t) : NULL;
}

/* The password is fetched now: dav_cred_get's result does not outlive the next set or forget. */
static struct dav_http *user_http(TALLOC_CTX *mem_ctx, const char *username, const char *home)
{
	const char *password = dav_cred_get(username);

	return password && home ? dav_http_new(mem_ctx, home, username, password) : NULL;
}

struct dav_http *dav_context_http(struct dav_context *ctx, TALLOC_CTX *mem_ctx)
{
	return user_http(mem_ctx, ctx->username, ctx->home);
}

/* personal as the main Contacts folder; the other books are its subfolders (open_table, open_folder).
   No password or SOGo unreachable: an error, so provisioning keeps the folders it knows. */
static enum mapistore_error dav_list_contexts(const char *username, struct indexing_context *ictx,
					      TALLOC_CTX *mem_ctx, struct mapistore_contexts_list **listp)
{
	struct mapistore_contexts_list	*list = NULL, *e;
	struct dav_book			*books;
	struct dav_http			*h;
	TALLOC_CTX			*tmp;
	enum mapistore_error		ret;
	size_t				n, i;
	bool				have_main = false;

	*listp = NULL;
	if (!dav_backend_settings()) {
		return MAPISTORE_SUCCESS;
	}
	tmp = talloc_new(NULL);
	if (!tmp || !username) {
		talloc_free(tmp);
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	h = user_http(tmp, username, home_url(tmp, username));
	ret = h ? dav_list_books(h, tmp, &books, &n) : MAPISTORE_ERR_CONN_REFUSED;
	if (ret != MAPISTORE_SUCCESS) {
		OC_DEBUG(1, "DAV backend: address books of %s unavailable (%s); contacts folders kept\n", username,
			 h ? mapistore_errstr(ret) : "no password");
		talloc_free(tmp);
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	for (i = 0; i < n && !have_main; i++) {
		if (strcmp(books[i].segment, "personal") != 0) continue;
		e = talloc_zero(mem_ctx, struct mapistore_contexts_list);
		if (!e || !(e->url = talloc_asprintf(e, DAV_CONTACTS_URI "%s/", books[i].segment)) ||
		    !(e->name = talloc_strdup(e, books[i].displayname ? books[i].displayname : books[i].segment))) {
			talloc_free(e);
			ret = MAPISTORE_ERR_NO_MEMORY;
			break;
		}
		e->role = MAPISTORE_CONTACTS_ROLE;
		e->main_folder = have_main = true;
		DLIST_ADD_END(list, e, struct mapistore_contexts_list *);
	}
	talloc_free(tmp);
	if (ret != MAPISTORE_SUCCESS) {
		while ((e = list)) {
			DLIST_REMOVE(list, e);
			talloc_free(e);
		}
		return ret;
	}
	*listp = list;
	return MAPISTORE_SUCCESS;
}

/* The ID of uri, allocated and recorded on first sight (replica ID 1, as the IMAP backend). */
static enum mapistore_error fmid_for_uri(struct dav_context *ctx, const char *uri, uint64_t *fmid)
{
	struct indexing_context	*ictx = ctx->ictx;
	enum mapistore_error	ret;
	bool			soft_deleted = false;
	uint64_t		raw;

	if (ictx->get_fmid(ictx, ctx->username, uri, false, fmid, &soft_deleted) == MAPISTORE_SUCCESS) {
		return MAPISTORE_SUCCESS;
	}
	ret = ictx->allocate_fmid(ictx, ctx->username, &raw);
	if (ret != MAPISTORE_SUCCESS) {
		return ret;
	}
	*fmid = (exchange_globcnt(raw) << 16) | 0x0001;
	return ictx->add_fmid(ictx, ctx->username, *fmid, uri);
}

/* Change numbers share the indexing ID counter, as the IMAP backend's (see id_counter_cn there). */
static enum mapistore_error cn_source(void *p, uint64_t *cn)
{
	struct dav_context	*ctx = p;
	uint64_t		raw;
	enum mapistore_error	ret = ctx->ictx->allocate_fmid(ctx->ictx, ctx->username, &raw);

	if (ret == MAPISTORE_SUCCESS) {
		*cn = (exchange_globcnt(raw) << 16) | 0x0001;
	}
	return ret;
}

void *dav_change_value(TALLOC_CTX *mem_ctx, struct dav_context *ctx, const char *uri, const char *state,
		       enum MAPITAGS tag)
{
	uint64_t	cn;
	time_t		when;

	if (!uri || !state || mapistore_change_number(ctx->username, uri, state, cn_source, ctx, &cn, &when) != MAPISTORE_SUCCESS) {
		return NULL;
	}
	return mapistore_change_value(mem_ctx, ctx->username, uri, &ctx->replica_guid, cn, when, tag);
}

/* The book named segment in ctx (user, home and indexing set): its URI, server path and root folder. */
static enum mapistore_error context_book(struct dav_context *ctx, const char *segment)
{
	const char *path = strchr(strstr(ctx->home, "://") ? strstr(ctx->home, "://") + 3 : ctx->home, '/');

	ctx->uri = talloc_asprintf(ctx, DAV_CONTACTS_URI "%s/", segment);
	ctx->book_href = talloc_asprintf(ctx, "%s%s%s/", path ? path : "/", path && path[strlen(path) - 1] == '/' ? "" : "/",
					 escape_segment(ctx, segment, true));
	ctx->book_norm = ctx->book_href ? dav_href_norm(ctx, ctx->book_href) : NULL;
	ctx->root = talloc_zero(ctx, struct dav_folder);
	if (!ctx->uri || !ctx->book_norm || !ctx->root) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	ctx->root->type = DAV_OBJ_FOLDER;
	ctx->root->ctx = ctx;
	return fmid_for_uri(ctx, ctx->uri, &ctx->root->fid) == MAPISTORE_SUCCESS ? MAPISTORE_SUCCESS : MAPISTORE_ERR_DATABASE_OPS;
}

static bool is_personal(const struct dav_context *ctx);

/* Another book of the same user and session, as its root folder. Through personal (kept) the book's context is
   personal's, reused by later opens; mem_ctx holds a reference, so the folder outlives personal if need be. */
static struct dav_folder *book_folder(TALLOC_CTX *mem_ctx, struct dav_context *like, const char *segment, bool kept)
{
	struct dav_context	*ctx, **grown;
	char			*uri = talloc_asprintf(mem_ctx, DAV_CONTACTS_URI "%s/", segment);
	size_t			i;

	kept = kept && is_personal(like);
	for (i = 0; uri && kept && i < like->nchildren && strcmp(like->children[i]->uri, uri) != 0; i++);
	talloc_free(uri);
	if (kept && i < like->nchildren) {
		return talloc_reference(mem_ctx, like->children[i]) ? like->children[i]->root : NULL;
	}
	ctx = talloc_zero(kept ? (TALLOC_CTX *) like : mem_ctx, struct dav_context);
	if (!ctx) return NULL;
	ctx->username = talloc_strdup(ctx, like->username);
	ctx->ictx = like->ictx;
	ctx->replica_guid = like->replica_guid;
	ctx->mailbox_guid = like->mailbox_guid;
	ctx->tags = like->tags;
	ctx->fp = like->fp;
	ctx->home = talloc_strdup(ctx, like->home);
	if (!ctx->username || !ctx->home || context_book(ctx, segment) != MAPISTORE_SUCCESS) {
		talloc_free(ctx);
		return NULL;
	}
	if (kept) {
		grown = talloc_realloc(like, like->children, struct dav_context *, like->nchildren + 1);
		if (!grown || !talloc_reference(mem_ctx, ctx)) {
			if (grown) like->children = grown;
			talloc_free(ctx);
			return NULL;
		}
		like->children = grown;
		like->children[like->nchildren++] = ctx;
	}
	return ctx->root;
}

/* The context's user is the session's own: a URI only chooses one of that user's books. */
static enum mapistore_error dav_create_context(TALLOC_CTX *mem_ctx, struct mapistore_connection_info *conn_info,
					       struct indexing_context *ictx, const char *uri, void **backend_object)
{
	struct dav_context	*ctx;
	const char		*seg;
	char			*name;
	size_t			len;
	enum mapistore_error	ret;

	*backend_object = NULL;
	if (!dav_backend_settings()) {
		return MAPISTORE_ERR_NOT_AVAILABLE;
	}
	if (!conn_info || !conn_info->username || !ictx || !uri) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (!conn_info->mstore_ctx || !conn_info->mstore_ctx->nprops_ctx) {
		return MAPISTORE_ERR_NOT_INITIALIZED;
	}
	ctx = talloc_zero(mem_ctx, struct dav_context);
	if (!ctx) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	/* mapistore_add_context hands over the URI without its "dav://" namespace. */
	if (strncmp(uri, DAV_NAMESPACE, strlen(DAV_NAMESPACE)) != 0) {
		uri = talloc_asprintf(ctx, DAV_NAMESPACE "%s", uri);
	}
	len = strlen(DAV_CONTACTS_URI);
	if (!uri || strncmp(uri, DAV_CONTACTS_URI, len) != 0 || strlen(uri + len) < 2 || uri[strlen(uri) - 1] != '/' ||
	    strchr(uri + len, '/') != uri + strlen(uri) - 1) {
		talloc_free(ctx);
		return MAPISTORE_ERR_INVALID_URI;
	}
	seg = uri + len;
	name = talloc_strndup(ctx, seg, strlen(seg) - 1);
	if (!name || !strcmp(name, ".") || !strcmp(name, "..")) {
		talloc_free(ctx);
		return MAPISTORE_ERR_INVALID_URI;
	}
	ctx->username = talloc_strdup(ctx, conn_info->username);
	ctx->ictx = ictx;
	ctx->replica_guid = conn_info->replica_guid;
	if (conn_info->oc_ctx) {
		uint16_t repl_id;

		openchangedb_get_MailboxReplica(conn_info->oc_ctx, ctx->username, &repl_id, &ctx->replica_guid);
		openchangedb_get_MailboxGuid(conn_info->oc_ctx, ctx->username, &ctx->mailbox_guid);
	}
	if (dav_named_tags_resolve(conn_info->mstore_ctx->nprops_ctx, &ctx->tags) != MAPISTORE_SUCCESS) {
		talloc_free(ctx);
		return MAPISTORE_ERR_NOT_INITIALIZED;
	}
	if (!fpstore) {
		fpstore = dav_fpstore_open(NULL, ictx->url);
	}
	ctx->fp = fpstore;
	ctx->home = home_url(ctx, ctx->username);
	if (!ctx->username || !ctx->home) {
		talloc_free(ctx);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	ret = context_book(ctx, name);
	if (ret != MAPISTORE_SUCCESS) {
		talloc_free(ctx);
		return ret;
	}
	*backend_object = ctx->root;
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error get_path(void *object, TALLOC_CTX *mem_ctx, uint64_t fmid, char **path)
{
	struct dav_folder	*f = object;
	bool			soft_deleted;

	if (!f || f->type != DAV_OBJ_FOLDER) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	return f->ctx->ictx->get_uri(f->ctx->ictx, f->ctx->username, mem_ctx, fmid, path, &soft_deleted);
}

static enum mapistore_error get_root_folder(void *object, TALLOC_CTX *mem_ctx, uint64_t fid, void **folder)
{
	struct dav_folder *f = object;

	if (!f || f->type != DAV_OBJ_FOLDER) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	/* emsmdb knows the root by the ID it provisioned; the indexing may hold another for the URI. */
	if (fid) {
		f->ctx->root->fid = fid;
	}
	*folder = f->ctx->root;
	return MAPISTORE_SUCCESS;
}

char *dav_item_uri(TALLOC_CTX *mem_ctx, struct dav_context *ctx, const char *norm)
{
	return talloc_asprintf(mem_ctx, "%s%s", ctx->uri, strrchr(norm, '/') + 1);
}

struct dav_item *dav_item_by_mid(struct dav_context *ctx, uint64_t mid)
{
	size_t i;

	for (i = 0; i < ctx->nitems; i++) {
		if (ctx->items[i].mid == mid) return &ctx->items[i];
	}
	return NULL;
}

static bool deleted_add(struct dav_context *ctx, uint64_t mid)
{
	size_t i;

	for (i = 0; i < ctx->ndeleted && ctx->deleted[i] != mid; i++);
	if (i < ctx->ndeleted) return true;
	ctx->deleted = talloc_realloc(ctx, ctx->deleted, uint64_t, ctx->ndeleted + 1);
	if (!ctx->deleted) {
		ctx->ndeleted = 0;
		return false;
	}
	ctx->deleted[ctx->ndeleted++] = mid;
	ctx->deletions++;
	return true;
}

/* A card that comes back (same href) is no longer deleted. */
static void deleted_remove(struct dav_context *ctx, uint64_t mid)
{
	size_t i;

	for (i = 0; i < ctx->ndeleted; i++) {
		if (ctx->deleted[i] == mid) {
			ctx->deleted[i] = ctx->deleted[--ctx->ndeleted];
			return;
		}
	}
}

/* Open messages keep their reference to the card. */
static void item_drop_card(struct dav_context *ctx, struct dav_item *it)
{
	if (it->card) {
		talloc_unlink(ctx, it->card);
		it->card = NULL;
	}
}

static void item_free(struct dav_context *ctx, size_t i)
{
	struct dav_item *it = &ctx->items[i];

	item_drop_card(ctx, it);
	talloc_free(it->href);
	talloc_free(it->norm);
	talloc_free(it->etag);
	memmove(it, it + 1, (ctx->nitems - i - 1) * sizeof *it);
	ctx->nitems--;
}

static bool item_remove(struct dav_context *ctx, size_t i)
{
	bool ok = deleted_add(ctx, ctx->items[i].mid);

	item_free(ctx, i);
	return ok;
}

static struct dav_item *item_find(struct dav_context *ctx, const char *norm, size_t *index)
{
	size_t i;

	for (i = 0; i < ctx->nitems; i++) {
		if (strcmp(ctx->items[i].norm, norm) == 0) {
			if (index) *index = i;
			return &ctx->items[i];
		}
	}
	return NULL;
}

static enum mapistore_error item_upsert(struct dav_context *ctx, const char *href, const char *norm, const char *etag)
{
	struct dav_item		*it = item_find(ctx, norm, NULL), *items;
	char			*uri;
	uint64_t		mid;
	enum mapistore_error	ret;

	if (it) {
		if (strcmp(it->etag, etag) != 0) {
			talloc_free(it->etag);
			if (!(it->etag = talloc_strdup(ctx, etag))) return MAPISTORE_ERR_NO_MEMORY;
			item_drop_card(ctx, it);
		}
		it->listed = true;
		return MAPISTORE_SUCCESS;
	}
	/* Identity is the href, through the indexing: a relisting never mints a second MID. */
	uri = dav_item_uri(ctx, ctx, norm);
	ret = uri ? fmid_for_uri(ctx, uri, &mid) : MAPISTORE_ERR_NO_MEMORY;
	talloc_free(uri);
	if (ret != MAPISTORE_SUCCESS) return ret;
	items = talloc_realloc(ctx, ctx->items, struct dav_item, ctx->nitems + 1);
	if (!items) return MAPISTORE_ERR_NO_MEMORY;
	ctx->items = items;
	it = &items[ctx->nitems];
	memset(it, 0, sizeof *it);
	it->href = talloc_strdup(ctx, href);
	it->norm = talloc_strdup(ctx, norm);
	it->etag = talloc_strdup(ctx, etag);
	it->mid = mid;
	it->listed = true;
	if (!it->href || !it->norm || !it->etag) return MAPISTORE_ERR_NO_MEMORY;
	ctx->nitems++;
	deleted_remove(ctx, mid);
	return MAPISTORE_SUCCESS;
}

/* After a full listing: the cards Outlook was given (they have fingerprints) that are gone. */
static enum mapistore_error prune_gone(struct dav_context *ctx, TALLOC_CTX *tmp)
{
	char			**live = talloc_array(tmp, char *, ctx->nitems + 1), **gone, *uri;
	size_t			ngone, i;
	uint64_t		mid;
	bool			soft_deleted;
	enum mapistore_error	ret;

	if (!live) return MAPISTORE_ERR_NO_MEMORY;
	for (i = 0; i < ctx->nitems; i++) live[i] = ctx->items[i].norm;
	ret = dav_fp_prune(ctx->fp, ctx->username, ctx->book_norm, live, ctx->nitems, tmp, &gone, &ngone);
	if (ret != MAPISTORE_SUCCESS) {
		OC_DEBUG(1, "DAV backend: fingerprint prune failed (%s)\n", mapistore_errstr(ret));
		return MAPISTORE_SUCCESS;
	}
	for (i = 0; i < ngone; i++) {
		uri = dav_item_uri(tmp, ctx, gone[i]);
		if (uri && ctx->ictx->get_fmid(ctx->ictx, ctx->username, uri, false, &mid, &soft_deleted) == MAPISTORE_SUCCESS &&
		    !deleted_add(ctx, mid)) {
			return MAPISTORE_ERR_NO_MEMORY;
		}
	}
	return MAPISTORE_SUCCESS;
}

/* Any result is an upsert by href (SOGo answers an unknown token with everything plus tombstones);
   a full listing also removes what it does not list. */
enum mapistore_error dav_context_sync(struct dav_context *ctx)
{
	TALLOC_CTX		*tmp;
	struct dav_http		*h;
	struct dav_change	*ch;
	size_t			n, i, k;
	char			*token, *norm;
	bool			full;
	enum mapistore_error	ret;

	if (fresh(ctx->synced_at, ctx->synced_gen)) return MAPISTORE_SUCCESS;
	if (!(tmp = talloc_new(NULL))) return MAPISTORE_ERR_NO_MEMORY;
	h = dav_context_http(ctx, tmp);
	ret = h ? dav_sync(h, tmp, ctx->book_href, ctx->token, &ch, &n, &token, &full) : MAPISTORE_ERR_CONN_REFUSED;
	if (ret != MAPISTORE_SUCCESS) {
		talloc_free(tmp);
		return ret;
	}
	for (i = 0; full && i < ctx->nitems; i++) ctx->items[i].listed = false;
	for (i = 0; ret == MAPISTORE_SUCCESS && i < n; i++) {
		if (!(norm = dav_href_norm(tmp, ch[i].href))) continue;
		if (ch[i].etag) {
			ret = item_upsert(ctx, ch[i].href, norm, ch[i].etag);
		} else if (item_find(ctx, norm, &k) && !item_remove(ctx, k)) {
			ret = MAPISTORE_ERR_NO_MEMORY;
		}
	}
	for (i = ctx->nitems; full && ret == MAPISTORE_SUCCESS && i > 0; i--) {
		if (!ctx->items[i - 1].listed && !item_remove(ctx, i - 1)) ret = MAPISTORE_ERR_NO_MEMORY;
	}
	if (full && ret == MAPISTORE_SUCCESS) {
		ret = prune_gone(ctx, tmp);
	}
	if (ret == MAPISTORE_SUCCESS) {
		talloc_free(ctx->token);
		ctx->token = token ? talloc_strdup(ctx, token) : NULL;
		ctx->synced_at = time(NULL);
		ctx->synced_gen = generation;
	}
	talloc_free(tmp);
	return ret;
}

enum mapistore_error dav_context_resync(struct dav_context *ctx)
{
	ctx->synced_at = 0;
	return dav_context_sync(ctx);
}

/* The user's books as ctx last listed them (within the sync window), or listed now. */
static enum mapistore_error context_books(struct dav_context *ctx, struct dav_book **books, size_t *n)
{
	struct dav_http		*h;
	struct dav_book		*list;
	size_t			nb;
	enum mapistore_error	ret;

	if (!fresh(ctx->books_at, ctx->books_gen)) {
		h = dav_context_http(ctx, NULL);
		ret = h ? dav_list_books(h, ctx, &list, &nb) : MAPISTORE_ERR_CONN_REFUSED;
		talloc_free(h);
		if (ret != MAPISTORE_SUCCESS) return ret;
		talloc_free(ctx->books);
		ctx->books = list;
		ctx->nbooks = nb;
		ctx->books_at = time(NULL);
		ctx->books_gen = generation;
	}
	*books = ctx->books;
	*n = ctx->nbooks;
	return MAPISTORE_SUCCESS;
}

enum mapistore_error dav_context_fetch(struct dav_context *ctx)
{
	TALLOC_CTX		*tmp = talloc_new(NULL);
	struct dav_http		*h;
	char			**hrefs, **bodies, **etags;
	size_t			*idx, i, k;
	enum mapistore_error	ret = MAPISTORE_SUCCESS;

	hrefs = tmp ? talloc_array(tmp, char *, DAV_MULTIGET_BATCH) : NULL;
	idx = tmp ? talloc_array(tmp, size_t, DAV_MULTIGET_BATCH) : NULL;
	h = hrefs && idx ? dav_context_http(ctx, tmp) : NULL;
	if (!h) {
		talloc_free(tmp);
		return hrefs && idx ? MAPISTORE_ERR_CONN_REFUSED : MAPISTORE_ERR_NO_MEMORY;
	}
	for (i = 0; ret == MAPISTORE_SUCCESS && i < ctx->nitems;) {
		for (k = 0; i < ctx->nitems && k < DAV_MULTIGET_BATCH; i++) {
			if (ctx->items[i].card) continue;
			idx[k] = i;
			hrefs[k++] = ctx->items[i].href;
		}
		if (!k) break;
		ret = dav_multiget(h, tmp, ctx->book_href, hrefs, k, &bodies, &etags);
		for (; ret == MAPISTORE_SUCCESS && k > 0; k--) {
			struct dav_item *it = &ctx->items[idx[k - 1]];

			if (!bodies[k - 1] || !(it->card = dav_card_parse(ctx, bodies[k - 1], strlen(bodies[k - 1])))) continue;
			/* the body shown is the version its ETag names */
			if (etags[k - 1] && strcmp(etags[k - 1], it->etag) != 0) {
				talloc_free(it->etag);
				if (!(it->etag = talloc_strdup(ctx, etags[k - 1]))) ret = MAPISTORE_ERR_NO_MEMORY;
			}
		}
	}
	talloc_free(tmp);
	return ret;
}

time_t dav_etag_time(struct dav_context *ctx, const char *norm, const char *etag)
{
	char		*uri = dav_item_uri(NULL, ctx, norm);
	uint64_t	cn;
	time_t		when;

	if (!uri || !etag || mapistore_change_number(ctx->username, uri, etag, cn_source, ctx, &cn, &when) != MAPISTORE_SUCCESS) {
		when = time(NULL);
	}
	talloc_free(uri);
	return when;
}

enum mapistore_error dav_item_put(struct dav_context *ctx, uint64_t mid, const char *href, const char *etag, struct dav_card *card)
{
	struct indexing_context	*ictx = ctx->ictx;
	TALLOC_CTX		*tmp = talloc_new(NULL);
	char			*norm = tmp ? dav_href_norm(tmp, href) : NULL, *uri = norm ? dav_item_uri(tmp, ctx, norm) : NULL, *old;
	struct dav_item		*it;
	enum mapistore_error	ret;
	bool			soft;
	size_t			i;

	if (!uri) {
		talloc_free(tmp);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	/* a card recreated at a new href: the old one leaves the list without being reported deleted */
	for (i = ctx->nitems; i > 0; i--) {
		if (ctx->items[i - 1].mid == mid && strcmp(ctx->items[i - 1].norm, norm) != 0) item_free(ctx, i - 1);
	}
	if (ictx->get_uri(ictx, ctx->username, tmp, mid, &old, &soft) != MAPISTORE_SUCCESS) {
		ret = ictx->add_fmid(ictx, ctx->username, mid, uri);
	} else {
		ret = strcmp(old, uri) == 0 ? MAPISTORE_SUCCESS : ictx->update_fmid(ictx, ctx->username, mid, uri);
	}
	if (ret == MAPISTORE_SUCCESS) ret = item_upsert(ctx, href, norm, etag);
	if (ret == MAPISTORE_SUCCESS && (it = item_find(ctx, norm, NULL))) {
		item_drop_card(ctx, it);
		it->card = talloc_steal(ctx, card);
		deleted_remove(ctx, mid);
	}
	talloc_free(tmp);
	return ret;
}

static enum mapistore_error cn_given(void *p, uint64_t *cn)
{
	*cn = *(uint64_t *) p;
	return MAPISTORE_SUCCESS;
}

/* pcl with xid (a SizedXid) as its entry for xid's replica. */
static struct Binary_r *pcl_with(TALLOC_CTX *mem_ctx, const struct Binary_r *pcl, const struct Binary_r *xid)
{
	struct Binary_r	*b = talloc_zero(mem_ctx, struct Binary_r);
	uint32_t	i = 0, n;

	if (!b || !xid || xid->cb != 23 || !(b->lpb = talloc_array(b, uint8_t, pcl->cb + xid->cb))) {
		return NULL;
	}
	while (i < pcl->cb && (n = pcl->lpb[i]) >= 17 && i + 1 + n <= pcl->cb) {
		if (memcmp(pcl->lpb + i + 1, xid->lpb + 1, 16) != 0) {
			memcpy(b->lpb + b->cb, pcl->lpb + i, 1 + n);
			b->cb += 1 + n;
		}
		i += 1 + n;
	}
	memcpy(b->lpb + b->cb, xid->lpb, xid->cb);
	b->cb += xid->cb;
	return b;
}

void dav_change_record(struct dav_context *ctx, const char *uri, const char *etag, const struct Binary_r *ck,
		       const struct Binary_r *pcl, bool merged)
{
	TALLOC_CTX		*tmp;
	enum mapistore_error	ret;
	uint64_t		cn;
	time_t			when;

	if (!uri || !etag || !ck || !pcl || !(tmp = talloc_new(NULL))) {
		return;	/* no keys from Outlook (online save): the new ETag is a server change */
	}
	if (!merged) {
		ret = mapistore_change_record_client(ctx->username, uri, cn_source, ctx, ck, pcl);
	} else if ((ret = cn_source(ctx, &cn)) == MAPISTORE_SUCCESS) {
		/* a server change that follows Outlook's: Outlook takes it without a conflict */
		ret = mapistore_change_record_client(ctx->username, uri, cn_given, &cn,
			mapistore_change_value(tmp, ctx->username, uri, &ctx->replica_guid, cn, 0, PidTagChangeKey),
			pcl_with(tmp, pcl, mapistore_change_value(tmp, ctx->username, uri, &ctx->replica_guid, cn, 0,
								  PidTagPredecessorChangeList)));
	}
	/* the version just stored is that change */
	if (ret != MAPISTORE_SUCCESS ||
	    mapistore_change_number(ctx->username, uri, etag, cn_source, ctx, &cn, &when) != MAPISTORE_SUCCESS) {
		OC_DEBUG(1, "DAV backend: change keys of %s not kept\n", uri);
	}
	talloc_free(tmp);
}

static char *book_displayname(struct dav_context *);

static bool is_personal(const struct dav_context *ctx)
{
	return strcmp(ctx->uri, DAV_CONTACTS_URI "personal/") == 0;
}

static const char *row_string(struct SRow *row, enum MAPITAGS unicode_tag, enum MAPITAGS string8_tag)
{
	uint32_t i;

	for (i = 0; row && i < row->cValues; i++) {
		if ((enum MAPITAGS) row->lpProps[i].ulPropTag == unicode_tag) return row->lpProps[i].value.lpszW;
		if ((enum MAPITAGS) row->lpProps[i].ulPropTag == string8_tag) return row->lpProps[i].value.lpszA;
	}
	return NULL;
}

/* The user's other books, as subfolders of personal (books are flat: none below another book). Their IDs
   come from the indexing of their URIs, so they stay the same across sessions. */
static enum mapistore_error child_books(TALLOC_CTX *mem_ctx, struct dav_folder *p, struct dav_folder ***out, uint32_t *n)
{
	struct dav_book		*books;
	struct dav_folder	*f, **list;
	TALLOC_CTX		*tmp;
	enum mapistore_error	ret;
	size_t			nb, i;
	char			*norm;

	*out = NULL;
	*n = 0;
	if (!is_personal(p->ctx)) return MAPISTORE_SUCCESS;
	tmp = talloc_new(NULL);
	ret = !tmp ? MAPISTORE_ERR_NO_MEMORY : context_books(p->ctx, &books, &nb);
	list = ret == MAPISTORE_SUCCESS ? talloc_array(mem_ctx, struct dav_folder *, nb + 1) : NULL;
	if (ret == MAPISTORE_SUCCESS && !list) ret = MAPISTORE_ERR_NO_MEMORY;
	for (i = 0; ret == MAPISTORE_SUCCESS && i < nb; i++) {
		norm = dav_href_norm(tmp, books[i].href);
		if (!norm || strcmp(norm, p->ctx->book_norm) == 0) continue;
		if (!(f = book_folder(list, p->ctx, books[i].segment, true))) {
			ret = MAPISTORE_ERR_NO_MEMORY;
			break;
		}
		talloc_free(f->ctx->displayname);
		if (!(f->ctx->displayname = talloc_strdup(f->ctx, books[i].displayname ? books[i].displayname : books[i].segment))) {
			ret = MAPISTORE_ERR_NO_MEMORY;
			break;
		}
		f->parent_fid = p->fid;
		list[(*n)++] = f;
	}
	talloc_free(tmp);
	if (ret != MAPISTORE_SUCCESS) {
		talloc_free(list);
		*n = 0;
		return ret;
	}
	*out = list;
	return MAPISTORE_SUCCESS;
}

/* The other books open through personal. */
static enum mapistore_error open_folder(void *parent, TALLOC_CTX *mem_ctx, uint64_t fid, void **child)
{
	struct dav_folder	*p = parent, *f;
	size_t			len = strlen(DAV_CONTACTS_URI);
	char			*uri, *seg;
	bool			soft;

	if (!p || p->type != DAV_OBJ_FOLDER || !child) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (!is_personal(p->ctx) || p->ctx->ictx->get_uri(p->ctx->ictx, p->ctx->username, mem_ctx, fid, &uri, &soft) != MAPISTORE_SUCCESS ||
	    strncmp(uri, DAV_CONTACTS_URI, len) != 0 || strlen(uri + len) < 2 || strchr(uri + len, '/') != uri + strlen(uri) - 1 ||
	    strcmp(uri, p->ctx->uri) == 0) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	seg = talloc_strndup(mem_ctx, uri + len, strlen(uri + len) - 1);
	f = seg ? book_folder(mem_ctx, p->ctx, seg, true) : NULL;
	if (!f) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	f->parent_fid = p->fid;
	*child = f;
	return MAPISTORE_SUCCESS;
}

/* A contacts folder Outlook creates under Contacts is a new address book (books are flat). */
static enum mapistore_error create_folder(void *parent, TALLOC_CTX *mem_ctx, uint64_t fid, struct SRow *row, void **childp)
{
	struct dav_folder	*p = parent, *f;
	struct indexing_context	*ictx;
	struct dav_http		*h;
	const char		*name, *klass;
	struct GUID		g = GUID_random();
	char			*seg, *uri;
	enum mapistore_error	ret;

	if (!p || p->type != DAV_OBJ_FOLDER || !childp || !fid) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	klass = row_string(row, PidTagContainerClass, PR_CONTAINER_CLASS);
	if (!is_personal(p->ctx) || (klass && strcmp(klass, "IPF.Contact") != 0)) {
		return MAPISTORE_ERR_DENIED;
	}
	name = row_string(row, PidTagDisplayName, PR_DISPLAY_NAME);
	if (!name || !*name) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	ictx = p->ctx->ictx;
	seg = GUID_string(mem_ctx, &g);
	uri = seg ? talloc_asprintf(mem_ctx, DAV_CONTACTS_URI "%s/", seg) : NULL;
	if (!uri) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	/* first, so the book's root takes the folder ID Outlook was given */
	ret = ictx->add_fmid(ictx, p->ctx->username, fid, uri);
	f = ret == MAPISTORE_SUCCESS ? book_folder(mem_ctx, p->ctx, seg, false) : NULL;
	h = f ? dav_context_http(f->ctx, mem_ctx) : NULL;
	ret = ret != MAPISTORE_SUCCESS ? ret : !f ? MAPISTORE_ERR_NO_MEMORY : !h ? MAPISTORE_ERR_CONN_REFUSED
	      : dav_mkcol_book(h, f->ctx->book_href, name);
	talloc_free(h);
	if (ret != MAPISTORE_SUCCESS) {
		if (f && ictx->del_fmid) ictx->del_fmid(ictx, p->ctx->username, fid, MAPISTORE_PERMANENT_DELETE);
		if (f) talloc_free(f->ctx);
		return ret;
	}
	f->ctx->displayname = talloc_strdup(f->ctx, name);
	f->parent_fid = p->fid;
	generation++;
	*childp = f;
	return MAPISTORE_SUCCESS;
}

/* A new PidTagDisplayName renames the book; other folder properties are not kept. */
enum mapistore_error dav_folder_set_properties(struct dav_folder *f, struct SRow *row)
{
	const char		*name = row_string(row, PidTagDisplayName, PR_DISPLAY_NAME);
	struct dav_http		*h;
	enum mapistore_error	ret;

	if (!name || !*name || (book_displayname(f->ctx) && strcmp(name, f->ctx->displayname) == 0)) {
		return MAPISTORE_SUCCESS;
	}
	h = dav_context_http(f->ctx, NULL);
	ret = h ? dav_rename_book(h, f->ctx->book_href, name) : MAPISTORE_ERR_CONN_REFUSED;
	talloc_free(h);
	if (ret == MAPISTORE_SUCCESS) {
		talloc_free(f->ctx->displayname);
		f->ctx->displayname = talloc_strdup(f->ctx, name);
		generation++;
	}
	return ret;
}

/* personal is the user's default book: SOGo refuses to delete it, and so do we. */
static enum mapistore_error delete_folder(void *folder)
{
	struct dav_folder	*f = folder;
	struct dav_http		*h;
	enum mapistore_error	ret;

	if (!f || f->type != DAV_OBJ_FOLDER) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (is_personal(f->ctx)) {
		return MAPISTORE_ERR_DENIED;
	}
	h = dav_context_http(f->ctx, NULL);
	ret = h ? dav_delete_book(h, f->ctx->book_href) : MAPISTORE_ERR_CONN_REFUSED;
	talloc_free(h);
	generation++;
	return ret == MAPISTORE_ERR_NOT_FOUND ? MAPISTORE_SUCCESS : ret;
}

/* Outlook deletes the version it was last shown (If-Match): a card changed on another client since is
   kept, and its newer version reaches Outlook again on the next sync (nothing lost wins over delete). */
static enum mapistore_error delete_message(void *folder, uint64_t mid, uint8_t flags)
{
	struct dav_folder	*f = folder;
	struct dav_context	*ctx;
	struct dav_item		*it;
	struct dav_http		*h;
	TALLOC_CTX		*tmp;
	uint64_t		fp[DAV_F_COUNT];
	char			*etag = NULL, *norm, *uri;
	enum mapistore_error	ret;

	if (!f || f->type != DAV_OBJ_FOLDER) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	ctx = f->ctx;
	if (!(it = dav_item_by_mid(ctx, mid))) {
		ret = dav_context_resync(ctx);
		if (ret != MAPISTORE_SUCCESS) return ret;
		if (!(it = dav_item_by_mid(ctx, mid))) return MAPISTORE_SUCCESS;	/* already gone */
	}
	tmp = talloc_new(NULL);
	norm = tmp ? talloc_strdup(tmp, it->norm) : NULL;
	if (!norm) {
		talloc_free(tmp);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	if (dav_fp_get(ctx->fp, tmp, ctx->username, norm, fp, &etag) != MAPISTORE_SUCCESS) {
		etag = talloc_strdup(tmp, it->etag);
	}
	h = dav_context_http(ctx, tmp);
	ret = h ? dav_delete(h, it->href, etag) : MAPISTORE_ERR_CONN_REFUSED;
	if (ret == MAPISTORE_ERR_CONFLICT) {
		OC_DEBUG(3, "DAV backend: %s changed elsewhere; Outlook's delete dropped\n", norm);
		/* a fresh change number on the next read, whatever Outlook was shown */
		uri = dav_item_uri(tmp, ctx, norm);
		dav_change_value(tmp, ctx, uri, talloc_asprintf(tmp, "%s kept", etag), PidTagChangeNumber);
		dav_context_resync(ctx);
		ret = MAPISTORE_SUCCESS;
	} else if (ret == MAPISTORE_SUCCESS || ret == MAPISTORE_ERR_NOT_FOUND) {
		/* a tombstone: every other client of the user learns the deletion too */
		if (dav_fp_tombstone(ctx->fp, ctx->username, norm) != MAPISTORE_SUCCESS) {
			OC_DEBUG(1, "DAV backend: tombstone of %s not kept\n", norm);
		}
		dav_context_resync(ctx);
		ret = MAPISTORE_SUCCESS;
	}
	talloc_free(tmp);
	return ret;
}

static enum mapistore_error get_child_count(void *object, enum mapistore_table_type type, uint32_t *count)
{
	struct dav_folder	*f = object;
	enum mapistore_error	ret;

	if (!f || f->type != DAV_OBJ_FOLDER || !count) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	*count = 0;
	if (type == MAPISTORE_FOLDER_TABLE) {
		struct dav_folder **children;

		ret = child_books(NULL, f, &children, count);
		talloc_free(children);
		return ret;
	}
	if (type != MAPISTORE_MESSAGE_TABLE) {
		return MAPISTORE_SUCCESS;
	}
	ret = dav_context_sync(f->ctx);
	if (ret == MAPISTORE_SUCCESS) {
		*count = f->ctx->nitems;
	}
	return ret;
}

static enum mapistore_error open_table(void *object, TALLOC_CTX *mem_ctx, enum mapistore_table_type type,
				       uint32_t handle_id, void **table, uint32_t *row_count)
{
	struct dav_folder	*f = object;
	struct dav_table	*t;
	enum mapistore_error	ret;
	size_t			i;

	if (!f || f->type != DAV_OBJ_FOLDER || !table || !row_count) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	t = talloc_zero(mem_ctx, struct dav_table);
	if (!t) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	t->type = DAV_OBJ_TABLE;
	t->folder = f;
	t->table_type = type;
	if (type == MAPISTORE_MESSAGE_TABLE) {
		ret = dav_context_sync(f->ctx);
		if (ret == MAPISTORE_SUCCESS) ret = dav_context_fetch(f->ctx);
		if (ret == MAPISTORE_SUCCESS && !(t->mids = talloc_array(t, uint64_t, f->ctx->nitems + 1))) {
			ret = MAPISTORE_ERR_NO_MEMORY;
		}
		if (ret != MAPISTORE_SUCCESS) {
			talloc_free(t);
			return ret;
		}
		for (i = 0; i < f->ctx->nitems; i++) t->mids[i] = f->ctx->items[i].mid;
		t->row_count = f->ctx->nitems;
	} else if (type == MAPISTORE_FOLDER_TABLE) {
		ret = child_books(t, f, &t->folders, &t->row_count);
		if (ret != MAPISTORE_SUCCESS) {
			talloc_free(t);
			return ret;
		}
	}
	*table = t;
	*row_count = t->row_count;
	return MAPISTORE_SUCCESS;
}

/* Books of the user the indexing knows that are gone (deleted in webmail or in Outlook). */
static enum mapistore_error deleted_books(struct dav_folder *f, struct UI8Array_r *ids, uint64_t *cnp)
{
	struct indexing_context	*ictx = f->ctx->ictx;
	struct dav_folder	**children = NULL;
	TALLOC_CTX		*tmp = talloc_new(NULL);
	uint64_t		*fmids, *cn;
	uint32_t		n = 0, nchildren = 0, i, j;
	size_t			len = strlen(DAV_CONTACTS_URI);
	char			**uris, *state;
	enum mapistore_error	ret;

	*cnp = 0;
	if (!tmp) return MAPISTORE_ERR_NO_MEMORY;
	ret = child_books(tmp, f, &children, &nchildren);
	if (ret == MAPISTORE_SUCCESS && is_personal(f->ctx) && ictx->list_folders &&
	    ictx->list_folders(ictx, f->ctx->username, tmp, &n, &fmids, &uris) != MAPISTORE_SUCCESS) {
		n = 0;
	}
	state = talloc_strdup(tmp, "deleted books");
	ids->lpui8 = talloc_array(ids, uint64_t, n + 1);
	for (i = 0; ret == MAPISTORE_SUCCESS && i < n; i++) {
		const char *u = uris[i];

		if (strncmp(u, DAV_CONTACTS_URI, len) != 0 || strchr(u + len, '/') != u + strlen(u) - 1 || !strcmp(u, f->ctx->uri)) continue;
		for (j = 0; j < nchildren && strcmp(children[j]->ctx->uri, u) != 0; j++);
		if (j < nchildren) continue;
		if (!ids->lpui8 || !state) {
			ret = MAPISTORE_ERR_NO_MEMORY;
			break;
		}
		ids->lpui8[ids->cValues++] = fmids[i];
		state = talloc_asprintf_append_buffer(state, " %"PRIx64, fmids[i]);
	}
	/* the change that carries them: renewed when the set changes */
	cn = ret == MAPISTORE_SUCCESS && state ? dav_change_value(tmp, f->ctx, talloc_asprintf(tmp, "%s#deleted-books", f->ctx->uri),
								     state, PidTagChangeNumber) : NULL;
	if (ret == MAPISTORE_SUCCESS && !cn) ret = MAPISTORE_ERR_NO_MEMORY;
	if (cn) *cnp = *cn;
	talloc_free(tmp);
	return ret;
}

static enum mapistore_error get_deleted_fmids(void *folder, TALLOC_CTX *mem_ctx, enum mapistore_table_type type,
					      uint64_t since, struct UI8Array_r **idsp, uint64_t *cnp)
{
	struct dav_folder	*f = folder;
	struct dav_context	*ctx;
	struct UI8Array_r	*ids;
	uint64_t		*cn;
	enum mapistore_error	ret;

	if (!f || f->type != DAV_OBJ_FOLDER || !idsp || !cnp) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	ctx = f->ctx;
	ids = talloc_zero(mem_ctx, struct UI8Array_r);
	if (!ids) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	*idsp = ids;
	if (type == MAPISTORE_FOLDER_TABLE) {
		return deleted_books(f, ids, cnp);
	}
	if (type != MAPISTORE_MESSAGE_TABLE) {
		return MAPISTORE_SUCCESS;
	}
	ret = dav_context_sync(ctx);
	if (ret != MAPISTORE_SUCCESS) {
		return ret;
	}
	if (ctx->ndeleted && !(ids->lpui8 = talloc_memdup(ids, ctx->deleted, ctx->ndeleted * sizeof(uint64_t)))) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	ids->cValues = ctx->ndeleted;
	/* The change that carries the deletions: renewed whenever one more is known. */
	cn = dav_change_value(ids, ctx, talloc_asprintf(ids, "%s#deleted", ctx->uri),
			      talloc_asprintf(ids, "deleted %u", ctx->deletions), PidTagChangeNumber);
	if (!cn) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	*cnp = *cn;
	return MAPISTORE_SUCCESS;
}

static void set(struct mapistore_property_data *d, void *value)
{
	d->data = value;
	d->error = value ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NOT_FOUND;
}

/* The book's name as last listed: a rename elsewhere shows once the listing is renewed; when the server cannot
   be asked, the name known so far (a missing name would change the folder's state). */
static char *book_displayname(struct dav_context *ctx)
{
	TALLOC_CTX	*tmp;
	struct dav_book	*books;
	size_t		n, i;
	char		*norm, *name;

	if (!(tmp = talloc_new(NULL))) {
		return ctx->displayname;
	}
	if (context_books(ctx, &books, &n) == MAPISTORE_SUCCESS) {
		for (i = 0; i < n; i++) {
			norm = dav_href_norm(tmp, books[i].href);
			if (norm && strcmp(norm, ctx->book_norm) == 0) {
				name = books[i].displayname ? books[i].displayname : books[i].segment;
				if (!ctx->displayname || strcmp(ctx->displayname, name) != 0) {
					talloc_free(ctx->displayname);
					ctx->displayname = talloc_strdup(ctx, name);
				}
				break;
			}
		}
	}
	talloc_free(tmp);
	return ctx->displayname;
}

/* The folder's state for ICS: the sync token, or every ETag when the server keeps no token. */
static char *folder_state(TALLOC_CTX *mem_ctx, struct dav_context *ctx)
{
	char	*s = talloc_asprintf(mem_ctx, "%zu %s %s", ctx->nitems, ctx->token ? ctx->token : "",
				     book_displayname(ctx) ? ctx->displayname : "");
	size_t	i;

	for (i = 0; s && !ctx->token && i < ctx->nitems; i++) {
		s = talloc_asprintf_append_buffer(s, " %s", ctx->items[i].etag);
	}
	return s;
}

static enum mapistore_error folder_properties(struct dav_folder *f, TALLOC_CTX *mem_ctx, uint16_t count,
					      enum MAPITAGS *tags, struct mapistore_property_data *data)
{
	struct dav_context	*ctx = f->ctx;
	bool			tried = false, synced = false;
	uint16_t		i;

	for (i = 0; i < count; i++) {
		struct mapistore_property_data *d = &data[i];

		d->data = NULL;
		d->error = MAPISTORE_ERR_NOT_FOUND;
		switch (tags[i]) {
		case PidTagChangeNumber:
		case PidTagChangeKey:
		case PidTagPredecessorChangeList:
		case PidTagLastModificationTime:
		/* Cached-mode Outlook resyncs a folder when its hierarchy row brings a newer commit time. */
		case PidTagLocalCommitTimeMax:
		case PidTagContentCount:
			if (!tried) {
				synced = dav_context_sync(ctx) == MAPISTORE_SUCCESS;
				tried = true;
			}
			if (synced) {
				set(d, tags[i] == PidTagContentCount ? (void *) dav_long(mem_ctx, ctx->nitems)
				       : dav_change_value(mem_ctx, ctx, ctx->uri, folder_state(mem_ctx, ctx), tags[i]));
			}
			break;
		case PidTagContentUnreadCount:
			set(d, dav_long(mem_ctx, 0));
			break;
		case PidTagSubfolders: {
			struct dav_folder **children;
			uint32_t n = 0;

			if (child_books(NULL, f, &children, &n) == MAPISTORE_SUCCESS) set(d, dav_bool(mem_ctx, n > 0));
			talloc_free(children);
			break;
		}
		case PidTagParentFolderId:
			if (f->parent_fid) set(d, dav_i8(mem_ctx, f->parent_fid));
			break;
		case PidTagAttributeHidden:
			set(d, dav_bool(mem_ctx, false));
			break;
		case PidTagDisplayName:
			set(d, book_displayname(ctx) ? talloc_strdup(mem_ctx, ctx->displayname) : NULL);
			break;
		case PidTagContainerClass:
			set(d, talloc_strdup(mem_ctx, "IPF.Contact"));
			break;
		case PidTagFolderType:
			set(d, dav_long(mem_ctx, 1)); /* FOLDER_GENERIC */
			break;
		case PidTagFolderId:
			set(d, dav_i8(mem_ctx, f->fid));
			break;
		default:
			break;
		}
	}
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error get_properties(void *object, TALLOC_CTX *mem_ctx, uint16_t count, enum MAPITAGS *tags,
					   struct mapistore_property_data *data)
{
	uint32_t *type = object;

	if (!object || (count && (!tags || !data))) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	switch (*type) {
	case DAV_OBJ_FOLDER:
		return folder_properties(object, mem_ctx, count, tags, data);
	case DAV_OBJ_MESSAGE:
		return dav_message_properties(object, mem_ctx, count, tags, data);
	case DAV_OBJ_ATTACHMENT:
		return dav_attachment_properties(((struct dav_attachment *) object)->message, mem_ctx, count, tags, data);
	default:
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
}

static const enum MAPITAGS folder_candidates[] = {
	PidTagDisplayName, PidTagContainerClass, PidTagContentCount, PidTagContentUnreadCount, PidTagSubfolders,
	PidTagFolderType, PidTagFolderId, PidTagParentFolderId, PidTagAttributeHidden, PidTagChangeNumber, PidTagChangeKey,
	PidTagPredecessorChangeList, PidTagLastModificationTime,
};

static const enum MAPITAGS message_candidates[] = {
	PidTagMessageClass, PidTagDisplayName, PidTagSurname, PidTagGivenName, PidTagMiddleName, PidTagDisplayNamePrefix,
	PidTagGeneration, PidTagBusinessTelephoneNumber, PidTagHomeTelephoneNumber, PidTagMobileTelephoneNumber,
	PidTagBusinessFaxNumber, PidTagCompanyName, PidTagDepartmentName, PidTagTitle, PidTagBody, PidTagBusinessHomePage,
	PidTagHomeAddressPostOfficeBox, PidTagHomeAddressStreet, PidTagHomeAddressCity, PidTagHomeAddressStateOrProvince,
	PidTagHomeAddressPostalCode, PidTagHomeAddressCountry, PidTagBirthday, PidTagMid, PidTagFolderId,
	PidTagParentFolderId, PidTagChangeNumber, PidTagChangeKey, PidTagPredecessorChangeList, PidTagLastModificationTime,
	PidTagMessageFlags, PidTagRead, PidTagHasAttachments,
};

static const enum MAPITAGS attachment_candidates[] = {
	PidTagAttachNumber, PidTagAttachMethod, PidTagAttachSize, PidTagRenderingPosition, PidTagAttachFlags,
	PidTagAttachmentHidden, PidTagAttachLongFilename, PidTagAttachFilename, PidTagDisplayName, PidTagAttachExtension,
	PidTagAttachDataBinary, PidTagAttachmentContactPhoto,
};

/* Candidates for an object type; messages add the contact's named properties of this store. */
static struct SPropTagArray *candidates(TALLOC_CTX *mem_ctx, struct dav_context *ctx, uint32_t type)
{
	const enum MAPITAGS	*fixed = type == DAV_OBJ_FOLDER ? folder_candidates : type == DAV_OBJ_ATTACHMENT ? attachment_candidates : message_candidates;
	size_t			n = type == DAV_OBJ_FOLDER ? N(folder_candidates)
				    : type == DAV_OBJ_ATTACHMENT ? N(attachment_candidates) : N(message_candidates);
	const uint32_t		*named = (const uint32_t *) &ctx->tags;	/* dav_named_tags holds only tags */
	size_t			nnamed = type == DAV_OBJ_MESSAGE ? sizeof ctx->tags / sizeof(uint32_t) : 0, i;
	struct SPropTagArray	*a = talloc_zero(mem_ctx, struct SPropTagArray);

	if (!a || !(a->aulPropTag = talloc_array(a, enum MAPITAGS, n + nnamed))) {
		talloc_free(a);
		return NULL;
	}
	for (i = 0; i < n; i++) a->aulPropTag[a->cValues++] = fixed[i];
	for (i = 0; i < nnamed; i++) a->aulPropTag[a->cValues++] = named[i];
	return a;
}

static struct dav_context *object_context(void *object)
{
	uint32_t *type = object;

	switch (*type) {
	case DAV_OBJ_FOLDER:	 return ((struct dav_folder *) object)->ctx;
	case DAV_OBJ_MESSAGE:	 return ((struct dav_message *) object)->folder->ctx;
	case DAV_OBJ_ATTACHMENT: return ((struct dav_attachment *) object)->message->folder->ctx;
	case DAV_OBJ_TABLE:	 return ((struct dav_table *) object)->folder->ctx;
	default:		 return NULL;
	}
}

/* The candidates this object has a value for: what ICS full sync and GetPropertiesAll send. */
static enum mapistore_error properties_available(void *object, TALLOC_CTX *mem_ctx, struct SPropTagArray **propsp)
{
	struct dav_context		*ctx = object && propsp ? object_context(object) : NULL;
	struct mapistore_property_data	*data;
	struct SPropTagArray		*all, *props;
	TALLOC_CTX			*tmp;
	uint32_t			i;

	if (!ctx || *(uint32_t *) object == DAV_OBJ_TABLE) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	tmp = talloc_new(NULL);
	all = tmp ? candidates(tmp, ctx, *(uint32_t *) object) : NULL;
	data = all ? talloc_zero_array(tmp, struct mapistore_property_data, all->cValues) : NULL;
	props = talloc_zero(mem_ctx, struct SPropTagArray);
	if (!data || !props || !(props->aulPropTag = talloc_array(props, enum MAPITAGS, all->cValues)) ||
	    get_properties(object, tmp, all->cValues, all->aulPropTag, data) != MAPISTORE_SUCCESS) {
		talloc_free(tmp);
		talloc_free(props);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	for (i = 0; i < all->cValues; i++) {
		if (data[i].error == MAPISTORE_SUCCESS) {
			props->aulPropTag[props->cValues++] = all->aulPropTag[i];
		}
	}
	talloc_free(tmp);
	*propsp = props;
	return MAPISTORE_SUCCESS;
}

/* Columns a table of this type can show. */
static enum mapistore_error table_available(void *object, TALLOC_CTX *mem_ctx, struct SPropTagArray **propsp)
{
	struct dav_table *t = object;

	if (!t || t->type != DAV_OBJ_TABLE || !propsp) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	*propsp = candidates(mem_ctx, t->folder->ctx, t->table_type == MAPISTORE_FOLDER_TABLE ? DAV_OBJ_FOLDER
			     : t->table_type == MAPISTORE_ATTACHMENT_TABLE ? DAV_OBJ_ATTACHMENT : DAV_OBJ_MESSAGE);
	return *propsp ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
}

static enum mapistore_error table_set_columns(void *object, uint16_t count, enum MAPITAGS *columns)
{
	struct dav_table *t = object;

	if (!t || t->type != DAV_OBJ_TABLE || (count && !columns)) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	talloc_free(t->columns);
	t->columns = count ? talloc_memdup(t, columns, sizeof(enum MAPITAGS) * count) : NULL;
	if (count && !t->columns) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	t->column_count = count;
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error table_get_row_count(void *object, enum mapistore_query_type type, uint32_t *count)
{
	struct dav_table *t = object;

	if (!t || t->type != DAV_OBJ_TABLE || !count) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	*count = t->row_count;
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error table_get_row(void *object, TALLOC_CTX *mem_ctx, enum mapistore_query_type type,
					  uint32_t row, struct mapistore_property_data **data)
{
	struct dav_table	*t = object;
	struct dav_item		*it;
	uint16_t		i;

	if (!t || t->type != DAV_OBJ_TABLE || !data) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (row >= t->row_count) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	*data = talloc_zero_array(mem_ctx, struct mapistore_property_data, t->column_count ? t->column_count : 1);
	if (!*data) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	if (t->table_type == MAPISTORE_ATTACHMENT_TABLE) {
		return dav_attachment_properties(t->message, mem_ctx, t->column_count, t->columns, *data);
	}
	if (t->table_type == MAPISTORE_FOLDER_TABLE) {
		return folder_properties(t->folders[row], mem_ctx, t->column_count, t->columns, *data);
	}
	/* a card removed by a later sync is gone from the table too */
	if (t->table_type != MAPISTORE_MESSAGE_TABLE || !(it = dav_item_by_mid(t->folder->ctx, t->mids[row]))) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	for (i = 0; i < t->column_count; i++) {
		set(&(*data)[i], dav_item_value(mem_ctx, t->folder, it->mid, it->norm, it->etag, it->card, t->columns[i]));
	}
	return MAPISTORE_SUCCESS;
}

/* R13: what one session last saw of each book, so every session of a user hears of every change. Owned by the
   session's connection info: it goes when the session does. */
struct dav_poll_book {
	char	*norm, *uri, *name;
	char	*state;		/* the sync token, or every href and ETag when the server keeps no token */
};

struct dav_poll {
	struct dav_poll				*prev, *next;
	const struct mapistore_connection_info	*owner;
	struct dav_poll_book			*books;
	size_t					nbooks;
	bool					primed;
};

static struct dav_poll *polls;

static int dav_poll_destructor(struct dav_poll *p)
{
	DLIST_REMOVE(polls, p);
	return 0;
}

static char *book_state(TALLOC_CTX *mem_ctx, struct dav_http *h, const struct dav_book *b)
{
	struct dav_change	*ch;
	size_t			n, i;
	char			*token, *s;
	bool			full;

	if (b->sync_token) return talloc_asprintf(mem_ctx, "token %s", b->sync_token);
	/* shortcut: the server's listing order is taken as stable; sort the lines if a server reorders them */
	if (dav_sync(h, mem_ctx, b->href, NULL, &ch, &n, &token, &full) != MAPISTORE_SUCCESS) return NULL;
	if (token) return talloc_asprintf(mem_ctx, "token %s", token);
	for (s = talloc_strdup(mem_ctx, "etags"), i = 0; s && i < n; i++) {
		s = talloc_asprintf_append_buffer(s, " %s %s", ch[i].href, ch[i].etag ? ch[i].etag : "-");
	}
	return s;
}

static bool change_add(TALLOC_CTX *mem_ctx, struct mapistore_change **list, size_t *n, const char *uri,
		       enum mapistore_change_kind kind)
{
	struct mapistore_change *grown = talloc_realloc(mem_ctx, *list, struct mapistore_change, *n + 1);

	if (!grown) return false;
	*list = grown;
	grown[*n].kind = kind;
	return (grown[(*n)++].uri = talloc_strdup(grown, uri)) != NULL;
}

/* One PROPFIND of the books (names and sync tokens), a full listing only for a book without a token. Added and
   deleted books are reported on personal, the folder holding them. */
static enum mapistore_error dav_poll_changes(struct mapistore_connection_info *conn_info, TALLOC_CTX *mem_ctx,
					     struct mapistore_change **listp, size_t *np)
{
	static const char	personal[] = DAV_CONTACTS_URI "personal/";
	struct dav_poll		*p;
	struct dav_poll_book	*now, *old;
	struct dav_book		*books;
	struct dav_http		*h;
	TALLOC_CTX		*tmp;
	enum mapistore_error	ret;
	size_t			nb, i, j;
	bool			ok = true;

	*listp = NULL;
	*np = 0;
	if (!dav_backend_settings()) return MAPISTORE_SUCCESS;
	if (!conn_info || !conn_info->username) return MAPISTORE_ERR_INVALID_PARAMETER;
	for (p = polls; p && p->owner != conn_info; p = p->next);
	if (!p) {
		if (!(p = talloc_zero(conn_info, struct dav_poll))) return MAPISTORE_ERR_NO_MEMORY;
		p->owner = conn_info;
		DLIST_ADD(polls, p);
		talloc_set_destructor(p, dav_poll_destructor);
	}
	if (!(tmp = talloc_new(NULL))) return MAPISTORE_ERR_NO_MEMORY;
	h = user_http(tmp, conn_info->username, home_url(tmp, conn_info->username));
	ret = h ? dav_list_books(h, tmp, &books, &nb) : MAPISTORE_ERR_CONN_REFUSED;
	now = ret == MAPISTORE_SUCCESS ? talloc_zero_array(p, struct dav_poll_book, nb + 1) : NULL;
	if (ret == MAPISTORE_SUCCESS && !now) ret = MAPISTORE_ERR_NO_MEMORY;
	for (i = 0; ret == MAPISTORE_SUCCESS && i < nb; i++) {
		now[i].norm = dav_href_norm(now, books[i].href);
		now[i].uri = talloc_asprintf(now, DAV_CONTACTS_URI "%s/", books[i].segment);
		now[i].name = talloc_strdup(now, books[i].displayname ? books[i].displayname : books[i].segment);
		if (!now[i].norm || !now[i].uri || !now[i].name) ret = MAPISTORE_ERR_NO_MEMORY;
		for (j = 0; ret == MAPISTORE_SUCCESS && j < p->nbooks && strcmp(p->books[j].norm, now[i].norm) != 0; j++);
		old = ret == MAPISTORE_SUCCESS && j < p->nbooks ? &p->books[j] : NULL;
		now[i].state = book_state(now, h, &books[i]);
		/* unreadable now: as last seen, so nothing is reported for it */
		if (!now[i].state && old && old->state) now[i].state = talloc_strdup(now, old->state);
		if (!p->primed || ret != MAPISTORE_SUCCESS) continue;
		if (!old) {
			ok = ok && change_add(mem_ctx, listp, np, personal, MAPISTORE_CHANGE_FOLDER_ADDED);
			continue;
		}
		if (strcmp(old->name, now[i].name) != 0) {
			ok = ok && change_add(mem_ctx, listp, np, now[i].uri, MAPISTORE_CHANGE_FOLDER_RENAMED);
		}
		if (now[i].state && old->state && strcmp(old->state, now[i].state) != 0) {
			ok = ok && change_add(mem_ctx, listp, np, now[i].uri, MAPISTORE_CHANGE_CONTENTS);
		}
	}
	for (j = 0; ret == MAPISTORE_SUCCESS && p->primed && j < p->nbooks; j++) {
		for (i = 0; i < nb && strcmp(p->books[j].norm, now[i].norm) != 0; i++);
		if (i == nb) ok = ok && change_add(mem_ctx, listp, np, personal, MAPISTORE_CHANGE_FOLDER_DELETED);
	}
	if (ret == MAPISTORE_SUCCESS && !ok) ret = MAPISTORE_ERR_NO_MEMORY;
	talloc_free(tmp);
	if (ret != MAPISTORE_SUCCESS) {
		/* the state stays as it was: the next poll reports these changes */
		talloc_free(now);
		talloc_free(*listp);
		*listp = NULL;
		*np = 0;
		return ret;
	}
	talloc_free(p->books);
	p->books = now;
	p->nbooks = nb;
	p->primed = true;
	/* reads stop reusing what they listed before */
	if (*np) generation++;
	return MAPISTORE_SUCCESS;
}

void dav_folder_fill(struct mapistore_backend *backend)
{
	backend->backend.poll_changes = dav_poll_changes;
	backend->backend.list_contexts = dav_list_contexts;
	backend->backend.create_context = dav_create_context;
	backend->context.get_path = get_path;
	backend->context.get_root_folder = get_root_folder;
	backend->folder.open_folder = open_folder;
	backend->folder.create_folder = create_folder;
	backend->folder.delete = delete_folder;
	backend->folder.delete_message = delete_message;
	backend->folder.open_table = open_table;
	backend->folder.get_child_count = get_child_count;
	backend->folder.get_deleted_fmids = get_deleted_fmids;
	backend->table.set_columns = table_set_columns;
	backend->table.get_row = table_get_row;
	backend->table.get_row_count = table_get_row_count;
	backend->table.get_available_properties = table_available;
	backend->properties.get_properties = get_properties;
	backend->properties.get_available_properties = properties_available;
}
