/*
   OpenChange Storage Abstraction Layer library
   Read-only IMAP backend: contexts, folders, hierarchy tables and folder properties

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

#include <string.h>
#include <strings.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "utils/dlinklist.h"
#include "mapiproxy/libmapiproxy/libmapiproxy.h"
#include "imap_backend.h"

/* One IMAP connection per user, shared by that user's contexts. The C worker that
   drives mapistore runs on a single thread, so this list needs no lock. */
struct shared_conn {
	struct shared_conn	*prev, *next;
	char			*username;
	struct imap_conn	*conn;
	unsigned		refs;
};
static struct shared_conn *shared_conns;

static struct shared_conn *find_shared(const char *username)
{
	struct shared_conn *s;

	for (s = shared_conns; s; s = s->next) {
		if (strcmp(s->username, username) == 0) {
			return s;
		}
	}
	return NULL;
}

/* The user's connection, reopened once when the server dropped it. */
_PUBLIC_ struct imap_conn *imap_context_conn(struct imap_context *ctx)
{
	const struct imap_settings	*settings = imap_backend_settings();
	struct shared_conn		*s = ctx->shared;

	if (!settings || !s) {
		return NULL;
	}
	if (!imap_conn_alive(s->conn)) {
		talloc_free(s->conn);
		s->conn = imap_conn_open(s, settings, s->username);
	}
	return s->conn;
}

static int context_destructor(struct imap_context *ctx)
{
	struct shared_conn *s = ctx->shared;

	if (s && --s->refs == 0) {
		DLIST_REMOVE(shared_conns, s);
		talloc_free(s);
	}
	return 0;
}

static struct imap_context *context_new(TALLOC_CTX *mem_ctx, const char *username, struct indexing_context *ictx)
{
	struct imap_context	*ctx = talloc_zero(mem_ctx, struct imap_context);
	struct shared_conn	*s;

	if (!ctx) {
		return NULL;
	}
	ctx->username = talloc_strdup(ctx, username);
	ctx->ictx = ictx;
	s = find_shared(username);
	if (!s) {
		s = talloc_zero(NULL, struct shared_conn);
		if (!s || !(s->username = talloc_strdup(s, username))) {
			talloc_free(s);
			talloc_free(ctx);
			return NULL;
		}
		DLIST_ADD(shared_conns, s);
	}
	s->refs++;
	ctx->shared = s;
	talloc_set_destructor(ctx, context_destructor);
	if (!ctx->username || !imap_context_conn(ctx)) {
		talloc_free(ctx);
		return NULL;
	}
	return ctx;
}

_PUBLIC_ char imap_context_delimiter(struct imap_context *ctx)
{
	return imap_conn_delimiter(imap_context_conn(ctx));
}

/* The folder ID of `uri`, allocated and recorded on first sight (replica ID 1, as
   mapistore_indexing_get_new_folderID_as_user builds it). */
_PUBLIC_ enum mapistore_error imap_fmid_for_uri(struct imap_context *ctx, const char *uri, uint64_t *fmid)
{
	struct indexing_context	*ictx = ctx->ictx;
	enum mapistore_error	ret;
	bool			soft_deleted = false;
	uint64_t		raw;

	ret = ictx->get_fmid(ictx, ctx->username, uri, false, fmid, &soft_deleted);
	if (ret == MAPISTORE_SUCCESS) {
		return MAPISTORE_SUCCESS;
	}
	ret = ictx->allocate_fmid(ictx, ctx->username, &raw);
	if (ret != MAPISTORE_SUCCESS) {
		return ret;
	}
	*fmid = (exchange_globcnt(raw) << 16) | 0x0001;
	return ictx->add_fmid(ictx, ctx->username, *fmid, uri);
}

static struct imap_folder *folder_new(TALLOC_CTX *mem_ctx, struct imap_context *ctx, const char *mailbox)
{
	struct imap_folder	*f = talloc_zero(mem_ctx, struct imap_folder);
	char			*uri;

	if (!f) {
		return NULL;
	}
	f->type = IMAP_OBJ_FOLDER;
	f->ctx = ctx;
	f->mailbox = talloc_strdup(f, mailbox);
	uri = imap_uri(f, ctx->username, mailbox, imap_context_delimiter(ctx));
	if (!f->mailbox || !uri || imap_fmid_for_uri(ctx, uri, &f->fid) != MAPISTORE_SUCCESS) {
		talloc_free(f);
		return NULL;
	}
	talloc_free(uri);
	return f;
}

/* Mailboxes Outlook should see: no \Noselect containers, \NonExistent names or \All views. */
static bool offered(const struct imap_mailbox *mb)
{
	return !(mb->flags & (IMAP_MB_NOSELECT | IMAP_MB_NONEXISTENT | IMAP_MB_ALL));
}

static enum mapistore_error add_entry(TALLOC_CTX *mem_ctx, struct mapistore_contexts_list **list, const char *username,
				      const struct imap_mailbox *mb, char delimiter, const char *name,
				      enum mapistore_context_role role, bool main_folder)
{
	struct mapistore_contexts_list *e = talloc_zero(mem_ctx, struct mapistore_contexts_list);

	if (!e) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	e->url = imap_uri(e, username, mb->name, delimiter);
	e->name = name ? talloc_strdup(e, name) : imap_display_name(e, mb->name, delimiter);
	e->role = role;
	e->main_folder = main_folder;
	if (!e->url || !e->name) {
		talloc_free(e);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	DLIST_ADD_END(*list, e, struct mapistore_contexts_list *);
	return MAPISTORE_SUCCESS;
}

/* Top-level mailboxes: INBOX, Drafts, Sent and Trash (SPECIAL-USE) as main folders, which take
   over the native ones; every other top-level mailbox as a secondary mail folder. */
_PUBLIC_ enum mapistore_error imap_list_contexts(const char *username, struct indexing_context *ictx,
						 TALLOC_CTX *mem_ctx, struct mapistore_contexts_list **listp)
{
	static const struct { uint32_t flag; enum mapistore_context_role role; } special[] = {
		{ IMAP_MB_DRAFTS, MAPISTORE_DRAFTS_ROLE }, { IMAP_MB_SENT, MAPISTORE_SENTITEMS_ROLE },
		{ IMAP_MB_TRASH, MAPISTORE_DELETEDITEMS_ROLE },
	};
	const struct imap_settings	*settings = imap_backend_settings();
	struct mapistore_contexts_list	*list = NULL;
	struct imap_mailbox		*mbs;
	struct imap_conn		*conn;
	bool				taken[MAPISTORE_MAX_ROLES] = { false };
	enum mapistore_error		ret;
	size_t				n, i, k;
	char				delimiter;

	*listp = NULL;
	if (!settings) {
		return imap_backend_broken() ? MAPISTORE_ERR_CONN_REFUSED : MAPISTORE_SUCCESS;
	}
	conn = imap_conn_open(mem_ctx, settings, username);
	if (!conn) {
		/* Not an empty list: provisioning would drop every IMAP folder it knows. */
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	delimiter = imap_conn_delimiter(conn);
	ret = imap_list(conn, conn, &mbs, &n);
	/* Outlook's Outbox lives in IMAP (one MIME path with Drafts), unsubscribed so that IMAP
	   clients honouring subscriptions hide it. */
	for (i = 0; ret == MAPISTORE_SUCCESS && i < n && strcmp(mbs[i].name, "Outbox") != 0; i++);
	if (ret == MAPISTORE_SUCCESS && i == n) {
		if (imap_create_mailbox(conn, "Outbox", false) == 0) {
			ret = imap_list(conn, conn, &mbs, &n);
		} else {
			OC_DEBUG(1, "IMAP backend: cannot create the Outbox mailbox; Outlook keeps its native Outbox\n");
		}
	}
	for (i = 0; ret == MAPISTORE_SUCCESS && i < n; i++) {
		const struct imap_mailbox *mb = &mbs[i];
		enum mapistore_context_role role = MAPISTORE_MAIL_ROLE;
		bool main_folder = false;
		const char *name = NULL;

		if (!offered(mb) || (delimiter && strchr(mb->name, delimiter))) {
			continue;
		}
		if (strcasecmp(mb->name, "INBOX") == 0) {
			main_folder = !taken[MAPISTORE_MAIL_ROLE];
			name = "Inbox";
		} else if (strcmp(mb->name, "Outbox") == 0 && !taken[MAPISTORE_OUTBOX_ROLE]) {
			role = MAPISTORE_OUTBOX_ROLE;
			main_folder = true;
		}
		for (k = 0; k < sizeof special / sizeof special[0]; k++) {
			if ((mb->flags & special[k].flag) && !taken[special[k].role]) {
				role = special[k].role;
				main_folder = true;
			}
		}
		taken[role] |= main_folder;
		ret = add_entry(mem_ctx, &list, username, mb, delimiter, name, role, main_folder);
	}
	talloc_free(conn);
	if (ret != MAPISTORE_SUCCESS) {
		return ret;
	}
	*listp = list;
	return MAPISTORE_SUCCESS;
}

/* The context's user is the session's own: a URI never chooses whose mailbox is opened. */
_PUBLIC_ enum mapistore_error imap_create_context(TALLOC_CTX *mem_ctx, struct mapistore_connection_info *conn_info,
						  struct indexing_context *ictx, const char *uri, void **backend_object)
{
	struct imap_context	*ctx;
	struct imap_folder	*root;
	char			*user, *mailbox;

	*backend_object = NULL;
	if (!conn_info || !conn_info->username || !ictx || !uri) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	/* mapistore_add_context hands over the URI without its "imap://" namespace. */
	if (strncmp(uri, IMAP_NAMESPACE, strlen(IMAP_NAMESPACE)) != 0) {
		uri = talloc_asprintf(mem_ctx, IMAP_NAMESPACE "%s", uri);
		if (!uri) {
			return MAPISTORE_ERR_NO_MEMORY;
		}
	}
	if (imap_uri_parse(mem_ctx, uri, '/', &user, &mailbox) != 0) {
		return MAPISTORE_ERR_INVALID_URI;
	}
	if (strcasecmp(user, conn_info->username) != 0) {
		OC_DEBUG(1, "IMAP backend: context URI names another mailbox; refused\n");
		return MAPISTORE_ERR_DENIED;
	}
	ctx = context_new(mem_ctx, conn_info->username, ictx);
	if (!ctx) {
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	ctx->oc_ctx = conn_info->oc_ctx;
	ctx->replica_guid = conn_info->replica_guid;
	if (ctx->oc_ctx) {
		uint16_t repl_id;

		openchangedb_get_MailboxReplica(ctx->oc_ctx, ctx->username, &repl_id, &ctx->replica_guid);
	}
	/* URIs are built with the server's delimiter; '/' was only a guess for the user part. */
	if (imap_context_delimiter(ctx) != '/' && imap_uri_parse(ctx, uri, imap_context_delimiter(ctx), &user, &mailbox) != 0) {
		talloc_free(ctx);
		return MAPISTORE_ERR_INVALID_URI;
	}
	root = folder_new(ctx, ctx, mailbox);
	if (!root) {
		talloc_free(ctx);
		return MAPISTORE_ERR_NOT_FOUND;
	}
	ctx->root = root;
	*backend_object = root;
	return MAPISTORE_SUCCESS;
}

/* Top-level folders Outlook creates stay native in openchangedb: Outlook creates hidden IPF.Note
   folders there itself (Sync Issues and its children), which must not show up in webmail. Folders
   created below an IMAP folder become mailboxes (create_folder). */
_PUBLIC_ enum mapistore_error imap_create_root_folder(const char *username, enum mapistore_context_role role,
						      uint64_t fid, const char *name, TALLOC_CTX *mem_ctx, char **uri)
{
	return MAPISTORE_ERR_NOT_FOUND;
}

static enum mapistore_error get_path(void *object, TALLOC_CTX *mem_ctx, uint64_t fmid, char **path)
{
	struct imap_folder	*f = object;
	bool			soft_deleted;

	if (!f || f->type != IMAP_OBJ_FOLDER) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	return f->ctx->ictx->get_uri(f->ctx->ictx, f->ctx->username, mem_ctx, fmid, path, &soft_deleted);
}

static enum mapistore_error get_root_folder(void *object, TALLOC_CTX *mem_ctx, uint64_t fid, void **folder)
{
	struct imap_folder *f = object;

	if (!f || f->type != IMAP_OBJ_FOLDER) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	/* emsmdb knows the root by the ID it provisioned; the indexing may hold another for the URI. */
	if (fid) {
		f->ctx->root->fid = fid;
	}
	*folder = f->ctx->root;
	return MAPISTORE_SUCCESS;
}

/* Opens a folder below `parent` by ID; any ID outside its subtree is NOT_FOUND. */
_PUBLIC_ enum mapistore_error imap_folder_open_folder(void *parent, TALLOC_CTX *mem_ctx, uint64_t fid, void **child)
{
	struct imap_folder	*p = parent, *f;
	struct imap_context	*ctx;
	char			*uri, *user, *mailbox;
	bool			soft_deleted = false;
	size_t			len;

	if (!p || p->type != IMAP_OBJ_FOLDER) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	ctx = p->ctx;
	if (ctx->ictx->get_uri(ctx->ictx, ctx->username, mem_ctx, fid, &uri, &soft_deleted) != MAPISTORE_SUCCESS ||
	    soft_deleted || imap_uri_parse(mem_ctx, uri, imap_context_delimiter(ctx), &user, &mailbox) != 0 ||
	    strcasecmp(user, ctx->username) != 0) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	len = strlen(p->mailbox);
	if (strncmp(mailbox, p->mailbox, len) != 0 || mailbox[len] != imap_context_delimiter(ctx)) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	f = folder_new(mem_ctx, ctx, mailbox);
	if (!f) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	if (!strchr(mailbox + len + 1, imap_context_delimiter(ctx))) {
		f->parent_fid = p->fid;
	}
	*child = f;
	return MAPISTORE_SUCCESS;
}

/* Direct children of `f`, in server order. */
static enum mapistore_error list_children(struct imap_folder *f, TALLOC_CTX *mem_ctx, char ***names, uint32_t *count)
{
	struct imap_conn	*conn = imap_context_conn(f->ctx);
	struct imap_mailbox	*mbs;
	char			delimiter = imap_context_delimiter(f->ctx);
	char			**out;
	size_t			n, i, len = strlen(f->mailbox);
	uint32_t		k = 0;

	if (!conn) {
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	if (!delimiter || imap_list(conn, mem_ctx, &mbs, &n) != MAPISTORE_SUCCESS) {
		*names = NULL;
		*count = 0;
		return delimiter ? MAPISTORE_ERR_NOT_FOUND : MAPISTORE_SUCCESS;
	}
	out = talloc_array(mem_ctx, char *, n ? n : 1);
	if (!out) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	for (i = 0; i < n; i++) {
		const char *name = mbs[i].name;

		if (offered(&mbs[i]) && strncmp(name, f->mailbox, len) == 0 && name[len] == delimiter &&
		    name[len + 1] && !strchr(name + len + 1, delimiter)) {
			out[k++] = talloc_steal(out, mbs[i].name);
		}
	}
	talloc_free(mbs);
	*names = out;
	*count = k;
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error imap_folder_get_child_count(void *object, enum mapistore_table_type type, uint32_t *count)
{
	struct imap_folder	*f = object;
	struct imap_status	st;
	char			**names;
	enum mapistore_error	ret;

	if (!f || f->type != IMAP_OBJ_FOLDER || !count) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	switch (type) {
	case MAPISTORE_FOLDER_TABLE:
		ret = list_children(f, f, &names, count);
		talloc_free(names);
		return ret;
	case MAPISTORE_MESSAGE_TABLE:
		if (imap_status(imap_context_conn(f->ctx), f->mailbox, &st) != MAPISTORE_SUCCESS) {
			return MAPISTORE_ERR_NOT_FOUND;
		}
		*count = st.messages;
		return MAPISTORE_SUCCESS;
	default:
		/* No FAI, rules or permissions are stored in IMAP. */
		*count = 0;
		return MAPISTORE_SUCCESS;
	}
}

/* All rows, in load order. */
static enum mapistore_error view_reset(struct imap_table *t)
{
	uint32_t i;

	talloc_free(t->view);
	t->view = talloc_array(t, uint32_t, t->row_count ? t->row_count : 1);
	if (!t->view) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	for (i = 0; i < t->row_count; i++) {
		t->view[i] = i;
	}
	t->view_count = t->row_count;
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error imap_folder_open_table(void *object, TALLOC_CTX *mem_ctx, enum mapistore_table_type type,
						     uint32_t handle_id, void **table, uint32_t *row_count)
{
	struct imap_folder	*f = object;
	struct imap_table	*t;
	enum mapistore_error	ret = MAPISTORE_SUCCESS;

	if (!f || f->type != IMAP_OBJ_FOLDER || !table || !row_count) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	t = talloc_zero(mem_ctx, struct imap_table);
	if (!t) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	t->type = IMAP_OBJ_TABLE;
	t->folder = f;
	t->table_type = type;
	switch (type) {
	case MAPISTORE_FOLDER_TABLE:
		ret = list_children(f, t, &t->children, &t->row_count);
		break;
	case MAPISTORE_MESSAGE_TABLE:
		ret = imap_message_table_load(t);
		break;
	default:
		break;
	}
	if (ret == MAPISTORE_SUCCESS) {
		ret = view_reset(t);
	}
	if (ret != MAPISTORE_SUCCESS) {
		talloc_free(t);
		return ret;
	}
	*table = t;
	*row_count = t->view_count;
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error imap_table_set_columns(void *object, uint16_t count, enum MAPITAGS *columns)
{
	struct imap_table *t = object;

	if (!t || t->type != IMAP_OBJ_TABLE || (count && !columns)) {
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

_PUBLIC_ enum mapistore_error imap_table_get_row_count(void *object, enum mapistore_query_type type, uint32_t *count)
{
	struct imap_table *t = object;

	if (!t || t->type != IMAP_OBJ_TABLE || !count) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	*count = t->view ? t->view_count : t->row_count;
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error imap_table_get_row(void *object, TALLOC_CTX *mem_ctx, enum mapistore_query_type type,
						 uint32_t row, struct mapistore_property_data **data)
{
	struct imap_table	*t = object;
	struct imap_folder	*child;
	enum mapistore_error	ret;

	if (!t || t->type != IMAP_OBJ_TABLE || !data) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (t->view) {
		if (row >= t->view_count) {
			return MAPISTORE_ERR_NOT_FOUND;
		}
		row = t->view[row];
	}
	if (row >= t->row_count) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	*data = talloc_zero_array(mem_ctx, struct mapistore_property_data, t->column_count ? t->column_count : 1);
	if (!*data) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	switch (t->table_type) {
	case MAPISTORE_FOLDER_TABLE:
		child = folder_new(mem_ctx, t->folder->ctx, t->children[row]);
		if (!child) {
			return MAPISTORE_ERR_NOT_FOUND;
		}
		child->parent_fid = t->folder->fid;
		ret = imap_folder_properties(child, mem_ctx, t->column_count, t->columns, *data);
		talloc_free(child);
		return ret;
	case MAPISTORE_MESSAGE_TABLE:
		return imap_message_row(t, mem_ctx, row, *data);
	case MAPISTORE_ATTACHMENT_TABLE:
		return imap_attachment_properties(&t->message->attachments[row], mem_ctx, t->column_count, t->columns, *data);
	default:
		return MAPISTORE_ERR_NOT_FOUND;
	}
}

/* One property of raw row `row`, or NULL. */
static void *table_value(TALLOC_CTX *mem_ctx, struct imap_table *t, uint32_t row, enum MAPITAGS tag)
{
	struct mapistore_property_data	d = { NULL, MAPISTORE_ERR_NOT_FOUND };
	struct imap_folder		*child;

	switch (t->table_type) {
	case MAPISTORE_MESSAGE_TABLE:
		return imap_row_value(mem_ctx, &t->rows[row], t->folder, tag);
	case MAPISTORE_FOLDER_TABLE:
		child = folder_new(mem_ctx, t->folder->ctx, t->children[row]);
		if (child) {
			child->parent_fid = t->folder->fid;
			imap_folder_properties(child, mem_ctx, 1, &tag, &d);
		}
		return d.error == MAPISTORE_SUCCESS ? d.data : NULL;
	case MAPISTORE_ATTACHMENT_TABLE:
		imap_attachment_properties(&t->message->attachments[row], mem_ctx, 1, &tag, &d);
		return d.error == MAPISTORE_SUCCESS ? d.data : NULL;
	default:
		return NULL;
	}
}

/* <0, 0, >0 for values of property type `type`; strings case-insensitive. */
static int compare_values(uint16_t type, const void *a, const void *b)
{
	switch (type) {
	case PT_LONG: {
		uint32_t x = *(const uint32_t *) a, y = *(const uint32_t *) b;
		return x < y ? -1 : x > y;
	}
	case PT_I8: {
		uint64_t x = *(const uint64_t *) a, y = *(const uint64_t *) b;
		return x < y ? -1 : x > y;
	}
	case PT_BOOLEAN:
		return (int) *(const uint8_t *) a - (int) *(const uint8_t *) b;
	case PT_SYSTIME: {
		const struct FILETIME *x = a, *y = b;
		uint64_t u = ((uint64_t) x->dwHighDateTime << 32) | x->dwLowDateTime;
		uint64_t v = ((uint64_t) y->dwHighDateTime << 32) | y->dwLowDateTime;
		return u < v ? -1 : u > v;
	}
	case PT_UNICODE:
	case PT_STRING8:
		return strcasecmp(a, b);
	case PT_BINARY: {
		const struct Binary_r *x = a, *y = b;
		int c = memcmp(x->lpb, y->lpb, x->cb < y->cb ? x->cb : y->cb);
		return c ? c : (x->cb < y->cb ? -1 : x->cb > y->cb);
	}
	default:
		return 0;
	}
}

/* The value a restriction compares against, as table_value returns it. */
static const void *restriction_value(const struct mapi_SPropValue *p, struct Binary_r *bin)
{
	switch (p->ulPropTag & 0xFFFF) {
	case PT_LONG:		return &p->value.l;
	case PT_I8:		return &p->value.d;
	case PT_BOOLEAN:	return &p->value.b;
	case PT_SYSTIME:	return &p->value.ft;
	case PT_UNICODE:	return p->value.lpszW;
	case PT_STRING8:	return p->value.lpszA;
	case PT_BINARY:
		bin->cb = p->value.bin.cb;
		bin->lpb = p->value.bin.lpb;
		return bin;
	default:		return NULL;
	}
}

static bool is_string_tag(uint32_t tag)
{
	return (tag & 0xFFFF) == PT_UNICODE || (tag & 0xFFFF) == PT_STRING8;
}

static bool contains(const char *hay, const char *needle, uint32_t fuzzy)
{
	size_t hl = strlen(hay), nl = strlen(needle), i;
	bool icase = fuzzy & 0x00010000;	/* FL_IGNORECASE */

	switch (fuzzy & 0xFFFF) {
	case 0:	/* FL_FULLSTRING */
		return (icase ? strcasecmp(hay, needle) : strcmp(hay, needle)) == 0;
	case 2:	/* FL_PREFIX */
		return nl <= hl && (icase ? strncasecmp(hay, needle, nl) : strncmp(hay, needle, nl)) == 0;
	default: /* FL_SUBSTRING */
		for (i = 0; i + nl <= hl; i++) {
			if ((icase ? strncasecmp(hay + i, needle, nl) : strncmp(hay + i, needle, nl)) == 0) {
				return true;
			}
		}
		return nl == 0;
	}
}

/* Whether raw row `row` matches `r`. Unsupported restrictions match (and are logged): showing
   a row too many beats an empty table. */
static bool matches(TALLOC_CTX *mem_ctx, struct imap_table *t, uint32_t row, const struct mapi_SRestriction *r, int depth)
{
	struct Binary_r	bin;
	const void	*want;
	void		*have;
	uint16_t	i;
	int		c;

	if (!r || depth > 16) {
		return true;
	}
	switch (r->rt) {
	case RES_AND:
		for (i = 0; i < r->res.resAnd.cRes; i++) {
			if (!matches(mem_ctx, t, row, (const struct mapi_SRestriction *) &r->res.resAnd.res[i], depth + 1)) return false;
		}
		return true;
	case RES_OR:
		for (i = 0; i < r->res.resOr.cRes; i++) {
			if (matches(mem_ctx, t, row, (const struct mapi_SRestriction *) &r->res.resOr.res[i], depth + 1)) return true;
		}
		return r->res.resOr.cRes == 0;
	case RES_EXIST:
		return table_value(mem_ctx, t, row, r->res.resExist.ulPropTag) != NULL;
	case RES_BITMASK:
		have = table_value(mem_ctx, t, row, r->res.resBitmask.ulPropTag);
		if (!have || (r->res.resBitmask.ulPropTag & 0xFFFF) != PT_LONG) {
			return r->res.resBitmask.relMBR == BMR_EQZ;
		}
		return ((*(uint32_t *) have & r->res.resBitmask.ulMask) == 0) == (r->res.resBitmask.relMBR == BMR_EQZ);
	case RES_CONTENT:
		/* Both sides strings of the tag's type, or the value would be read as the wrong member. */
		if (!is_string_tag(r->res.resContent.ulPropTag) ||
		    (r->res.resContent.ulPropTag & 0xFFFF) != (r->res.resContent.lpProp.ulPropTag & 0xFFFF)) {
			break;
		}
		want = restriction_value(&r->res.resContent.lpProp, &bin);
		if (!want) {
			break;
		}
		have = table_value(mem_ctx, t, row, r->res.resContent.ulPropTag);
		if (!have) {
			return false;
		}
		return contains(have, want, r->res.resContent.fuzzy);
	case RES_PROPERTY:
		if ((r->res.resProperty.ulPropTag & 0xFFFF) != (r->res.resProperty.lpProp.ulPropTag & 0xFFFF)) {
			break;
		}
		want = restriction_value(&r->res.resProperty.lpProp, &bin);
		if (!want) {
			break;
		}
		have = table_value(mem_ctx, t, row, r->res.resProperty.ulPropTag);
		if (!have) {
			return r->res.resProperty.relop == 5; /* RELOP_NE */
		}
		c = compare_values(r->res.resProperty.ulPropTag & 0xFFFF, have, want);
		switch (r->res.resProperty.relop) {
		case 0: return c < 0;	/* RELOP_LT */
		case 1: return c <= 0;	/* RELOP_LE */
		case 2: return c > 0;	/* RELOP_GT */
		case 3: return c >= 0;	/* RELOP_GE */
		case 4: return c == 0;	/* RELOP_EQ */
		case 5: return c != 0;	/* RELOP_NE */
		default: break;
		}
		break;
	default:
		break;
	}
	OC_DEBUG(3, "IMAP backend: restriction type %u not supported; rows are not filtered by it\n", r->rt);
	return true;
}

struct sort_key {
	uint32_t	row;
	void		**values;
};

static const struct SSortOrder	*sort_spec;
static uint16_t			sort_spec_count;

static int sort_cmp(const void *a, const void *b)
{
	const struct sort_key	*x = a, *y = b;
	uint16_t		i;

	for (i = 0; i < sort_spec_count; i++) {
		const void *u = x->values[i], *v = y->values[i];
		int c = (!u || !v) ? (u ? 1 : v ? -1 : 0) : compare_values(sort_spec[i].ulPropTag & 0xFFFF, u, v);

		if (c) {
			return sort_spec[i].ulOrder == TABLE_SORT_DESCEND ? -c : c;
		}
	}
	return x->row < y->row ? -1 : x->row > y->row; /* stable */
}

static enum mapistore_error view_sort(struct imap_table *t)
{
	TALLOC_CTX	*tmp;
	struct sort_key	*keys;
	uint32_t	i;
	uint16_t	k;

	if (!t->sort_count || t->view_count < 2) {
		return MAPISTORE_SUCCESS;
	}
	tmp = talloc_new(NULL);
	keys = talloc_array(tmp, struct sort_key, t->view_count);
	if (!keys) {
		talloc_free(tmp);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	for (i = 0; i < t->view_count; i++) {
		keys[i].row = t->view[i];
		keys[i].values = talloc_array(keys, void *, t->sort_count);
		if (!keys[i].values) {
			talloc_free(tmp);
			return MAPISTORE_ERR_NO_MEMORY;
		}
		for (k = 0; k < t->sort_count; k++) {
			keys[i].values[k] = table_value(keys, t, t->view[i], t->sort[k].ulPropTag);
		}
	}
	/* qsort has no context argument; the C worker runs mapistore on one thread. */
	sort_spec = t->sort;
	sort_spec_count = t->sort_count;
	qsort(keys, t->view_count, sizeof keys[0], sort_cmp);
	for (i = 0; i < t->view_count; i++) {
		t->view[i] = keys[i].row;
	}
	talloc_free(tmp);
	return MAPISTORE_SUCCESS;
}

/* The shape of a restriction for the log: types, operators and tags, never values. */
static char *describe(TALLOC_CTX *mem_ctx, const struct mapi_SRestriction *r, int depth)
{
	char	*out;
	uint16_t i;

	if (!r || depth > 6) {
		return talloc_strdup(mem_ctx, "...");
	}
	switch (r->rt) {
	case RES_AND:
	case RES_OR:
		out = talloc_asprintf(mem_ctx, "%s(", r->rt == RES_AND ? "AND" : "OR");
		for (i = 0; out && i < (r->rt == RES_AND ? r->res.resAnd.cRes : r->res.resOr.cRes); i++) {
			const struct mapi_SRestriction *c = (const struct mapi_SRestriction *)
				(r->rt == RES_AND ? (void *) &r->res.resAnd.res[i] : (void *) &r->res.resOr.res[i]);
			out = talloc_asprintf_append_buffer(out, "%s%s", i ? "," : "", describe(mem_ctx, c, depth + 1));
		}
		return out ? talloc_strdup_append_buffer(out, ")") : NULL;
	case RES_PROPERTY:
		return talloc_asprintf(mem_ctx, "PROP(%u,%.8x)", r->res.resProperty.relop, r->res.resProperty.ulPropTag);
	case RES_BITMASK:
		return talloc_asprintf(mem_ctx, "BITMASK(%u,%.8x,%.8x)", r->res.resBitmask.relMBR, r->res.resBitmask.ulPropTag, r->res.resBitmask.ulMask);
	case RES_EXIST:
		return talloc_asprintf(mem_ctx, "EXIST(%.8x)", r->res.resExist.ulPropTag);
	case RES_CONTENT:
		return talloc_asprintf(mem_ctx, "CONTENT(%.8x,%.8x)", r->res.resContent.fuzzy, r->res.resContent.ulPropTag);
	default:
		return talloc_asprintf(mem_ctx, "TYPE%u", r->rt);
	}
}

_PUBLIC_ enum mapistore_error imap_table_set_restrictions(void *object, struct mapi_SRestriction *res, uint8_t *status)
{
	struct imap_table	*t = object;
	TALLOC_CTX		*tmp;
	enum mapistore_error	ret;
	uint32_t		i, n = 0;

	if (!t || t->type != IMAP_OBJ_TABLE) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (status) {
		*status = 0; /* TBLSTAT_COMPLETE */
	}
	ret = view_reset(t);
	if (ret != MAPISTORE_SUCCESS || !res) {
		return ret == MAPISTORE_SUCCESS ? view_sort(t) : ret;
	}
	tmp = talloc_new(NULL);
	for (i = 0; i < t->row_count; i++) {
		if (matches(tmp, t, i, res, 0)) {
			t->view[n++] = i;
		}
	}
	OC_DEBUG(3, "IMAP backend: table type %d restricted by %s: %u of %u rows\n", t->table_type,
		 describe(tmp, res, 0), n, t->row_count);
	talloc_free(tmp);
	t->view_count = n;
	return view_sort(t);
}

_PUBLIC_ enum mapistore_error imap_table_set_sort_order(void *object, struct SSortOrderSet *set, uint8_t *status)
{
	struct imap_table *t = object;

	if (!t || t->type != IMAP_OBJ_TABLE) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (status) {
		*status = 0; /* TBLSTAT_COMPLETE */
	}
	talloc_free(t->sort);
	t->sort = NULL;
	t->sort_count = 0;
	if (set && set->cSorts && set->aSort) {
		t->sort = talloc_memdup(t, set->aSort, sizeof(struct SSortOrder) * set->cSorts);
		if (!t->sort) {
			return MAPISTORE_ERR_NO_MEMORY;
		}
		t->sort_count = set->cSorts;
	}
	return view_sort(t);
}

static void set(struct mapistore_property_data *d, void *value)
{
	d->data = value;
	d->error = value ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
}

_PUBLIC_ uint32_t *imap_long(TALLOC_CTX *mem_ctx, uint32_t v)
{
	uint32_t *p = talloc(mem_ctx, uint32_t);

	if (p) *p = v;
	return p;
}

_PUBLIC_ uint8_t *imap_bool(TALLOC_CTX *mem_ctx, bool v)
{
	uint8_t *p = talloc(mem_ctx, uint8_t);

	if (p) *p = v ? 1 : 0;
	return p;
}

_PUBLIC_ uint64_t *imap_i8(TALLOC_CTX *mem_ctx, uint64_t v)
{
	uint64_t *p = talloc(mem_ctx, uint64_t);

	if (p) *p = v;
	return p;
}

/* A change kept per object URI for the life of the process (bounded by the objects shown). */
struct change {
	struct change	*prev, *next;
	char		*key;		/* user, then URI */
	char		*state;
	uint64_t	cn;
	time_t		when;
};
static struct change *changes;

static enum mapistore_error openchangedb_cn(struct imap_context *ctx, uint64_t *cn)
{
	if (!ctx->oc_ctx) {
		return MAPISTORE_ERR_NOT_INITIALIZED;
	}
	return openchangedb_get_new_changeNumber(ctx->oc_ctx, ctx->username, cn) == MAPI_E_SUCCESS
		? MAPISTORE_SUCCESS : MAPISTORE_ERR_DATABASE_OPS;
}
static imap_cn_source cn_source = openchangedb_cn;

_PUBLIC_ void imap_backend_set_cn_source(imap_cn_source source)
{
	cn_source = source ? source : openchangedb_cn;
}

_PUBLIC_ enum mapistore_error imap_change_number(struct imap_context *ctx, const char *uri, const char *state,
						 uint64_t *cn, time_t *when)
{
	struct change		*c;
	char			*key = talloc_asprintf(NULL, "%s\n%s", ctx->username, uri);
	enum mapistore_error	ret;

	if (!key || !state) {
		talloc_free(key);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	for (c = changes; c && strcmp(c->key, key) != 0; c = c->next);
	if (c && strcmp(c->state, state) == 0) {
		talloc_free(key);
		*cn = c->cn;
		*when = c->when;
		return MAPISTORE_SUCCESS;
	}
	ret = cn_source(ctx, cn);
	if (ret != MAPISTORE_SUCCESS) {
		talloc_free(key);
		return ret;
	}
	if (!c) {
		c = talloc_zero(NULL, struct change);
		if (!c) {
			talloc_free(key);
			return MAPISTORE_ERR_NO_MEMORY;
		}
		c->key = talloc_steal(c, key);
		DLIST_ADD(changes, c);
	} else {
		talloc_free(key);
	}
	talloc_free(c->state);
	c->state = talloc_strdup(c, state);
	c->cn = *cn;
	c->when = time(NULL);
	*when = c->when;
	return c->state ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
}

/* XID of a change: the replica GUID (NDR) and the 6 low bytes of cn >> 16, as oxcfxics_make_gid. */
static struct Binary_r *change_key(TALLOC_CTX *mem_ctx, const struct GUID *g, uint64_t cn, bool sized)
{
	struct Binary_r	*b = talloc_zero(mem_ctx, struct Binary_r);
	uint8_t		*p;
	uint64_t	id = (cn >> 16) & 0x0000FFFFFFFFFFFFULL;
	int		i;

	if (!b || !(b->lpb = talloc_array(b, uint8_t, 23))) {
		return NULL;
	}
	p = b->lpb;
	if (sized) {
		*p++ = 22; /* PredecessorChangeList: one SizedXid */
	}
	for (i = 0; i < 4; i++) *p++ = (g->time_low >> (8 * i)) & 0xFF;
	for (i = 0; i < 2; i++) *p++ = (g->time_mid >> (8 * i)) & 0xFF;
	for (i = 0; i < 2; i++) *p++ = (g->time_hi_and_version >> (8 * i)) & 0xFF;
	memcpy(p, g->clock_seq, 2);
	p += 2;
	memcpy(p, g->node, 6);
	p += 6;
	for (i = 0; i < 6; i++, id >>= 8) *p++ = id & 0xFF;
	b->cb = sized ? 23 : 22;
	return b;
}

static struct FILETIME *change_time(TALLOC_CTX *mem_ctx, time_t t)
{
	struct FILETIME	*ft = talloc(mem_ctx, struct FILETIME);
	uint64_t	nt = ((uint64_t) t + 11644473600ULL) * 10000000ULL;

	if (ft) {
		ft->dwLowDateTime = (uint32_t) nt;
		ft->dwHighDateTime = (uint32_t) (nt >> 32);
	}
	return ft;
}

_PUBLIC_ void *imap_change_value(TALLOC_CTX *mem_ctx, struct imap_context *ctx, uint64_t cn, time_t when,
				 enum MAPITAGS tag)
{
	switch (tag) {
	case PidTagChangeNumber:		return imap_i8(mem_ctx, cn);
	case PidTagChangeKey:			return change_key(mem_ctx, &ctx->replica_guid, cn, false);
	case PidTagPredecessorChangeList:	return change_key(mem_ctx, &ctx->replica_guid, cn, true);
	case PidTagLastModificationTime:	return change_time(mem_ctx, when);
	default:				return NULL;
	}
}

/* Folder properties (plan Decision 6); STATUS is asked only when a count is wanted. */
_PUBLIC_ enum mapistore_error imap_folder_properties(struct imap_folder *f, TALLOC_CTX *mem_ctx, uint16_t count,
						     enum MAPITAGS *tags, struct mapistore_property_data *data)
{
	struct imap_status	st;
	bool			have_status = false, status_failed = false;
	uint32_t		children = 0;
	bool			have_children = false;
	char			**names = NULL;
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
			if (!have_status && !status_failed) {
				status_failed = imap_status(imap_context_conn(f->ctx), f->mailbox, &st) != MAPISTORE_SUCCESS;
				have_status = !status_failed;
			}
			if (have_status) {
				char *uri = imap_uri(mem_ctx, f->ctx->username, f->mailbox, imap_context_delimiter(f->ctx));
				char *state = talloc_asprintf(mem_ctx, "%u:%u:%u:%u", st.uidvalidity, st.messages, st.unseen, st.uidnext);
				uint64_t cn;
				time_t when;

				if (uri && state && imap_change_number(f->ctx, uri, state, &cn, &when) == MAPISTORE_SUCCESS) {
					set(d, imap_change_value(mem_ctx, f->ctx, cn, when, tags[i]));
				}
			}
			break;
		case PidTagContentCount:
		case PidTagContentUnreadCount:
			if (!have_status && !status_failed) {
				status_failed = imap_status(imap_context_conn(f->ctx), f->mailbox, &st) != MAPISTORE_SUCCESS;
				have_status = !status_failed;
			}
			if (have_status) {
				set(d, imap_long(mem_ctx, tags[i] == PidTagContentCount ? st.messages : st.unseen));
			}
			break;
		case PidTagSubfolders:
			if (!have_children) {
				have_children = list_children(f, mem_ctx, &names, &children) == MAPISTORE_SUCCESS;
				talloc_free(names);
			}
			if (have_children) {
				set(d, imap_bool(mem_ctx, children > 0));
			}
			break;
		case PidTagDisplayName:
			set(d, strcasecmp(f->mailbox, "INBOX") == 0 ? talloc_strdup(mem_ctx, "Inbox")
			       : imap_display_name(mem_ctx, f->mailbox, imap_context_delimiter(f->ctx)));
			break;
		case PidTagContainerClass:
			set(d, talloc_strdup(mem_ctx, "IPF.Note"));
			break;
		case PidTagFolderType:
			set(d, imap_long(mem_ctx, 1)); /* FOLDER_GENERIC */
			break;
		case PidTagFolderId:
			set(d, imap_i8(mem_ctx, f->fid));
			break;
		case PidTagParentFolderId:
			if (f->parent_fid) {
				set(d, imap_i8(mem_ctx, f->parent_fid));
			}
			break;
		case PidTagAttributeHidden:
			set(d, imap_bool(mem_ctx, false));
			break;
		default:
			break;
		}
	}
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error imap_properties_get(void *object, TALLOC_CTX *mem_ctx, uint16_t count,
						  enum MAPITAGS *tags, struct mapistore_property_data *data)
{
	uint32_t *type = object;

	if (!object || (count && (!tags || !data))) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	switch (*type) {
	case IMAP_OBJ_FOLDER:
		return imap_folder_properties(object, mem_ctx, count, tags, data);
	case IMAP_OBJ_MESSAGE:
		return imap_message_properties(object, mem_ctx, count, tags, data);
	case IMAP_OBJ_ATTACHMENT:
		return imap_attachment_properties(object, mem_ctx, count, tags, data);
	case IMAP_OBJ_DRAFT_ATTACHMENT:
		object = imap_draft_attachment_get(object);
		return object ? imap_attachment_properties(object, mem_ctx, count, tags, data) : MAPISTORE_ERR_NOT_FOUND;
	default:
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
}

static const enum MAPITAGS folder_candidates[] = {
	PidTagDisplayName, PidTagContainerClass, PidTagContentCount, PidTagContentUnreadCount, PidTagSubfolders,
	PidTagFolderType, PidTagFolderId, PidTagParentFolderId, PidTagAttributeHidden, PidTagChangeNumber,
	PidTagChangeKey, PidTagPredecessorChangeList, PidTagLastModificationTime,
};

static const enum MAPITAGS message_candidates[] = {
	PidTagSubject, PidTagNormalizedSubject, PidTagSubjectPrefix, PidTagConversationTopic, PidTagSenderName,
	PidTagSenderEmailAddress, PidTagSenderSmtpAddress, PidTagSenderAddressType, PidTagSentRepresentingName,
	PidTagSentRepresentingEmailAddress, PidTagSentRepresentingSmtpAddress, PidTagSentRepresentingAddressType,
	PidTagDisplayTo, PidTagDisplayCc, PidTagDisplayBcc, PidTagMessageDeliveryTime, PidTagClientSubmitTime,
	PidTagCreationTime, PidTagLastModificationTime, PidTagMessageSize, PidTagMessageFlags, PidTagRead,
	PidTagHasAttachments, PidTagMessageClass, PidTagInternetMessageId, PidTagImportance, PidTagSensitivity,
	PidTagPriority, PidTagIconIndex, PidTagFlagStatus, PidTagMid, PidTagFolderId, PidTagParentFolderId,
	PidTagChangeNumber, PidTagChangeKey, PidTagPredecessorChangeList, PidTagBody, PidTagHtml, PidTagNativeBody,
	PidTagInternetCodepage, PidTagTransportMessageHeaders,
};

static const enum MAPITAGS attachment_candidates[] = {
	PidTagAttachNumber, PidTagAttachMethod, PidTagAttachSize, PidTagRenderingPosition, PidTagAttachFlags,
	PidTagAttachmentHidden, PidTagAttachLongFilename, PidTagAttachFilename, PidTagDisplayName,
	PidTagAttachExtension, PidTagAttachMimeTag, PidTagAttachContentId, PidTagAttachDataBinary,
};

/* The candidates this object has a value for: what ICS full sync and GetPropertiesAll send. */
_PUBLIC_ enum mapistore_error imap_properties_available(void *object, TALLOC_CTX *mem_ctx, struct SPropTagArray **propsp)
{
	const enum MAPITAGS		*candidates;
	struct mapistore_property_data	*data;
	struct SPropTagArray		*props;
	TALLOC_CTX			*tmp;
	uint16_t			n, i;
	uint32_t			*type = object;

	if (!object || !propsp) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	switch (*type) {
	case IMAP_OBJ_FOLDER:	  candidates = folder_candidates; n = sizeof folder_candidates / sizeof folder_candidates[0]; break;
	case IMAP_OBJ_MESSAGE:	  candidates = message_candidates; n = sizeof message_candidates / sizeof message_candidates[0]; break;
	case IMAP_OBJ_ATTACHMENT:
	case IMAP_OBJ_DRAFT_ATTACHMENT: candidates = attachment_candidates; n = sizeof attachment_candidates / sizeof attachment_candidates[0]; break;
	default:		  return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	tmp = talloc_new(NULL);
	data = talloc_zero_array(tmp, struct mapistore_property_data, n);
	props = talloc_zero(mem_ctx, struct SPropTagArray);
	if (!tmp || !data || !props || !(props->aulPropTag = talloc_array(props, enum MAPITAGS, n)) ||
	    imap_properties_get(object, tmp, n, (enum MAPITAGS *) candidates, data) != MAPISTORE_SUCCESS) {
		talloc_free(tmp);
		talloc_free(props);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	for (i = 0; i < n; i++) {
		if (data[i].error == MAPISTORE_SUCCESS) {
			props->aulPropTag[props->cValues++] = candidates[i];
		}
	}
	talloc_free(tmp);
	*propsp = props;
	return MAPISTORE_SUCCESS;
}

/* Columns a table of this type can show. */
_PUBLIC_ enum mapistore_error imap_table_available(void *object, TALLOC_CTX *mem_ctx, struct SPropTagArray **propsp)
{
	struct imap_table	*t = object;
	const enum MAPITAGS	*candidates;
	size_t			n;

	if (!t || t->type != IMAP_OBJ_TABLE || !propsp) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	switch (t->table_type) {
	case MAPISTORE_FOLDER_TABLE:	 candidates = folder_candidates; n = sizeof folder_candidates / sizeof folder_candidates[0]; break;
	case MAPISTORE_ATTACHMENT_TABLE: candidates = attachment_candidates; n = sizeof attachment_candidates / sizeof attachment_candidates[0]; break;
	default:			 candidates = message_candidates; n = sizeof message_candidates / sizeof message_candidates[0]; break;
	}
	*propsp = talloc_zero(mem_ctx, struct SPropTagArray);
	if (!*propsp || !((*propsp)->aulPropTag = talloc_memdup(*propsp, candidates, n * sizeof candidates[0]))) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	(*propsp)->cValues = n;
	return MAPISTORE_SUCCESS;
}

/* Write operations keep mapistore's defaults (MAPISTORE_ERR_NOT_IMPLEMENTED): M3 is read-only. */
/* An IMAP write the server refused, or a connection that went away. */
static enum mapistore_error write_error(struct imap_conn *conn)
{
	return imap_conn_alive(conn) ? MAPISTORE_ERR_DENIED : MAPISTORE_ERR_CONN_REFUSED;
}

/* The UIDs of `mids` in `f`, all of the mailbox's current UIDVALIDITY. */
static enum mapistore_error mids_to_uids(struct imap_folder *f, struct imap_conn *conn, TALLOC_CTX *mem_ctx,
					 uint32_t count, const uint64_t *mids, uint32_t **uidsp)
{
	struct imap_status	st;
	uint32_t		*uids, v, i;

	if (imap_status(conn, f->mailbox, &st) != MAPISTORE_SUCCESS) {
		return imap_conn_alive(conn) ? MAPISTORE_ERR_NOT_FOUND : MAPISTORE_ERR_CONN_REFUSED;
	}
	uids = talloc_array(mem_ctx, uint32_t, count);
	if (!uids) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	for (i = 0; i < count; i++) {
		if (imap_mid_uid(f, uids, mids[i], &v, &uids[i]) != MAPISTORE_SUCCESS || v != st.uidvalidity) {
			talloc_free(uids);
			return MAPISTORE_ERR_NOT_FOUND;
		}
	}
	*uidsp = uids;
	return MAPISTORE_SUCCESS;
}

/* UID MOVE/COPY between two IMAP folders of the user; the index follows only once the server said OK. */
static enum mapistore_error move_copy_messages(void *target_folder, void *source_folder, TALLOC_CTX *mem_ctx,
					       uint32_t count, uint64_t *src_mids, uint64_t *t_mids,
					       struct Binary_r **change_keys, struct Binary_r **predecessors,
					       uint8_t want_copy)
{
	struct imap_folder	*dst = target_folder, *src = source_folder;
	struct indexing_context	*ictx;
	struct imap_conn	*conn;
	uint32_t		*uids, *dest, validity = 0, i;
	TALLOC_CTX		*tmp;
	enum mapistore_error	ret;

	/* Another backend's folder (openchangedb) cannot hold an IMAP message: emsmdb answers NO_SUPPORT. */
	if (!dst || !src || dst->type != IMAP_OBJ_FOLDER || src->type != IMAP_OBJ_FOLDER ||
	    strcmp(dst->ctx->username, src->ctx->username) != 0) {
		return MAPISTORE_ERR_DENIED;
	}
	if (count == 0) {
		return MAPISTORE_SUCCESS;
	}
	if (!src_mids) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	conn = imap_context_conn(src->ctx);
	if (!conn) {
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	tmp = talloc_new(NULL);
	dest = tmp ? talloc_zero_array(tmp, uint32_t, count) : NULL;
	if (!dest) {
		talloc_free(tmp);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	ret = mids_to_uids(src, conn, tmp, count, src_mids, &uids);
	if (ret != MAPISTORE_SUCCESS) {
		talloc_free(tmp);
		return ret;
	}
	if (imap_uid_move(conn, src->mailbox, uids, count, dst->mailbox, want_copy, &validity, dest)) {
		talloc_free(tmp);
		return write_error(conn);
	}
	ictx = dst->ctx->ictx;
	for (i = 0; i < count; i++) {
		char *uri = imap_message_uri(tmp, dst, validity, dest[i]);
		enum mapistore_error r = MAPISTORE_SUCCESS;

		if (!uri) {
			r = MAPISTORE_ERR_NO_MEMORY;
		} else if (t_mids && t_mids[i]) {
			/* emsmdb allocated the target mid: the message answers to it from now on. */
			r = ictx->add_fmid(ictx, dst->ctx->username, t_mids[i], uri);
			if (r == MAPISTORE_SUCCESS && !want_copy) {
				r = ictx->del_fmid(ictx, src->ctx->username, src_mids[i], MAPISTORE_PERMANENT_DELETE);
			}
		} else if (!want_copy) {
			r = ictx->update_fmid(ictx, dst->ctx->username, src_mids[i], uri);
		}
		if (r != MAPISTORE_SUCCESS) {
			/* IMAP already moved it; the next listing gives it a fresh mid. */
			OC_DEBUG(1, "IMAP backend: index update after %s of mid 0x%"PRIx64" failed: %s\n",
				 want_copy ? "copy" : "move", src_mids[i], mapistore_errstr(r));
		}
	}
	talloc_free(tmp);
	return MAPISTORE_SUCCESS;
}

/* Shift+Delete, emptying Deleted Items, ICS deletes: gone from IMAP, exactly this UID. */
static enum mapistore_error delete_message(void *folder, uint64_t mid, uint8_t flags)
{
	struct imap_folder	*f = folder;
	struct imap_conn	*conn;
	uint32_t		*uid;
	enum mapistore_error	ret;

	if (!f || f->type != IMAP_OBJ_FOLDER) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	conn = imap_context_conn(f->ctx);
	if (!conn) {
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	ret = mids_to_uids(f, conn, f, 1, &mid, &uid);
	if (ret != MAPISTORE_SUCCESS) {
		return ret;
	}
	if (imap_uid_expunge(conn, f->mailbox, uid, 1)) {
		talloc_free(uid);
		return write_error(conn);
	}
	talloc_free(uid);
	ret = f->ctx->ictx->del_fmid(f->ctx->ictx, f->ctx->username, mid, MAPISTORE_PERMANENT_DELETE);
	if (ret != MAPISTORE_SUCCESS) {
		OC_DEBUG(1, "IMAP backend: index delete of mid 0x%"PRIx64" failed: %s\n", mid, mapistore_errstr(ret));
	}
	return MAPISTORE_SUCCESS;
}

/* Inbox, Outbox and the SPECIAL-USE mailboxes are the user's default folders: Outlook cannot
   rename, move or delete them (webmail and other clients rely on them). */
static bool is_default_folder(struct imap_folder *f, struct imap_conn *conn)
{
	struct imap_mailbox	*mbs;
	size_t			n, i;
	bool			special = false;

	if (strcasecmp(f->mailbox, "INBOX") == 0 || strcmp(f->mailbox, "Outbox") == 0) {
		return true;
	}
	if (imap_list(conn, f, &mbs, &n) != MAPISTORE_SUCCESS) {
		return true; /* unknown: do not touch it */
	}
	for (i = 0; i < n; i++) {
		if (strcmp(mbs[i].name, f->mailbox) == 0) {
			special = mbs[i].flags & (IMAP_MB_SENT | IMAP_MB_DRAFTS | IMAP_MB_TRASH | IMAP_MB_JUNK |
						  IMAP_MB_ARCHIVE | IMAP_MB_ALL);
		}
	}
	talloc_free(mbs);
	return special;
}

static const char *row_string(struct SRow *row, enum MAPITAGS unicode_tag, enum MAPITAGS string8_tag)
{
	uint32_t i;

	for (i = 0; row && i < row->cValues; i++) {
		if ((enum MAPITAGS) row->lpProps[i].ulPropTag == unicode_tag) {
			return row->lpProps[i].value.lpszW;
		}
		if ((enum MAPITAGS) row->lpProps[i].ulPropTag == string8_tag) {
			return row->lpProps[i].value.lpszA;
		}
	}
	return NULL;
}

/* `parent`'s mailbox + delimiter + `leaf` (already on-the-wire). */
static char *child_mailbox(TALLOC_CTX *mem_ctx, const char *parent, char delimiter, const char *leaf)
{
	return parent && parent[0] ? talloc_asprintf(mem_ctx, "%s%c%s", parent, delimiter, leaf) : talloc_strdup(mem_ctx, leaf);
}

/* RENAME `f` to `to`, then everything indexed below it follows: same fids and mids. */
static enum mapistore_error rename_folder(struct imap_folder *f, struct imap_conn *conn, const char *to)
{
	struct imap_context	*ctx = f->ctx;
	char			delimiter = imap_context_delimiter(ctx);
	char			*old_uri, *new_uri;
	enum mapistore_error	ret;

	if (is_default_folder(f, conn)) {
		return MAPISTORE_ERR_DENIED;
	}
	old_uri = imap_uri(f, ctx->username, f->mailbox, delimiter);
	new_uri = imap_uri(f, ctx->username, to, delimiter);
	if (!old_uri || !new_uri) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	if (imap_rename_mailbox(conn, f->mailbox, to)) {
		return write_error(conn);
	}
	ret = ctx->ictx->update_uri_prefix
		? ctx->ictx->update_uri_prefix(ctx->ictx, ctx->username, old_uri, new_uri) : MAPISTORE_ERR_NOT_IMPLEMENTED;
	if (ret != MAPISTORE_SUCCESS) {
		/* The folder kept its name in IMAP's eyes only: the next sync shows it as new. */
		OC_DEBUG(1, "IMAP backend: index rewrite after RENAME failed: %s\n", mapistore_errstr(ret));
	}
	/* A context root is also known to openchangedb by its URI (provisioning). */
	if (f == ctx->root && ctx->oc_ctx &&
	    openchangedb_set_mapistoreURI(ctx->oc_ctx, ctx->username, f->fid, new_uri) != MAPI_E_SUCCESS) {
		OC_DEBUG(1, "IMAP backend: openchangedb URI update after RENAME failed\n");
	}
	talloc_free(f->mailbox);
	f->mailbox = talloc_strdup(f, to);
	talloc_free(old_uri);
	talloc_free(new_uri);
	return f->mailbox ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
}

/* A mail folder created below an IMAP folder becomes an IMAP mailbox, subscribed. */
static enum mapistore_error create_folder(void *parent, TALLOC_CTX *mem_ctx, uint64_t fid, struct SRow *aRow,
					  void **childp)
{
	struct imap_folder	*p = parent, *f;
	struct imap_conn	*conn;
	const char		*name, *klass;
	char			*leaf, *mailbox, *uri;
	char			delimiter;
	enum mapistore_error	ret;

	if (!p || p->type != IMAP_OBJ_FOLDER || !childp || !fid) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	klass = row_string(aRow, PidTagContainerClass, PR_CONTAINER_CLASS);
	if (klass && strncmp(klass, "IPF.Note", 8) != 0) {
		return MAPISTORE_ERR_DENIED; /* calendars, contacts...: IMAP cannot hold them */
	}
	conn = imap_context_conn(p->ctx);
	if (!conn) {
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	delimiter = imap_context_delimiter(p->ctx);
	name = row_string(aRow, PidTagDisplayName, PR_DISPLAY_NAME);
	leaf = imap_mailbox_name(mem_ctx, name, delimiter);
	if (!leaf || !delimiter) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	mailbox = child_mailbox(mem_ctx, p->mailbox, delimiter, leaf);
	uri = mailbox ? imap_uri(mem_ctx, p->ctx->username, mailbox, delimiter) : NULL;
	if (!uri) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	if (imap_create_mailbox(conn, mailbox, true)) {
		return write_error(conn);
	}
	ret = p->ctx->ictx->add_fmid(p->ctx->ictx, p->ctx->username, fid, uri);
	if (ret != MAPISTORE_SUCCESS) {
		OC_DEBUG(1, "IMAP backend: index add of new folder 0x%"PRIx64" failed: %s\n", fid, mapistore_errstr(ret));
	}
	f = folder_new(mem_ctx, p->ctx, mailbox);
	if (!f) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	f->parent_fid = p->fid;
	*childp = f;
	return MAPISTORE_SUCCESS;
}

/* Folder properties: a new PidTagDisplayName renames the mailbox; others are not kept. */
_PUBLIC_ enum mapistore_error imap_folder_set_properties(struct imap_folder *f, struct SRow *row)
{
	struct imap_conn	*conn;
	const char		*name = row_string(row, PidTagDisplayName, PR_DISPLAY_NAME);
	const char		*sep;
	char			*leaf, *to, *parent;
	char			delimiter = imap_context_delimiter(f->ctx);

	if (!name) {
		return MAPISTORE_SUCCESS;
	}
	leaf = imap_mailbox_name(f, name, delimiter);
	if (!leaf || !delimiter) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	sep = strrchr(f->mailbox, delimiter);
	parent = sep ? talloc_strndup(leaf, f->mailbox, sep - f->mailbox) : NULL;
	to = child_mailbox(leaf, parent, delimiter, leaf);
	if (!to) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	if (strcmp(to, f->mailbox) == 0) {
		talloc_free(leaf);
		return MAPISTORE_SUCCESS;
	}
	conn = imap_context_conn(f->ctx);
	if (!conn) {
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	{
		enum mapistore_error ret = rename_folder(f, conn, to);

		talloc_free(leaf);
		return ret;
	}
}

static enum mapistore_error move_folder(void *folder, void *target_parent, TALLOC_CTX *mem_ctx, const char *new_name)
{
	struct imap_folder	*f = folder, *t = target_parent;
	struct imap_conn	*conn;
	const char		*sep;
	char			*leaf, *to;
	char			delimiter;

	if (!f || f->type != IMAP_OBJ_FOLDER) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (!t || t->type != IMAP_OBJ_FOLDER || strcmp(t->ctx->username, f->ctx->username) != 0) {
		return MAPISTORE_ERR_DENIED;
	}
	conn = imap_context_conn(f->ctx);
	if (!conn) {
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	delimiter = imap_context_delimiter(f->ctx);
	if (!delimiter) {
		return MAPISTORE_ERR_DENIED;
	}
	sep = strrchr(f->mailbox, delimiter);
	leaf = new_name ? imap_mailbox_name(mem_ctx, new_name, delimiter) : talloc_strdup(mem_ctx, sep ? sep + 1 : f->mailbox);
	if (!leaf) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	to = child_mailbox(mem_ctx, t->mailbox, delimiter, leaf);
	if (!to) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	/* Into itself or its own subtree: IMAP refuses, and so do we, before asking. */
	if (strncmp(t->mailbox, f->mailbox, strlen(f->mailbox)) == 0 &&
	    (t->mailbox[strlen(f->mailbox)] == '\0' || t->mailbox[strlen(f->mailbox)] == delimiter)) {
		return MAPISTORE_ERR_DENIED;
	}
	return rename_folder(f, conn, to);
}

/* Deletes an empty mailbox; Outlook removes the contents first. */
static enum mapistore_error delete_folder(void *folder)
{
	struct imap_folder	*f = folder;
	struct imap_conn	*conn;
	struct imap_status	st;
	uint32_t		children = 0;
	enum mapistore_error	ret;

	if (!f || f->type != IMAP_OBJ_FOLDER) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	conn = imap_context_conn(f->ctx);
	if (!conn) {
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	if (is_default_folder(f, conn)) {
		return MAPISTORE_ERR_DENIED;
	}
	if (imap_status(conn, f->mailbox, &st) != MAPISTORE_SUCCESS) {
		return write_error(conn);
	}
	ret = imap_folder_get_child_count(f, MAPISTORE_FOLDER_TABLE, &children);
	if (ret != MAPISTORE_SUCCESS) {
		return ret;
	}
	if (st.messages || children) {
		return MAPISTORE_ERR_EXIST;
	}
	if (imap_delete_mailbox(conn, f->mailbox)) {
		return write_error(conn);
	}
	ret = f->ctx->ictx->del_fmid(f->ctx->ictx, f->ctx->username, f->fid, MAPISTORE_PERMANENT_DELETE);
	if (ret != MAPISTORE_SUCCESS) {
		OC_DEBUG(1, "IMAP backend: index delete of folder 0x%"PRIx64" failed: %s\n", f->fid, mapistore_errstr(ret));
	}
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ void imap_backend_fill(struct mapistore_backend *backend)
{
	backend->backend.list_contexts = imap_list_contexts;
	backend->backend.create_context = imap_create_context;
	backend->backend.create_root_folder = imap_create_root_folder;
	backend->context.get_path = get_path;
	backend->context.get_root_folder = get_root_folder;
	backend->folder.open_folder = imap_folder_open_folder;
	backend->folder.open_table = imap_folder_open_table;
	backend->folder.get_child_count = imap_folder_get_child_count;
	backend->folder.open_message = imap_folder_open_message;
	backend->folder.move_copy_messages = move_copy_messages;
	backend->folder.delete_message = delete_message;
	backend->folder.create_folder = create_folder;
	backend->folder.move_folder = move_folder;
	backend->folder.delete = delete_folder;
	backend->table.set_columns = imap_table_set_columns;
	backend->table.get_row = imap_table_get_row;
	backend->table.get_row_count = imap_table_get_row_count;
	backend->table.get_available_properties = imap_table_available;
	backend->table.set_restrictions = imap_table_set_restrictions;
	backend->table.set_sort_order = imap_table_set_sort_order;
	backend->properties.get_properties = imap_properties_get;
	backend->properties.get_available_properties = imap_properties_available;
	imap_message_fill(backend);
}
