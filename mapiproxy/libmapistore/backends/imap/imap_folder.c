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
		return MAPISTORE_SUCCESS;
	}
	conn = imap_conn_open(mem_ctx, settings, username);
	if (!conn) {
		/* Not an empty list: provisioning would drop every IMAP folder it knows. */
		return MAPISTORE_ERR_CONN_REFUSED;
	}
	delimiter = imap_conn_delimiter(conn);
	ret = imap_list(conn, conn, &mbs, &n);
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

/* Folders created by Outlook stay native in openchangedb (read-only backend, M3). */
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
	if (ret != MAPISTORE_SUCCESS) {
		talloc_free(t);
		return ret;
	}
	*table = t;
	*row_count = t->row_count;
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
	*count = t->row_count;
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
	default:
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
}

/* Write operations keep mapistore's defaults (MAPISTORE_ERR_NOT_IMPLEMENTED): M3 is read-only. */
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
	backend->table.set_columns = imap_table_set_columns;
	backend->table.get_row = imap_table_get_row;
	backend->table.get_row_count = imap_table_get_row_count;
	backend->properties.get_properties = imap_properties_get;
	imap_message_fill(backend);
}
