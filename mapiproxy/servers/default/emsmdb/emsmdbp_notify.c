/*
   OpenChange Server implementation

   EMSMDBP: folder change notifications for Outlook's hierarchy tables

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

/*
  Cached-mode Outlook keeps a deep hierarchy table (RopGetHierarchyTable with
  TableFlags_Depth) open on the mailbox root and synchronizes a folder when that
  table reports the folder's row changed (RopNotify TableModified, MS-OXCNOTIF
  2.2.1.4.1.2) with a newer PidTagLocalCommitTimeMax. The replies are queued on
  the session and appended to its next Execute response.
 */

#include "mapiproxy/dcesrv_mapiproxy.h"
#include "mapiproxy/libmapiproxy/libmapiproxy.h"
#include "mapiproxy/libmapiserver/libmapiserver.h"
#include "dcesrv_exchange_emsmdb.h"

struct emsmdbp_notify_table {
	struct emsmdbp_notify_table	*prev, *next;
	struct emsmdbp_context		*ctx;
	struct emsmdbp_object		*table;
	uint32_t			handle;
	uint8_t				logon_id;
};

struct emsmdbp_notify_entry {
	struct emsmdbp_notify_entry	*prev, *next;
	struct emsmdbp_context		*ctx;	/* set while on ctx->notify_queue */
	uint32_t			handle;
	uint64_t			fid;
	uint32_t			size;	/* bytes of repl on the wire */
	struct EcDoRpc_MAPI_REPL	repl;
};

/* Entries leave the queue whenever they are freed: the session's memory goes in no fixed order. */
static int emsmdbp_notify_entry_destructor(struct emsmdbp_notify_entry *e)
{
	if (e->ctx) {
		DLIST_REMOVE(e->ctx->notify_queue, e);
	}
	return 0;
}

/* A released table gets no more rows, and its handle may be reused: its queued replies go too. */
static int emsmdbp_notify_table_destructor(struct emsmdbp_notify_table *t)
{
	struct emsmdbp_notify_entry *e, *next;

	for (e = t->ctx->notify_queue; e; e = next) {
		next = e->next;
		if (e->handle == t->handle) {
			talloc_free(e);
		}
	}
	DLIST_REMOVE(t->ctx->notify_tables, t);
	return 0;
}

_PUBLIC_ void emsmdbp_notify_track_table(struct emsmdbp_context *ctx, struct emsmdbp_object *table,
					 uint32_t handle, uint8_t logon_id)
{
	struct emsmdbp_notify_table *t;

	if (!ctx || !table) return;
	/* Owned by the table object: freed, and so untracked, when the table is released. */
	t = talloc_zero(table, struct emsmdbp_notify_table);
	if (!t) return;
	t->ctx = ctx;
	t->table = table;
	t->handle = handle;
	t->logon_id = logon_id;
	DLIST_ADD_END(ctx->notify_tables, t, struct emsmdbp_notify_table *);
	talloc_set_destructor(t, emsmdbp_notify_table_destructor);
}

static bool emsmdbp_notify_in_subtree(struct emsmdbp_object *folder, struct emsmdbp_object *base)
{
	struct emsmdbp_object *o;

	for (o = folder->parent_object; o; o = o->parent_object) {
		if (o == base) return true;
	}
	return false;
}

/* The folder's row in the table's columns, as RopQueryRows sends it; false when it cannot be read. */
static bool emsmdbp_notify_row(TALLOC_CTX *mem_ctx, struct emsmdbp_context *ctx, struct emsmdbp_object *table,
			       uint64_t fid, DATA_BLOB *row)
{
	/* The opened folders (and their mapistore contexts) live only for this call, not in the queue. */
	TALLOC_CTX		*tmp = talloc_new(NULL);
	struct emsmdbp_object	*folder = NULL;
	struct SPropTagArray	columns;
	enum MAPISTATUS		*retvals = NULL;
	void			**values;
	DATA_BLOB		blob = data_blob_null;
	bool			ok = false;

	if (!tmp) return false;
	if (emsmdbp_object_open_folder_by_fid(tmp, ctx, table->parent_object, fid, &folder) != MAPI_E_SUCCESS ||
	    !folder || !emsmdbp_notify_in_subtree(folder, table->parent_object)) {
		goto end;
	}
	columns.cValues = table->object.table->prop_count;
	columns.aulPropTag = table->object.table->properties;
	values = emsmdbp_object_get_properties(tmp, ctx, folder, &columns, &retvals);
	if (!values) goto end;
	emsmdbp_fill_table_row_blob(tmp, ctx, &blob, columns.cValues, columns.aulPropTag, values, retvals);
	if (!blob.length || blob.length > UINT16_MAX) goto end;
	*row = data_blob_talloc(mem_ctx, blob.data, blob.length);
	ok = row->data != NULL;
end:
	talloc_free(tmp);
	return ok;
}

/* Queues one reply; a folder already queued for the table is replaced, so the queue stays bounded. */
static bool emsmdbp_notify_queue(struct emsmdbp_context *ctx, struct emsmdbp_notify_entry *entry)
{
	struct emsmdbp_notify_entry	*e;
	struct ndr_push			*push;
	enum RichTableNotificationType	*event = &entry->repl.u.mapi_Notify.NotificationData.HierarchyTableChange.TableEvent;

	for (e = ctx->notify_queue; e; e = e->next) {
		if (e->handle == entry->handle && e->fid == entry->fid) break;
	}
	/* Outlook has not seen the row yet: it stays an addition. */
	if (e && *event == TABLE_ROW_MODIFIED &&
	    e->repl.u.mapi_Notify.NotificationData.HierarchyTableChange.TableEvent == TABLE_ROW_ADDED) {
		*event = TABLE_ROW_ADDED;
	}
	push = ndr_push_init_ctx(entry);
	if (!push) return false;
	ndr_set_flags(&push->flags, LIBNDR_FLAG_NOALIGN);
	if (ndr_push_EcDoRpc_MAPI_REPL(push, NDR_SCALARS, &entry->repl) != NDR_ERR_SUCCESS) return false;
	entry->size = push->offset;
	talloc_free(push);
	talloc_free(e);
	talloc_steal(ctx, entry);
	entry->ctx = ctx;
	DLIST_ADD_END(ctx->notify_queue, entry, struct emsmdbp_notify_entry *);
	talloc_set_destructor(entry, emsmdbp_notify_entry_destructor);
	return true;
}

/**
   \details Queue a RopNotify TableModified for every tracked hierarchy table holding the folder

   \param ctx the session's EMSMDB provider context
   \param fid the folder, as Outlook knows it (see emsmdbp_fid_for_mailbox)
   \param kind modified, added or deleted

   \return the number of replies queued
 */
_PUBLIC_ int emsmdbp_notify_folder_changed(struct emsmdbp_context *ctx, uint64_t fid, enum emsmdbp_folder_change kind)
{
	struct emsmdbp_notify_table	*t;
	struct emsmdbp_notify_entry	*entry;
	struct HierarchyTableChange	*change;
	DATA_BLOB			row;
	int				queued = 0;

	if (!ctx) return 0;
	for (t = ctx->notify_tables; t; t = t->next) {
		entry = talloc_zero(NULL, struct emsmdbp_notify_entry);
		if (!entry) break;
		entry->handle = t->handle;
		entry->fid = fid;
		entry->repl.opnum = op_MAPI_Notify;
		entry->repl.u.mapi_Notify.NotificationHandle = t->handle;
		entry->repl.u.mapi_Notify.LogonId = t->logon_id;
		entry->repl.u.mapi_Notify.NotificationType = fnevTableModified;
		change = &entry->repl.u.mapi_Notify.NotificationData.HierarchyTableChange;
		if (kind == EMSMDBP_FOLDER_DELETED) {
			/* shortcut: a gone folder cannot be placed in a subtree, every tracked table hears of it;
			   Outlook ignores rows it does not hold. */
			change->TableEvent = TABLE_ROW_DELETED;
			change->HierarchyTableChangeUnion.HierarchyRowDeletedNotification.FID = fid;
		} else if (emsmdbp_notify_row(entry, ctx, t->table, fid, &row)) {
			/* Added and modified rows share one layout. InsertAfterFID stays 0: the previous row would
			   cost a listing of the parent per change, and cached mode only compares the row's values. */
			change->TableEvent = kind == EMSMDBP_FOLDER_ADDED ? TABLE_ROW_ADDED : TABLE_ROW_MODIFIED;
			change->HierarchyTableChangeUnion.HierarchyRowModifiedNotification.FID = fid;
			change->HierarchyTableChangeUnion.HierarchyRowModifiedNotification.ColumnSize = row.length;
			change->HierarchyTableChangeUnion.HierarchyRowModifiedNotification.Columns = row;
		} else {
			talloc_free(entry);
			continue;
		}
		if (!emsmdbp_notify_queue(ctx, entry)) {
			talloc_free(entry);
			continue;
		}
		queued++;
	}
	return queued;
}

_PUBLIC_ bool emsmdbp_notify_pending(struct emsmdbp_context *ctx)
{
	return ctx && ctx->notify_queue;
}

struct emsmdbp_hierrev {
	struct emsmdbp_hierrev	*prev, *next;
	uint64_t		fid;
	struct FILETIME		time;
};

/**
   \details The PidTagHierRev a folder got when its subfolders changed during the session

   \param ctx the session's EMSMDB provider context
   \param fid the folder

   \return the time, or NULL when the folder's subfolders did not change
 */
_PUBLIC_ const struct FILETIME *emsmdbp_notify_hierrev(struct emsmdbp_context *ctx, uint64_t fid)
{
	struct emsmdbp_hierrev *h;

	for (h = ctx ? ctx->hierrev : NULL; h; h = h->next) {
		if (h->fid == fid) return &h->time;
	}
	return NULL;
}

/* A subfolder of parent_fid was added or deleted: cached-mode Outlook synchronizes the hierarchy when a
   row of its deep hierarchy table shows a newer PidTagHierRev (a row added or deleted alone it leaves to
   the next synchronization), so the parent gets one, strictly newer than any before, and its row goes
   out. shortcut: the time lives in the session only; a new session starts with a full hierarchy
   synchronization anyway. */
static int emsmdbp_notify_hierarchy_changed(struct emsmdbp_context *ctx, uint64_t parent_fid)
{
	static NTTIME		last;
	struct emsmdbp_hierrev	*h;
	struct timeval		tv;
	NTTIME			now;

	gettimeofday(&tv, NULL);
	now = timeval_to_nttime(&tv);
	now = now > last ? now : last + 1;
	last = now;
	for (h = ctx->hierrev; h && h->fid != parent_fid; h = h->next);
	if (!h) {
		h = talloc_zero(ctx, struct emsmdbp_hierrev);
		if (!h) return 0;
		h->fid = parent_fid;
		DLIST_ADD(ctx->hierrev, h);
	}
	h->time.dwLowDateTime = now & 0xffffffff;
	h->time.dwHighDateTime = now >> 32;
	return emsmdbp_notify_folder_changed(ctx, parent_fid, EMSMDBP_FOLDER_MODIFIED);
}

/**
   \details Move queued replies into an Execute response, oldest first, while they fit

   \param ctx the session's EMSMDB provider context
   \param response the response being built; mapi_repl grows
   \param idx the next free reply slot; advanced
   \param size the bytes of replies so far; advanced
   \param limit the most bytes of replies the response may hold

   \return MAPI_E_SUCCESS, or MAPI_E_NOT_ENOUGH_RESOURCES
 */
_PUBLIC_ enum MAPISTATUS emsmdbp_notify_append(struct emsmdbp_context *ctx, struct mapi_response *response,
					       uint32_t *idx, uint16_t *size, uint32_t limit)
{
	struct emsmdbp_notify_entry	*e;
	struct EcDoRpc_MAPI_REPL	*grown;

	while (ctx && (e = ctx->notify_queue) && (uint32_t) *size + e->size <= limit) {
		grown = talloc_realloc(response, response->mapi_repl, struct EcDoRpc_MAPI_REPL, *idx + 2);
		if (!grown) return MAPI_E_NOT_ENOUGH_RESOURCES;
		response->mapi_repl = grown;
		DLIST_REMOVE(ctx->notify_queue, e);
		e->ctx = NULL;
		talloc_steal(response, e);	/* keeps the row's columns alive with the response */
		grown[*idx] = e->repl;
		ZERO_STRUCT(grown[*idx + 1]);
		*size += e->size;
		(*idx)++;
	}
	return MAPI_E_SUCCESS;
}

/* The IMAP backend's URI segment encoding (imap_names.c, a dlopen()ed module): unsafe bytes as %XX. */
static char *emsmdbp_notify_uri_append(char *out, const char *s, size_t len)
{
	static const char	hex[] = "0123456789ABCDEF";
	size_t			i;

	for (i = 0; out && i < len; i++) {
		unsigned char c = (unsigned char) s[i];
		bool safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-' || c == '~' || c == '&' || c == ',' || c == '+';

		out = safe ? talloc_asprintf_append_buffer(out, "%c", c)
			: talloc_asprintf_append_buffer(out, "%%%c%c", hex[c >> 4], hex[c & 0xF]);
	}
	return out;
}

/**
   \details The folder ID Outlook knows for an IMAP mailbox

   \param ctx the session's EMSMDB provider context
   \param mailbox the mailbox name as IMAP sends it (modified UTF-7)
   \param delimiter the server's hierarchy delimiter ('\0' for a flat namespace)
   \param fid the folder ID on success

   \return MAPI_E_SUCCESS, or MAPI_E_NOT_FOUND
 */
_PUBLIC_ enum MAPISTATUS emsmdbp_fid_for_mailbox(struct emsmdbp_context *ctx, const char *mailbox, char delimiter,
						 uint64_t *fid)
{
	const char	*start, *end;
	char		*uri;
	int		ret;

	if (!ctx || !ctx->username || !mailbox || !mailbox[0] || !fid) return MAPI_E_NOT_FOUND;
	uri = talloc_strdup(NULL, "imap://");
	uri = emsmdbp_notify_uri_append(uri, ctx->username, strlen(ctx->username));
	uri = uri ? talloc_strdup_append_buffer(uri, "/") : NULL;
	for (start = mailbox; uri; start = end + 1) {
		end = delimiter ? strchr(start, delimiter) : NULL;
		if (!end) end = start + strlen(start);
		uri = emsmdbp_notify_uri_append(uri, start, end - start);
		uri = uri ? talloc_strdup_append_buffer(uri, "/") : NULL;
		if (!*end) break;
	}
	/* System folders (Inbox, Sent, ...) keep their openchangedb ID; others have the indexing one. */
	ret = uri ? emsmdbp_get_fid_from_uri(ctx, uri, fid) : MAPI_E_NOT_ENOUGH_RESOURCES;
	talloc_free(uri);
	return ret == MAPI_E_SUCCESS ? MAPI_E_SUCCESS : MAPI_E_NOT_FOUND;
}

/* Makes a mailbox created while the session is open known to the store, as logon or a listing of its
   parent would: a top-level one is provisioned (a mapistore context, like at logon); a subfolder is
   indexed by listing its parent's subtree. */
static void emsmdbp_notify_learn(struct emsmdbp_context *ctx, const char *mailbox, char delimiter)
{
	TALLOC_CTX		*tmp;
	const char		*last = delimiter ? strrchr(mailbox, delimiter) : NULL;
	char			*parent;
	uint64_t		parent_fid;
	struct emsmdbp_object	*folder = NULL;
	uint32_t		count = 0;

	if (!last) {
		emsmdbp_mailbox_provision(ctx, ctx->username);
		return;
	}
	tmp = talloc_new(NULL);
	parent = tmp ? talloc_strndup(tmp, mailbox, last - mailbox) : NULL;
	if (parent && emsmdbp_fid_for_mailbox(ctx, parent, delimiter, &parent_fid) == MAPI_E_SUCCESS &&
	    emsmdbp_object_open_folder_by_fid(tmp, ctx, ctx->notify_tables->table->parent_object, parent_fid,
					      &folder) == MAPI_E_SUCCESS && folder) {
		emsmdbp_folder_get_recursive_folder_count(ctx, folder, &count);
	}
	talloc_free(tmp);
}

/**
   \details An IMAP mailbox changed: queue the rows for the folder Outlook knows, making a new
   mailbox known first

   \param ctx the session's EMSMDB provider context
   \param mailbox the mailbox name as IMAP sends it (modified UTF-7)
   \param delimiter the server's hierarchy delimiter ('\\0' when flat)
   \param kind modified, added or deleted

   \return the number of replies queued
 */
_PUBLIC_ int emsmdbp_notify_mailbox_changed(struct emsmdbp_context *ctx, const char *mailbox, char delimiter,
					    enum emsmdbp_folder_change kind)
{
	uint64_t	fid;
	int		queued;

	if (!ctx || !ctx->notify_tables) return 0;	/* nobody to tell: nothing to learn either */
	if (emsmdbp_fid_for_mailbox(ctx, mailbox, delimiter, &fid) != MAPI_E_SUCCESS) {
		/* Only a creation is worth a provisioning or a subtree listing; the watcher reports one as added. */
		if (kind != EMSMDBP_FOLDER_ADDED) return 0;
		emsmdbp_notify_learn(ctx, mailbox, delimiter);
		if (emsmdbp_fid_for_mailbox(ctx, mailbox, delimiter, &fid) != MAPI_E_SUCCESS) return 0;
	}
	queued = emsmdbp_notify_folder_changed(ctx, fid, kind);
	/* A top-level mailbox is a provisioned folder: provisioning drops it now that the server lists it no
	   more, or Outlook's next hierarchy synchronization would bring it back. */
	if (kind == EMSMDBP_FOLDER_DELETED && !(delimiter && strchr(mailbox, delimiter))) {
		emsmdbp_mailbox_provision(ctx, ctx->username);
	}
	if (kind != EMSMDBP_FOLDER_MODIFIED) {
		const char	*last = delimiter ? strrchr(mailbox, delimiter) : NULL;
		char		*parent = last ? talloc_strndup(NULL, mailbox, last - mailbox) : NULL;
		uint64_t	parent_fid = 0;

		/* A top-level mailbox's parent is the IPM subtree. */
		if (last ? (parent && emsmdbp_fid_for_mailbox(ctx, parent, delimiter, &parent_fid) == MAPI_E_SUCCESS)
			 : openchangedb_get_SystemFolderID(ctx->oc_ctx, ctx->username, EMSMDBP_TOP_INFORMATION_STORE,
							   &parent_fid) == MAPI_E_SUCCESS) {
			emsmdbp_notify_hierarchy_changed(ctx, parent_fid);
		}
		talloc_free(parent);
	}
	return queued;
}

/**
   \details Other clients changed folders of mapistore backends (mapistore_poll_changes): queue their rows

   A folder whose contents changed sends its row (a newer PidTagLocalCommitTimeMax makes Outlook sync it); a
   folder that gained, lost or renamed a subfolder gets a newer PidTagHierRev, as in emsmdbp_notify_mailbox_changed:
   cached-mode Outlook learns a subfolder's new name only from that hierarchy synchronization.
   Changes of folders Outlook does not know are skipped.

   \param ctx the session's EMSMDB provider context

   \return the number of replies queued
 */
_PUBLIC_ int emsmdbp_notify_poll_changes(struct emsmdbp_context *ctx)
{
	TALLOC_CTX		*tmp;
	struct mapistore_change	*changes;
	size_t			n, i;
	uint64_t		fid;
	int			queued = 0;

	if (!ctx || !ctx->notify_tables || !ctx->username) return 0;	/* nobody to tell: no need to ask */
	tmp = talloc_new(NULL);
	if (!tmp) return 0;
	if (mapistore_poll_changes(ctx->mstore_ctx, ctx->username, tmp, &changes, &n) != MAPISTORE_SUCCESS) n = 0;
	for (i = 0; i < n; i++) {
		if (emsmdbp_get_fid_from_uri(ctx, changes[i].uri, &fid) != MAPI_E_SUCCESS) continue;
		if (changes[i].kind != MAPISTORE_CHANGE_CONTENTS) {
			queued += emsmdbp_notify_hierarchy_changed(ctx, fid);
		} else {
			queued += emsmdbp_notify_folder_changed(ctx, fid, EMSMDBP_FOLDER_MODIFIED);
		}
	}
	talloc_free(tmp);
	return queued;
}
