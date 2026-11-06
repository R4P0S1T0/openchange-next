/*
   OpenChange Storage Abstraction Layer library
   IMAP backend: mutations on the wire (move, copy, flags, expunge, append, mailboxes)

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

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <libetpan/libetpan.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "imap_conn.h"

/* UIDPLUS, from the cached capabilities or a fresh CAPABILITY. */
static bool has_uidplus(mailimap *imap)
{
	struct mailimap_capability_data *cap = NULL;

	if (mailimap_has_uidplus(imap)) {
		return true;
	}
	if (mailimap_capability(imap, &cap) == MAILIMAP_NO_ERROR && cap &&
	    !(imap->imap_connection_info && imap->imap_connection_info->imap_capability == cap)) {
		mailimap_capability_data_free(cap); /* ours only when libetpan did not keep it as the session's */
	}
	return mailimap_has_uidplus(imap);
}

static struct mailimap_set *uid_set(const uint32_t *uids, uint32_t count)
{
	struct mailimap_set	*set;
	uint32_t		i;

	if (!uids || count == 0) {
		return NULL;
	}
	set = mailimap_set_new_empty();
	for (i = 0; set && i < count; i++) {
		if (uids[i] == 0 || mailimap_set_add_single(set, uids[i]) != MAILIMAP_NO_ERROR) {
			mailimap_set_free(set);
			return NULL;
		}
	}
	return set;
}

static int select_rw(struct imap_conn *conn, const char *mailbox)
{
	int r = imap_conn_check(conn, mailimap_select(imap_conn_session(conn), mailbox));

	if (r != MAILIMAP_NO_ERROR) {
		OC_DEBUG(3, "IMAP backend: SELECT failed (%d)\n", r);
		return -1;
	}
	return 0;
}

_PUBLIC_ uint32_t imap_uid_by_message_id(struct imap_conn *conn, const char *mailbox, const char *message_id, const char *subject,
				       bool newest)
{
	struct mailimap_search_key	*key, *by_id, *by_subject;
	clist				*found = NULL;
	uint32_t			uid = 0;
	char				*id, *name, *subj;
	int				r;

	if (!conn || !mailbox || !message_id || !*message_id || !subject ||
	    imap_conn_check(conn, mailimap_examine(imap_conn_session(conn), mailbox)) != MAILIMAP_NO_ERROR) {
		return 0;
	}
	id = strdup(message_id);
	name = strdup("Message-ID");
	subj = strdup(subject);
	key = mailimap_search_key_new_multiple_empty();
	by_id = id && name ? mailimap_search_key_new_header(name, id) : NULL;
	by_subject = by_id && subj ? mailimap_search_key_new_subject(subj) : NULL;
	if (!key || !by_id || !by_subject ||
	    mailimap_search_key_multiple_add(key, by_id) != MAILIMAP_NO_ERROR) {
		if (key) mailimap_search_key_free(key);
		if (by_id) mailimap_search_key_free(by_id); else { free(id); free(name); }
		if (by_subject) mailimap_search_key_free(by_subject); else free(subj);
		return 0;
	}
	if (mailimap_search_key_multiple_add(key, by_subject) != MAILIMAP_NO_ERROR) {
		mailimap_search_key_free(key);
		mailimap_search_key_free(by_subject);
		return 0;
	}
	r = imap_conn_check(conn, mailimap_uid_search(imap_conn_session(conn), NULL, key, &found));
	mailimap_search_key_free(key);
	if (r == MAILIMAP_NO_ERROR && found) {
		clistiter *it = newest ? clist_end(found) : clist_begin(found);
		uid = it && clist_content(it) ? *(uint32_t *) clist_content(it) : 0;
	}
	if (found) {
		mailimap_search_result_free(found);
	}
	return uid;
}

static struct mailimap_flag_list *flag_list(uint32_t flags)
{
	struct mailimap_flag_list	*l = mailimap_flag_list_new_empty();
	struct mailimap_flag		*f;
	char				*kw;

#define ADD(make) do { f = (make); \
		if (!f || mailimap_flag_list_add(l, f) != MAILIMAP_NO_ERROR) { \
			if (f) mailimap_flag_free(f); \
			mailimap_flag_list_free(l); return NULL; } } while (0)
	if (!l) {
		return NULL;
	}
	if (flags & IMAP_FLAG_SEEN)	ADD(mailimap_flag_new_seen());
	if (flags & IMAP_FLAG_FLAGGED)	ADD(mailimap_flag_new_flagged());
	if (flags & IMAP_FLAG_ANSWERED)	ADD(mailimap_flag_new_answered());
	if (flags & IMAP_FLAG_DELETED)	ADD(mailimap_flag_new_deleted());
	if (flags & IMAP_FLAG_DRAFT)	ADD(mailimap_flag_new_draft());
	if (flags & IMAP_FLAG_FORWARDED) {
		kw = strdup("$Forwarded");
		if (!kw) {
			mailimap_flag_list_free(l);
			return NULL;
		}
		f = mailimap_flag_new_flag_keyword(kw);
		if (!f) {
			free(kw);
		}
		ADD(f);
	}
#undef ADD
	return l;
}

/* Expands a COPYUID set into at most `max` UIDs, in the server's order. */
static uint32_t expand_set(const struct mailimap_set *set, uint32_t *out, uint32_t max)
{
	clistiter	*it;
	uint32_t	n = 0, u;

	for (it = set ? clist_begin(set->set_list) : NULL; it; it = clist_next(it)) {
		const struct mailimap_set_item *item = clist_content(it);

		for (u = item->set_first; n < max && u != 0 && u <= item->set_last; u++) {
			out[n++] = u;
			if (u == UINT32_MAX) {
				break;
			}
		}
	}
	return n;
}

_PUBLIC_ int imap_uid_move(struct imap_conn *conn, const char *from, const uint32_t *uids, uint32_t count,
			   const char *to, bool copy, uint32_t *dest_uidvalidity, uint32_t *dest_uids)
{
	mailimap		*imap = imap_conn_session(conn);
	struct mailimap_set	*set, *src = NULL, *dst = NULL;
	uint32_t		*src_uids, *dst_uids, n_src, n_dst, i, j, validity = 0;
	int			r;

	if (!imap || !from || !to || !dest_uids || !has_uidplus(imap) || select_rw(conn, from)) {
		return -1;
	}
	set = uid_set(uids, count);
	if (!set) {
		return -1;
	}
	r = copy ? mailimap_uidplus_uid_copy(imap, set, to, &validity, &src, &dst)
		 : mailimap_uidplus_uid_move(imap, set, to, &validity, &src, &dst);
	mailimap_set_free(set);
	r = imap_conn_check(conn, r);
	if (r != MAILIMAP_NO_ERROR) {
		OC_DEBUG(3, "IMAP backend: UID %s of %u message(s) failed (%d)\n", copy ? "COPY" : "MOVE", count, r);
		if (src) mailimap_set_free(src);
		if (dst) mailimap_set_free(dst);
		return -1;
	}
	src_uids = calloc(count, sizeof *src_uids);
	dst_uids = calloc(count, sizeof *dst_uids);
	n_src = src_uids ? expand_set(src, src_uids, count) : 0;
	n_dst = dst_uids ? expand_set(dst, dst_uids, count) : 0;
	if (src) mailimap_set_free(src);
	if (dst) mailimap_set_free(dst);
	/* COPYUID pairs the two sets element by element (RFC 4315 3); map each asked UID through it. */
	r = (n_src == n_dst && n_src > 0 && validity) ? 0 : -1;
	for (i = 0; r == 0 && i < count; i++) {
		dest_uids[i] = 0;
		for (j = 0; j < n_src; j++) {
			if (src_uids[j] == uids[i]) {
				dest_uids[i] = dst_uids[j];
				break;
			}
		}
		if (!dest_uids[i]) {
			r = -1;
		}
	}
	free(src_uids);
	free(dst_uids);
	if (r != 0) {
		/* The server did the move but did not say where: the caller leaves its index alone. */
		OC_DEBUG(1, "IMAP backend: UID %s without a usable COPYUID\n", copy ? "COPY" : "MOVE");
		return -1;
	}
	if (dest_uidvalidity) {
		*dest_uidvalidity = validity;
	}
	return 0;
}

_PUBLIC_ int imap_uid_set_flags(struct imap_conn *conn, const char *mailbox, uint32_t uid, uint32_t add, uint32_t remove)
{
	mailimap			*imap = imap_conn_session(conn);
	struct mailimap_store_att_flags	*att;
	struct mailimap_flag_list	*l;
	struct mailimap_set		*set;
	uint32_t			pass[2] = { add, remove & ~add };
	int				i, r = MAILIMAP_NO_ERROR;

	if (!imap || !mailbox || uid == 0 || select_rw(conn, mailbox)) {
		return -1;
	}
	for (i = 0; i < 2 && r == MAILIMAP_NO_ERROR; i++) {
		if (!pass[i]) {
			continue;
		}
		set = mailimap_set_new_single(uid);
		l = flag_list(pass[i]);
		att = l ? (i == 0 ? mailimap_store_att_flags_new_add_flags_silent(l)
				  : mailimap_store_att_flags_new_remove_flags_silent(l)) : NULL;
		if (!set || !att) {
			if (att) mailimap_store_att_flags_free(att);
			else if (l) mailimap_flag_list_free(l);
			if (set) mailimap_set_free(set);
			return -1;
		}
		r = imap_conn_check(conn, mailimap_uid_store(imap, set, att));
		mailimap_store_att_flags_free(att);
		mailimap_set_free(set);
	}
	if (r != MAILIMAP_NO_ERROR) {
		OC_DEBUG(3, "IMAP backend: UID STORE of UID %u failed (%d)\n", uid, r);
		return -1;
	}
	return 0;
}

_PUBLIC_ int imap_uid_expunge(struct imap_conn *conn, const char *mailbox, const uint32_t *uids, uint32_t count)
{
	mailimap		*imap = imap_conn_session(conn);
	struct mailimap_set	*set;
	uint32_t		i;
	int			r;

	/* Never a bare EXPUNGE: it would also remove what other clients flagged \Deleted. */
	if (!imap || !mailbox || !has_uidplus(imap)) {
		OC_DEBUG(1, "IMAP backend: permanent delete needs UIDPLUS; refused\n");
		return -1;
	}
	for (i = 0; i < count; i++) {
		if (imap_uid_set_flags(conn, mailbox, uids[i], IMAP_FLAG_DELETED, 0)) {
			return -1;
		}
	}
	set = uid_set(uids, count);
	if (!set) {
		return -1;
	}
	r = imap_conn_check(conn, mailimap_uid_expunge(imap, set));
	mailimap_set_free(set);
	if (r != MAILIMAP_NO_ERROR) {
		OC_DEBUG(3, "IMAP backend: UID EXPUNGE of %u message(s) failed (%d)\n", count, r);
		return -1;
	}
	OC_DEBUG(5, "IMAP backend: expunged %u message(s)\n", count);
	return 0;
}

_PUBLIC_ int imap_append(struct imap_conn *conn, const char *mailbox, const char *data, size_t len, uint32_t flags,
			 uint32_t *uidvalidity, uint32_t *uid)
{
	mailimap			*imap = imap_conn_session(conn);
	struct mailimap_flag_list	*l;
	uint32_t			v = 0, u = 0;
	int				r;

	if (!imap || !mailbox || !data || len == 0) {
		return -1;
	}
	l = flag_list(flags);
	if (!l) {
		return -1;
	}
	r = imap_conn_check(conn, mailimap_uidplus_append(imap, mailbox, l, NULL, data, len, &v, &u));
	mailimap_flag_list_free(l);
	if (r != MAILIMAP_NO_ERROR || !v || !u) {
		OC_DEBUG(3, "IMAP backend: APPEND failed (%d)\n", r);
		return -1;
	}
	if (uidvalidity) *uidvalidity = v;
	if (uid) *uid = u;
	return 0;
}

_PUBLIC_ int imap_create_mailbox(struct imap_conn *conn, const char *name, bool subscribe)
{
	mailimap	*imap = imap_conn_session(conn);
	int		r;

	if (!imap || !name || !name[0]) {
		return -1;
	}
	r = imap_conn_check(conn, mailimap_create(imap, name));
	if (r == MAILIMAP_NO_ERROR && subscribe) {
		r = imap_conn_check(conn, mailimap_subscribe(imap, name));
	}
	if (r != MAILIMAP_NO_ERROR) {
		OC_DEBUG(3, "IMAP backend: CREATE failed (%d)\n", r);
		return -1;
	}
	return 0;
}

/* Subscribed names equal to `name` or below it. */
static clist *subscriptions_under(struct imap_conn *conn, const char *name)
{
	mailimap	*imap = imap_conn_session(conn);
	clist		*res = NULL, *out = clist_new();
	clistiter	*it;
	size_t		len = strlen(name);
	char		delim = imap_conn_delimiter(conn);

	if (!out || imap_conn_check(conn, mailimap_lsub(imap, "", "*", &res)) != MAILIMAP_NO_ERROR) {
		return out;
	}
	for (it = clist_begin(res); it; it = clist_next(it)) {
		const struct mailimap_mailbox_list *mb = clist_content(it);
		char *copy;

		if (mb->mb_name && strncmp(mb->mb_name, name, len) == 0 &&
		    (mb->mb_name[len] == '\0' || mb->mb_name[len] == delim) && (copy = strdup(mb->mb_name))) {
			if (clist_append(out, copy) < 0) {
				free(copy);
			}
		}
	}
	mailimap_list_result_free(res);
	return out;
}

_PUBLIC_ int imap_rename_mailbox(struct imap_conn *conn, const char *from, const char *to)
{
	mailimap	*imap = imap_conn_session(conn);
	clist		*subs;
	clistiter	*it;
	int		r;

	if (!imap || !from || !to || !to[0]) {
		return -1;
	}
	subs = subscriptions_under(conn, from);
	r = imap_conn_check(conn, mailimap_rename(imap, from, to));
	if (r != MAILIMAP_NO_ERROR) {
		OC_DEBUG(3, "IMAP backend: RENAME failed (%d)\n", r);
	}
	/* Dovecot leaves subscriptions on the old names: carry them over, children included. */
	for (it = subs ? clist_begin(subs) : NULL; it; it = clist_next(it)) {
		char *old = clist_content(it), *new_name;

		if (r == MAILIMAP_NO_ERROR && (new_name = talloc_asprintf(NULL, "%s%s", to, old + strlen(from)))) {
			imap_conn_check(conn, mailimap_unsubscribe(imap, old));
			imap_conn_check(conn, mailimap_subscribe(imap, new_name));
			talloc_free(new_name);
		}
		free(old);
	}
	if (subs) {
		clist_free(subs);
	}
	return r == MAILIMAP_NO_ERROR ? 0 : -1;
}

_PUBLIC_ int imap_delete_mailbox(struct imap_conn *conn, const char *name)
{
	mailimap	*imap = imap_conn_session(conn);
	int		r;

	if (!imap || !name) {
		return -1;
	}
	r = imap_conn_check(conn, mailimap_delete(imap, name));
	if (r != MAILIMAP_NO_ERROR) {
		OC_DEBUG(3, "IMAP backend: DELETE failed (%d)\n", r);
		return -1;
	}
	/* A subscription outliving its mailbox shows up as a ghost in other clients. */
	imap_conn_check(conn, mailimap_unsubscribe(imap, name));
	return 0;
}
