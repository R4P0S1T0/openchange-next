/*
   OpenChange Storage Abstraction Layer library
   Read-only IMAP backend: message tables and messages

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
#include <time.h>

#include <libetpan/libetpan.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "imap_backend.h"

/* Rows of one message table; larger mailboxes show their first (oldest) messages only.
   shortcut: a full envelope fetch per table open; page with UID ranges when mailboxes grow. */
#define MAX_TABLE_ROWS 100000
/* Header text kept per field. */
#define MAX_HEADER_TEXT 4096


/* Replaces every byte sequence that is not well-formed UTF-8 by U+FFFD, and controls by spaces. */
_PUBLIC_ char *imap_utf8_clean(TALLOC_CTX *mem_ctx, const char *s, size_t len)
{
	const unsigned char	*p = (const unsigned char *) s;
	char			*out;
	size_t			i = 0, n = 0;

	if (len > MAX_HEADER_TEXT) {
		len = MAX_HEADER_TEXT;
	}
	out = talloc_array(mem_ctx, char, len * 3 + 1);
	if (!out) {
		return NULL;
	}
	while (i < len) {
		unsigned char c = p[i];
		size_t need = c < 0x80 ? 0 : (c & 0xE0) == 0xC0 ? 1 : (c & 0xF0) == 0xE0 ? 2 : (c & 0xF8) == 0xF0 ? 3 : 9;
		uint32_t cp = need == 0 ? c : need == 1 ? (c & 0x1F) : need == 2 ? (c & 0x0F) : (c & 0x07);
		size_t k;

		if (need == 0) {
			out[n++] = (c < 0x20 || c == 0x7F) ? ' ' : c;
			i++;
			continue;
		}
		for (k = 1; need != 9 && k <= need; k++) {
			if (i + k >= len || (p[i + k] & 0xC0) != 0x80) {
				break;
			}
			cp = (cp << 6) | (p[i + k] & 0x3F);
		}
		if (need == 9 || k <= need || (need == 1 && cp < 0x80) || (need == 2 && cp < 0x800) ||
		    (need == 3 && (cp < 0x10000 || cp > 0x10FFFF)) || (cp >= 0xD800 && cp <= 0xDFFF)) {
			memcpy(out + n, "\xEF\xBF\xBD", 3);
			n += 3;
			i++;
			continue;
		}
		memcpy(out + n, p + i, need + 1);
		n += need + 1;
		i += need + 1;
	}
	out[n] = '\0';
	return out;
}

/* An RFC 2047 header value as UTF-8; raw 8-bit text is read as UTF-8 (then cleaned). */
_PUBLIC_ char *imap_decode_header(TALLOC_CTX *mem_ctx, const char *raw)
{
	char	*decoded = NULL, *out;
	size_t	idx = 0;

	if (!raw) {
		return NULL;
	}
	if (mailmime_encoded_phrase_parse("utf-8", raw, strlen(raw), &idx, "utf-8", &decoded) == MAILIMF_NO_ERROR && decoded) {
		out = imap_utf8_clean(mem_ctx, decoded, strlen(decoded));
		free(decoded);
		return out;
	}
	return imap_utf8_clean(mem_ctx, raw, strlen(raw));
}

static time_t date_to_time(int year, int month, int day, int hour, int min, int sec, int zone)
{
	struct tm	tm;
	time_t		t;
	int		offset;

	if (year < 1970 || year > 9999 || month < 1 || month > 12 || day < 1 || day > 31 ||
	    hour < 0 || hour > 23 || min < 0 || min > 59 || sec < 0 || sec > 60 || zone < -2359 || zone > 2359) {
		return 0;
	}
	memset(&tm, 0, sizeof tm);
	tm.tm_year = year - 1900;
	tm.tm_mon = month - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = min;
	tm.tm_sec = sec;
	t = timegm(&tm);
	offset = (zone / 100) * 3600 + (zone % 100) * 60;
	return t == (time_t) -1 ? 0 : t - offset;
}

static time_t header_date(const char *raw)
{
	struct mailimf_date_time	*dt = NULL;
	size_t				idx = 0;
	time_t				t;

	if (!raw || mailimf_date_time_parse(raw, strlen(raw), &idx, &dt) != MAILIMF_NO_ERROR || !dt) {
		return 0;
	}
	t = date_to_time(dt->dt_year, dt->dt_month, dt->dt_day, dt->dt_hour, dt->dt_min, dt->dt_sec, dt->dt_zone);
	mailimf_date_time_free(dt);
	return t;
}

static char *address_text(TALLOC_CTX *mem_ctx, const struct mailimap_address *a, bool want_name)
{
	char *name;

	if (!a || !a->ad_mailbox_name) {
		return NULL;
	}
	if (want_name && a->ad_personal_name && (name = imap_decode_header(mem_ctx, a->ad_personal_name)) && name[0]) {
		return name;
	}
	name = talloc_asprintf(mem_ctx, "%s%s%s", a->ad_mailbox_name, a->ad_host_name ? "@" : "",
			       a->ad_host_name ? a->ad_host_name : "");
	return name ? imap_utf8_clean(mem_ctx, name, strlen(name)) : NULL;
}

/* PidTagDisplayTo/Cc: the recipients' names (their address when unnamed), joined by "; ". */
static char *display_list(TALLOC_CTX *mem_ctx, clist *list)
{
	clistiter	*it;
	char		*out = NULL;

	for (it = list ? clist_begin(list) : NULL; it; it = clist_next(it)) {
		char *one = address_text(mem_ctx, clist_content(it), true);

		if (!one) {
			continue;
		}
		out = out ? talloc_asprintf_append_buffer(out, "; %s", one) : talloc_strdup(mem_ctx, one);
	}
	return out ? out : talloc_strdup(mem_ctx, "");
}

static bool part_is_attachment(const struct mailimap_body_type_1part *p)
{
	const struct mailimap_body_ext_1part *ext = p->bd_ext_1part;

	if (ext && ext->bd_disposition && ext->bd_disposition->dsp_type &&
	    strcasecmp(ext->bd_disposition->dsp_type, "attachment") == 0) {
		return true;
	}
	/* Anything that is not text (images, applications, forwarded messages) shows as an attachment. */
	return p->bd_type == MAILIMAP_BODY_TYPE_1PART_BASIC || p->bd_type == MAILIMAP_BODY_TYPE_1PART_MSG;
}

static bool has_attachment(const struct mailimap_body *b, int depth)
{
	clistiter *it;

	if (!b || depth > 16) {
		return false;
	}
	if (b->bd_type == MAILIMAP_BODY_1PART) {
		/* A single-part message is the body itself, unless it is not text. */
		return depth > 0 ? part_is_attachment(b->bd_data.bd_body_1part)
			: b->bd_data.bd_body_1part->bd_type == MAILIMAP_BODY_TYPE_1PART_BASIC;
	}
	for (it = clist_begin(b->bd_data.bd_body_mpart->bd_list); it; it = clist_next(it)) {
		const struct mailimap_body *child = clist_content(it);

		if (child->bd_type == MAILIMAP_BODY_MPART ? has_attachment(child, depth + 1)
		    : part_is_attachment(child->bd_data.bd_body_1part)) {
			return true;
		}
	}
	return false;
}

static void read_flags(struct imap_message_row *row, const struct mailimap_msg_att_dynamic *dyn)
{
	clistiter *it;

	for (it = dyn && dyn->att_list ? clist_begin(dyn->att_list) : NULL; it; it = clist_next(it)) {
		const struct mailimap_flag_fetch *ff = clist_content(it);

		if (!ff || ff->fl_type != MAILIMAP_FLAG_FETCH_OTHER || !ff->fl_flag) {
			continue;
		}
		switch (ff->fl_flag->fl_type) {
		case MAILIMAP_FLAG_SEEN:	row->seen = true; break;
		case MAILIMAP_FLAG_FLAGGED:	row->flagged = true; break;
		case MAILIMAP_FLAG_ANSWERED:	row->answered = true; break;
		case MAILIMAP_FLAG_DRAFT:	row->draft = true; break;
		default: break;
		}
	}
}

static void read_envelope(TALLOC_CTX *mem_ctx, struct imap_message_row *row, const struct mailimap_envelope *env)
{
	const struct mailimap_address *from = NULL;

	if (!env) {
		return;
	}
	row->subject = imap_decode_header(mem_ctx, env->env_subject);
	row->date = header_date(env->env_date);
	row->message_id = env->env_message_id ? imap_utf8_clean(mem_ctx, env->env_message_id, strlen(env->env_message_id)) : NULL;
	if (env->env_from && env->env_from->frm_list && clist_begin(env->env_from->frm_list)) {
		from = clist_content(clist_begin(env->env_from->frm_list));
	}
	row->from_name = address_text(mem_ctx, from, true);
	row->from_address = address_text(mem_ctx, from, false);
	row->display_to = display_list(mem_ctx, env->env_to ? env->env_to->to_list : NULL);
	row->display_cc = display_list(mem_ctx, env->env_cc ? env->env_cc->cc_list : NULL);
}

static void read_static(TALLOC_CTX *mem_ctx, struct imap_message_row *row, const struct mailimap_msg_att_static *st)
{
	const struct mailimap_date_time *d;

	switch (st->att_type) {
	case MAILIMAP_MSG_ATT_UID:
		row->uid = st->att_data.att_uid;
		break;
	case MAILIMAP_MSG_ATT_RFC822_SIZE:
		row->size = st->att_data.att_rfc822_size;
		break;
	case MAILIMAP_MSG_ATT_INTERNALDATE:
		d = st->att_data.att_internal_date;
		if (d) {
			row->internal = date_to_time(d->dt_year, d->dt_month, d->dt_day, d->dt_hour, d->dt_min, d->dt_sec, d->dt_zone);
		}
		break;
	case MAILIMAP_MSG_ATT_ENVELOPE:
		read_envelope(mem_ctx, row, st->att_data.att_env);
		break;
	case MAILIMAP_MSG_ATT_BODYSTRUCTURE:
		row->has_attachments = has_attachment(st->att_data.att_bodystructure, 0);
		break;
	default:
		break;
	}
}

_PUBLIC_ char *imap_message_uri(TALLOC_CTX *mem_ctx, struct imap_folder *f, uint32_t uidvalidity, uint32_t uid)
{
	char *folder_uri = imap_uri(mem_ctx, f->ctx->username, f->mailbox, imap_context_delimiter(f->ctx));

	return folder_uri ? talloc_asprintf_append_buffer(folder_uri, "%u_%u", uidvalidity, uid) : NULL;
}

/* UID FETCH 1:* of the envelope, flags, size, dates and structure; one row per message. */
_PUBLIC_ enum mapistore_error imap_message_table_load(struct imap_table *t)
{
	struct imap_folder		*f = t->folder;
	struct imap_conn		*conn = imap_context_conn(f->ctx);
	struct mailimap_fetch_type	*ft;
	struct mailimap_set		*set;
	struct imap_status		st;
	clist				*result = NULL;
	clistiter			*it;
	uint32_t			n = 0;
	int				r;

	if (!conn || imap_examine(conn, f->mailbox, &st) != MAPISTORE_SUCCESS) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	t->uidvalidity = st.uidvalidity;
	t->row_count = 0;
	if (st.messages == 0) {
		return MAPISTORE_SUCCESS;
	}
	ft = mailimap_fetch_type_new_fetch_att_list_empty();
	set = mailimap_set_new_interval(1, 0);
	if (!ft || !set ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_uid()) != MAILIMAP_NO_ERROR ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_flags()) != MAILIMAP_NO_ERROR ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_rfc822_size()) != MAILIMAP_NO_ERROR ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_internaldate()) != MAILIMAP_NO_ERROR ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_envelope()) != MAILIMAP_NO_ERROR ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_bodystructure()) != MAILIMAP_NO_ERROR) {
		if (ft) mailimap_fetch_type_free(ft);
		if (set) mailimap_set_free(set);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	r = mailimap_uid_fetch(imap_conn_session(conn), set, ft, &result);
	mailimap_fetch_type_free(ft);
	mailimap_set_free(set);
	if (r != MAILIMAP_NO_ERROR) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	t->rows = talloc_zero_array(t, struct imap_message_row, clist_count(result) ? clist_count(result) : 1);
	if (!t->rows) {
		mailimap_fetch_list_free(result);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	for (it = clist_begin(result); it && n < MAX_TABLE_ROWS; it = clist_next(it)) {
		const struct mailimap_msg_att *att = clist_content(it);
		struct imap_message_row *row = &t->rows[n];
		clistiter *ai;
		char *uri;

		for (ai = att && att->att_list ? clist_begin(att->att_list) : NULL; ai; ai = clist_next(ai)) {
			const struct mailimap_msg_att_item *item = clist_content(ai);

			if (item->att_type == MAILIMAP_MSG_ATT_ITEM_DYNAMIC) {
				read_flags(row, item->att_data.att_dyn);
			} else if (item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC && item->att_data.att_static) {
				read_static(t->rows, row, item->att_data.att_static);
			}
		}
		if (row->uid == 0) {
			continue;
		}
		uri = imap_message_uri(t, f, t->uidvalidity, row->uid);
		if (!uri || imap_fmid_for_uri(f->ctx, uri, &row->mid) != MAPISTORE_SUCCESS) {
			mailimap_fetch_list_free(result);
			return MAPISTORE_ERR_NO_MEMORY;
		}
		talloc_free(uri);
		n++;
	}
	mailimap_fetch_list_free(result);
	t->row_count = n;
	return MAPISTORE_SUCCESS;
}

static struct FILETIME *filetime(TALLOC_CTX *mem_ctx, time_t t)
{
	struct FILETIME	*ft;
	uint64_t	nt;

	if (t <= 0) {
		return NULL;
	}
	ft = talloc(mem_ctx, struct FILETIME);
	if (ft) {
		nt = ((uint64_t) t + 11644473600ULL) * 10000000ULL;
		ft->dwLowDateTime = (uint32_t) nt;
		ft->dwHighDateTime = (uint32_t) (nt >> 32);
	}
	return ft;
}

static char *dup_or_empty(TALLOC_CTX *mem_ctx, const char *s)
{
	return talloc_strdup(mem_ctx, s ? s : "");
}

/* One property of a message row (plan Decision 5); NULL when the message has no such value. */
_PUBLIC_ void *imap_row_value(TALLOC_CTX *mem_ctx, const struct imap_message_row *row, const struct imap_folder *f,
			      enum MAPITAGS tag)
{
	uint32_t flags;

	switch (tag) {
	case PidTagSubject:
	case PidTagNormalizedSubject:
	case PidTagConversationTopic:
		return dup_or_empty(mem_ctx, row->subject);
	case PidTagSubjectPrefix:
		return talloc_strdup(mem_ctx, "");
	case PidTagSenderName:
	case PidTagSentRepresentingName:
		return row->from_name ? talloc_strdup(mem_ctx, row->from_name) : NULL;
	case PidTagSenderEmailAddress:
	case PidTagSentRepresentingEmailAddress:
	case PidTagSenderSmtpAddress:
	case PidTagSentRepresentingSmtpAddress:
		return row->from_address ? talloc_strdup(mem_ctx, row->from_address) : NULL;
	case PidTagSenderAddressType:
	case PidTagSentRepresentingAddressType:
		return row->from_address ? talloc_strdup(mem_ctx, "SMTP") : NULL;
	case PidTagDisplayTo:
		return dup_or_empty(mem_ctx, row->display_to);
	case PidTagDisplayCc:
		return dup_or_empty(mem_ctx, row->display_cc);
	case PidTagDisplayBcc:
		return talloc_strdup(mem_ctx, "");
	case PidTagMessageDeliveryTime:
	case PidTagLastModificationTime:
	case PidTagCreationTime:
		return filetime(mem_ctx, row->internal ? row->internal : row->date);
	case PidTagClientSubmitTime:
		return filetime(mem_ctx, row->date ? row->date : row->internal);
	case PidTagMessageSize:
		return imap_long(mem_ctx, row->size);
	case PidTagMessageFlags:
		flags = (row->seen ? MSGFLAG_READ : 0) | (row->has_attachments ? MSGFLAG_HASATTACH : 0) |
			(row->draft ? MSGFLAG_UNSENT : 0);
		return imap_long(mem_ctx, flags);
	case PidTagRead:
		return imap_bool(mem_ctx, row->seen);
	case PidTagHasAttachments:
		return imap_bool(mem_ctx, row->has_attachments);
	case PidTagMessageClass:
		return talloc_strdup(mem_ctx, "IPM.Note");
	case PidTagInternetMessageId:
		return row->message_id ? talloc_strdup(mem_ctx, row->message_id) : NULL;
	case PidTagImportance:
		return imap_long(mem_ctx, 1); /* normal */
	case PidTagSensitivity:
	case PidTagPriority:
		return imap_long(mem_ctx, 0);
	case PidTagIconIndex:
		/* Read, unread, replied (MS-OXOMSG 2.2.1.10). */
		return imap_long(mem_ctx, row->answered ? 0x105 : row->seen ? 0x100 : 0x101);
	case PidTagFlagStatus:
		return row->flagged ? imap_long(mem_ctx, 2) : NULL; /* followupFlagged */
	case PidTagMid:
		return imap_i8(mem_ctx, row->mid);
	case PidTagFolderId:
	case PidTagParentFolderId:
		return imap_i8(mem_ctx, f->fid);
	default:
		return NULL;
	}
}

_PUBLIC_ enum mapistore_error imap_message_row(struct imap_table *t, TALLOC_CTX *mem_ctx, uint32_t row,
					       struct mapistore_property_data *data)
{
	uint16_t i;

	for (i = 0; i < t->column_count; i++) {
		data[i].data = imap_row_value(mem_ctx, &t->rows[row], t->folder, t->columns[i]);
		data[i].error = data[i].data ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NOT_FOUND;
	}
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error imap_folder_open_message(void *folder, TALLOC_CTX *mem_ctx, uint64_t mid, bool read_write,
						       void **message)
{
	return MAPISTORE_ERR_NOT_FOUND;
}

_PUBLIC_ enum mapistore_error imap_message_properties(void *message, TALLOC_CTX *mem_ctx, uint16_t count,
						      enum MAPITAGS *tags, struct mapistore_property_data *data)
{
	return MAPISTORE_ERR_NOT_FOUND;
}

_PUBLIC_ void imap_message_fill(struct mapistore_backend *backend)
{
	(void) backend;
}
