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
#include <iconv.h>

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


/* Replaces every byte sequence that is not well-formed UTF-8 by U+FFFD, and controls other than
   tab, CR and LF by spaces. */
_PUBLIC_ char *imap_utf8_clean(TALLOC_CTX *mem_ctx, const char *s, size_t len)
{
	const unsigned char	*p = (const unsigned char *) s;
	char			*out;
	size_t			i = 0, n = 0;

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
			out[n++] = ((c < 0x20 && c != '\t' && c != '\r' && c != '\n') || c == 0x7F) ? ' ' : c;
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
	/* Only encoded words need decoding; libetpan's conversion drops invalid raw bytes silently. */
	if (strstr(raw, "=?") && mailmime_encoded_phrase_parse("utf-8", raw, strlen(raw), &idx, "utf-8", &decoded) == MAILIMF_NO_ERROR && decoded) {
		out = imap_utf8_clean(mem_ctx, decoded, MIN(strlen(decoded), MAX_HEADER_TEXT));
		free(decoded);
		return out;
	}
	return imap_utf8_clean(mem_ctx, raw, MIN(strlen(raw), MAX_HEADER_TEXT));
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
	return name ? imap_utf8_clean(mem_ctx, name, MIN(strlen(name), MAX_HEADER_TEXT)) : NULL;
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

static void add_recipients(TALLOC_CTX *mem_ctx, struct imap_message_row *row, clist *list, enum ulRecipClass type)
{
	clistiter *it;

	for (it = list ? clist_begin(list) : NULL; it; it = clist_next(it)) {
		const struct mailimap_address *a = clist_content(it);
		struct imap_recipient *r;
		char *address = address_text(mem_ctx, a, false);

		if (!address) {
			continue; /* group syntax markers carry no mailbox */
		}
		r = talloc_realloc(mem_ctx, row->recipients, struct imap_recipient, row->recipient_count + 1);
		if (!r) {
			return;
		}
		row->recipients = r;
		r[row->recipient_count].type = type;
		r[row->recipient_count].address = address;
		r[row->recipient_count].name = address_text(mem_ctx, a, true);
		row->recipient_count++;
	}
}

static void read_envelope(TALLOC_CTX *mem_ctx, struct imap_message_row *row, const struct mailimap_envelope *env,
			  bool want_recipients)
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
	if (want_recipients) {
		add_recipients(mem_ctx, row, env->env_to ? env->env_to->to_list : NULL, MAPI_TO);
		add_recipients(mem_ctx, row, env->env_cc ? env->env_cc->cc_list : NULL, MAPI_CC);
		add_recipients(mem_ctx, row, env->env_bcc ? env->env_bcc->bcc_list : NULL, MAPI_BCC);
	}
}

static void read_static(TALLOC_CTX *mem_ctx, struct imap_message_row *row, const struct mailimap_msg_att_static *st,
			bool want_recipients)
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
		read_envelope(mem_ctx, row, st->att_data.att_env, want_recipients);
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

/* UID FETCH `set` of the envelope, flags, size, dates and structure: one row per message, each
   with its message ID from imap://<user>/<folder>/<uidvalidity>_<uid>. */
static enum mapistore_error fetch_rows(TALLOC_CTX *mem_ctx, struct imap_folder *f, uint32_t uidvalidity,
				       struct mailimap_set *set, bool want_recipients,
				       struct imap_message_row **rowsp, uint32_t *countp)
{
	struct imap_conn		*conn = imap_context_conn(f->ctx);
	struct mailimap_fetch_type	*ft;
	struct imap_message_row		*rows;
	clist				*result = NULL;
	clistiter			*it;
	uint32_t			n = 0;
	int				r;

	*rowsp = NULL;
	*countp = 0;
	ft = mailimap_fetch_type_new_fetch_att_list_empty();
	if (!conn || !ft ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_uid()) != MAILIMAP_NO_ERROR ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_flags()) != MAILIMAP_NO_ERROR ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_rfc822_size()) != MAILIMAP_NO_ERROR ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_internaldate()) != MAILIMAP_NO_ERROR ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_envelope()) != MAILIMAP_NO_ERROR ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_bodystructure()) != MAILIMAP_NO_ERROR) {
		if (ft) mailimap_fetch_type_free(ft);
		return conn ? MAPISTORE_ERR_NO_MEMORY : MAPISTORE_ERR_CONN_REFUSED;
	}
	r = imap_conn_check(conn, mailimap_uid_fetch(imap_conn_session(conn), set, ft, &result));
	mailimap_fetch_type_free(ft);
	if (r != MAILIMAP_NO_ERROR) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	rows = talloc_zero_array(mem_ctx, struct imap_message_row, clist_count(result) ? clist_count(result) : 1);
	if (!rows) {
		mailimap_fetch_list_free(result);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	for (it = clist_begin(result); it && n < MAX_TABLE_ROWS; it = clist_next(it)) {
		const struct mailimap_msg_att *att = clist_content(it);
		struct imap_message_row *row = &rows[n];
		clistiter *ai;
		char *uri;

		for (ai = att && att->att_list ? clist_begin(att->att_list) : NULL; ai; ai = clist_next(ai)) {
			const struct mailimap_msg_att_item *item = clist_content(ai);

			if (item->att_type == MAILIMAP_MSG_ATT_ITEM_DYNAMIC) {
				read_flags(row, item->att_data.att_dyn);
			} else if (item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC && item->att_data.att_static) {
				read_static(rows, row, item->att_data.att_static, want_recipients);
			}
		}
		if (row->uid == 0) {
			/* An unsolicited FETCH (a flag change) without UID: not a row, and not the next one's. */
			memset(row, 0, sizeof *row);
			continue;
		}
		uri = imap_message_uri(rows, f, uidvalidity, row->uid);
		if (!uri || imap_fmid_for_uri(f->ctx, uri, &row->mid) != MAPISTORE_SUCCESS) {
			mailimap_fetch_list_free(result);
			talloc_free(rows);
			return MAPISTORE_ERR_NO_MEMORY;
		}
		talloc_free(uri);
		n++;
	}
	mailimap_fetch_list_free(result);
	*rowsp = rows;
	*countp = n;
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error imap_message_table_load(struct imap_table *t)
{
	struct imap_folder	*f = t->folder;
	struct imap_conn	*conn = imap_context_conn(f->ctx);
	struct mailimap_set	*set;
	struct imap_status	st;
	enum mapistore_error	ret;

	if (!conn || imap_examine(conn, f->mailbox, &st) != MAPISTORE_SUCCESS) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	t->uidvalidity = st.uidvalidity;
	t->row_count = 0;
	if (st.messages == 0) {
		return MAPISTORE_SUCCESS;
	}
	set = mailimap_set_new_interval(1, 0);
	if (!set) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	ret = fetch_rows(t, f, t->uidvalidity, set, false, &t->rows, &t->row_count);
	mailimap_set_free(set);
	return ret;
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


/* Nested MIME parts followed; deeper ones are ignored. */
#define MAX_MIME_DEPTH 16
/* Attachments kept per message. */
#define MAX_ATTACHMENTS 256

/* `len` bytes in `charset` as UTF-8 (glibc iconv; libetpan's charconv leaks on unknown charsets).
   NULL when the charset is unknown or the text does not convert. */
static char *to_utf8(TALLOC_CTX *mem_ctx, const char *charset, const char *in, size_t len)
{
	iconv_t	cd = iconv_open("UTF-8", charset);
	char	*out, *op, *ip = (char *) in;
	size_t	il = len, ol, size;

	if (cd == (iconv_t) -1) {
		return NULL;
	}
	size = len * 4 + 1; /* any charset to UTF-8 grows at most 4x per input byte */
	out = talloc_array(mem_ctx, char, size);
	op = out;
	ol = size - 1;
	if (!out || iconv(cd, &ip, &il, &op, &ol) == (size_t) -1) {
		iconv_close(cd);
		talloc_free(out);
		return NULL;
	}
	iconv_close(cd);
	*op = '\0';
	return out;
}

/* A part's bytes after its Content-Transfer-Encoding, as UTF-8 text when `text` is set. */
static char *part_content(TALLOC_CTX *mem_ctx, struct mailmime *mime, const struct mailmime_single_fields *sf,
			  bool text, size_t *lenp)
{
	struct mailmime_data	*d = mime->mm_type == MAILMIME_SINGLE ? mime->mm_data.mm_single : mime->mm_body;
	char			*decoded = NULL, *converted = NULL, *out;
	size_t			idx = 0, len = 0;
	int			encoding = sf->fld_encoding ? sf->fld_encoding->enc_type : MAILMIME_MECHANISM_8BIT;

	if (!d || d->dt_type != MAILMIME_DATA_TEXT || !d->dt_data.dt_text.dt_data) {
		return NULL;
	}
	if (mime->mm_type != MAILMIME_SINGLE) {
		encoding = MAILMIME_MECHANISM_8BIT; /* a forwarded message is kept as it was */
	}
	if (mailmime_part_parse(d->dt_data.dt_text.dt_data, d->dt_data.dt_text.dt_length, &idx, encoding,
				&decoded, &len) != MAILIMF_NO_ERROR || !decoded) {
		return NULL;
	}
	if (!text) {
		out = talloc_memdup(mem_ctx, decoded, len ? len : 1);
		mailmime_decoded_part_free(decoded);
		*lenp = len;
		return out;
	}
	/* Unknown or broken charsets fall back to the raw bytes, cleaned as UTF-8. */
	converted = (sf->fld_content_charset && strcasecmp(sf->fld_content_charset, "utf-8") != 0)
		? to_utf8(mem_ctx, sf->fld_content_charset, decoded, len) : NULL;
	out = converted ? imap_utf8_clean(mem_ctx, converted, strlen(converted)) : imap_utf8_clean(mem_ctx, decoded, len);
	talloc_free(converted);
	mailmime_decoded_part_free(decoded);
	*lenp = out ? strlen(out) : 0;
	return out;
}

static bool is_subtype(const struct mailmime_content *ct, const char *subtype)
{
	return ct && ct->ct_subtype && strcasecmp(ct->ct_subtype, subtype) == 0;
}

static bool is_text(const struct mailmime_content *ct)
{
	return ct && ct->ct_type && ct->ct_type->tp_type == MAILMIME_TYPE_DISCRETE_TYPE &&
		ct->ct_type->tp_data.tp_discrete_type->dt_type == MAILMIME_DISCRETE_TYPE_TEXT;
}

static void add_attachment(struct imap_message *m, struct mailmime *mime, const struct mailmime_single_fields *sf)
{
	struct imap_attachment	*a;
	const struct mailmime_content *ct = mime->mm_content_type;
	const char		*name = sf->fld_disposition_filename ? sf->fld_disposition_filename : sf->fld_content_name;
	size_t			len = 0;
	uint8_t			*data;

	if (m->attachment_count >= MAX_ATTACHMENTS) {
		return;
	}
	data = (uint8_t *) part_content(m, mime, sf, false, &len);
	if (!data || len > UINT32_MAX) {
		return;
	}
	a = talloc_realloc(m, m->attachments, struct imap_attachment, m->attachment_count + 1);
	if (!a) {
		return;
	}
	m->attachments = a;
	a = &a[m->attachment_count];
	memset(a, 0, sizeof *a);
	a->type = IMAP_OBJ_ATTACHMENT;
	a->number = m->attachment_count;
	a->data = data;
	a->size = len;
	a->filename = name ? imap_decode_header(m, name)
		: talloc_strdup(m, mime->mm_type == MAILMIME_MESSAGE ? "message.eml" : "attachment");
	a->mime_type = talloc_asprintf(m, "%s/%s",
				       mime->mm_type == MAILMIME_MESSAGE ? "message" :
				       !ct || !ct->ct_type ? "application" :
				       ct->ct_type->tp_type == MAILMIME_TYPE_COMPOSITE_TYPE ? "message" :
				       ct->ct_type->tp_data.tp_discrete_type->dt_type == MAILMIME_DISCRETE_TYPE_TEXT ? "text" :
				       ct->ct_type->tp_data.tp_discrete_type->dt_type == MAILMIME_DISCRETE_TYPE_IMAGE ? "image" :
				       ct->ct_type->tp_data.tp_discrete_type->dt_type == MAILMIME_DISCRETE_TYPE_AUDIO ? "audio" :
				       ct->ct_type->tp_data.tp_discrete_type->dt_type == MAILMIME_DISCRETE_TYPE_VIDEO ? "video" :
				       "application",
				       mime->mm_type == MAILMIME_MESSAGE ? "rfc822" :
				       ct && ct->ct_subtype ? ct->ct_subtype : "octet-stream");
	a->content_id = sf->fld_id ? imap_utf8_clean(m, sf->fld_id, strlen(sf->fld_id)) : NULL;
	if (a->filename && a->mime_type) {
		m->attachment_count++;
	}
}

/* The first text/plain and text/html parts (not attachments) become the body; the rest attachments. */
static void walk_mime(struct imap_message *m, struct mailmime *mime, int depth)
{
	struct mailmime_single_fields	sf;
	clistiter			*it;
	bool				attachment;
	size_t				len;

	if (!mime || depth > MAX_MIME_DEPTH) {
		return;
	}
	memset(&sf, 0, sizeof sf);
	mailmime_single_fields_init(&sf, mime->mm_mime_fields, mime->mm_content_type);
	attachment = sf.fld_disposition && sf.fld_disposition->dsp_type &&
		sf.fld_disposition->dsp_type->dsp_type == MAILMIME_DISPOSITION_TYPE_ATTACHMENT;
	switch (mime->mm_type) {
	case MAILMIME_MULTIPLE:
		for (it = mime->mm_data.mm_multipart.mm_mp_list ? clist_begin(mime->mm_data.mm_multipart.mm_mp_list) : NULL;
		     it; it = clist_next(it)) {
			walk_mime(m, clist_content(it), depth + 1);
		}
		break;
	case MAILMIME_MESSAGE:
		if (depth == 0) {
			walk_mime(m, mime->mm_data.mm_message.mm_msg_mime, depth + 1);
		} else {
			add_attachment(m, mime, &sf);
		}
		break;
	case MAILMIME_SINGLE:
		if (!attachment && !mime->mm_content_type) {
			if (!m->body) m->body = part_content(m, mime, &sf, true, &len);
		} else if (!attachment && is_text(mime->mm_content_type) && is_subtype(mime->mm_content_type, "html") && !m->html) {
			m->html = part_content(m, mime, &sf, true, &len);
		} else if (!attachment && is_text(mime->mm_content_type) && !is_subtype(mime->mm_content_type, "html") && !m->body) {
			m->body = part_content(m, mime, &sf, true, &len);
		} else {
			add_attachment(m, mime, &sf);
		}
		break;
	default:
		break;
	}
}

/* Plain text of an HTML body: tags dropped, the common entities decoded. */
static char *html_to_text(TALLOC_CTX *mem_ctx, const char *html)
{
	static const struct { const char *entity; char c; } entities[] = {
		{ "&amp;", '&' }, { "&lt;", '<' }, { "&gt;", '>' }, { "&quot;", '"' }, { "&#39;", '\'' }, { "&nbsp;", ' ' },
	};
	char	*out = talloc_array(mem_ctx, char, strlen(html) + 1);
	size_t	n = 0, k;
	bool	in_tag = false;

	if (!out) {
		return NULL;
	}
	while (*html) {
		if (in_tag) {
			in_tag = *html++ != '>';
			continue;
		}
		if (*html == '<') {
			in_tag = true;
			html++;
			continue;
		}
		for (k = 0; k < sizeof entities / sizeof entities[0]; k++) {
			if (strncmp(html, entities[k].entity, strlen(entities[k].entity)) == 0) {
				break;
			}
		}
		if (k < sizeof entities / sizeof entities[0]) {
			out[n++] = entities[k].c;
			html += strlen(entities[k].entity);
		} else {
			out[n++] = *html++;
		}
	}
	out[n] = '\0';
	return out;
}

/* BODY.PEEK[] of one UID (read-only: \Seen is not set). */
static char *fetch_body(TALLOC_CTX *mem_ctx, struct imap_conn *conn, uint32_t uid, size_t *lenp)
{
	struct mailimap_fetch_type	*ft = mailimap_fetch_type_new_fetch_att_list_empty();
	struct mailimap_section		*section = mailimap_section_new(NULL);
	struct mailimap_set		*set = mailimap_set_new_single(uid);
	clist				*result = NULL;
	clistiter			*it, *ai;
	char				*out = NULL;

	if (!ft || !section || !set ||
	    mailimap_fetch_type_new_fetch_att_list_add(ft, mailimap_fetch_att_new_body_peek_section(section)) != MAILIMAP_NO_ERROR) {
		if (ft) mailimap_fetch_type_free(ft);
		else if (section) mailimap_section_free(section);
		if (set) mailimap_set_free(set);
		return NULL;
	}
	if (imap_conn_check(conn, mailimap_uid_fetch(imap_conn_session(conn), set, ft, &result)) == MAILIMAP_NO_ERROR) {
		for (it = clist_begin(result); it && !out; it = clist_next(it)) {
			const struct mailimap_msg_att *att = clist_content(it);

			for (ai = att->att_list ? clist_begin(att->att_list) : NULL; ai && !out; ai = clist_next(ai)) {
				const struct mailimap_msg_att_item *item = clist_content(ai);
				const struct mailimap_msg_att_body_section *bs;

				if (item->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC || !item->att_data.att_static ||
				    item->att_data.att_static->att_type != MAILIMAP_MSG_ATT_BODY_SECTION) {
					continue;
				}
				bs = item->att_data.att_static->att_data.att_body_section;
				if (bs && bs->sec_body_part) {
					out = talloc_memdup(mem_ctx, bs->sec_body_part, bs->sec_length + 1);
					if (out) {
						out[bs->sec_length] = '\0';
						*lenp = bs->sec_length;
					}
				}
			}
		}
		mailimap_fetch_list_free(result);
	}
	mailimap_fetch_type_free(ft);
	mailimap_set_free(set);
	return out;
}

/* The header block, up to the first empty line. */
static char *header_block(TALLOC_CTX *mem_ctx, const char *raw, size_t len)
{
	const char *end = NULL;
	size_t i;

	for (i = 0; i + 3 < len && !end; i++) {
		if (memcmp(raw + i, "\r\n\r\n", 4) == 0) {
			end = raw + i + 2;
		}
	}
	return imap_utf8_clean(mem_ctx, raw, end ? (size_t) (end - raw) : len);
}

/* Opens `mid` of folder `f`: only an ID of this folder, of the mailbox's current UIDVALIDITY,
   of a message that still exists, opens. */
_PUBLIC_ enum mapistore_error imap_folder_open_message(void *folder, TALLOC_CTX *mem_ctx, uint64_t mid, bool read_write,
						       void **message)
{
	struct imap_folder		*f = folder;
	const struct imap_settings	*settings = imap_backend_settings();
	struct imap_conn		*conn;
	struct imap_message		*m;
	struct imap_message_row		*rows;
	struct mailimap_set		*set;
	struct imap_status		st;
	struct mailmime			*mime = NULL;
	char				*uri, *folder_uri, *raw, *end;
	bool				soft_deleted = false;
	unsigned long			uidvalidity, uid;
	uint32_t			count;
	size_t				len = 0, idx = 0;
	enum mapistore_error		ret;

	if (!f || f->type != IMAP_OBJ_FOLDER || !message || !settings) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	*message = NULL;
	folder_uri = imap_uri(mem_ctx, f->ctx->username, f->mailbox, imap_context_delimiter(f->ctx));
	if (!folder_uri || f->ctx->ictx->get_uri(f->ctx->ictx, f->ctx->username, mem_ctx, mid, &uri, &soft_deleted)
	    != MAPISTORE_SUCCESS || soft_deleted || strncmp(uri, folder_uri, strlen(folder_uri)) != 0) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	raw = uri + strlen(folder_uri);
	uidvalidity = strtoul(raw, &end, 10);
	if (end == raw || *end != '_') {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	raw = end + 1;
	uid = strtoul(raw, &end, 10);
	if (end == raw || *end || uid == 0 || uid > UINT32_MAX || uidvalidity > UINT32_MAX) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	conn = imap_context_conn(f->ctx);
	if (!conn || imap_examine(conn, f->mailbox, &st) != MAPISTORE_SUCCESS || st.uidvalidity != uidvalidity) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	set = mailimap_set_new_single((uint32_t) uid);
	if (!set) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	m = talloc_zero(mem_ctx, struct imap_message);
	ret = m ? fetch_rows(m, f, st.uidvalidity, set, true, &rows, &count) : MAPISTORE_ERR_NO_MEMORY;
	mailimap_set_free(set);
	if (ret != MAPISTORE_SUCCESS || count != 1 || rows[0].uid != uid) {
		talloc_free(m);
		return MAPISTORE_ERR_NOT_FOUND;
	}
	m->type = IMAP_OBJ_MESSAGE;
	m->folder = f;
	m->row = rows[0];
	if (m->row.size > settings->max_message_size) {
		m->body = talloc_asprintf(m, "[This message is too large to display here (%u bytes); open it in webmail.]\r\n",
					  m->row.size);
	} else if ((raw = fetch_body(m, conn, (uint32_t) uid, &len)) != NULL) {
		m->headers = header_block(m, raw, len);
		if (mailmime_parse(raw, len, &idx, &mime) == MAILIMF_NO_ERROR && mime) {
			walk_mime(m, mime, 0);
			mailmime_free(mime);
		}
		talloc_free(raw);
	}
	if (!m->body && m->html) {
		m->body = html_to_text(m, m->html);
	}
	if (!m->body) {
		m->body = talloc_strdup(m, "");
	}
	*message = m;
	return MAPISTORE_SUCCESS;
}

static struct Binary_r *binary(TALLOC_CTX *mem_ctx, const void *data, size_t len)
{
	struct Binary_r *b = talloc(mem_ctx, struct Binary_r);

	if (!b) {
		return NULL;
	}
	b->cb = len;
	b->lpb = len ? talloc_memdup(b, data, len) : NULL;
	return (len && !b->lpb) ? NULL : b;
}

_PUBLIC_ enum mapistore_error imap_message_properties(void *object, TALLOC_CTX *mem_ctx, uint16_t count,
						      enum MAPITAGS *tags, struct mapistore_property_data *data)
{
	struct imap_message	*m = object;
	uint16_t		i;

	for (i = 0; i < count; i++) {
		void *v;

		switch (tags[i]) {
		case PidTagBody:
			v = talloc_strdup(mem_ctx, m->body);
			break;
		case PidTagHtml:
			v = m->html ? binary(mem_ctx, m->html, strlen(m->html)) : NULL;
			break;
		case PidTagNativeBody:
			v = imap_long(mem_ctx, m->html ? 3 : 1); /* HTML : plain text */
			break;
		case PidTagInternetCodepage:
			v = imap_long(mem_ctx, 65001); /* bodies are UTF-8 */
			break;
		case PidTagTransportMessageHeaders:
			v = m->headers ? talloc_strdup(mem_ctx, m->headers) : NULL;
			break;
		case PidTagHasAttachments:
			v = imap_bool(mem_ctx, m->attachment_count > 0);
			break;
		default:
			v = imap_row_value(mem_ctx, &m->row, m->folder, tags[i]);
			break;
		}
		data[i].data = v;
		data[i].error = v ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NOT_FOUND;
	}
	return MAPISTORE_SUCCESS;
}

/* Recipient columns: SMTP recipients only, so emsmdb never searches the directory by name. */
static const enum MAPITAGS recipient_columns[] = {
	PidTagDisplayName, PidTagEmailAddress, PidTagAddressType, PidTagSmtpAddress, PidTagRecipientDisplayName,
};
#define N_RECIPIENT_COLUMNS (sizeof recipient_columns / sizeof recipient_columns[0])

_PUBLIC_ enum mapistore_error imap_message_get_data(void *object, TALLOC_CTX *mem_ctx, struct mapistore_message **msgp)
{
	struct imap_message		*m = object;
	struct mapistore_message	*msg;
	uint32_t			i;

	if (!m || m->type != IMAP_OBJ_MESSAGE || !msgp) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	msg = talloc_zero(mem_ctx, struct mapistore_message);
	if (!msg) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	msg->subject_prefix = talloc_strdup(msg, "");
	msg->normalized_subject = talloc_strdup(msg, m->row.subject ? m->row.subject : "");
	msg->columns = talloc_zero(msg, struct SPropTagArray);
	msg->recipients = talloc_zero_array(msg, struct mapistore_message_recipient,
					    m->row.recipient_count ? m->row.recipient_count : 1);
	if (!msg->subject_prefix || !msg->normalized_subject || !msg->columns || !msg->recipients) {
		talloc_free(msg);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	msg->columns->cValues = N_RECIPIENT_COLUMNS;
	msg->columns->aulPropTag = talloc_memdup(msg->columns, recipient_columns, sizeof recipient_columns);
	for (i = 0; i < m->row.recipient_count; i++) {
		const struct imap_recipient *r = &m->row.recipients[i];
		void **d = talloc_zero_array(msg->recipients, void *, N_RECIPIENT_COLUMNS);

		if (!d) {
			talloc_free(msg);
			return MAPISTORE_ERR_NO_MEMORY;
		}
		d[0] = talloc_strdup(d, r->name);
		d[1] = talloc_strdup(d, r->address);
		d[2] = talloc_strdup(d, "SMTP");
		d[3] = talloc_strdup(d, r->address);
		d[4] = talloc_strdup(d, r->name);
		msg->recipients[i].type = r->type;
		msg->recipients[i].username = NULL;
		msg->recipients[i].data = d;
	}
	msg->recipients_count = m->row.recipient_count;
	*msgp = msg;
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error imap_attachment_properties(struct imap_attachment *a, TALLOC_CTX *mem_ctx, uint16_t count,
							 enum MAPITAGS *tags, struct mapistore_property_data *data)
{
	const char	*dot = a->filename ? strrchr(a->filename, '.') : NULL;
	uint16_t	i;

	for (i = 0; i < count; i++) {
		void *v;

		switch (tags[i]) {
		case PidTagAttachNumber:	v = imap_long(mem_ctx, a->number); break;
		case PidTagAttachMethod:	v = imap_long(mem_ctx, 1); break; /* afByValue */
		case PidTagAttachSize:		v = imap_long(mem_ctx, a->size); break;
		case PidTagRenderingPosition:	v = imap_long(mem_ctx, 0xFFFFFFFF); break;
		case PidTagAttachFlags:		v = imap_long(mem_ctx, 0); break;
		case PidTagAttachmentHidden:	v = imap_bool(mem_ctx, false); break;
		case PidTagAttachLongFilename:
		case PidTagAttachFilename:
		case PidTagDisplayName:		v = talloc_strdup(mem_ctx, a->filename); break;
		case PidTagAttachExtension:	v = dot ? talloc_strdup(mem_ctx, dot) : NULL; break;
		case PidTagAttachMimeTag:	v = talloc_strdup(mem_ctx, a->mime_type); break;
		case PidTagAttachContentId:	v = a->content_id ? talloc_strdup(mem_ctx, a->content_id) : NULL; break;
		case PidTagAttachDataBinary:	v = binary(mem_ctx, a->data, a->size); break;
		default:			v = NULL; break;
		}
		data[i].data = v;
		data[i].error = v ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NOT_FOUND;
	}
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error imap_message_get_attachment_table(void *object, TALLOC_CTX *mem_ctx, void **tablep,
								uint32_t *row_count)
{
	struct imap_message	*m = object;
	struct imap_table	*t;

	if (!m || m->type != IMAP_OBJ_MESSAGE || !tablep || !row_count) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	t = talloc_zero(mem_ctx, struct imap_table);
	if (!t) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	t->type = IMAP_OBJ_TABLE;
	t->folder = m->folder;
	t->message = m;
	t->table_type = MAPISTORE_ATTACHMENT_TABLE;
	t->row_count = m->attachment_count;
	*tablep = t;
	*row_count = t->row_count;
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error imap_message_open_attachment(void *object, TALLOC_CTX *mem_ctx, uint32_t number,
							   void **attachment)
{
	struct imap_message *m = object;

	if (!m || m->type != IMAP_OBJ_MESSAGE || !attachment) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (number >= m->attachment_count) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	*attachment = &m->attachments[number];
	return MAPISTORE_SUCCESS;
}

/* M3 is read-only: the read state Outlook sets stays in its own cache (STORE comes with M4). */
static enum mapistore_error set_read_flag(void *message, uint8_t flag)
{
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error open_attachment(void *message, TALLOC_CTX *mem_ctx, uint32_t number, void **attachment)
{
	return imap_message_open_attachment(message, mem_ctx, number, attachment);
}

static enum mapistore_error get_attachment_table(void *message, TALLOC_CTX *mem_ctx, void **table, uint32_t *count)
{
	return imap_message_get_attachment_table(message, mem_ctx, table, count);
}

_PUBLIC_ void imap_message_fill(struct mapistore_backend *backend)
{
	backend->message.get_message_data = imap_message_get_data;
	backend->message.set_read_flag = set_read_flag;
	backend->message.open_attachment = open_attachment;
	backend->message.get_attachment_table = get_attachment_table;
}
