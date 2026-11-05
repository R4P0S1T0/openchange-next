/*
   OpenChange Storage Abstraction Layer library
   IMAP backend: RFC 5322 / MIME rendering of a message Outlook wrote

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
#include <unistd.h>
#include <sys/random.h>

#include <libetpan/libetpan.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "imap_backend.h"

/* Raw bytes per encoded word: base64 of 45 bytes + "=?UTF-8?B??=" stays under 75 (RFC 2047 2). */
#define WORD_BYTES 45

static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64(TALLOC_CTX *mem_ctx, const uint8_t *p, size_t n)
{
	char	*out = talloc_array(mem_ctx, char, (n + 2) / 3 * 4 + 1);
	size_t	i, j = 0;

	for (i = 0; out && i < n; i += 3) {
		uint32_t v = p[i] << 16 | (i + 1 < n ? p[i + 1] << 8 : 0) | (i + 2 < n ? p[i + 2] : 0);

		out[j++] = b64chars[v >> 18 & 0x3F];
		out[j++] = b64chars[v >> 12 & 0x3F];
		out[j++] = i + 1 < n ? b64chars[v >> 6 & 0x3F] : '=';
		out[j++] = i + 2 < n ? b64chars[v & 0x3F] : '=';
	}
	if (out) {
		out[j] = '\0';
	}
	return out;
}

/* Header text as is when it is plain printable ASCII, else as UTF-8 encoded words, each holding
   whole characters, separated by a fold. Line breaks never survive as such. */
static char *header_text(TALLOC_CTX *mem_ctx, const char *s)
{
	const unsigned char	*p = (const unsigned char *) s;
	bool			plain = true;
	size_t			len = strlen(s), start, end;
	char			*out = NULL, *word;

	for (start = 0; start < len; start++) {
		if (p[start] < 0x20 || p[start] >= 0x7F) {
			plain = false;
		}
	}
	if (plain && !strstr(s, "=?")) {
		return talloc_strdup(mem_ctx, s);
	}
	for (start = 0; start < len; start = end) {
		end = start + WORD_BYTES < len ? start + WORD_BYTES : len;
		while (end > start + 1 && end < len && (p[end] & 0xC0) == 0x80) {
			end--; /* never split a UTF-8 sequence */
		}
		word = base64(mem_ctx, p + start, end - start);
		out = word ? (out ? talloc_asprintf_append_buffer(out, "\r\n =?UTF-8?B?%s?=", word)
				  : talloc_asprintf(mem_ctx, "=?UTF-8?B?%s?=", word)) : NULL;
		talloc_free(word);
		if (!out) {
			return NULL;
		}
	}
	return out ? out : talloc_strdup(mem_ctx, "");
}

/* An addr-spec Outlook gave us: one token, no header syntax inside. */
static bool valid_address(const char *a)
{
	const unsigned char *p;

	if (!a || !a[0] || !strchr(a, '@')) {
		return false;
	}
	for (p = (const unsigned char *) a; *p; p++) {
		if (*p <= 0x20 || *p >= 0x7F || strchr("<>()[],;:\\\"", *p)) {
			return false;
		}
	}
	return true;
}

/* `Name <addr>`, or just `addr` without a distinct name. */
static char *mailbox_text(TALLOC_CTX *mem_ctx, const char *name, const char *address)
{
	char		*n, *q;
	const char	*c;

	if (!name || !name[0] || strcasecmp(name, address) == 0) {
		return talloc_strdup(mem_ctx, address);
	}
	n = header_text(mem_ctx, name);
	if (!n) {
		return NULL;
	}
	if (strncmp(n, "=?", 2) != 0) {
		/* ASCII: a quoted string, so commas and dots in names stay one phrase. */
		q = talloc_strdup(mem_ctx, "\"");
		for (c = n; q && *c; c++) {
			q = (*c == '"' || *c == '\\') ? talloc_asprintf_append_buffer(q, "\\%c", *c)
						       : talloc_asprintf_append_buffer(q, "%c", *c);
		}
		n = q ? talloc_strdup_append_buffer(q, "\"") : NULL;
	}
	return n ? talloc_asprintf(mem_ctx, "%s <%s>", n, address) : NULL;
}

/* A Message-ID list from Outlook, kept only when it is plain `<...>` tokens. */
static bool valid_ids(const char *s)
{
	const unsigned char *p;

	if (!s || s[0] != '<') {
		return false;
	}
	for (p = (const unsigned char *) s; *p; p++) {
		if (*p < 0x20 || *p >= 0x7F) {
			return false;
		}
	}
	return s[strlen(s) - 1] == '>';
}

static char *address_header(TALLOC_CTX *mem_ctx, const struct imap_draft *d, enum ulRecipClass type, bool *bad)
{
	char		*out = NULL, *mb;
	uint32_t	i;

	for (i = 0; i < d->recipient_count; i++) {
		const struct imap_recipient *r = &d->recipients[i];

		if (r->type != type) {
			continue;
		}
		if (!valid_address(r->address)) {
			*bad = true;
			return NULL;
		}
		mb = mailbox_text(mem_ctx, r->name, r->address);
		out = mb ? (out ? talloc_asprintf_append_buffer(out, ",\r\n %s", mb) : mb) : NULL;
		if (!out) {
			*bad = true;
			return NULL;
		}
	}
	return out;
}

static char *rfc5322_date(TALLOC_CTX *mem_ctx, time_t now)
{
	static const char *days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	static const char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	struct tm tm;

	/* UTC with fixed English names: the daemon's locale must not leak into a header. */
	if (!gmtime_r(&now, &tm)) {
		return NULL;
	}
	return talloc_asprintf(mem_ctx, "%s, %02d %s %04d %02d:%02d:%02d +0000", days[tm.tm_wday], tm.tm_mday,
			       months[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static char *new_message_id(TALLOC_CTX *mem_ctx, const char *from_address)
{
	uint8_t	r[12];
	char	*hex;
	size_t	i;

	if (getrandom(r, sizeof r, 0) != sizeof r) {
		return NULL;
	}
	hex = talloc_strdup(mem_ctx, "<");
	for (i = 0; hex && i < sizeof r; i++) {
		hex = talloc_asprintf_append_buffer(hex, "%02x", r[i]);
	}
	return hex ? talloc_asprintf_append_buffer(hex, "@%s>", strchr(from_address, '@') + 1) : NULL;
}

/* MIME charset name of an Outlook PidTagInternetCodepage for the HTML body. */
static const char *html_charset(uint32_t codepage)
{
	switch (codepage) {
	case 1252:	return "windows-1252";
	case 28591:	return "iso-8859-1";
	case 28605:	return "iso-8859-15";
	case 20127:	return "us-ascii";
	default:	return "utf-8";
	}
}

static struct mailmime *text_part(const char *type, const char *charset, const char *data, size_t len)
{
	struct mailmime_content		*content = mailmime_content_new_with_str(type);
	struct mailmime_parameter	*param = mailmime_param_new_with_data("charset", (char *) charset);
	struct mailmime_fields		*fields = mailmime_fields_new_encoding(MAILMIME_MECHANISM_QUOTED_PRINTABLE);
	struct mailmime			*part;

	if (!content || !param || !fields || clist_append(content->ct_parameters, param) < 0) {
		if (content) mailmime_content_free(content);
		if (param) mailmime_parameter_free(param);
		if (fields) mailmime_fields_free(fields);
		return NULL;
	}
	part = mailmime_new_empty(content, fields);
	if (!part) {
		mailmime_content_free(content);
		mailmime_fields_free(fields);
		return NULL;
	}
	/* libetpan keeps a pointer to `data`: it lives in the compose context until the write. */
	mailmime_set_body_text(part, (char *) data, len);
	return part;
}

static struct mailmime *attachment_part(TALLOC_CTX *mem_ctx, const struct imap_attachment *a)
{
	struct mailmime_content		*content;
	struct mailmime_parameter	*param;
	struct mailmime_fields		*fields;
	struct mailmime_disposition	*dsp;
	struct mailmime_mechanism	*mech;
	struct mailmime			*part;
	const char			*fname = a->filename && a->filename[0] ? a->filename : "attachment";
	char				*encoded = header_text(mem_ctx, fname);
	char				*cid = NULL;

	/* RFC 2047 words inside the quoted parameters: what Outlook and Exchange send, and what the
	   M3 reader decodes. */
	if (!encoded || strpbrk(encoded, "\"\\\r\n")) {
		encoded = talloc_strdup(mem_ctx, "attachment");
	}
	content = mailmime_content_new_with_str(a->mime_type && a->mime_type[0] && !strpbrk(a->mime_type, " \"\r\n;")
						? a->mime_type : "application/octet-stream");
	if (!content) {
		content = mailmime_content_new_with_str("application/octet-stream");
	}
	param = mailmime_param_new_with_data("name", encoded);
	if (!content || !param || clist_append(content->ct_parameters, param) < 0) {
		if (content) mailmime_content_free(content);
		if (param) mailmime_parameter_free(param);
		return NULL;
	}
	if (a->content_id && a->content_id[0] && !strpbrk(a->content_id, "<> \"\r\n")) {
		cid = strdup(a->content_id);
	}
	dsp = mailmime_disposition_new_with_data(cid ? MAILMIME_DISPOSITION_TYPE_INLINE : MAILMIME_DISPOSITION_TYPE_ATTACHMENT,
						 strdup(encoded), NULL, NULL, NULL, (size_t) -1);
	mech = mailmime_mechanism_new(MAILMIME_MECHANISM_BASE64, NULL);
	fields = (dsp && mech) ? mailmime_fields_new_with_data(mech, cid, NULL, dsp, NULL) : NULL;
	if (!fields) {
		if (dsp) mailmime_disposition_free(dsp);
		if (mech) mailmime_mechanism_free(mech);
		free(cid);
		mailmime_content_free(content);
		return NULL;
	}
	part = mailmime_new_empty(content, fields);
	if (!part) {
		mailmime_content_free(content);
		mailmime_fields_free(fields);
		return NULL;
	}
	mailmime_set_body_text(part, (char *) a->data, a->size);
	return part;
}

static bool add(struct mailmime *multi, struct mailmime *part)
{
	if (!part) {
		return false;
	}
	if (mailmime_smart_add_part(multi, part) != MAILIMF_NO_ERROR) {
		mailmime_free(part);
		return false;
	}
	return true;
}

/* text/plain, text/html, alternative of both, related with inline images, mixed with attachments. */
static struct mailmime *body_tree(TALLOC_CTX *mem_ctx, const struct imap_draft *d)
{
	struct mailmime	*text = NULL, *html = NULL, *body, *alt, *rel, *mixed;
	const char	*plain = d->body;
	uint32_t	i, inline_count = 0;
	bool		ok = true;

	/* shortcut: PidTagRtfCompressed is not read; the body comes from PidTagBody (Outlook always
	   sets it) and PidTagHtml. Upgrade when Outlook is seen sending HTML only inside RTF. */
	if (plain || !d->html) {
		text = text_part("text/plain", "utf-8", plain ? plain : "", plain ? strlen(plain) : 0);
		if (!text) {
			return NULL;
		}
	}
	if (d->html) {
		html = text_part("text/html", html_charset(d->html_codepage), (const char *) d->html, d->html_len);
		if (!html) {
			if (text) mailmime_free(text);
			return NULL;
		}
		for (i = 0; i < d->attachment_count; i++) {
			inline_count += d->attachments[i].content_id != NULL;
		}
	}
	if (html && inline_count) {
		rel = mailmime_multiple_new("multipart/related");
		ok = rel && add(rel, html);
		for (i = 0; ok && i < d->attachment_count; i++) {
			if (d->attachments[i].content_id) {
				ok = add(rel, attachment_part(mem_ctx, &d->attachments[i]));
			}
		}
		if (!ok) {
			if (rel) mailmime_free(rel); else mailmime_free(html);
			if (text) mailmime_free(text);
			return NULL;
		}
		html = rel;
	}
	if (text && html) {
		alt = mailmime_multiple_new("multipart/alternative");
		if (!alt || !add(alt, text) || !add(alt, html)) {
			if (alt) mailmime_free(alt);
			return NULL;
		}
		body = alt;
	} else {
		body = text ? text : html;
	}
	if (d->attachment_count == inline_count && (html || !inline_count)) {
		return body;
	}
	mixed = mailmime_multiple_new("multipart/mixed");
	ok = mixed && add(mixed, body);
	for (i = 0; ok && i < d->attachment_count; i++) {
		/* Inline parts without an HTML body to point at them travel as plain attachments. */
		if (!d->attachments[i].content_id || !html) {
			ok = add(mixed, attachment_part(mem_ctx, &d->attachments[i]));
		}
	}
	if (!ok) {
		if (mixed) mailmime_free(mixed); else mailmime_free(body);
		return NULL;
	}
	return mixed;
}

_PUBLIC_ char *imap_compose(TALLOC_CTX *mem_ctx, const struct imap_draft *d, const char *from_address,
			    const char *from_name, time_t now, bool with_bcc, size_t *len)
{
	TALLOC_CTX	*tmp;
	struct mailmime	*tree, *body;
	MMAPString	*str;
	char		*headers, *field, *out = NULL;
	bool		bad = false;
	int		col = 0, r;

	if (!d || !valid_address(from_address) || !len) {
		return NULL;
	}
	tmp = talloc_new(NULL);
	if (!tmp) {
		return NULL;
	}
	headers = mailbox_text(tmp, from_name, from_address);
	headers = headers ? talloc_asprintf(tmp, "From: %s\r\n", headers) : NULL;
	field = address_header(tmp, d, MAPI_TO, &bad);
	if (headers && field) headers = talloc_asprintf_append_buffer(headers, "To: %s\r\n", field);
	field = bad ? NULL : address_header(tmp, d, MAPI_CC, &bad);
	if (headers && field) headers = talloc_asprintf_append_buffer(headers, "Cc: %s\r\n", field);
	/* Bcc recipients exist in the SMTP envelope only; a stored draft keeps them as a header. */
	field = (bad || !with_bcc) ? NULL : address_header(tmp, d, MAPI_BCC, &bad);
	if (headers && field) headers = talloc_asprintf_append_buffer(headers, "Bcc: %s\r\n", field);
	field = header_text(tmp, d->subject ? d->subject : "");
	if (headers && field) headers = talloc_asprintf_append_buffer(headers, "Subject: %s\r\n", field);
	field = rfc5322_date(tmp, now);
	if (headers && field) headers = talloc_asprintf_append_buffer(headers, "Date: %s\r\n", field);
	field = valid_ids(d->message_id) && !strchr(d->message_id, ' ') ? talloc_strdup(tmp, d->message_id)
									 : new_message_id(tmp, from_address);
	if (headers && field) headers = talloc_asprintf_append_buffer(headers, "Message-ID: %s\r\n", field);
	if (headers && valid_ids(d->in_reply_to)) {
		headers = talloc_asprintf_append_buffer(headers, "In-Reply-To: %s\r\n", d->in_reply_to);
	}
	if (headers && valid_ids(d->references)) {
		headers = talloc_asprintf_append_buffer(headers, "References: %s\r\n", d->references);
	}
	if (bad || !headers || !field) {
		talloc_free(tmp);
		return NULL;
	}
	body = body_tree(tmp, d);
	/* As the body of a message part, the top part gets its Content-Type and MIME-Version written. */
	tree = body ? mailmime_new_message_data(NULL) : NULL;
	if (tree && mailmime_smart_add_part(tree, body) != MAILIMF_NO_ERROR) {
		mailmime_free(tree);
		tree = NULL;
	}
	if (!tree && body) {
		mailmime_free(body);
	}
	str = tree ? mmap_string_new("") : NULL;
	if (!str) {
		if (tree) mailmime_free(tree);
		talloc_free(tmp);
		return NULL;
	}
	r = mailmime_write_mem(str, &col, tree);
	if (r == MAILIMF_NO_ERROR) {
		out = talloc_asprintf(mem_ctx, "%s%s", headers, str->str);
		if (out) {
			*len = strlen(out);
		}
	}
	mmap_string_free(str);
	mailmime_free(tree);
	talloc_free(tmp);
	return out;
}

_PUBLIC_ uint32_t imap_draft_envelope(const struct imap_draft *d, TALLOC_CTX *mem_ctx, const char ***rcpts)
{
	const char	**out;
	uint32_t	i, j, n = 0;

	out = talloc_zero_array(mem_ctx, const char *, d->recipient_count + 1);
	if (!out) {
		*rcpts = NULL;
		return 0;
	}
	for (i = 0; i < d->recipient_count; i++) {
		const char *a = d->recipients[i].address;
		bool seen = false;

		for (j = 0; a && j < n; j++) {
			seen = seen || strcasecmp(out[j], a) == 0;
		}
		if (a && !seen) {
			out[n++] = a;
		}
	}
	*rcpts = out;
	return n;
}
