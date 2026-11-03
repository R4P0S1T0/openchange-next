/*
   OpenChange Storage Abstraction Layer library
   Read-only IMAP backend: mailbox names and URIs

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

#include <stdint.h>
#include <string.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "libmapi/libmapi_private.h"
#include "imap_backend.h"

/* Bytes kept as is in a URI segment; everything else is %XX (so '/', '%' and NUL never appear raw). */
static bool uri_safe(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '.' || c == '_' || c == '-' || c == '~' || c == '&' || c == ',' || c == '+';
}

static char *append_encoded(char *out, const char *s, size_t len)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t i;

	for (i = 0; out && i < len; i++) {
		unsigned char c = (unsigned char) s[i];

		out = uri_safe(c) ? talloc_asprintf_append_buffer(out, "%c", c)
			: talloc_asprintf_append_buffer(out, "%%%c%c", hex[c >> 4], hex[c & 0xF]);
	}
	return out;
}

_PUBLIC_ char *imap_uri(TALLOC_CTX *mem_ctx, const char *username, const char *mailbox, char delimiter)
{
	const char	*start = mailbox, *end;
	char		*out;

	if (!username || !mailbox || !mailbox[0]) {
		return NULL;
	}
	out = talloc_strdup(mem_ctx, IMAP_NAMESPACE);
	out = append_encoded(out, username, strlen(username));
	out = out ? talloc_strdup_append_buffer(out, "/") : NULL;
	while (out) {
		end = delimiter ? strchr(start, delimiter) : NULL;
		if (!end) {
			end = start + strlen(start);
		}
		out = append_encoded(out, start, end - start);
		out = out ? talloc_strdup_append_buffer(out, "/") : NULL;
		if (!*end) {
			break;
		}
		start = end + 1;
	}
	return out;
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Decodes one non-empty segment; NULL on a bad escape or an encoded NUL/delimiter. */
static char *decode_segment(TALLOC_CTX *mem_ctx, const char *s, size_t len, char delimiter)
{
	char	*out;
	size_t	i, n = 0;

	if (len == 0) {
		return NULL;
	}
	out = talloc_array(mem_ctx, char, len + 1);
	for (i = 0; out && i < len; i++) {
		if (s[i] == '%') {
			int hi, lo;

			if (i + 2 >= len) {
				talloc_free(out);
				return NULL;
			}
			hi = hexval(s[i + 1]);
			lo = hexval(s[i + 2]);
			if (hi < 0 || lo < 0 || (hi == 0 && lo == 0) || (char) (hi << 4 | lo) == delimiter) {
				talloc_free(out);
				return NULL;
			}
			out[n++] = (char) (hi << 4 | lo);
			i += 2;
		} else {
			out[n++] = s[i];
		}
	}
	if (out) {
		out[n] = '\0';
	}
	return out;
}

_PUBLIC_ int imap_uri_parse(TALLOC_CTX *mem_ctx, const char *uri, char delimiter, char **username, char **mailbox)
{
	const char	*p, *slash;
	char		*user, *box = NULL, *seg;
	char		sep[2] = { delimiter, '\0' };

	if (!uri || strncmp(uri, IMAP_NAMESPACE, strlen(IMAP_NAMESPACE)) != 0) {
		return -1;
	}
	p = uri + strlen(IMAP_NAMESPACE);
	slash = strchr(p, '/');
	if (!slash || !(user = decode_segment(mem_ctx, p, slash - p, '\0'))) {
		return -1;
	}
	for (p = slash + 1; *p; p = slash + 1) {
		slash = strchr(p, '/');
		if (!slash || !(seg = decode_segment(mem_ctx, p, slash - p, delimiter))) {
			talloc_free(user);
			talloc_free(box);
			return -1;
		}
		box = box ? talloc_asprintf_append_buffer(box, "%s%s", sep, seg) : talloc_strdup(mem_ctx, seg);
		talloc_free(seg);
		if (!box || (!delimiter && slash[1])) {
			talloc_free(user);
			talloc_free(box);
			return -1;
		}
	}
	if (!box) {
		talloc_free(user);
		return -1;
	}
	*username = user;
	*mailbox = box;
	return 0;
}

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

static char *append_utf8(char *out, uint32_t cp)
{
	char buf[5];

	if (cp < 0x80) {
		buf[0] = cp; buf[1] = 0;
	} else if (cp < 0x800) {
		buf[0] = 0xC0 | (cp >> 6); buf[1] = 0x80 | (cp & 0x3F); buf[2] = 0;
	} else if (cp < 0x10000) {
		buf[0] = 0xE0 | (cp >> 12); buf[1] = 0x80 | ((cp >> 6) & 0x3F); buf[2] = 0x80 | (cp & 0x3F); buf[3] = 0;
	} else {
		buf[0] = 0xF0 | (cp >> 18); buf[1] = 0x80 | ((cp >> 12) & 0x3F);
		buf[2] = 0x80 | ((cp >> 6) & 0x3F); buf[3] = 0x80 | (cp & 0x3F); buf[4] = 0;
	}
	return talloc_strdup_append_buffer(out, buf);
}

/* Modified UTF-7 (RFC 3501 5.1.3) to UTF-8; NULL when malformed. */
static char *mutf7_decode(TALLOC_CTX *mem_ctx, const char *s)
{
	char *out = talloc_strdup(mem_ctx, "");

	while (out && *s) {
		uint32_t bits = 0, high = 0;
		int nbits = 0;

		if (*s != '&') {
			if ((unsigned char) *s < 0x20 || (unsigned char) *s > 0x7E) {
				break;
			}
			out = talloc_asprintf_append_buffer(out, "%c", *s++);
			continue;
		}
		s++;
		if (*s == '-') {
			out = talloc_strdup_append_buffer(out, "&");
			s++;
			continue;
		}
		while (out && *s && *s != '-') {
			const char *pos = strchr(b64, *s);

			if (!pos || !*s) {
				goto bad;
			}
			bits = (bits << 6) | (uint32_t) (pos - b64);
			nbits += 6;
			if (nbits >= 16) {
				uint32_t unit = (bits >> (nbits - 16)) & 0xFFFF;

				nbits -= 16;
				if (unit >= 0xD800 && unit <= 0xDBFF) {
					if (high) goto bad;
					high = unit;
				} else if (unit >= 0xDC00 && unit <= 0xDFFF) {
					if (!high) goto bad;
					out = append_utf8(out, 0x10000 + ((high - 0xD800) << 10) + (unit - 0xDC00));
					high = 0;
				} else {
					if (high || unit < 0x20) goto bad;
					out = append_utf8(out, unit);
				}
			}
			s++;
		}
		/* A shift must end with '-', no pending surrogate and only zero padding bits. */
		if (*s != '-' || high || nbits >= 6 || (bits & ((1u << nbits) - 1))) {
			goto bad;
		}
		s++;
	}
	if (out && *s) {
		goto bad;
	}
	return out;
bad:
	talloc_free(out);
	return NULL;
}

_PUBLIC_ char *imap_display_name(TALLOC_CTX *mem_ctx, const char *mailbox, char delimiter)
{
	const char	*leaf = delimiter ? strrchr(mailbox, delimiter) : NULL;
	char		*name;

	leaf = leaf ? leaf + 1 : mailbox;
	name = mutf7_decode(mem_ctx, leaf);
	return name ? name : talloc_strdup(mem_ctx, leaf);
}
