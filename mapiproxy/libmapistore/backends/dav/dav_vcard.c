/*
   CardDAV mapistore backend: vCard 3.0 / SOGo VLIST line model

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   Observed on SOGo 5 (lab, 17/11/2026), a list created by the web UI:

     BEGIN:VLIST
     UID:<id>.vcf
     VERSION:1.0
     CARD;EMAIL=<email>;FN=<display name>:<uid of the member card>.vcf
     CARD;EMAIL=<email>;FN=<display name>:<uid of a stub card SOGo made for a free address>.vcf
     FN:<list name>
     END:VLIST

   - A member is "CARD" with EMAIL and FN as parameters (no UID parameter) and the
     member card's UID (with .vcf) as the VALUE. A free address becomes a stub
     VCARD (EMAIL;TYPE=work + FN) that SOGo creates next to the list.
   - SOGo folds by characters, not octets, so untouched lines are kept in their
     original folded form (raw) instead of being re-folded.
   - Shortcut: BEGIN/END are not kept as lines (kind is upper-cased) and blank
     lines are dropped; revisit if a client is found to depend on either.
 */

#include <ctype.h>
#include <string.h>
#include <strings.h>

#include "dav_vcard.h"

static char *dupn(TALLOC_CTX *mem, const char *s, size_t n)
{
	return talloc_strndup(mem, s, n);
}

/* Parses one unfolded line into l; raw is the physical (folded) text. */
static void parse_line(TALLOC_CTX *mem, struct dav_line *l, const char *u, size_t n, const char *raw, size_t rawlen)
{
	size_t i = 0, start, nm;
	bool quoted = false;

	memset(l, 0, sizeof(*l));
	l->raw = dupn(mem, raw, rawlen);
	/* group: alnum/- run followed by '.' before any ';' or ':' */
	while (i < n && (isalnum((unsigned char)u[i]) || u[i] == '-')) i++;
	if (i > 0 && i < n && u[i] == '.') {
		l->group = dupn(mem, u, i);
		i++;
	} else {
		i = 0;
	}
	start = i;
	while (i < n && u[i] != ';' && u[i] != ':') i++;
	nm = i - start;
	l->name = dupn(mem, u + start, nm);
	while (i < n && u[i] == ';') {
		size_t p = ++i;
		while (i < n && (quoted || (u[i] != ';' && u[i] != ':'))) {
			if (u[i] == '"') quoted = !quoted;
			i++;
		}
		l->params = talloc_realloc(mem, l->params, char *, l->nparams + 1);
		l->params[l->nparams++] = dupn(mem, u + p, i - p);
	}
	l->value = i < n ? dupn(mem, u + i + 1, n - i - 1) : talloc_strdup(mem, "");
}

struct dav_card *dav_card_parse(TALLOC_CTX *mem, const char *text, size_t len)
{
	struct dav_card *c;
	const char *p = text, *end = text + len;
	char *un = NULL, *rw = NULL;
	size_t unlen = 0, rwlen = 0;
	bool begun = false, ended = false, ok = true;
	TALLOC_CTX *tmp = talloc_new(NULL);

	c = talloc_zero(mem, struct dav_card);
	if (!c || !tmp) {
		talloc_free(c);
		talloc_free(tmp);
		return NULL;
	}

	/* One more pass than lines so the last pending logical line is flushed. */
	while (ok && !ended) {
		const char *e = p;
		bool have = p < end;
		bool fold = false;

		if (have) {
			while (e < end && *e != '\n' && *e != '\r') e++;
			fold = (*p == ' ' || *p == '\t') && un;
		}
		if (un && (!have || !fold)) {
			/* flush the pending logical line */
			if (unlen == 0) {
				/* blank */
			} else if (!begun) {
				if (strncasecmp(un, "BEGIN:", 6) != 0) { ok = false; break; }
				if (strcasecmp(un + 6, "VCARD") == 0) c->kind = talloc_strdup(c, "VCARD");
				else if (strcasecmp(un + 6, "VLIST") == 0) c->kind = talloc_strdup(c, "VLIST");
				else { ok = false; break; }
				begun = true;
			} else if (strncasecmp(un, "END:", 4) == 0 && strcasecmp(un + 4, c->kind) == 0) {
				ended = true;
			} else {
				c->lines = talloc_realloc(c, c->lines, struct dav_line, c->nlines + 1);
				if (!c->lines) { ok = false; break; }
				parse_line(c, &c->lines[c->nlines++], un, unlen, rw, rwlen);
			}
			talloc_free(un); talloc_free(rw);
			un = rw = NULL; unlen = rwlen = 0;
		}
		if (!have || ended) break; /* p still points at the first line after END */
		if (fold) {
			un = talloc_realloc(tmp, un, char, unlen + (e - p));
			memcpy(un + unlen, p + 1, e - p - 1);
			unlen += e - p - 1;
			rw = talloc_realloc(tmp, rw, char, rwlen + 2 + (e - p));
			memcpy(rw + rwlen, "\r\n", 2);
			memcpy(rw + rwlen + 2, p, e - p);
			rwlen += 2 + (e - p);
		} else {
			un = talloc_array(tmp, char, (e - p) + 1);
			memcpy(un, p, e - p);
			unlen = e - p;
			rw = talloc_array(tmp, char, (e - p) + 1);
			memcpy(rw, p, e - p);
			rwlen = e - p;
		}
		/* keep the buffers NUL-terminated for the string compares above */
		un = talloc_realloc(tmp, un, char, unlen + 1); un[unlen] = '\0';
		rw = talloc_realloc(tmp, rw, char, rwlen + 1); rw[rwlen] = '\0';
		p = e;
		if (p < end && *p == '\r') p++;
		if (p < end && *p == '\n') p++;
	}
	talloc_free(tmp);
	/* anything but blanks after END would be dropped on render: refuse */
	while (ok && ended && p < end && strchr(" \t\r\n", *p)) p++;
	if (!ok || !ended || p < end) {
		talloc_free(c);
		return NULL;
	}
	return c;
}

const char *dav_card_kind(const struct dav_card *c)
{
	return c->kind;
}

/* Appends s to *out, folding at 75 octets without splitting a UTF-8 sequence. */
static char *append_folded(TALLOC_CTX *mem, char *out, const char *s)
{
	size_t used = 0, n = strlen(s);

	while (n) {
		size_t room = used ? 74 : 75, take = n < room ? n : room;
		if (take < n) {
			while (take > 0 && ((unsigned char)s[take] & 0xC0) == 0x80) take--;
			if (take == 0) take = n < room ? n : room; /* malformed, hard cut */
		}
		out = talloc_asprintf_append_buffer(out, "%s%.*s\r\n", used ? " " : "", (int)take, s);
		s += take; n -= take; used = 1;
	}
	return out;
}

char *dav_card_render(TALLOC_CTX *mem, const struct dav_card *c)
{
	char *out = talloc_asprintf(mem, "BEGIN:%s\r\n", c->kind);
	size_t i, k;

	for (i = 0; out && i < c->nlines; i++) {
		const struct dav_line *l = &c->lines[i];
		if (!l->touched) {
			out = talloc_asprintf_append_buffer(out, "%s\r\n", l->raw);
		} else {
			char *s = talloc_asprintf(mem, "%s%s%s", l->group ? l->group : "", l->group ? "." : "", l->name);
			for (k = 0; s && k < l->nparams; k++) s = talloc_asprintf_append_buffer(s, ";%s", l->params[k]);
			if (s) s = talloc_asprintf_append_buffer(s, ":%s", l->value);
			if (!s) { talloc_free(out); return NULL; }
			out = append_folded(mem, out, s);
			talloc_free(s);
		}
	}
	if (out) out = talloc_asprintf_append_buffer(out, "END:%s\r\n", c->kind);
	return out;
}

static bool has_type(const struct dav_line *l, const char *type)
{
	size_t i, tl = strlen(type);

	for (i = 0; i < l->nparams; i++) {
		const char *v = l->params[i], *q;
		if (strncasecmp(v, "TYPE=", 5) == 0) v += 5;
		for (q = v; ; ) {
			size_t n = strcspn(q, ",");
			if (n == tl && strncasecmp(q, type, n) == 0) return true;
			if (!q[n]) break;
			q += n + 1;
		}
	}
	return false;
}

struct dav_line *dav_card_find(const struct dav_card *c, const char *name, const char *type, unsigned index)
{
	size_t i;

	for (i = 0; i < c->nlines; i++) {
		struct dav_line *l = &c->lines[i];
		if (strcasecmp(l->name, name) != 0) continue;
		if (type && !has_type(l, type)) continue;
		if (index-- == 0) return l;
	}
	return NULL;
}

void dav_card_set(struct dav_card *c, const char *name, const char *type, unsigned index, const char *value)
{
	struct dav_line *l = dav_card_find(c, name, type, index);

	if (l) {
		if (!value) {
			talloc_free(l->group); talloc_free(l->name); talloc_free(l->params);
			talloc_free(l->value); talloc_free(l->raw);
			memmove(l, l + 1, (c->lines + c->nlines - l - 1) * sizeof(*l));
			c->nlines--;
			return;
		}
		talloc_free(l->value);
		l->value = talloc_strdup(c, value);
		l->touched = true;
		return;
	}
	if (!value) return;
	c->lines = talloc_realloc(c, c->lines, struct dav_line, c->nlines + 1);
	l = &c->lines[c->nlines++];
	memset(l, 0, sizeof(*l));
	l->name = talloc_strdup(c, name);
	if (type) {
		l->params = talloc_array(c, char *, 1);
		l->params[l->nparams++] = talloc_asprintf(c, "TYPE=%s", type);
	}
	l->value = talloc_strdup(c, value);
	l->touched = true;
}

char *dav_text_unescape(TALLOC_CTX *mem, const char *s)
{
	char *out = talloc_array(mem, char, strlen(s) + 1), *o = out;

	for (; *s; s++) {
		if (*s == '\\' && s[1]) {
			s++;
			*o++ = (*s == 'n' || *s == 'N') ? '\n' : *s;
		} else {
			*o++ = *s;
		}
	}
	*o = '\0';
	return out;
}

char *dav_text_escape(TALLOC_CTX *mem, const char *s)
{
	char *out = talloc_array(mem, char, 2 * strlen(s) + 1), *o = out;

	for (; *s; s++) {
		if (*s == '\r') continue;
		if (*s == '\n') { *o++ = '\\'; *o++ = 'n'; continue; }
		if (*s == '\\' || *s == ',' || *s == ';') *o++ = '\\';
		*o++ = *s;
	}
	*o = '\0';
	return out;
}
