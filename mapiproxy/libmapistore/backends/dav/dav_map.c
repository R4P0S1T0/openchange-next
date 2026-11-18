/*
   CardDAV mapistore backend: vCard / VLIST <-> merge fields <-> MAPI contact and distribution list

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   Lists: members are PidLidDistributionListMembers (wrapped EntryID of the
   member's contact, or a one-off EntryID when it has none) with the matching
   one-off in PidLidDistributionListOneOffMembers (MS-OXOCNTC 2.2.2.2.4,
   MS-OXCDATA 2.2.5.1); the checksum is the CRC-32 of the members' bytes.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <ldb.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "gen_ndr/ndr_property.h"
#include "dav_map.h"

/* Which vCard line holds a field: name, a TYPE it must have / must not have, index, component. */
static const struct dav_field_def {
	const char	*name, *type, *not_type, *new_param;
	unsigned	index;
	int		comp, ncomp;
} defs[DAV_F_COUNT] = {
	[DAV_F_FN]		= { "FN", NULL, NULL, NULL, 0, -1, 0 },
	[DAV_F_N_FAMILY]	= { "N", NULL, NULL, NULL, 0, 0, 5 },
	[DAV_F_N_GIVEN]		= { "N", NULL, NULL, NULL, 0, 1, 5 },
	[DAV_F_N_MIDDLE]	= { "N", NULL, NULL, NULL, 0, 2, 5 },
	[DAV_F_N_PREFIX]	= { "N", NULL, NULL, NULL, 0, 3, 5 },
	[DAV_F_N_SUFFIX]	= { "N", NULL, NULL, NULL, 0, 4, 5 },
	[DAV_F_EMAIL1]		= { "EMAIL", NULL, NULL, "TYPE=INTERNET", 0, -1, 0 },
	[DAV_F_EMAIL2]		= { "EMAIL", NULL, NULL, "TYPE=INTERNET", 1, -1, 0 },
	[DAV_F_EMAIL3]		= { "EMAIL", NULL, NULL, "TYPE=INTERNET", 2, -1, 0 },
	[DAV_F_TEL_WORK]	= { "TEL", "WORK", "FAX", "TYPE=WORK,VOICE", 0, -1, 0 },
	[DAV_F_TEL_HOME]	= { "TEL", "HOME", "FAX", "TYPE=HOME,VOICE", 0, -1, 0 },
	[DAV_F_TEL_CELL]	= { "TEL", "CELL", NULL, "TYPE=CELL", 0, -1, 0 },
	[DAV_F_TEL_FAX]		= { "TEL", "FAX", NULL, "TYPE=FAX,WORK", 0, -1, 0 },
	[DAV_F_ORG]		= { "ORG", NULL, NULL, NULL, 0, 0, 2 },
	[DAV_F_ORG_UNIT]	= { "ORG", NULL, NULL, NULL, 0, 1, 2 },
	[DAV_F_TITLE]		= { "TITLE", NULL, NULL, NULL, 0, -1, 0 },
	[DAV_F_ADR_WORK]	= { "ADR", "WORK", NULL, "TYPE=WORK", 0, -1, 7 },
	[DAV_F_ADR_HOME]	= { "ADR", "HOME", NULL, "TYPE=HOME", 0, -1, 7 },
	[DAV_F_NOTE]		= { "NOTE", NULL, NULL, NULL, 0, -1, 0 },
	[DAV_F_BDAY]		= { "BDAY", NULL, NULL, NULL, 0, -1, 0 },
	[DAV_F_URL]		= { "URL", NULL, NULL, NULL, 0, -1, 0 },
	[DAV_F_PHOTO]		= { "PHOTO", NULL, NULL, NULL, 0, -1, 0 },
	[DAV_F_LIST_NAME]	= { "FN", NULL, NULL, NULL, 0, -1, 0 },
	[DAV_F_LIST_MEMBERS]	= { "CARD", NULL, NULL, NULL, 0, -1, 0 },
};

static const uint8_t wrapped_uid[16] = {
	0xC0, 0x91, 0xAD, 0xD3, 0x51, 0x9D, 0xCF, 0x11, 0xA4, 0xA9, 0x00, 0xAA, 0x00, 0x47, 0xFA, 0xA4,
};
static const uint8_t one_off_uid[16] = {
	0x81, 0x2B, 0x1F, 0xA4, 0xBE, 0xA3, 0x10, 0x19, 0x9D, 0x6E, 0x00, 0xDD, 0x01, 0x0F, 0x54, 0x02,
};
#define WRAPPED_CONTACT_EMAIL1	0xC3	/* message EntryID, Email1, contact */

static bool is_list(const struct dav_card *c)
{
	return strcmp(dav_card_kind(c), "VLIST") == 0;
}

static bool applies(const struct dav_card *c, enum dav_field f)
{
	if (f >= DAV_F_COUNT) return false;
	if (is_list(c)) return f == DAV_F_LIST_NAME || f == DAV_F_LIST_MEMBERS || f == DAV_F_NOTE;
	return f != DAV_F_LIST_NAME && f != DAV_F_LIST_MEMBERS;
}

static const char *line_name(const struct dav_card *c, enum dav_field f)
{
	return f == DAV_F_NOTE && is_list(c) ? "DESCRIPTION" : defs[f].name;
}

static struct dav_line *find_line(const struct dav_card *c, enum dav_field f)
{
	const struct dav_field_def *d = &defs[f];
	unsigned idx = d->index;
	size_t i;

	for (i = 0; i < c->nlines; i++) {
		struct dav_line *l = &c->lines[i];
		if (strcasecmp(l->name, line_name(c, f)) != 0) continue;
		if (d->type && !dav_line_has_type(l, d->type)) continue;
		if (d->not_type && dav_line_has_type(l, d->not_type)) continue;
		if (idx-- == 0) return l;
	}
	return NULL;
}

static void drop_line(struct dav_card *c, struct dav_line *l)
{
	talloc_free(l->group); talloc_free(l->name); talloc_free(l->params);
	talloc_free(l->value); talloc_free(l->raw);
	memmove(l, l + 1, (c->lines + c->nlines - l - 1) * sizeof(*l));
	c->nlines--;
}

/* Replaces l's value (and its params when nparams > 0), or appends a new line when l is NULL. */
static void put_line(struct dav_card *c, struct dav_line *l, const char *name, const char **params, size_t nparams,
		     const char *value)
{
	size_t i;

	if (!l) {
		struct dav_line *n = talloc_realloc(c, c->lines, struct dav_line, c->nlines + 1);
		if (!n) return;
		c->lines = n;
		l = &c->lines[c->nlines++];
		memset(l, 0, sizeof(*l));
		l->name = talloc_strdup(c, name);
	}
	if (nparams) {
		talloc_free(l->params);
		l->params = talloc_array(c, char *, nparams);
		for (i = 0; l->params && i < nparams; i++) l->params[i] = talloc_strdup(l->params, params[i]);
		l->nparams = l->params ? nparams : 0;
	}
	talloc_free(l->value);
	l->value = talloc_strdup(c, value);
	l->touched = true;
}

static char *trim(TALLOC_CTX *mem, const char *s)
{
	size_t n;

	while (*s && isspace((unsigned char)*s)) s++;
	n = strlen(s);
	while (n && isspace((unsigned char)s[n - 1])) n--;
	return talloc_strndup(mem, s, n);
}

static char *nonempty(char *s)
{
	return s && *s ? s : NULL;
}

/* Unescaped, trimmed text of an escaped vCard value. */
static char *text(TALLOC_CTX *mem, const char *escaped)
{
	char *u = dav_text_unescape(mem, escaped);
	return u ? trim(mem, u) : NULL;
}

/* Anything that is not an escaped text value: no control characters, so no line break. */
static char *neutral(TALLOC_CTX *mem, const char *s)
{
	char *out = talloc_array(mem, char, strlen(s) + 1), *o = out;

	if (!out) return NULL;
	for (; *s; s++) {
		if ((unsigned char)*s >= 0x20 && *s != 0x7f) *o++ = *s;
	}
	*o = '\0';
	return out;
}

/* Splits at sep (';' honoring backslash escapes, or a plain '\n'); at least min parts. */
static char **split(TALLOC_CTX *mem, const char *v, char sep, size_t min, size_t *n)
{
	char **out = NULL;
	const char *p = v, *s = v;
	size_t k = 0;

	for (;; p++) {
		if (sep == ';' && *p == '\\' && p[1]) { p++; continue; }
		if (*p == sep || !*p) {
			out = talloc_realloc(mem, out, char *, k + 1);
			if (!out) return NULL;
			out[k++] = talloc_strndup(out, s, p - s);
			if (!*p) break;
			s = p + 1;
		}
	}
	while (k < min) {
		out = talloc_realloc(mem, out, char *, k + 1);
		if (!out) return NULL;
		out[k++] = talloc_strdup(out, "");
	}
	*n = k;
	return out;
}

static char *join(TALLOC_CTX *mem, char **parts, size_t n, const char *sep)
{
	char *out = talloc_strdup(mem, "");
	size_t i;

	for (i = 0; out && i < n; i++) out = talloc_asprintf_append_buffer(out, "%s%s", i ? sep : "", parts[i]);
	return out;
}

/* Value of a parameter NAME=value (quotes removed), or NULL. */
static char *param_value(TALLOC_CTX *mem, const struct dav_line *l, const char *name)
{
	size_t i, n = strlen(name), len;

	for (i = 0; i < l->nparams; i++) {
		const char *p = l->params[i];
		if (strncasecmp(p, name, n) != 0 || p[n] != '=') continue;
		p += n + 1;
		len = strlen(p);
		if (len >= 2 && p[0] == '"' && p[len - 1] == '"') return talloc_strndup(mem, p + 1, len - 2);
		return talloc_strdup(mem, p);
	}
	return NULL;
}

/* NAME=value from untrusted text: no control characters or quotes, quoted when it holds ;:, */
static char *make_param(TALLOC_CTX *mem, const char *name, const char *v)
{
	char *s = neutral(mem, v), *o, *p;

	if (!s) return NULL;
	for (o = p = s; *p; p++) if (*p != '"') *o++ = *p;
	*o = '\0';
	return talloc_asprintf(mem, strpbrk(s, ";:,") ? "%s=\"%s\"" : "%s=%s", name, s);
}

static char *lower(TALLOC_CTX *mem, const char *s)
{
	char *out = talloc_strdup(mem, s), *p;

	for (p = out; p && *p; p++) *p = tolower((unsigned char)*p);
	return out;
}

static char *normalize_date(TALLOC_CTX *mem, const char *t)
{
	int y, m, d;

	if ((sscanf(t, "%4d-%2d-%2d", &y, &m, &d) == 3 || (strlen(t) >= 8 && sscanf(t, "%4d%2d%2d", &y, &m, &d) == 3))
	    && y > 0 && m >= 1 && m <= 12 && d >= 1 && d <= 31) {
		return talloc_asprintf(mem, "%04d-%02d-%02d", y, m, d);
	}
	return talloc_strdup(mem, t);
}

/* Decoded inline PHOTO (ENCODING=b/BASE64); NULL for a PHOTO by URI or none. */
static struct Binary_r *photo_bytes(TALLOC_CTX *mem, const struct dav_card *c)
{
	struct dav_line *l = is_list(c) ? NULL : find_line(c, DAV_F_PHOTO);
	char *enc, *buf;
	struct Binary_r *b;
	int n;

	if (!l || !(enc = param_value(mem, l, "ENCODING"))) return NULL;
	if (strcasecmp(enc, "b") != 0 && strcasecmp(enc, "BASE64") != 0) return NULL;
	buf = talloc_strdup(mem, l->value);
	if (!buf || (n = ldb_base64_decode(buf)) <= 0) return NULL;
	b = talloc_zero(mem, struct Binary_r);
	if (!b) return NULL;
	b->cb = n;
	b->lpb = (uint8_t *)talloc_steal(b, buf);
	return b;
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char * const *)a, *(char * const *)b);
}

/* Member key of a VLIST CARD line: the card UID (value without .vcf), else mailto:<email>. */
static char *member_key(TALLOC_CTX *mem, const struct dav_line *l)
{
	char *v = text(mem, l->value), *email;
	size_t n = v ? strlen(v) : 0;

	if (n > 4 && strcasecmp(v + n - 4, ".vcf") == 0) v[n - 4] = '\0';
	if (v && *v) return v;
	email = param_value(mem, l, "EMAIL");
	return email && *email ? talloc_asprintf(mem, "mailto:%s", lower(mem, email)) : NULL;
}

/* Whether Outlook sees this member (its contact resolves, or it has an address); *eid set when it resolves. */
static bool member_visible(TALLOC_CTX *mem, const struct dav_line *l, const char *key,
			   const struct dav_member_resolver *r, struct Binary_r **eid)
{
	char *email = param_value(mem, l, "EMAIL");

	*eid = NULL;
	if (strncmp(key, "mailto:", 7) != 0 && r && r->entryid_for_uid) *eid = r->entryid_for_uid(r->ctx, mem, key);
	return *eid || (email && *email);
}

/* An Outlook member key names this line: same key, or mailto: of the line's EMAIL (shown as a one-off). */
static bool member_matches(TALLOC_CTX *mem, const struct dav_line *l, const char *line_key, const char *key)
{
	char *email;

	if (strcmp(line_key, key) == 0) return true;
	if (strncmp(key, "mailto:", 7) != 0 || !(email = param_value(mem, l, "EMAIL"))) return false;
	return strcmp(lower(mem, email), key + 7) == 0;
}

static char *keys_field(TALLOC_CTX *mem, char **keys, size_t n)
{
	qsort(keys, n, sizeof(*keys), cmp_str);
	return n ? join(mem, keys, n, "\n") : NULL;
}

static char *members_field(TALLOC_CTX *mem, const struct dav_card *c)
{
	char **keys = talloc_array(mem, char *, c->nlines + 1), *k;
	size_t i, n = 0;

	for (i = 0; keys && i < c->nlines; i++) {
		if (strcasecmp(c->lines[i].name, "CARD") != 0) continue;
		if ((k = member_key(keys, &c->lines[i]))) keys[n++] = k;
	}
	return keys ? keys_field(mem, keys, n) : NULL;
}

_PUBLIC_ char *dav_field_get(TALLOC_CTX *mem, const struct dav_card *c, enum dav_field f)
{
	struct dav_line *l;
	struct Binary_r *b;
	char **comps, *v;
	size_t n, i;
	bool any = false;

	if (!applies(c, f)) return NULL;
	if (f == DAV_F_LIST_MEMBERS) return members_field(mem, c);
	if (!(l = find_line(c, f))) return NULL;
	switch (f) {
	case DAV_F_ADR_WORK:
	case DAV_F_ADR_HOME:
		if (!(comps = split(mem, l->value, ';', 7, &n))) return NULL;
		for (i = 0; i < 7; i++) {
			comps[i] = i == 1 ? talloc_strdup(comps, "") : dav_text_escape(comps, text(comps, comps[i]));
			if (!comps[i]) return NULL;
			if (*comps[i]) any = true;
		}
		/* the extended address has no Outlook field: kept in the card, never compared */
		return any ? join(mem, comps, 7, "\n") : NULL;
	case DAV_F_BDAY:
		v = text(mem, l->value);
		return v && *v ? normalize_date(mem, v) : NULL;
	case DAV_F_PHOTO:
		b = photo_bytes(mem, c);
		return b ? ldb_base64_encode(mem, (const char *)b->lpb, b->cb) : NULL;
	default:
		if (defs[f].comp >= 0) {
			comps = split(mem, l->value, ';', defs[f].ncomp, &n);
			return comps ? nonempty(text(mem, comps[defs[f].comp])) : NULL;
		}
		return nonempty(text(mem, l->value));
	}
}

_PUBLIC_ void dav_list_set_members(struct dav_card *c, const struct dav_member_resolver *r,
				   const struct dav_member *m, size_t count)
{
	TALLOC_CTX *tmp = talloc_new(NULL);
	struct Binary_r *eid;
	size_t i, j;
	char *k;

	if (!tmp) return;
	/* drop the members Outlook no longer has (back to front: drop_line shifts); a member Outlook
	   was never shown (no contact, no address) is not Outlook's to remove */
	for (i = c->nlines; i-- > 0; ) {
		if (strcasecmp(c->lines[i].name, "CARD") != 0) continue;
		k = member_key(tmp, &c->lines[i]);
		if (!k || !member_visible(tmp, &c->lines[i], k, r, &eid)) continue;
		for (j = 0; j < count; j++) if (m[j].key && member_matches(tmp, &c->lines[i], k, m[j].key)) break;
		if (j == count) drop_line(c, &c->lines[i]);
	}
	for (j = 0; j < count; j++) {
		const char *params[2];
		size_t np = 0;
		bool mailto = m[j].key && strncmp(m[j].key, "mailto:", 7) == 0;
		const char *email = m[j].email ? m[j].email : (mailto ? m[j].key + 7 : NULL);
		char *value;

		if (!m[j].key || !*m[j].key) continue;
		for (i = 0; i < c->nlines; i++) {
			if (strcasecmp(c->lines[i].name, "CARD") != 0) continue;
			k = member_key(tmp, &c->lines[i]);
			if (k && member_matches(tmp, &c->lines[i], k, m[j].key)) break;
		}
		if (i < c->nlines) continue;	/* already a member: its line stays as it is */
		if (email && *email) params[np++] = make_param(tmp, "EMAIL", email);
		if (m[j].name && *m[j].name) params[np++] = make_param(tmp, "FN", m[j].name);
		value = mailto ? talloc_strdup(tmp, "") : talloc_asprintf(tmp, "%s.vcf", neutral(tmp, m[j].key));
		put_line(c, NULL, "CARD", params, np, value);
	}
	talloc_free(tmp);
}

_PUBLIC_ char *dav_line_param(TALLOC_CTX *mem, const struct dav_line *l, const char *name)
{
	return param_value(mem, l, name);
}

_PUBLIC_ void dav_list_complete(struct dav_card *c, const struct dav_member *m, size_t count)
{
	TALLOC_CTX *tmp = talloc_new(NULL);
	size_t i, j;
	char *k;

	for (i = 0; tmp && i < c->nlines; i++) {
		struct dav_line *l = &c->lines[i];
		bool email, fn;

		if (strcasecmp(l->name, "CARD") != 0 || !(k = member_key(tmp, l))) continue;
		email = param_value(tmp, l, "EMAIL") != NULL;
		fn = param_value(tmp, l, "FN") != NULL;
		for (j = 0; j < count && !(email && fn); j++) {
			char **p, *e, *n;

			if (!m[j].key || !member_matches(tmp, l, k, m[j].key)) continue;
			e = !email && m[j].email ? make_param(tmp, "EMAIL", m[j].email) : NULL;
			n = !fn && m[j].name ? make_param(tmp, "FN", m[j].name) : NULL;
			p = talloc_realloc(c, l->params, char *, l->nparams + 2);
			if (!p) break;
			l->params = p;
			if (e) p[l->nparams++] = talloc_steal(p, e);
			if (n) p[l->nparams++] = talloc_steal(p, n);
			email = fn = true;
			l->touched = true;
		}
	}
	talloc_free(tmp);
}

static void set_members_from_keys(struct dav_card *c, const char *value)
{
	TALLOC_CTX *tmp = talloc_new(NULL);
	struct dav_member *m;
	char **keys;
	size_t n = 0, i, k = 0;

	keys = value ? split(tmp, value, '\n', 0, &n) : NULL;
	m = talloc_zero_array(tmp, struct dav_member, n + 1);
	for (i = 0; m && keys && i < n; i++) {
		char *key = trim(m, neutral(m, keys[i]));
		if (!key || !*key) continue;
		m[k].key = key;
		k++;
	}
	if (m) dav_list_set_members(c, NULL, m, k);
	talloc_free(tmp);
}

static const char *photo_type(const char *b64)
{
	if (strncmp(b64, "iVBOR", 5) == 0) return "TYPE=PNG";
	if (strncmp(b64, "R0lGOD", 6) == 0) return "TYPE=GIF";
	return "TYPE=JPEG";
}

_PUBLIC_ void dav_field_set(struct dav_card *c, enum dav_field f, const char *value)
{
	const struct dav_field_def *d = &defs[f];
	TALLOC_CTX *tmp;
	struct dav_line *l;
	char *v = NULL, **comps, **old;
	const char *params[2];
	size_t n, i, nold;

	if (!applies(c, f)) return;
	if (f == DAV_F_LIST_MEMBERS) {
		set_members_from_keys(c, value);
		return;
	}
	if (!(tmp = talloc_new(NULL))) return;
	/* ADR: leading empty components are "\n"s, not blanks to trim */
	if (value) v = nonempty(d->ncomp == 7 ? talloc_strdup(tmp, value) : trim(tmp, value));
	l = find_line(c, f);
	params[0] = d->new_param;
	if (!v) {
		if (l && d->comp >= 0) {
			/* clear one component; ORG goes when it is empty, N stays (vCard 3.0 requires it) */
			comps = split(tmp, l->value, ';', d->ncomp, &n);
			if (comps) {
				comps[d->comp] = "";
				put_line(c, l, NULL, NULL, 0, join(tmp, comps, n, ";"));
				if ((f == DAV_F_ORG || f == DAV_F_ORG_UNIT) && !dav_field_get(tmp, c, DAV_F_ORG)
				    && !dav_field_get(tmp, c, DAV_F_ORG_UNIT)) {
					drop_line(c, find_line(c, f));
				}
			}
		} else if (l) {
			drop_line(c, l);
		}
		talloc_free(tmp);
		return;
	}
	switch (f) {
	case DAV_F_ADR_WORK:
	case DAV_F_ADR_HOME:
		/* value: 7 escaped components; the card's extended address (index 1) is kept */
		comps = split(tmp, v, '\n', 7, &n);
		old = l ? split(tmp, l->value, ';', 7, &nold) : NULL;
		if (!comps) break;
		for (i = 0; i < n; i++) comps[i] = neutral(comps, comps[i]);
		comps[1] = old ? old[1] : "";
		put_line(c, l, d->name, params, l ? 0 : 1, join(tmp, comps, n, ";"));
		break;
	case DAV_F_BDAY:
	case DAV_F_URL:
		put_line(c, l, d->name, params, 0, neutral(tmp, v));
		break;
	case DAV_F_PHOTO:
		if (strspn(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") != strlen(v)) break;
		params[0] = "ENCODING=b";
		params[1] = photo_type(v);
		put_line(c, l, d->name, params, 2, v);
		break;
	default:
		if (d->comp >= 0) {
			comps = l ? split(tmp, l->value, ';', d->ncomp, &n) : split(tmp, "", ';', d->ncomp, &n);
			if (!comps) break;
			comps[d->comp] = dav_text_escape(comps, v);
			put_line(c, l, d->name, params, 0, join(tmp, comps, n, ";"));
		} else {
			put_line(c, l, line_name(c, f), params, (!l && d->new_param) ? 1 : 0, dav_text_escape(tmp, v));
		}
		break;
	}
	talloc_free(tmp);
}

/* String MAPI property -> (field, ADR component or -1). */
static bool tag_field(const struct dav_named_tags *t, uint32_t tag, enum dav_field *f, int *comp)
{
	static const struct { uint32_t tag; enum dav_field f; int comp; } fixed[] = {
		{ PidTagDisplayName, DAV_F_FN, -1 }, { PidTagSurname, DAV_F_N_FAMILY, -1 },
		{ PidTagGivenName, DAV_F_N_GIVEN, -1 }, { PidTagMiddleName, DAV_F_N_MIDDLE, -1 },
		{ PidTagDisplayNamePrefix, DAV_F_N_PREFIX, -1 }, { PidTagGeneration, DAV_F_N_SUFFIX, -1 },
		{ PidTagBusinessTelephoneNumber, DAV_F_TEL_WORK, -1 }, { PidTagHomeTelephoneNumber, DAV_F_TEL_HOME, -1 },
		{ PidTagMobileTelephoneNumber, DAV_F_TEL_CELL, -1 }, { PidTagBusinessFaxNumber, DAV_F_TEL_FAX, -1 },
		{ PidTagCompanyName, DAV_F_ORG, -1 }, { PidTagDepartmentName, DAV_F_ORG_UNIT, -1 },
		{ PidTagTitle, DAV_F_TITLE, -1 }, { PidTagBody, DAV_F_NOTE, -1 }, { PidTagBusinessHomePage, DAV_F_URL, -1 },
		{ PidTagHomeAddressPostOfficeBox, DAV_F_ADR_HOME, 0 }, { PidTagHomeAddressStreet, DAV_F_ADR_HOME, 2 },
		{ PidTagHomeAddressCity, DAV_F_ADR_HOME, 3 }, { PidTagHomeAddressStateOrProvince, DAV_F_ADR_HOME, 4 },
		{ PidTagHomeAddressPostalCode, DAV_F_ADR_HOME, 5 }, { PidTagHomeAddressCountry, DAV_F_ADR_HOME, 6 },
	};
	const struct { uint32_t tag; enum dav_field f; int comp; } named[] = {
		{ t->email_address[0], DAV_F_EMAIL1, -1 }, { t->email_address[1], DAV_F_EMAIL2, -1 },
		{ t->email_address[2], DAV_F_EMAIL3, -1 }, { t->dl_name, DAV_F_LIST_NAME, -1 },
		{ t->work_po_box, DAV_F_ADR_WORK, 0 }, { t->work_street, DAV_F_ADR_WORK, 2 },
		{ t->work_city, DAV_F_ADR_WORK, 3 }, { t->work_state, DAV_F_ADR_WORK, 4 },
		{ t->work_postal_code, DAV_F_ADR_WORK, 5 }, { t->work_country, DAV_F_ADR_WORK, 6 },
	};
	size_t i;

	for (i = 0; i < sizeof fixed / sizeof fixed[0]; i++) {
		if (fixed[i].tag == tag) { *f = fixed[i].f; *comp = fixed[i].comp; return true; }
	}
	for (i = 0; tag && i < sizeof named / sizeof named[0]; i++) {
		if (named[i].tag == tag) { *f = named[i].f; *comp = named[i].comp; return true; }
	}
	return false;
}

static struct Binary_r *one_off(TALLOC_CTX *mem, const char *name, const char *email)
{
	struct OneOffEntryId o;
	struct Binary_r *b;
	DATA_BLOB blob;

	memset(&o, 0, sizeof o);
	GUID_from_string("a41f2b81-a3be-1910-9d6e-00dd010f5402", &o.ProviderUID);
	o.OneOffEntryIdFlags = 0x9001;	/* Unicode, no rich info (as Outlook writes them) */
	o.DisplayName.lpszW = name && *name ? name : (email ? email : "");
	o.AddressType.lpszW = "SMTP";
	o.EmailAddress.lpszW = email ? email : "";
	if (ndr_push_struct_blob(&blob, mem, &o, (ndr_push_flags_fn_t)ndr_push_OneOffEntryId) != NDR_ERR_SUCCESS) {
		return NULL;
	}
	b = talloc_zero(mem, struct Binary_r);
	if (!b) return NULL;
	b->cb = blob.length;
	b->lpb = talloc_steal(b, blob.data);
	return b;
}

static struct Binary_r *wrapped(TALLOC_CTX *mem, const struct Binary_r *eid)
{
	struct Binary_r *b = talloc_zero(mem, struct Binary_r);

	if (!b || !(b->lpb = talloc_zero_array(b, uint8_t, 21 + eid->cb))) return NULL;
	memcpy(b->lpb + 4, wrapped_uid, sizeof wrapped_uid);
	b->lpb[20] = WRAPPED_CONTACT_EMAIL1;
	memcpy(b->lpb + 21, eid->lpb, eid->cb);
	b->cb = 21 + eid->cb;
	return b;
}

/* Members and one-offs of a VLIST, index-aligned; members[i] wraps the contact when the resolver knows it. */
static bool list_entries(TALLOC_CTX *mem, const struct dav_card *c, const struct dav_member_resolver *r,
			 struct BinaryArray_r **membersp, struct BinaryArray_r **oneoffsp)
{
	struct BinaryArray_r *m = talloc_zero(mem, struct BinaryArray_r), *o = talloc_zero(mem, struct BinaryArray_r);
	size_t i;

	if (!m || !o) return false;
	m->lpbin = talloc_zero_array(m, struct Binary_r, c->nlines + 1);
	o->lpbin = talloc_zero_array(o, struct Binary_r, c->nlines + 1);
	if (!m->lpbin || !o->lpbin) return false;
	for (i = 0; i < c->nlines; i++) {
		const struct dav_line *l = &c->lines[i];
		char *key, *email, *name;
		struct Binary_r *eid, *mb, *ob;

		if (strcasecmp(l->name, "CARD") != 0 || !(key = member_key(mem, l))) continue;
		if (!member_visible(mem, l, key, r, &eid)) continue;	/* nothing Outlook could send to */
		email = param_value(mem, l, "EMAIL");
		name = param_value(mem, l, "FN");
		ob = one_off(o->lpbin, name, email);
		mb = eid ? wrapped(m->lpbin, eid) : one_off(m->lpbin, name, email);
		if (!ob || !mb) return false;
		m->lpbin[m->cValues++] = *mb;
		o->lpbin[o->cValues++] = *ob;
	}
	*membersp = m;
	*oneoffsp = o;
	return true;
}

static struct FILETIME *birthday(TALLOC_CTX *mem, const char *date)
{
	struct tm tm;
	struct FILETIME *ft;
	uint64_t nt;
	int y, m, d;

	if (!date || sscanf(date, "%4d-%2d-%2d", &y, &m, &d) != 3) return NULL;
	memset(&tm, 0, sizeof tm);
	tm.tm_year = y - 1900; tm.tm_mon = m - 1; tm.tm_mday = d;
	if (!(ft = talloc(mem, struct FILETIME))) return NULL;
	nt = ((uint64_t)(int64_t)timegm(&tm) + 11644473600ULL) * 10000000ULL;
	ft->dwLowDateTime = (uint32_t)nt;
	ft->dwHighDateTime = (uint32_t)(nt >> 32);
	return ft;
}

static void *ulong_value(TALLOC_CTX *mem, uint32_t v)
{
	uint32_t *p = talloc(mem, uint32_t);
	if (p) *p = v;
	return p;
}

static void *bool_value(TALLOC_CTX *mem, bool v)
{
	uint8_t *p = talloc(mem, uint8_t);
	if (p) *p = v ? 1 : 0;
	return p;
}

_PUBLIC_ enum mapistore_error dav_card_get_prop(TALLOC_CTX *mem, const struct dav_card *c,
						const struct dav_named_tags *t, const struct dav_member_resolver *r,
						enum MAPITAGS tag, void **value)
{
	bool list = is_list(c);
	uint32_t tg = tag;
	enum dav_field f;
	int comp, i;
	void *v = NULL;
	char *s, *s2, **parts;
	size_t n;

	*value = NULL;
	if (tag == PidTagMessageClass) {
		v = talloc_strdup(mem, list ? "IPM.DistList" : "IPM.Contact");
	} else if (tag == PidTagDisplayName || tag == PidTagSubject || tag == PidTagNormalizedSubject) {
		v = dav_field_get(mem, c, list ? DAV_F_LIST_NAME : DAV_F_FN);
	} else if (tag == PidTagBirthday) {
		v = birthday(mem, dav_field_get(mem, c, DAV_F_BDAY));
	} else if (tag == PidTagAttachDataBinary) {
		v = photo_bytes(mem, c);
	} else if (!list && tg == t->has_picture) {
		v = bool_value(mem, photo_bytes(mem, c) != NULL);
	} else if (!list && tg == t->file_under) {
		s = dav_field_get(mem, c, DAV_F_N_FAMILY);
		s2 = dav_field_get(mem, c, DAV_F_N_GIVEN);
		v = s && s2 ? talloc_asprintf(mem, "%s, %s", s, s2) : s ? s : s2 ? s2 : dav_field_get(mem, c, DAV_F_FN);
	} else if (!list && (tg == t->abp_array_type || tg == t->abp_email_list)) {
		/* which Email1-3 slots hold an address: bit i / entry i is slot i */
		uint32_t slots[3], k = 0, bits = 0;
		struct LongArray_r *a;
		for (i = 0; i < 3; i++) {
			if (dav_field_get(mem, c, DAV_F_EMAIL1 + i)) { slots[k++] = i; bits |= 1u << i; }
		}
		if (!k) return MAPISTORE_ERR_NOT_FOUND;
		if (tg == t->abp_array_type) {
			v = ulong_value(mem, bits);
		} else if ((a = talloc_zero(mem, struct LongArray_r)) && (a->lpl = talloc_memdup(a, slots, k * sizeof *slots))) {
			a->cValues = k;
			v = a;
		}
		if (!v) return MAPISTORE_ERR_NO_MEMORY;
	} else if (list && (tg == t->dl_members || tg == t->dl_one_off_members || tg == t->dl_checksum)) {
		struct BinaryArray_r *m, *o;
		if (!list_entries(mem, c, r, &m, &o)) return MAPISTORE_ERR_NO_MEMORY;
		if (tg == t->dl_checksum) {
			uint8_t *cat = talloc_array(mem, uint8_t, 1);
			uint32_t total = 0;
			for (n = 0; cat && n < m->cValues; n++) {
				cat = talloc_realloc(mem, cat, uint8_t, total + m->lpbin[n].cb + 1);
				if (cat) memcpy(cat + total, m->lpbin[n].lpb, m->lpbin[n].cb);
				total += m->lpbin[n].cb;
			}
			if (!cat) return MAPISTORE_ERR_NO_MEMORY;
			v = ulong_value(mem, calculateCRC(cat, 0, total));
		} else {
			v = tg == t->dl_members ? m : o;
		}
	} else {
		for (i = 0; !list && i < 3; i++) {
			if (tg != t->email_display_name[i] && tg != t->email_address_type[i] &&
			    tg != t->email_original_display_name[i] && tg != t->email_original_entryid[i]) continue;
			if (!(s = dav_field_get(mem, c, DAV_F_EMAIL1 + i))) return MAPISTORE_ERR_NOT_FOUND;
			s2 = dav_field_get(mem, c, DAV_F_FN);
			if (tg == t->email_original_entryid[i]) {
				if (!(v = one_off(mem, s2, s))) return MAPISTORE_ERR_NO_MEMORY;
			} else if (tg == t->email_original_display_name[i]) {
				v = s;
			} else {
				v = tg == t->email_address_type[i] ? talloc_strdup(mem, "SMTP")
					: s2 ? talloc_asprintf(mem, "%s (%s)", s2, s) : s;
			}
			break;
		}
		if (i == 3 || list) {
			if (!tag_field(t, tg, &f, &comp)) return MAPISTORE_ERR_NOT_FOUND;
			s = dav_field_get(mem, c, f);
			if (s && comp >= 0) {
				parts = split(mem, s, '\n', 7, &n);
				s = parts ? nonempty(text(mem, parts[comp])) : NULL;
			}
			v = s;
		}
	}
	if (!v) return MAPISTORE_ERR_NOT_FOUND;
	*value = v;
	return MAPISTORE_SUCCESS;
}

/* A string property's UTF-8 value with CRLF as LF, and its tag with the PT_UNICODE type. */
static const char *prop_string(const struct SPropValue *p, uint32_t *tag)
{
	*tag = p->ulPropTag;
	switch (p->ulPropTag & 0xFFFF) {
	case PT_UNICODE:
		return p->value.lpszW;
	case PT_STRING8:
		*tag = (p->ulPropTag & 0xFFFF0000) | PT_UNICODE;
		return p->value.lpszA;
	default:
		return NULL;
	}
}

static char *clean(TALLOC_CTX *mem, const char *s)
{
	char *out = talloc_array(mem, char, strlen(s) + 1), *o = out;

	if (!out) return NULL;
	for (; *s; s++) if (*s != '\r') *o++ = *s;
	*o = '\0';
	return nonempty(trim(mem, out));
}

static const struct SPropValue *find_prop(const struct SRow *row, uint32_t tag)
{
	uint32_t i;

	for (i = 0; tag && i < row->cValues; i++) if ((uint32_t)row->lpProps[i].ulPropTag == tag) return &row->lpProps[i];
	return NULL;
}

_PUBLIC_ bool dav_props_members(TALLOC_CTX *mem, struct SRow *props, const struct dav_named_tags *t,
				const struct dav_member_resolver *r, struct dav_member **membersp, size_t *countp)
{
	const struct SPropValue *mp = find_prop(props, t->dl_members), *op = find_prop(props, t->dl_one_off_members);
	const struct BinaryArray_r *ma = mp ? &mp->value.MVbin : NULL, *oa = op ? &op->value.MVbin : NULL;
	struct dav_member *out;
	uint32_t i, n;
	size_t k = 0;

	if (!ma && !oa) return false;
	n = ma ? ma->cValues : oa->cValues;
	out = talloc_zero_array(mem, struct dav_member, n + 1);
	if (!out) return false;
	for (i = 0; i < n; i++) {
		struct Binary_r *e = ma ? &ma->lpbin[i] : NULL, *oe = oa && i < oa->cValues ? &oa->lpbin[i] : NULL;
		struct OneOffEntryId *oo = NULL;
		char *key = NULL;

		if (oe && oe->cb > 20 && memcmp(oe->lpb + 4, one_off_uid, 16) == 0) oo = get_OneOffEntryId(out, oe);
		if (!oo && e && e->cb > 20 && memcmp(e->lpb + 4, one_off_uid, 16) == 0) oo = get_OneOffEntryId(out, e);
		if (e && e->cb > 21 && memcmp(e->lpb + 4, wrapped_uid, 16) == 0
		    && ((e->lpb[20] & 0x0F) == 3 || (e->lpb[20] & 0x0F) == 4) && r && r->uid_for_entryid) {
			struct Binary_r inner = { .cb = e->cb - 21, .lpb = e->lpb + 21 };
			key = r->uid_for_entryid(r->ctx, out, &inner);
		}
		if (oo) {
			bool w = oo->OneOffEntryIdFlags & 0x8000;
			const char *nm = w ? oo->DisplayName.lpszW : oo->DisplayName.lpszA;
			const char *em = w ? oo->EmailAddress.lpszW : oo->EmailAddress.lpszA;
			out[k].name = nm && *nm ? talloc_strdup(out, nm) : NULL;
			out[k].email = em && *em ? lower(out, em) : NULL;
		}
		if (!key && out[k].email) key = talloc_asprintf(out, "mailto:%s", out[k].email);
		if (!key) {
			out[k].name = out[k].email = NULL;
			continue;
		}
		out[k++].key = key;
	}
	*membersp = out;
	*countp = k;
	return true;
}

_PUBLIC_ void dav_props_to_fields(TALLOC_CTX *mem, struct SRow *props, const struct dav_named_tags *t,
				  const struct dav_member_resolver *r, const struct dav_card *base,
				  char *values[DAV_F_COUNT], bool present[DAV_F_COUNT])
{
	char *adr[2][7];
	bool adr_present[2] = { false, false }, adr_comp[2][7];
	struct dav_member *m;
	uint32_t i, tag;
	size_t n, k;
	int comp;
	enum dav_field f;

	memset(adr_comp, 0, sizeof adr_comp);
	for (f = 0; f < DAV_F_COUNT; f++) {
		values[f] = NULL;
		present[f] = false;
	}
	for (i = 0; i < props->cValues; i++) {
		const struct SPropValue *p = &props->lpProps[i];
		const char *s = prop_string(p, &tag);

		if (s && tag_field(t, tag, &f, &comp)) {
			if (comp < 0) {
				values[f] = clean(mem, s);
				present[f] = true;
			} else {
				char *v = clean(mem, s);
				k = f == DAV_F_ADR_WORK ? 0 : 1;
				adr[k][comp] = v ? dav_text_escape(mem, v) : talloc_strdup(mem, "");
				adr_comp[k][comp] = adr_present[k] = true;
			}
		} else if (p->ulPropTag == PidTagBirthday) {
			uint64_t nt = ((uint64_t)p->value.ft.dwHighDateTime << 32) | p->value.ft.dwLowDateTime;
			/* nearest midnight: Outlook stores the local midnight of the birthday, in UTC */
			time_t when = (time_t)(nt / 10000000ULL - 11644473600ULL) + 12 * 3600;
			struct tm tm;
			if (gmtime_r(&when, &tm)) {
				values[DAV_F_BDAY] = talloc_asprintf(mem, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
				present[DAV_F_BDAY] = true;
			}
		} else if (p->ulPropTag == PidTagAttachDataBinary) {
			if (p->value.bin.cb > DAV_PHOTO_MAX) continue;	/* too big for SOGo and phones: not synced */
			values[DAV_F_PHOTO] = p->value.bin.cb ? ldb_base64_encode(mem, (const char *)p->value.bin.lpb, p->value.bin.cb) : NULL;
			present[DAV_F_PHOTO] = true;
		}
	}
	for (k = 0; k < 2; k++) {
		enum dav_field af = k ? DAV_F_ADR_HOME : DAV_F_ADR_WORK;
		char *b = base ? dav_field_get(mem, base, af) : NULL, **old = split(mem, b ? b : "", '\n', 7, &n);
		bool any = false;

		if (!adr_present[k] || !old) continue;
		for (comp = 0; comp < 7; comp++) {
			if (!adr_comp[k][comp]) adr[k][comp] = comp == 1 || comp >= (int)n ? "" : old[comp];
			if (comp == 1) adr[k][comp] = "";
			if (*adr[k][comp]) any = true;
		}
		values[af] = any ? join(mem, adr[k], 7, "\n") : NULL;
		present[af] = true;
	}
	if (dav_props_members(mem, props, t, r, &m, &n)) {
		char **keys = talloc_array(mem, char *, n + 1);
		for (k = 0; keys && k < n; k++) keys[k] = m[k].key;
		values[DAV_F_LIST_MEMBERS] = keys ? keys_field(mem, keys, n) : NULL;
		present[DAV_F_LIST_MEMBERS] = true;
	}
}

/* Maps one PSETID_Address LID, creating the mapping when the store has none yet. */
static enum mapistore_error map_lid(struct namedprops_context *np, uint32_t lid, uint16_t type, uint32_t *tag)
{
	struct MAPINAMEID nameid;
	enum mapistore_error ret;
	uint16_t id;

	memset(&nameid, 0, sizeof nameid);
	nameid.ulKind = MNID_ID;
	GUID_from_string(PSETID_Address, &nameid.lpguid);
	nameid.kind.lid = lid;
	ret = mapistore_namedprops_get_mapped_id(np, nameid, &id);
	if (ret == MAPISTORE_ERR_NOT_FOUND) {
		ret = mapistore_namedprops_transaction_start(np);
		if (ret != MAPISTORE_SUCCESS) return ret;
		/* another writer may have created it while we waited */
		ret = mapistore_namedprops_get_mapped_id(np, nameid, &id);
		if (ret == MAPISTORE_ERR_NOT_FOUND) {
			ret = mapistore_namedprops_next_unused_id(np, &id);
			if (ret == MAPISTORE_SUCCESS) ret = mapistore_namedprops_create_id(np, nameid, id);
			if (ret == MAPISTORE_ERR_EXIST) ret = mapistore_namedprops_get_mapped_id(np, nameid, &id);
		}
		if (ret == MAPISTORE_SUCCESS) {
			ret = mapistore_namedprops_transaction_commit(np);
		} else {
			mapistore_namedprops_transaction_cancel(np);
		}
	}
	if (ret == MAPISTORE_SUCCESS) *tag = ((uint32_t)id << 16) | type;
	return ret;
}

_PUBLIC_ enum mapistore_error dav_named_tags_resolve(struct namedprops_context *np, struct dav_named_tags *t)
{
	const struct { uint32_t lid; uint16_t type; uint32_t *tag; } lids[] = {
		{ 0x8083, PT_UNICODE, &t->email_address[0] }, { 0x8093, PT_UNICODE, &t->email_address[1] },
		{ 0x80a3, PT_UNICODE, &t->email_address[2] }, { 0x8080, PT_UNICODE, &t->email_display_name[0] },
		{ 0x8090, PT_UNICODE, &t->email_display_name[1] }, { 0x80a0, PT_UNICODE, &t->email_display_name[2] },
		{ 0x8082, PT_UNICODE, &t->email_address_type[0] }, { 0x8092, PT_UNICODE, &t->email_address_type[1] },
		{ 0x80a2, PT_UNICODE, &t->email_address_type[2] }, { 0x8005, PT_UNICODE, &t->file_under },
		{ 0x8015, PT_BOOLEAN, &t->has_picture }, { 0x8045, PT_UNICODE, &t->work_street },
		{ 0x8046, PT_UNICODE, &t->work_city }, { 0x8047, PT_UNICODE, &t->work_state },
		{ 0x8048, PT_UNICODE, &t->work_postal_code }, { 0x8049, PT_UNICODE, &t->work_country },
		{ 0x804a, PT_UNICODE, &t->work_po_box }, { 0x8053, PT_UNICODE, &t->dl_name },
		{ 0x8055, PT_MV_BINARY, &t->dl_members }, { 0x8054, PT_MV_BINARY, &t->dl_one_off_members },
		{ 0x804c, PT_LONG, &t->dl_checksum },
		{ 0x8084, PT_UNICODE, &t->email_original_display_name[0] }, { 0x8094, PT_UNICODE, &t->email_original_display_name[1] },
		{ 0x80a4, PT_UNICODE, &t->email_original_display_name[2] }, { 0x8085, PT_BINARY, &t->email_original_entryid[0] },
		{ 0x8095, PT_BINARY, &t->email_original_entryid[1] }, { 0x80a5, PT_BINARY, &t->email_original_entryid[2] },
		{ 0x8028, PT_MV_LONG, &t->abp_email_list }, { 0x8029, PT_LONG, &t->abp_array_type },
	};
	enum mapistore_error ret;
	size_t i;

	for (i = 0; i < sizeof lids / sizeof lids[0]; i++) {
		ret = map_lid(np, lids[i].lid, lids[i].type, lids[i].tag);
		if (ret != MAPISTORE_SUCCESS) return ret;
	}
	return MAPISTORE_SUCCESS;
}
