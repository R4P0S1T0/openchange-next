/*
   CardDAV mapistore backend: field-level merge of an Outlook write into the server's card

   Per field: whichever side changed it since the version both last agreed on (its fingerprint) wins;
   when both did, the most recent edit wins, whichever client made it, and the other value goes to
   the NOTE so nothing is lost. List members merge as sets.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "dav_backend.h"
#include "dav_fpstore.h"

/* Members whose base is searched among subsets of the two sides' difference (2^n fingerprints). */
#define MEMBERS_SEARCH_MAX 16

/* What the user reads in the NOTE line of a losing value. */
static const char *labels[DAV_F_COUNT] = {
	[DAV_F_FN] = "nome", [DAV_F_N_FAMILY] = "sobrenome", [DAV_F_N_GIVEN] = "nome próprio",
	[DAV_F_N_MIDDLE] = "nome do meio", [DAV_F_N_PREFIX] = "tratamento", [DAV_F_N_SUFFIX] = "sufixo",
	[DAV_F_EMAIL1] = "e-mail 1", [DAV_F_EMAIL2] = "e-mail 2", [DAV_F_EMAIL3] = "e-mail 3",
	[DAV_F_TEL_WORK] = "telefone comercial", [DAV_F_TEL_HOME] = "telefone residencial", [DAV_F_TEL_CELL] = "celular",
	[DAV_F_TEL_FAX] = "fax", [DAV_F_ORG] = "empresa", [DAV_F_ORG_UNIT] = "departamento", [DAV_F_TITLE] = "cargo",
	[DAV_F_ADR_WORK] = "endereço comercial", [DAV_F_ADR_HOME] = "endereço residencial", [DAV_F_NOTE] = "anotações",
	[DAV_F_BDAY] = "aniversário", [DAV_F_URL] = "página web", [DAV_F_PHOTO] = "foto substituída",
	[DAV_F_LIST_NAME] = "nome da lista", [DAV_F_LIST_MEMBERS] = "membros",
};

static bool same(const char *a, const char *b)
{
	return !a || !*a ? !b || !*b : b && strcmp(a, b) == 0;
}

/* Whether field f exists in a card of this kind (lists: name, members, description). */
bool dav_field_applies(const struct dav_card *c, enum dav_field f)
{
	bool list = strcmp(dav_card_kind(c), "VLIST") == 0;

	return f == DAV_F_NOTE || list == (f == DAV_F_LIST_NAME || f == DAV_F_LIST_MEMBERS);
}

/* A losing value as the user reads it: an address's components joined, unescaped. */
static char *readable(TALLOC_CTX *mem, enum dav_field f, const char *v)
{
	char *out, *s, *e;

	if (f != DAV_F_ADR_WORK && f != DAV_F_ADR_HOME) return talloc_strdup(mem, v);
	out = talloc_strdup(mem, "");
	for (s = talloc_strdup(mem, v); out && s; s = e) {
		char *t;

		if ((e = strchr(s, '\n'))) *e++ = '\0';
		t = dav_text_unescape(mem, s);
		if (t && *t) out = talloc_asprintf_append_buffer(out, "%s%s", *out ? ", " : "", t);
	}
	return out;
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char * const *)a, *(char * const *)b);
}

static char **keys_split(TALLOC_CTX *mem, const char *v, size_t *n)
{
	char **k = talloc_array(mem, char *, 1), *s, *e;

	*n = 0;
	for (s = v ? talloc_strdup(mem, v) : NULL; k && s && *s; s = e) {
		if ((e = strchr(s, '\n'))) *e++ = '\0';
		if (!*s) continue;
		if (!(k = talloc_realloc(mem, k, char *, *n + 2))) return NULL;
		k[(*n)++] = s;
	}
	return k;
}

/* The members field of a key set: sorted, '\n'-joined, NULL when empty (as dav_field_get gives it). */
static char *keys_join(TALLOC_CTX *mem, char **k, size_t n)
{
	char *out;
	size_t i;

	if (!n) return NULL;
	qsort(k, n, sizeof *k, cmp_str);
	out = talloc_strdup(mem, k[0]);
	for (i = 1; out && i < n; i++) out = talloc_asprintf_append_buffer(out, "\n%s", k[i]);
	return out;
}

static bool has(char **k, size_t n, const char *key)
{
	size_t i;

	for (i = 0; i < n; i++) if (strcmp(k[i], key) == 0) return true;
	return false;
}

static void add(char **k, size_t *n, char *key)
{
	if (!has(k, *n, key)) k[(*n)++] = key;
}

char *dav_members_normalize(TALLOC_CTX *mem, const struct dav_card *c, const char *keys)
{
	size_t n, i, j;
	char **k = keys_split(mem, keys, &n);
	struct dav_line *l;

	for (i = 0; k && i < n; i++) {
		if (strncmp(k[i], "mailto:", 7) != 0) continue;
		for (j = 0; (l = dav_card_find(c, "CARD", NULL, j)); j++) {
			char *email = dav_line_param(mem, l, "EMAIL"), *v = dav_text_unescape(mem, l->value), *p;
			size_t len = v ? strlen(v) : 0;

			for (p = email; p && *p; p++) *p = tolower((unsigned char)*p);
			if (!email || strcmp(email, k[i] + 7) != 0 || len == 0) continue;
			if (len > 4 && strcasecmp(v + len - 4, ".vcf") == 0) v[len - 4] = '\0';
			k[i] = v;
			break;
		}
	}
	return k ? keys_join(mem, k, n) : NULL;
}

/* The member set both sides last agreed on: the subset of S ∪ O whose fingerprint is base (members
   both removed are in neither side and need not be found). NULL when not found. */
static char **find_base(TALLOC_CTX *mem, char **s, size_t ns, char **o, size_t no, uint64_t base,
			const uint8_t *key, size_t key_len, size_t *nb)
{
	char **common = talloc_array(mem, char *, ns + 1), **diff = talloc_array(mem, char *, ns + no + 1);
	char **b = talloc_array(mem, char *, ns + no + 1);
	size_t nc = 0, nd = 0, i;
	unsigned long mask;

	if (!common || !diff || !b) return NULL;
	for (i = 0; i < ns; i++) {
		if (has(o, no, s[i])) add(common, &nc, s[i]);
		else add(diff, &nd, s[i]);
	}
	for (i = 0; i < no; i++) if (!has(s, ns, o[i])) add(diff, &nd, o[i]);
	if (nd > MEMBERS_SEARCH_MAX) return NULL;
	for (mask = 0; mask < (1UL << nd); mask++) {
		*nb = 0;
		for (i = 0; i < nc; i++) b[(*nb)++] = common[i];
		for (i = 0; i < nd; i++) if (mask & (1UL << i)) b[(*nb)++] = diff[i];
		if (dav_fp(key, key_len, DAV_F_LIST_MEMBERS, keys_join(mem, b, *nb)) == base) return b;
	}
	return NULL;
}

/* (S ∪ added by Outlook) − removed by Outlook; without the base set, S ∪ O. */
static void merge_members(TALLOC_CTX *mem, struct dav_card *server, const char *outlook, const uint64_t *base,
			  const uint8_t *key, size_t key_len)
{
	char *sv = dav_field_get(mem, server, DAV_F_LIST_MEMBERS), *ov = dav_members_normalize(mem, server, outlook);
	char **s, **o, **b = NULL, **r;
	size_t ns, no, nb = 0, nr = 0, i;

	if (same(sv, ov)) return;
	if (base && dav_fp(key, key_len, DAV_F_LIST_MEMBERS, ov) == *base) return;	/* Outlook did not change them */
	if (base && dav_fp(key, key_len, DAV_F_LIST_MEMBERS, sv) == *base) {
		dav_field_set(server, DAV_F_LIST_MEMBERS, ov);
		return;
	}
	s = keys_split(mem, sv, &ns);
	o = keys_split(mem, ov, &no);
	r = s && o ? talloc_array(mem, char *, ns + no + 1) : NULL;
	if (!r) return;
	if (base) b = find_base(mem, s, ns, o, no, *base, key, key_len, &nb);
	for (i = 0; i < ns; i++) if (!b || has(o, no, s[i]) || !has(b, nb, s[i])) add(r, &nr, s[i]);
	for (i = 0; i < no; i++) if (!b || !has(b, nb, o[i])) add(r, &nr, o[i]);
	dav_field_set(server, DAV_F_LIST_MEMBERS, keys_join(mem, r, nr));
}

enum mapistore_error dav_merge(TALLOC_CTX *mem_ctx, struct dav_card *server, const char *outlook[DAV_F_COUNT],
			       const bool outlook_present[DAV_F_COUNT], const uint64_t base[DAV_F_COUNT],
			       time_t outlook_time, time_t server_time, const uint8_t *key, size_t key_len,
			       const char *today)
{
	TALLOC_CTX	*tmp = talloc_new(mem_ctx);
	char		*notes = NULL, *sv, *note;
	enum dav_field	f;
	bool		o, s;

	if (!tmp) return MAPISTORE_ERR_NO_MEMORY;
	for (f = 0; f < DAV_F_COUNT; f++) {
		if (!outlook_present[f] || !dav_field_applies(server, f)) continue;
		if (f == DAV_F_LIST_MEMBERS) {
			merge_members(tmp, server, outlook[f], base ? &base[f] : NULL, key, key_len);
			continue;
		}
		sv = dav_field_get(tmp, server, f);
		if (same(sv, outlook[f])) continue;
		o = !base || dav_fp(key, key_len, f, outlook[f]) != base[f];
		s = !base || dav_fp(key, key_len, f, sv) != base[f];
		if (!o) continue;
		if (s) {
			/* both changed: the most recent edit wins (a tie keeps the stored one) */
			bool outlook_wins = outlook_time > server_time;
			const char *loser = outlook_wins ? sv : outlook[f];

			if (loser && *loser) {
				note = f == DAV_F_PHOTO ? talloc_asprintf(tmp, "[%s conflito] %s", today, labels[f])
				       : talloc_asprintf(tmp, "[%s conflito] %s: %s", today, labels[f], readable(tmp, f, loser));
				notes = note ? talloc_asprintf(tmp, "%s%s%s", notes ? notes : "", notes ? "\n" : "", note) : NULL;
				if (!notes) {
					talloc_free(tmp);
					return MAPISTORE_ERR_NO_MEMORY;
				}
			}
			if (!outlook_wins) continue;
		}
		dav_field_set(server, f, outlook[f]);
	}
	if (notes) {
		sv = dav_field_get(tmp, server, DAV_F_NOTE);
		dav_field_set(server, DAV_F_NOTE, sv ? talloc_asprintf(tmp, "%s\n%s", sv, notes) : notes);
	}
	talloc_free(tmp);
	return MAPISTORE_SUCCESS;
}
