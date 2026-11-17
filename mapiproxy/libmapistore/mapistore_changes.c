/*
   OpenChange Storage Abstraction Layer library

   Per-item change numbers shared by the backends that have no change counter of their own.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <string.h>

#include "mapistore.h"
#include "mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "utils/dlinklist.h"

/* A change kept per object URI for the life of the process (bounded by the objects shown). */
struct change {
	struct change	*prev, *next;
	char		*key;		/* user, then URI */
	char		*state;		/* NULL: Outlook's own change, state not seen yet */
	uint64_t	cn;
	time_t		when;
	struct Binary_r	*ck, *pcl;	/* Outlook's change key and PCL for its own change */
};
static struct change *changes;

static struct change *change_find(const char *key)
{
	struct change *c;

	for (c = changes; c && strcmp(c->key, key) != 0; c = c->next);
	return c;
}

/* The change for key, created when missing; takes key. */
static struct change *change_get(char *key)
{
	struct change *c = change_find(key);

	if (c) {
		talloc_free(key);
		return c;
	}
	c = talloc_zero(NULL, struct change);
	if (!c) {
		talloc_free(key);
		return NULL;
	}
	c->key = talloc_steal(c, key);
	DLIST_ADD(changes, c);
	return c;
}

_PUBLIC_ struct Binary_r *mapistore_binary_dup(TALLOC_CTX *mem_ctx, const struct Binary_r *b)
{
	struct Binary_r *d = b ? talloc_zero(mem_ctx, struct Binary_r) : NULL;

	if (d && b->cb && !(d->lpb = talloc_memdup(d, b->lpb, b->cb))) {
		talloc_free(d);
		return NULL;
	}
	if (d) {
		d->cb = b->cb;
	}
	return d;
}

_PUBLIC_ enum mapistore_error mapistore_change_number(const char *username, const char *uri, const char *state,
						      mapistore_cn_source source, void *source_ctx,
						      uint64_t *cn, time_t *when)
{
	struct change		*c;
	char			*key = talloc_asprintf(NULL, "%s\n%s", username, uri);
	enum mapistore_error	ret;

	if (!key || !state) {
		talloc_free(key);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	c = change_find(key);
	/* Outlook's own change: the first state seen after it is that change, not a new one. */
	if (c && !c->state) {
		c->state = talloc_strdup(c, state);
	}
	if (c && c->state && strcmp(c->state, state) == 0) {
		talloc_free(key);
		*cn = c->cn;
		*when = c->when;
		return MAPISTORE_SUCCESS;
	}
	ret = source(source_ctx, cn);
	if (ret != MAPISTORE_SUCCESS) {
		talloc_free(key);
		return ret;
	}
	c = change_get(key);
	if (!c) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	talloc_free(c->state);
	c->state = talloc_strdup(c, state);
	c->cn = *cn;
	c->when = time(NULL);
	TALLOC_FREE(c->ck);	/* changed on the server: the server's own key from now on */
	TALLOC_FREE(c->pcl);
	*when = c->when;
	return c->state ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
}

/* Outlook uploaded this object's current state with its own change key: report that key, so its
   next sync does not see a server change and open a conflict. */
_PUBLIC_ enum mapistore_error mapistore_change_record_client(const char *username, const char *uri,
							     mapistore_cn_source source, void *source_ctx,
							     const struct Binary_r *ck, const struct Binary_r *pcl)
{
	struct change		*c;
	char			*key;
	uint64_t		cn;
	enum mapistore_error	ret;

	if (!uri || !ck || !pcl) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	ret = source(source_ctx, &cn);
	key = ret == MAPISTORE_SUCCESS ? talloc_asprintf(NULL, "%s\n%s", username, uri) : NULL;
	if (!key) {
		return ret != MAPISTORE_SUCCESS ? ret : MAPISTORE_ERR_NO_MEMORY;
	}
	c = change_get(key);
	if (!c) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	TALLOC_FREE(c->state);
	TALLOC_FREE(c->ck);
	TALLOC_FREE(c->pcl);
	c->cn = cn;
	c->when = time(NULL);
	c->ck = mapistore_binary_dup(c, ck);
	c->pcl = mapistore_binary_dup(c, pcl);
	return c->ck && c->pcl ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
}

/* The keys Outlook uploaded for change number cn; with a NULL uri any object of the user that
   holds cn (change numbers come from per-user counters: another user's cn is not this one). */
_PUBLIC_ enum mapistore_error mapistore_change_client_keys(const char *username, const char *uri, uint64_t cn,
							   const struct Binary_r **ck, const struct Binary_r **pcl)
{
	const struct change	*c;
	char			*key = talloc_asprintf(NULL, "%s\n%s", username, uri ? uri : "");
	size_t			len;

	if (!username || !key) {
		talloc_free(key);
		return username ? MAPISTORE_ERR_NO_MEMORY : MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (uri) {
		c = change_find(key);
		if (c && !(c->cn == cn && c->ck)) {
			c = NULL;
		}
	} else {
		len = strlen(key);
		for (c = changes; c && !(c->cn == cn && c->ck && strncmp(c->key, key, len) == 0); c = c->next);
	}
	talloc_free(key);
	if (!c) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	*ck = c->ck;
	*pcl = c->pcl;
	return MAPISTORE_SUCCESS;
}

/* XID of a change: the replica GUID (NDR) and the 6 low bytes of cn >> 16, as oxcfxics_make_gid. */
static struct Binary_r *change_key(TALLOC_CTX *mem_ctx, const struct GUID *g, uint64_t cn, bool sized)
{
	struct Binary_r	*b = talloc_zero(mem_ctx, struct Binary_r);
	uint8_t		*p;
	uint64_t	id = (cn >> 16) & 0x0000FFFFFFFFFFFFULL;
	int		i;

	if (!b || !(b->lpb = talloc_array(b, uint8_t, 23))) {
		talloc_free(b);
		return NULL;
	}
	p = b->lpb;
	if (sized) {
		*p++ = 22; /* PredecessorChangeList: one SizedXid */
	}
	for (i = 0; i < 4; i++) *p++ = (g->time_low >> (8 * i)) & 0xFF;
	for (i = 0; i < 2; i++) *p++ = (g->time_mid >> (8 * i)) & 0xFF;
	for (i = 0; i < 2; i++) *p++ = (g->time_hi_and_version >> (8 * i)) & 0xFF;
	memcpy(p, g->clock_seq, 2);
	p += 2;
	memcpy(p, g->node, 6);
	p += 6;
	for (i = 0; i < 6; i++, id >>= 8) *p++ = id & 0xFF;
	b->cb = sized ? 23 : 22;
	return b;
}

static struct FILETIME *change_time(TALLOC_CTX *mem_ctx, time_t t)
{
	struct FILETIME	*ft = talloc(mem_ctx, struct FILETIME);
	uint64_t	nt = ((uint64_t) t + 11644473600ULL) * 10000000ULL;

	if (ft) {
		ft->dwLowDateTime = (uint32_t) nt;
		ft->dwHighDateTime = (uint32_t) (nt >> 32);
	}
	return ft;
}

/* PidTagChangeNumber, PidTagChangeKey, PidTagPredecessorChangeList, PidTagLastModificationTime or
   PidTagLocalCommitTimeMax of change cn; the keys Outlook uploaded when the change is its own. */
_PUBLIC_ void *mapistore_change_value(TALLOC_CTX *mem_ctx, const char *username, const char *uri,
				      const struct GUID *replica_guid, uint64_t cn, time_t when, enum MAPITAGS tag)
{
	const struct Binary_r	*ock = NULL, *opcl = NULL;
	uint64_t		*p;
	bool own = (tag == PidTagChangeKey || tag == PidTagPredecessorChangeList) &&
		   mapistore_change_client_keys(username, uri, cn, &ock, &opcl) == MAPISTORE_SUCCESS;

	switch (tag) {
	case PidTagChangeNumber:
		p = talloc(mem_ctx, uint64_t);
		if (p) *p = cn;
		return p;
	case PidTagChangeKey:			return own ? mapistore_binary_dup(mem_ctx, ock) : change_key(mem_ctx, replica_guid, cn, false);
	case PidTagPredecessorChangeList:	return own ? mapistore_binary_dup(mem_ctx, opcl) : change_key(mem_ctx, replica_guid, cn, true);
	case PidTagLastModificationTime:
	case PidTagLocalCommitTimeMax:		return change_time(mem_ctx, when);
	default:				return NULL;
	}
}
