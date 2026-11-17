/*
   CardDAV mapistore backend: field fingerprints of the version Outlook and SOGo last agreed on

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#ifndef	__DAV_FPSTORE_H__
#define	__DAV_FPSTORE_H__

#include <stdint.h>
#include <stddef.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "dav_map.h"

struct dav_fpstore;

/* HMAC-SHA-256 over field_id || 0x00 || value (absent: field_id || 0x01), first 8 bytes big-endian. */
uint64_t dav_fp(const uint8_t *key, size_t key_len, enum dav_field, const char *value);
/* Every field's fingerprint of a card. */
void dav_fp_card(const uint8_t *key, size_t key_len, const struct dav_card *, uint64_t fp[DAV_F_COUNT]);

/* indexing_url mysql://... keeps fingerprints in its database, anything else in process memory.
   shortcut: tdb indexing keeps fingerprints in memory only, which degrades to the "no fingerprint" rule after
   restart; add a tdb store if anyone runs tdb in production. */
struct dav_fpstore *dav_fpstore_open(TALLOC_CTX *, const char *indexing_url);
/* hrefs are normalized paths (dav_href_norm). NOT_FOUND when the item has no fingerprint. */
enum mapistore_error dav_fp_get(struct dav_fpstore *, TALLOC_CTX *, const char *user, const char *href,
				uint64_t fp[DAV_F_COUNT], char **etag);
enum mapistore_error dav_fp_put(struct dav_fpstore *, const char *user, const char *href,
				const uint64_t fp[DAV_F_COUNT], const char *etag);
enum mapistore_error dav_fp_delete(struct dav_fpstore *, const char *user, const char *href);
/* Deletes the rows of the book's items that are not in live; *gone (in mem_ctx) lists their hrefs: items
   Outlook was given that no longer exist. */
enum mapistore_error dav_fp_prune(struct dav_fpstore *, const char *user, const char *book_href, char **live, size_t n,
				  TALLOC_CTX *, char ***gone, size_t *ngone);

#endif /* ! __DAV_FPSTORE_H__ */
