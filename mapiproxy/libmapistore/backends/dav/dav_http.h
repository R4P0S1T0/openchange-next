/*
   CardDAV client for the dav mapistore backend (libcurl + expat)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#ifndef	__DAV_HTTP_H__
#define	__DAV_HTTP_H__

#include <stdbool.h>
#include <stddef.h>

#include "mapiproxy/libmapistore/mapistore.h"

struct dav_http;

struct dav_book {
	char	*href;		/* server path as returned, e.g. /SOGo/dav/u/Contacts/personal/ */
	char	*segment;	/* last path segment, e.g. personal */
	char	*displayname;	/* NULL when absent */
	char	*sync_token;	/* NULL when the server gives none */
};

struct dav_change {
	char	*href;
	char	*etag;		/* NULL = removed */
};

/* `password` is borrowed: it must outlive the dav_http. The scheme (http or https) comes
 * from base_url; TLS verification is always on. All hrefs below are server paths ("/..."). */
/* The path of href, percent-decoded (an encoded '/' stays "%2F"), without trailing '/' ("/" for the root);
 * NULL when it has "." or ".." segments or a NUL. Two hrefs name the same resource when these are equal. */
char *dav_href_norm(TALLOC_CTX *, const char *href);

struct dav_http *dav_http_new(TALLOC_CTX *, const char *base_url, const char *user, const char *password);

/* PROPFIND base_url, Depth 1: the address books (read-only directories are left out). */
enum mapistore_error dav_list_books(struct dav_http *, TALLOC_CTX *, struct dav_book **books, size_t *n);

/* token NULL = everything. An unusable token is retried as a full sync. *was_full is true
 * whenever the result is the full state (changes then lists only present members). */
enum mapistore_error dav_sync(struct dav_http *, TALLOC_CTX *, const char *book_href, const char *token,
			      struct dav_change **changes, size_t *n, char **new_token, bool *was_full);

/* bodies[i]/etags[i] are NULL for a href the server does not have. */
enum mapistore_error dav_multiget(struct dav_http *, TALLOC_CTX *, const char *book_href, char **hrefs, size_t n,
				  char ***bodies, char ***etags);
enum mapistore_error dav_get(struct dav_http *, TALLOC_CTX *, const char *href, char **body, char **etag);

/* *new_etag (in mem_ctx) may stay NULL when the server sends none. */
enum mapistore_error dav_put(struct dav_http *, TALLOC_CTX *, const char *href, const char *body, const char *content_type,
			     const char *if_match, bool if_none_match, char **new_etag);
enum mapistore_error dav_delete(struct dav_http *, const char *href, const char *if_match);
enum mapistore_error dav_mkcol_book(struct dav_http *, const char *href, const char *displayname);
enum mapistore_error dav_rename_book(struct dav_http *, const char *href, const char *displayname);
enum mapistore_error dav_delete_book(struct dav_http *, const char *href);

#endif /* ! __DAV_HTTP_H__ */
