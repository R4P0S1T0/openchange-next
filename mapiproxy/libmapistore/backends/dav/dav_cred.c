/*
   OpenChange Storage Abstraction Layer library
   Optional CardDAV contacts backend (M6): the users' passwords, in memory only

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <stdlib.h>
#include <string.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "dav_backend.h"

/* One entry per user with live sessions; every caller is the daemon's single C worker thread. */
struct dav_cred {
	struct dav_cred	*next;
	char		*username;
	char		*password;	/* malloc()ed, not talloc: wiped before free */
	unsigned int	refs;		/* sessions of the user; two must not wipe each other's password */
};

static struct dav_cred *creds;
static void (*free_hook)(const char *, size_t);

void dav_cred_set_free_hook(void (*hook)(const char *buf, size_t len))
{
	free_hook = hook;
}

static void wipe(char *password)
{
	size_t	len = strlen(password);

	explicit_bzero(password, len);
	if (free_hook) free_hook(password, len);
	free(password);
}

static struct dav_cred **find(const char *username)
{
	struct dav_cred	**c;

	for (c = &creds; *c && strcmp((*c)->username, username) != 0; c = &(*c)->next);
	return c;
}

const char *dav_cred_get(const char *username)
{
	struct dav_cred	*c = username ? *find(username) : NULL;

	return c ? c->password : NULL;
}

enum mapistore_error dav_cred_set(const char *username, const char *password)
{
	struct dav_cred	**slot, *c;
	char		*copy;

	if (!username || !password) return MAPISTORE_ERR_INVALID_PARAMETER;
	slot = find(username);
	if (*slot && strcmp((*slot)->password, password) == 0) {
		(*slot)->refs++;
		return MAPISTORE_SUCCESS;
	}
	copy = strdup(password);
	if (!copy) return MAPISTORE_ERR_NO_MEMORY;
	if (*slot) {
		/* The newest session's password was just verified; the older one may have been changed since. */
		wipe((*slot)->password);
		(*slot)->password = copy;
		(*slot)->refs++;
		return MAPISTORE_SUCCESS;
	}
	c = calloc(1, sizeof *c);
	if (c) c->username = strdup(username);
	if (!c || !c->username) {
		free(c);
		wipe(copy);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	c->password = copy;
	c->refs = 1;
	*slot = c;
	return MAPISTORE_SUCCESS;
}

enum mapistore_error dav_cred_forget(const char *username)
{
	struct dav_cred	**slot, *c;

	if (!username) return MAPISTORE_ERR_INVALID_PARAMETER;
	slot = find(username);
	c = *slot;
	if (!c || --c->refs > 0) return MAPISTORE_SUCCESS;
	*slot = c->next;
	wipe(c->password);
	free(c->username);
	free(c);
	return MAPISTORE_SUCCESS;
}
