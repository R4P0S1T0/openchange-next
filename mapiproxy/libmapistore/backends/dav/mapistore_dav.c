/*
   OpenChange Storage Abstraction Layer library
   Optional CardDAV contacts backend (M6): SOGo address books for Outlook

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "dav_backend.h"

#define DAV_MIN_KEY	32
#define DAV_MAX_KEY	4096

static struct dav_settings *settings;

const struct dav_settings *dav_backend_settings(void)
{
	return settings;
}

static bool read_key(TALLOC_CTX *mem_ctx, const char *path, struct dav_settings *s)
{
	struct stat	st;
	uint8_t		buf[DAV_MAX_KEY + 1];
	ssize_t		n;
	int		fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1) {
		OC_DEBUG(0, "DAV backend: cannot open the fingerprint key file %s: %s\n", path, strerror(errno));
		return false;
	}
	if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || (st.st_mode & 077)) {
		OC_DEBUG(0, "DAV backend: %s must be a regular file readable by its owner only (0600)\n", path);
		close(fd);
		return false;
	}
	n = read(fd, buf, sizeof buf);
	close(fd);
	if (n < DAV_MIN_KEY || n > DAV_MAX_KEY) {
		OC_DEBUG(0, "DAV backend: %s must hold %d to %d bytes\n", path, DAV_MIN_KEY, DAV_MAX_KEY);
		return false;
	}
	s->fp_key = talloc_memdup(s, buf, n);
	s->fp_key_len = n;
	memset(buf, 0, sizeof buf);
	return s->fp_key != NULL;
}

struct dav_settings *dav_settings_load(TALLOC_CTX *mem_ctx, struct loadparm_context *lp)
{
	struct dav_settings	*s;
	const char		*url, *key_file;

	url = lp ? lpcfg_parm_string(lp, NULL, "mapistore", "dav_url") : NULL;
	if (!url) {
		return NULL;
	}
	key_file = lpcfg_parm_string(lp, NULL, "mapistore", "dav_fingerprint_key_file");
	if (!key_file) {
		OC_DEBUG(0, "DAV backend: set mapistore:dav_fingerprint_key_file\n");
		return NULL;
	}
	s = talloc_zero(mem_ctx, struct dav_settings);
	if (!s) {
		return NULL;
	}
	s->url_template = talloc_strdup(s, url);
	if (!s->url_template || !read_key(mem_ctx, key_file, s)) {
		talloc_free(s);
		return NULL;
	}
	return s;
}

static enum mapistore_error dav_init(void)
{
	if (!settings) {
		settings = dav_settings_load(NULL, mapistore_backend_lp_ctx());
		if (!settings) {
			OC_DEBUG(0, "DAV backend: not configured or configuration unusable; contacts are not offered\n");
		}
	}
	/* A failed init would fail every logon: the backend stays loaded and inert. */
	return MAPISTORE_SUCCESS;
}

/* An empty list is a success: a failure would abort the list of every other backend. */
static enum mapistore_error dav_list_contexts(const char *user, struct indexing_context *ictx,
					      TALLOC_CTX *mem_ctx, struct mapistore_contexts_list **list)
{
	*list = NULL;
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error dav_create_context(TALLOC_CTX *mem_ctx, struct mapistore_connection_info *conn,
					       struct indexing_context *ictx, const char *uri, void **ctx)
{
	return MAPISTORE_ERR_NOT_AVAILABLE;
}

void dav_backend_fill(struct mapistore_backend *backend)
{
	backend->backend.init = dav_init;
	backend->backend.list_contexts = dav_list_contexts;
	backend->backend.create_context = dav_create_context;
	backend->backend.set_credentials = dav_cred_set;
	backend->backend.forget_credentials = dav_cred_forget;
}

_PUBLIC_ enum mapistore_error mapistore_init_backend(void)
{
	struct mapistore_backend	backend;
	enum mapistore_error		retval;

	memset(&backend, 0, sizeof backend);
	retval = mapistore_backend_init_defaults(&backend);
	if (retval != MAPISTORE_SUCCESS) {
		return retval;
	}
	backend.backend.name = "dav";
	backend.backend.description = "CardDAV contacts (SOGo)";
	backend.backend.namespace = DAV_NAMESPACE;
	dav_backend_fill(&backend);
	return mapistore_backend_register(&backend);
}
