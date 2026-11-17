/*
   OpenChange Storage Abstraction Layer library
   Optional CardDAV contacts backend (M6): SOGo address books for Outlook

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#ifndef	__DAV_BACKEND_H__
#define	__DAV_BACKEND_H__

#include <stdint.h>
#include <stddef.h>

#include "mapiproxy/libmapistore/mapistore.h"

#define DAV_NAMESPACE "dav://"

/* Process-wide settings from the smb.conf section [mapistore]. */
struct dav_settings {
	char		*url_template;	/* dav_url, "%u" is the mailbox user */
	uint8_t		*fp_key;	/* dav_fingerprint_key_file: 32+ random bytes, never logged */
	size_t		fp_key_len;
};

/* NULL when the backend is unconfigured or its configuration is unusable. */
const struct dav_settings *dav_backend_settings(void);
struct dav_settings *dav_settings_load(TALLOC_CTX *, struct loadparm_context *);
void dav_backend_fill(struct mapistore_backend *);

#endif /* ! __DAV_BACKEND_H__ */
