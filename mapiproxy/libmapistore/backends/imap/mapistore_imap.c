/*
   OpenChange Storage Abstraction Layer library
   Read-only IMAP backend (M3): Dovecot folders and messages for Outlook

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

#include <string.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "imap_backend.h"

/* Process-wide settings, read once by init() from smb.conf. */
static struct imap_settings *settings;

_PUBLIC_ const struct imap_settings *imap_backend_settings(void)
{
	return settings;
}

static enum mapistore_error imap_init(void)
{
	if (settings) {
		return MAPISTORE_SUCCESS;
	}
	settings = imap_settings_load(NULL, mapistore_backend_lp_ctx());
	/* A failed init would fail every logon (mapistore_backend_run_init): without settings the
	   backend stays loaded and offers no folders. */
	if (!settings) {
		OC_DEBUG(0, "IMAP backend: not configured; IMAP folders are not offered\n");
	}
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error mapistore_init_backend(void)
{
	struct mapistore_backend	backend;
	enum mapistore_error		retval;

	retval = mapistore_backend_init_defaults(&backend);
	if (retval != MAPISTORE_SUCCESS) {
		return retval;
	}
	backend.backend.name = "imap";
	backend.backend.description = "Read-only IMAP (Dovecot) mail folders";
	backend.backend.namespace = IMAP_NAMESPACE;
	backend.backend.init = imap_init;
	imap_backend_fill(&backend);
	return mapistore_backend_register(&backend);
}
