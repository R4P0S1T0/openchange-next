/*
   OpenChange Storage Abstraction Layer library
   Read-only IMAP backend: message tables and messages

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

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "imap_backend.h"

/* Message tables and messages arrive in Task 3/4 of the M3 plan. */
_PUBLIC_ enum mapistore_error imap_message_table_load(struct imap_table *t)
{
	t->row_count = 0;
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ enum mapistore_error imap_message_row(struct imap_table *t, TALLOC_CTX *mem_ctx, uint32_t row,
					       struct mapistore_property_data *data)
{
	return MAPISTORE_ERR_NOT_FOUND;
}

_PUBLIC_ enum mapistore_error imap_folder_open_message(void *folder, TALLOC_CTX *mem_ctx, uint64_t mid, bool read_write,
						       void **message)
{
	return MAPISTORE_ERR_NOT_FOUND;
}

_PUBLIC_ enum mapistore_error imap_message_properties(void *message, TALLOC_CTX *mem_ctx, uint16_t count,
						      enum MAPITAGS *tags, struct mapistore_property_data *data)
{
	return MAPISTORE_ERR_NOT_FOUND;
}

_PUBLIC_ void imap_message_fill(struct mapistore_backend *backend)
{
	(void) backend;
}
