/*
   OpenChange Storage Abstraction Layer library
   Read-only IMAP backend: shared declarations

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

#ifndef __IMAP_BACKEND_H__
#define __IMAP_BACKEND_H__

#include "imap_conn.h"

#define IMAP_NAMESPACE "imap://"

#include "mapiproxy/libmapistore/mapistore_errors.h"

struct mapistore_backend;

/* Entry point dlopen()ed by mapistore_backend_init. */
enum mapistore_error mapistore_init_backend(void);

/* Settings read by init(); NULL when the backend is not configured. */
const struct imap_settings *imap_backend_settings(void);

/* Sets the context, folder, table, message and properties operations. */
void imap_backend_fill(struct mapistore_backend *backend);

#endif /* __IMAP_BACKEND_H__ */
