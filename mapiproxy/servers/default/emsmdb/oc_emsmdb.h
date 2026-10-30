/*
   OpenChange EMSMDB service API for the MAPI/HTTP daemon

   OpenChange Project

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

/* Mirrored by hand in mapihttpd/src/ffi.rs: change both in one commit.
 * Returns are MAPI status codes; C owns every pointer it returns. */

#ifndef	__OC_EMSMDB_H
#define	__OC_EMSMDB_H

#include <stddef.h>
#include <stdint.h>

typedef struct oc_emsmdb_session oc_emsmdb_session;	/* opaque */

uint32_t oc_emsmdb_init(const char *smb_conf_path);
uint32_t oc_emsmdb_connect(const char *username, const char *user_dn,
			   uint32_t flags, uint32_t code_page,
			   uint32_t lcid_sort, uint32_t lcid_string,
			   oc_emsmdb_session **session,
			   const char **display_name, const char **dn_prefix);
uint32_t oc_emsmdb_execute(oc_emsmdb_session *session, uint32_t flags,
			   const uint8_t *rop_in, size_t rop_in_len,
			   uint8_t *rop_out, size_t rop_out_cap,
			   size_t *rop_out_len);
void	 oc_emsmdb_disconnect(oc_emsmdb_session *session);

#endif	/* __OC_EMSMDB_H */
