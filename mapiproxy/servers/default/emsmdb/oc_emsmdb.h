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
/* password is the one the daemon verified; mapistore keeps a copy in memory until disconnect. */
uint32_t oc_emsmdb_connect(const char *username, const char *password, const char *user_dn,
			   uint32_t flags, uint32_t code_page,
			   uint32_t lcid_sort, uint32_t lcid_string,
			   oc_emsmdb_session **session,
			   const char **display_name, const char **dn_prefix);
uint32_t oc_emsmdb_execute(oc_emsmdb_session *session, uint32_t flags,
			   const uint8_t *rop_in, size_t rop_in_len,
			   uint8_t *rop_out, size_t rop_out_cap,
			   size_t *rop_out_len);
void	 oc_emsmdb_disconnect(oc_emsmdb_session *session);

/* M5: an IMAP mailbox changed (kind 0 modified, 1 added, 2 deleted). mailbox is modified UTF-7 as IMAP
   sends it, delimiter the server's hierarchy delimiter ('\0' when flat). *pending is set to 1 when the
   session has notifications queued for its next Execute; left as is when the mailbox is unknown. */
uint32_t oc_emsmdb_folder_changed(oc_emsmdb_session *session, const char *mailbox, char delimiter,
				  uint32_t kind, uint32_t *pending);
/* M6: asks the mapistore backends what other clients changed since the session's previous call (every 60 s
   from the daemon) and queues the rows Outlook syncs on. *pending is 1 when this call queued any. */
uint32_t oc_emsmdb_poll_changes(oc_emsmdb_session *session, uint32_t *pending);
/* Where the IMAP backend reaches Dovecot (smb.conf mapistore:imap_*), for a watcher of the same mailboxes.
   Strings are malloc()ed, freed with oc_emsmdb_free; MAPI_E_NOT_FOUND when not configured. */
uint32_t oc_emsmdb_imap_watch_params(char **host, uint16_t *port, char **master_user, char **master_password);
void	 oc_emsmdb_free(void *p);
/* The session's mailbox owner; NULL for no session. */
const char *oc_emsmdb_username(oc_emsmdb_session *session);

#endif	/* __OC_EMSMDB_H */
