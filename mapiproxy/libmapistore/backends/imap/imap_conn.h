/*
   OpenChange Storage Abstraction Layer library
   Read-only IMAP backend: connection to Dovecot (libetpan)

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

#ifndef __IMAP_CONN_H__
#define __IMAP_CONN_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <talloc.h>

/* Where and how to reach Dovecot (smb.conf mapistore:imap_*). */
struct imap_settings {
	const char	*host;		 /* imap_host, default 127.0.0.1 */
	uint16_t	port;		 /* imap_port, default 143 */
	const char	*master_user;	 /* imap_master_user, default "openchange" */
	char		*master_password; /* read from imap_master_password_file; never logged */
	const char	*tunnel;	 /* imap_tunnel: PREAUTH IMAP on stdio, $USER = mailbox */
};

/* LIST attributes (RFC 3501, RFC 6154) the backend uses. */
#define IMAP_MB_NOSELECT	0x0001
#define IMAP_MB_NONEXISTENT	0x0002
#define IMAP_MB_HASCHILDREN	0x0004
#define IMAP_MB_SENT		0x0010
#define IMAP_MB_DRAFTS		0x0020
#define IMAP_MB_TRASH		0x0040
#define IMAP_MB_JUNK		0x0080
#define IMAP_MB_ALL		0x0100
#define IMAP_MB_ARCHIVE		0x0200

struct imap_mailbox {
	char		*name;		/* as on the wire: modified UTF-7 */
	char		delimiter;	/* 0 when the server has none */
	uint32_t	flags;		/* IMAP_MB_* */
};

struct imap_status {
	uint32_t	messages;
	uint32_t	unseen;
	uint32_t	uidvalidity;
	uint32_t	uidnext;
};

struct imap_conn;
struct loadparm_context;

/* Reads the smb.conf options; fails (NULL) when the password file is missing, empty or group/world readable. */
struct imap_settings *imap_settings_load(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx);

/* Logs in as `username` (master user, or the tunnel's PREAUTH); NULL on any failure. */
struct imap_conn *imap_conn_open(TALLOC_CTX *mem_ctx, const struct imap_settings *settings, const char *username);

int imap_list(struct imap_conn *conn, TALLOC_CTX *mem_ctx, struct imap_mailbox **mailboxes, size_t *count);
int imap_examine(struct imap_conn *conn, const char *name, struct imap_status *status);
int imap_status(struct imap_conn *conn, const char *name, struct imap_status *status);

/* libetpan session of an open connection (for the fetch code). */
struct mailimap *imap_conn_session(struct imap_conn *conn);

#endif /* __IMAP_CONN_H__ */
