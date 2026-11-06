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
#include <sys/types.h>
#include <talloc.h>

/* Where and how to reach Dovecot (smb.conf mapistore:imap_*). */
struct imap_settings {
	const char	*host;		 /* imap_host, default 127.0.0.1 */
	uint16_t	port;		 /* imap_port, default 143 */
	const char	*master_user;	 /* imap_master_user, default "openchange" */
	char		*master_password; /* read from imap_master_password_file; never logged */
	const char	*tunnel;	 /* imap_tunnel: PREAUTH IMAP on stdio, $USER = mailbox */
	uint32_t	max_message_size; /* imap_max_message_size: bodies larger than this are not fetched */
	const char	*smtp_host;	 /* smtp_host, default 127.0.0.1 (loopback only) */
	uint16_t	smtp_port;	 /* smtp_port, default 587 */
	const char	*smtp_tunnel;	 /* tests: SMTP without TLS on stdio, $USER = sender */
	const char	*expunged_mailbox; /* imap_expunged_mailbox: Dovecot's lazy_expunge mailbox, or NULL */
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

char imap_conn_delimiter(struct imap_conn *conn);
/* False once the server or the stream has gone away. */
bool imap_conn_alive(struct imap_conn *conn);
/* Marks the connection dead when the server hung up while it was idle. */
void imap_conn_probe(struct imap_conn *conn);
/* Passes a libetpan result through, marking the connection dead on a stream error. */
int imap_conn_check(struct imap_conn *conn, int r);
/* The tunnel child, or -1 (tests). */
pid_t imap_conn_pid(struct imap_conn *conn);

/* Runs `tunnel` (argv words, no shell) with $USER = username on a socketpair; our end, or -1. */
int imap_tunnel_spawn(TALLOC_CTX *mem_ctx, const char *tunnel, const char *username, pid_t *pid);

/* Submission (imap_submit.c): 0 sent; -1 the server refused the sender, a recipient, the size or
   the data (*smtp_code holds its reply); -2 connect, TLS or AUTH failed. Nothing is sent unless
   every recipient was accepted. */
int imap_smtp_send(const struct imap_settings *s, const char *username, const char *from, const char **rcpts,
		   uint32_t count, const char *data, size_t len, int *smtp_code);

/* libetpan session of an open connection (for the fetch code). */
struct mailimap *imap_conn_session(struct imap_conn *conn);

/* Writes (imap_write.c): 0 on the server's tagged OK, -1 otherwise. Mailbox names are modified
   UTF-7, as on the wire. Calls that act on messages SELECT the mailbox read-write first. */
#define IMAP_FLAG_SEEN		0x01
#define IMAP_FLAG_FLAGGED	0x02
#define IMAP_FLAG_ANSWERED	0x04
#define IMAP_FLAG_DELETED	0x08
#define IMAP_FLAG_FORWARDED	0x10	/* $Forwarded */
#define IMAP_FLAG_DRAFT		0x20

/* UID MOVE (or COPY); dest_uids[i] is the new UID of uids[i] (COPYUID). Needs UIDPLUS. */
int imap_uid_move(struct imap_conn *conn, const char *from, const uint32_t *uids, uint32_t count,
		  const char *to, bool copy, uint32_t *dest_uidvalidity, uint32_t *dest_uids);
/* UID of a message of `mailbox` with this Message-ID header and a subject containing `subject` (the
   newest one when `newest`), or 0 (none, or the search failed). Message-IDs alone repeat (broken clients, spam). */
uint32_t imap_uid_by_message_id(struct imap_conn *conn, const char *mailbox, const char *message_id, const char *subject,
				bool newest);
int imap_uid_set_flags(struct imap_conn *conn, const char *mailbox, uint32_t uid, uint32_t add, uint32_t remove);
/* \Deleted + UID EXPUNGE of exactly these UIDs; refused without UIDPLUS. */
int imap_uid_expunge(struct imap_conn *conn, const char *mailbox, const uint32_t *uids, uint32_t count);
int imap_append(struct imap_conn *conn, const char *mailbox, const char *data, size_t len, uint32_t flags,
		uint32_t *uidvalidity, uint32_t *uid);
int imap_create_mailbox(struct imap_conn *conn, const char *name, bool subscribe);
int imap_rename_mailbox(struct imap_conn *conn, const char *from, const char *to);
int imap_delete_mailbox(struct imap_conn *conn, const char *name);

#endif /* __IMAP_CONN_H__ */
