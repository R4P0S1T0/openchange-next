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

/**
   \file oc_emsmdb.c

   \brief The oc_emsmdb.h API over the EMSMDB provider, without DCE/RPC.
   All functions are called from one thread (the daemon's C worker).
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "mapiproxy/dcesrv_mapiproxy.h"
#include "dcesrv_exchange_emsmdb.h"
#include "emsmdbp_identity.h"
#include "oc_emsmdb.h"

struct oc_emsmdb_session {
	struct emsmdbp_context *ctx;
};

/* Process-wide state from oc_emsmdb_init; sessions are its talloc children. */
static TALLOC_CTX *oc_root;
static struct loadparm_context *oc_lp_ctx;
static void *oc_db_ctx;

/* Only the first successful call configures the process; later calls change nothing. */
uint32_t oc_emsmdb_init(const char *smb_conf_path)
{
	TALLOC_CTX *root;

	if (oc_root != NULL) return MAPI_E_SUCCESS;
	if (smb_conf_path == NULL || smb_conf_path[0] == '\0') return MAPI_E_INVALID_PARAMETER;
	/* The C code logs with printf too; on a pipe (journald) stdout is block-buffered and lines arrive late and cut. */
	setvbuf(stdout, NULL, _IOLBF, 0);
	root = talloc_named_const(NULL, 0, "oc_emsmdb");
	if (root == NULL) return MAPI_E_NOT_ENOUGH_RESOURCES;
	oc_lp_ctx = loadparm_init(root);
	if (oc_lp_ctx == NULL || !lpcfg_load(oc_lp_ctx, smb_conf_path)) {
		talloc_free(root);
		return MAPI_E_CALL_FAILED;
	}
	oc_db_ctx = emsmdbp_openchangedb_init(oc_lp_ctx);
	if (oc_db_ctx == NULL) {
		talloc_free(root);
		return MAPI_E_NOT_INITIALIZED;
	}
	oc_root = root;
	return MAPI_E_SUCCESS;
}

uint32_t oc_emsmdb_connect(const char *username, const char *user_dn,
			   uint32_t flags, uint32_t code_page,
			   uint32_t lcid_sort, uint32_t lcid_string,
			   oc_emsmdb_session **session,
			   const char **display_name, const char **dn_prefix)
{
	struct emsmdbp_context *ctx;
	struct ldb_message *msg;
	oc_emsmdb_session *s = NULL;
	uint32_t status;

	if (session == NULL || display_name == NULL || dn_prefix == NULL) return MAPI_E_INVALID_PARAMETER;
	*session = NULL;
	*display_name = *dn_prefix = "";
	if (oc_root == NULL) return MAPI_E_NOT_INITIALIZED;
	if (username == NULL || username[0] == '\0' || user_dn == NULL || user_dn[0] == '\0') return MAPI_E_NO_ACCESS;
	ctx = emsmdbp_init(oc_lp_ctx, username, oc_db_ctx);
	if (ctx == NULL) return MAPI_E_LOGON_FAILED;
	/* username is Dovecot's canonical user; the directory binds it to exactly one enabled LegacyDN. */
	status = MAPI_E_LOGON_FAILED;
	if (!emsmdbp_lookup_account(ctx, username, user_dn, &msg)) goto failure;
	status = MAPI_E_NOT_ENOUGH_RESOURCES;
	ctx->username = talloc_strdup(ctx, username);
	if (ctx->username == NULL) goto failure;
	s = talloc_zero(oc_root, oc_emsmdb_session);
	if (s == NULL) goto failure;
	status = emsmdbp_connect_identity(ctx, msg, user_dn, lcid_string, s, display_name, dn_prefix);
	if (status != MAPI_E_SUCCESS) goto failure;
	if (!emsmdbp_set_session_uuid(ctx, GUID_random())) goto failure;
	s->ctx = talloc_steal(s, ctx);
	*session = s;
	return MAPI_E_SUCCESS;
failure:
	talloc_free(s);
	talloc_free(ctx);
	*display_name = *dn_prefix = "";
	return status;
}

uint32_t oc_emsmdb_execute(oc_emsmdb_session *session, uint32_t flags,
			   const uint8_t *rop_in, size_t rop_in_len,
			   uint8_t *rop_out, size_t rop_out_cap,
			   size_t *rop_out_len)
{
	TALLOC_CTX *transaction;
	DATA_BLOB input, output;
	enum MAPISTATUS status;

	if (rop_out_len != NULL) *rop_out_len = 0;
	if (session == NULL || rop_out_len == NULL || rop_in == NULL || rop_out == NULL ||
	    rop_in_len < 8 || rop_in_len > UINT16_MAX + 8U) return ecRpcFailed;
	transaction = talloc_new(session);
	if (transaction == NULL) return MAPI_E_NOT_ENOUGH_RESOURCES;
	/* rop_in is borrowed for this call only; nothing the ROPs keep may point into it. */
	input = data_blob_talloc(transaction, rop_in, rop_in_len);
	status = MAPI_E_NOT_ENOUGH_RESOURCES;
	if (input.data == NULL) goto done;
	status = emsmdb_execute_buffer(transaction, session->ctx, &input, flags,
				       rop_out_cap > 0x40000 ? 0x40000 : (uint32_t)rop_out_cap, &output);
	if (status == MAPI_E_SUCCESS && output.length > rop_out_cap) status = ecBufferTooSmall;
	if (status != MAPI_E_SUCCESS) goto done;
	memcpy(rop_out, output.data, output.length);
	*rop_out_len = output.length;
done:
	talloc_free(transaction);
	return status;
}

void oc_emsmdb_disconnect(oc_emsmdb_session *session)
{
	talloc_free(session);
}

uint32_t oc_emsmdb_folder_changed(oc_emsmdb_session *session, const char *mailbox, char delimiter,
				  uint32_t kind, uint32_t *pending)
{
	if (session == NULL || mailbox == NULL || pending == NULL || kind > EMSMDBP_FOLDER_DELETED) {
		return MAPI_E_INVALID_PARAMETER;
	}
	if (emsmdbp_notify_mailbox_changed(session->ctx, mailbox, delimiter, (enum emsmdbp_folder_change) kind) == 0) {
		return MAPI_E_SUCCESS;	/* not a folder Outlook knows (or will know) */
	}
	*pending = emsmdbp_notify_pending(session->ctx) ? 1 : 0;
	return MAPI_E_SUCCESS;
}

/* The IMAP backend's rules (imap_conn.c, in the dlopen()ed module): only a loopback Dovecot gets the
   master password, read from a 0600 regular file holding one line. */
static bool oc_emsmdb_loopback(const char *host)
{
	struct in_addr	a4;
	struct in6_addr	a6;

	if (strcasecmp(host, "localhost") == 0) return true;
	if (inet_pton(AF_INET, host, &a4) == 1) return (ntohl(a4.s_addr) >> 24) == 127;
	return inet_pton(AF_INET6, host, &a6) == 1 && IN6_IS_ADDR_LOOPBACK(&a6);
}

static char *oc_emsmdb_read_password(const char *path)
{
	struct stat	st;
	char		buf[1025], *line;
	ssize_t		n;
	int		fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1) return NULL;
	if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || (st.st_mode & 077)) {
		close(fd);
		return NULL;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) return NULL;
	buf[n] = '\0';
	line = strndup(buf, strcspn(buf, "\r\n"));
	memset(buf, 0, sizeof(buf));
	if (line && !line[0]) {
		free(line);
		line = NULL;
	}
	return line;
}

uint32_t oc_emsmdb_imap_watch_params(char **host, uint16_t *port, char **master_user, char **master_password)
{
	const char	*h, *u, *file;
	int		p;

	if (host == NULL || port == NULL || master_user == NULL || master_password == NULL) {
		return MAPI_E_INVALID_PARAMETER;
	}
	*host = *master_user = *master_password = NULL;
	if (oc_lp_ctx == NULL) return MAPI_E_NOT_INITIALIZED;
	h = lpcfg_parm_string(oc_lp_ctx, NULL, "mapistore", "imap_host") ?: "127.0.0.1";
	u = lpcfg_parm_string(oc_lp_ctx, NULL, "mapistore", "imap_master_user") ?: "openchange";
	p = lpcfg_parm_int(oc_lp_ctx, NULL, "mapistore", "imap_port", 143);
	file = lpcfg_parm_string(oc_lp_ctx, NULL, "mapistore", "imap_master_password_file");
	if (file == NULL || p <= 0 || p > 65535 || !oc_emsmdb_loopback(h)) return MAPI_E_NOT_FOUND;
	*master_password = oc_emsmdb_read_password(file);
	*host = strdup(h);
	*master_user = strdup(u);
	if (*master_password == NULL || *host == NULL || *master_user == NULL) {
		oc_emsmdb_free(*master_password);
		free(*host);
		free(*master_user);
		*host = *master_user = *master_password = NULL;
		return MAPI_E_NOT_FOUND;
	}
	*port = (uint16_t) p;
	return MAPI_E_SUCCESS;
}

void oc_emsmdb_free(void *p)
{
	if (p) {
		memset(p, 0, strlen(p));	/* every string handed out is NUL-terminated; passwords among them */
		free(p);
	}
}

const char *oc_emsmdb_username(oc_emsmdb_session *session)
{
	return (session && session->ctx) ? session->ctx->username : NULL;
}
