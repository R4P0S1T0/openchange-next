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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <libetpan/libetpan.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "imap_conn.h"

extern char **environ;

#define IMAP_TIMEOUT_SECONDS 10

struct imap_conn {
	mailimap	*imap;
	bool		dead;		/* a command hit a stream error: reconnect */
	pid_t		tunnel_pid;
	char		delimiter;	/* hierarchy delimiter, from LIST "" "" */
};

/* Largest password file read; the master password is a random token. */
#define MAX_PASSWORD 1024
/* Tunnel argv words. */
#define MAX_TUNNEL_ARGS 16

static int imap_conn_destructor(struct imap_conn *conn)
{
	if (conn->imap) {
		/* Only a session that got past the greeting has someone to say LOGOUT to. */
		if (conn->imap->imap_stream && conn->imap->imap_state >= MAILIMAP_STATE_AUTHENTICATED) {
			mailimap_logout(conn->imap);
		}
		mailimap_free(conn->imap);
		conn->imap = NULL;
	}
	if (conn->tunnel_pid > 0) {
		waitpid(conn->tunnel_pid, NULL, 0);
	}
	return 0;
}

static bool is_loopback(const char *host);

static char *read_password(TALLOC_CTX *mem_ctx, const char *path)
{
	struct stat	st;
	char		buf[MAX_PASSWORD + 1];
	ssize_t		n;
	int		fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1) {
		OC_DEBUG(0, "IMAP backend: cannot open the master password file %s: %s\n", path, strerror(errno));
		return NULL;
	}
	if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || (st.st_mode & 077)) {
		OC_DEBUG(0, "IMAP backend: %s must be a regular file readable by its owner only (0600)\n", path);
		close(fd);
		return NULL;
	}
	n = read(fd, buf, MAX_PASSWORD + 1);
	close(fd);
	if (n <= 0 || n > MAX_PASSWORD) {
		OC_DEBUG(0, "IMAP backend: %s is empty or too long\n", path);
		return NULL;
	}
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
		n--;
	}
	if (n == 0 || memchr(buf, '\0', n) || memchr(buf, '\n', n)) {
		OC_DEBUG(0, "IMAP backend: %s must hold one password line\n", path);
		return NULL;
	}
	return talloc_strndup(mem_ctx, buf, n);
}

_PUBLIC_ struct imap_settings *imap_settings_load(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	struct imap_settings	*s;
	const char		*password_file;
	int			port;

	s = talloc_zero(mem_ctx, struct imap_settings);
	if (!s || !lp_ctx) {
		talloc_free(s);
		return NULL;
	}
	s->host = talloc_strdup(s, lpcfg_parm_string(lp_ctx, NULL, "mapistore", "imap_host") ?: "127.0.0.1");
	port = lpcfg_parm_int(lp_ctx, NULL, "mapistore", "imap_port", 143);
	s->master_user = talloc_strdup(s, lpcfg_parm_string(lp_ctx, NULL, "mapistore", "imap_master_user") ?: "openchange");
	s->tunnel = lpcfg_parm_string(lp_ctx, NULL, "mapistore", "imap_tunnel");
	if (s->tunnel) {
		s->tunnel = talloc_strdup(s, s->tunnel);
	}
	if (port <= 0 || port > 65535 || !s->host || !s->master_user) {
		talloc_free(s);
		return NULL;
	}
	s->port = port;
	/* mailimap_socket_starttls does not verify the server certificate, so the master password
	   only goes to a loopback Dovecot in M3. */
	if (!s->tunnel && !is_loopback(s->host)) {
		OC_DEBUG(0, "IMAP backend: mapistore:imap_host must be a loopback address\n");
		talloc_free(s);
		return NULL;
	}
	s->max_message_size = lpcfg_parm_ulong(lp_ctx, NULL, "mapistore", "imap_max_message_size", 32 * 1024 * 1024);
	if (!s->tunnel) {
		password_file = lpcfg_parm_string(lp_ctx, NULL, "mapistore", "imap_master_password_file");
		if (!password_file) {
			OC_DEBUG(0, "IMAP backend: set mapistore:imap_master_password_file (or imap_tunnel)\n");
			talloc_free(s);
			return NULL;
		}
		s->master_password = read_password(s, password_file);
		if (!s->master_password) {
			talloc_free(s);
			return NULL;
		}
	}
	return s;
}

static bool is_loopback(const char *host)
{
	struct in_addr	a4;
	struct in6_addr	a6;

	if (strcasecmp(host, "localhost") == 0) {
		return true;
	}
	if (inet_pton(AF_INET, host, &a4) == 1) {
		return (ntohl(a4.s_addr) >> 24) == 127;
	}
	return inet_pton(AF_INET6, host, &a6) == 1 && IN6_IS_ADDR_LOOPBACK(&a6);
}

/* Runs the tunnel command with $USER = username and speaks IMAP over a socketpair; no shell. */
static int open_tunnel(struct imap_conn *conn, const char *tunnel, const char *username)
{
	char		*words[MAX_TUNNEL_ARGS + 1];
	char		**envp;
	char		*copy, *save = NULL, *w, *user_env;
	size_t		n = 0, envc = 0, i, j;
	int		sv[2];
	mailstream	*stream;

	copy = talloc_strdup(conn, tunnel);
	user_env = talloc_asprintf(conn, "USER=%s", username);
	if (!copy || !user_env) {
		return -1;
	}
	for (w = strtok_r(copy, " \t", &save); w && n < MAX_TUNNEL_ARGS; w = strtok_r(NULL, " \t", &save)) {
		words[n++] = w;
	}
	words[n] = NULL;
	if (n == 0 || w) {
		return -1;
	}
	while (environ[envc]) {
		envc++;
	}
	envp = talloc_array(conn, char *, envc + 2);
	if (!envp) {
		return -1;
	}
	for (i = 0, j = 0; i < envc; i++) {
		if (strncmp(environ[i], "USER=", 5) != 0) {
			envp[j++] = environ[i];
		}
	}
	envp[j++] = user_env;
	envp[j] = NULL;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == -1) {
		return -1;
	}
	conn->tunnel_pid = fork();
	if (conn->tunnel_pid == -1) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}
	if (conn->tunnel_pid == 0) {
		/* Child: only async-signal-safe calls until exec. */
		if (dup2(sv[1], 0) == -1 || dup2(sv[1], 1) == -1) {
			_exit(127);
		}
		execve(words[0], words, envp);
		_exit(127);
	}
	close(sv[1]);
	stream = mailstream_socket_open(sv[0]);
	if (!stream) {
		close(sv[0]);
		return -1;
	}
	return mailimap_connect(conn->imap, stream) == MAILIMAP_NO_ERROR_AUTHENTICATED ? 0 : -1;
}

static int open_tcp(struct imap_conn *conn, const struct imap_settings *s, const char *username)
{
	char	*login;
	int	r;

	r = mailimap_socket_connect(conn->imap, s->host, s->port);
	if (r != MAILIMAP_NO_ERROR_NON_AUTHENTICATED) {
		OC_DEBUG(1, "IMAP backend: connect to %s:%u failed (%d)\n", s->host, s->port, r);
		return -1;
	}
	/* The master password never crosses the network in clear text. */
	if (!is_loopback(s->host) && mailimap_socket_starttls(conn->imap) != MAILIMAP_NO_ERROR) {
		OC_DEBUG(1, "IMAP backend: STARTTLS to %s failed; refusing a cleartext LOGIN\n", s->host);
		return -1;
	}
	login = talloc_asprintf(conn, "%s*%s", username, s->master_user);
	if (!login) {
		return -1;
	}
	r = mailimap_login(conn->imap, login, s->master_password);
	talloc_free(login);
	if (r != MAILIMAP_NO_ERROR) {
		OC_DEBUG(1, "IMAP backend: master LOGIN refused (%d)\n", r);
		return -1;
	}
	return 0;
}

_PUBLIC_ struct imap_conn *imap_conn_open(TALLOC_CTX *mem_ctx, const struct imap_settings *settings, const char *username)
{
	struct imap_conn	*conn;
	int			r;

	if (!settings || !username || !username[0] || strpbrk(username, "\r\n\"* ")) {
		return NULL;
	}
	conn = talloc_zero(mem_ctx, struct imap_conn);
	if (!conn) {
		return NULL;
	}
	conn->imap = mailimap_new(0, NULL);
	if (!conn->imap) {
		talloc_free(conn);
		return NULL;
	}
	talloc_set_destructor(conn, imap_conn_destructor);
	/* One worker serves every user: a server that stops answering must not block it for minutes. */
	mailimap_set_timeout(conn->imap, IMAP_TIMEOUT_SECONDS);
	r = settings->tunnel ? open_tunnel(conn, settings->tunnel, username) : open_tcp(conn, settings, username);
	if (r != 0) {
		talloc_free(conn);
		return NULL;
	}
	{
		clist *root = NULL;

		/* LIST "" "" names the hierarchy delimiter (RFC 3501 6.3.8); '/' when the server has none. */
		conn->delimiter = '/';
		if (mailimap_list(conn->imap, "", "", &root) == MAILIMAP_NO_ERROR && root && clist_begin(root)) {
			const struct mailimap_mailbox_list *mb = clist_content(clist_begin(root));

			if (mb && mb->mb_delimiter) {
				conn->delimiter = mb->mb_delimiter;
			}
		}
		if (root) {
			mailimap_list_result_free(root);
		}
	}
	return conn;
}

_PUBLIC_ char imap_conn_delimiter(struct imap_conn *conn)
{
	return conn ? conn->delimiter : '/';
}

_PUBLIC_ bool imap_conn_alive(struct imap_conn *conn)
{
	return conn && !conn->dead && conn->imap && conn->imap->imap_stream;
}

_PUBLIC_ int imap_conn_check(struct imap_conn *conn, int r)
{
	if (conn && (r == MAILIMAP_ERROR_STREAM || r == MAILIMAP_ERROR_CONNECTION_REFUSED)) {
		conn->dead = true;
	}
	return r;
}

_PUBLIC_ pid_t imap_conn_pid(struct imap_conn *conn)
{
	return conn ? conn->tunnel_pid : -1;
}

_PUBLIC_ struct mailimap *imap_conn_session(struct imap_conn *conn)
{
	return conn ? conn->imap : NULL;
}

static uint32_t list_flags(const struct mailimap_mbx_list_flags *f)
{
	static const struct { const char *name; uint32_t flag; } known[] = {
		{ "Noselect", IMAP_MB_NOSELECT }, { "NonExistent", IMAP_MB_NONEXISTENT },
		{ "HasChildren", IMAP_MB_HASCHILDREN }, { "Sent", IMAP_MB_SENT },
		{ "Drafts", IMAP_MB_DRAFTS }, { "Trash", IMAP_MB_TRASH }, { "Junk", IMAP_MB_JUNK },
		{ "All", IMAP_MB_ALL }, { "Archive", IMAP_MB_ARCHIVE },
	};
	clistiter	*it;
	uint32_t	flags = 0;
	size_t		i;

	if (!f) {
		return 0;
	}
	if (f->mbf_type == MAILIMAP_MBX_LIST_FLAGS_SFLAG && f->mbf_sflag == MAILIMAP_MBX_LIST_SFLAG_NOSELECT) {
		flags |= IMAP_MB_NOSELECT;
	}
	for (it = f->mbf_oflags ? clist_begin(f->mbf_oflags) : NULL; it; it = clist_next(it)) {
		const struct mailimap_mbx_list_oflag *o = clist_content(it);
		const char *name;

		if (!o || o->of_type != MAILIMAP_MBX_LIST_OFLAG_FLAG_EXT || !o->of_flag_ext) {
			continue;
		}
		name = o->of_flag_ext[0] == '\\' ? o->of_flag_ext + 1 : o->of_flag_ext;
		for (i = 0; i < sizeof known / sizeof known[0]; i++) {
			if (strcasecmp(name, known[i].name) == 0) {
				flags |= known[i].flag;
			}
		}
	}
	return flags;
}

_PUBLIC_ int imap_list(struct imap_conn *conn, TALLOC_CTX *mem_ctx, struct imap_mailbox **mailboxes, size_t *count)
{
	clist			*result = NULL;
	clistiter		*it;
	struct imap_mailbox	*out;
	size_t			n = 0;

	if (!conn || !mailboxes || !count) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (imap_conn_check(conn, mailimap_list(conn->imap, "", "*", &result)) != MAILIMAP_NO_ERROR) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	out = talloc_array(mem_ctx, struct imap_mailbox, clist_count(result) ? clist_count(result) : 1);
	if (!out) {
		mailimap_list_result_free(result);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	for (it = clist_begin(result); it; it = clist_next(it)) {
		const struct mailimap_mailbox_list *mb = clist_content(it);

		if (!mb || !mb->mb_name) {
			continue;
		}
		out[n].name = talloc_strdup(out, mb->mb_name);
		if (!out[n].name) {
			talloc_free(out);
			mailimap_list_result_free(result);
			return MAPISTORE_ERR_NO_MEMORY;
		}
		out[n].delimiter = mb->mb_delimiter;
		out[n].flags = list_flags(mb->mb_flag);
		n++;
	}
	mailimap_list_result_free(result);
	*mailboxes = out;
	*count = n;
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ int imap_examine(struct imap_conn *conn, const char *name, struct imap_status *status)
{
	struct mailimap_selection_info *sel;

	if (!conn || !name || !status) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (imap_conn_check(conn, mailimap_examine(conn->imap, name)) != MAILIMAP_NO_ERROR) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	sel = conn->imap->imap_selection_info;
	if (!sel) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	memset(status, 0, sizeof *status);
	status->messages = sel->sel_exists;
	status->uidvalidity = sel->sel_uidvalidity;
	status->uidnext = sel->sel_uidnext;
	status->unseen = sel->sel_unseen;
	return MAPISTORE_SUCCESS;
}

_PUBLIC_ int imap_status(struct imap_conn *conn, const char *name, struct imap_status *status)
{
	struct mailimap_status_att_list		*atts;
	struct mailimap_mailbox_data_status	*result = NULL;
	clistiter				*it;
	int					r;

	if (!conn || !name || !status) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	atts = mailimap_status_att_list_new_empty();
	if (!atts) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	if (mailimap_status_att_list_add(atts, MAILIMAP_STATUS_ATT_MESSAGES) != MAILIMAP_NO_ERROR ||
	    mailimap_status_att_list_add(atts, MAILIMAP_STATUS_ATT_UNSEEN) != MAILIMAP_NO_ERROR ||
	    mailimap_status_att_list_add(atts, MAILIMAP_STATUS_ATT_UIDVALIDITY) != MAILIMAP_NO_ERROR ||
	    mailimap_status_att_list_add(atts, MAILIMAP_STATUS_ATT_UIDNEXT) != MAILIMAP_NO_ERROR) {
		mailimap_status_att_list_free(atts);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	/* STATUS of the mailbox this session has open reports its view of it: NOOP brings the view up to date. */
	if (conn->imap->imap_state == MAILIMAP_STATE_SELECTED) {
		imap_conn_check(conn, mailimap_noop(conn->imap));
	}
	r = imap_conn_check(conn, mailimap_status(conn->imap, name, atts, &result));
	mailimap_status_att_list_free(atts);
	if (r != MAILIMAP_NO_ERROR || !result) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	memset(status, 0, sizeof *status);
	for (it = clist_begin(result->st_info_list); it; it = clist_next(it)) {
		const struct mailimap_status_info *info = clist_content(it);

		switch (info->st_att) {
		case MAILIMAP_STATUS_ATT_MESSAGES:	status->messages = info->st_value; break;
		case MAILIMAP_STATUS_ATT_UNSEEN:	status->unseen = info->st_value; break;
		case MAILIMAP_STATUS_ATT_UIDVALIDITY:	status->uidvalidity = info->st_value; break;
		case MAILIMAP_STATUS_ATT_UIDNEXT:	status->uidnext = info->st_value; break;
		default: break;
		}
	}
	mailimap_mailbox_data_status_free(result);
	return MAPISTORE_SUCCESS;
}
