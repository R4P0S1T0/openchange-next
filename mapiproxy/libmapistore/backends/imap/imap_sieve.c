/*
   OpenChange Storage Abstraction Layer library
   IMAP backend: ManageSieve (RFC 5804) client for the user's "outlook" script

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
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libetpan/libetpan.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "libmapi/libmapi_private.h"
#include "imap_backend.h"

#define SIEVE_TIMEOUT_SECONDS	10
#define SIEVE_SCRIPT_NAME	"outlook"
/* Dovecot's default sieve_max_script_size is 1M; anything bigger is not ours. */
#define SIEVE_MAX_LITERAL	(4 * 1024 * 1024)

struct sieve_session {
	mailstream	*stream;
	MMAPString	*line;
	pid_t		pid;
	bool		dead;	/* the server hung up or spoke garbage: no LOGOUT */
};

enum sieve_status { SIEVE_OK, SIEVE_NO, SIEVE_BAD };

static int tcp_connect(const char *host, uint16_t port)
{
	struct addrinfo	hints, *res = NULL, *ai;
	struct timeval	tv = { SIEVE_TIMEOUT_SECONDS, 0 };
	char		service[8];
	int		fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	snprintf(service, sizeof(service), "%u", port);
	if (getaddrinfo(host, service, &hints, &res) != 0) {
		return -1;
	}
	for (ai = res; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd == -1) {
			continue;
		}
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
			break;
		}
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

/* A failed write means the peer is gone: libetpan would wait on the closed socket forever, so no read follows. */
static int send_str(struct sieve_session *ss, const char *text, size_t len)
{
	if (mailstream_write(ss->stream, text, len) == (ssize_t)len) {
		return 0;
	}
	ss->dead = true;
	return -1;
}

/* Reads exactly n bytes of a literal into a new talloc string. */
static char *read_literal(struct sieve_session *ss, TALLOC_CTX *mem_ctx, size_t n)
{
	char	*buf;
	size_t	got = 0;
	ssize_t	r;

	if (n > SIEVE_MAX_LITERAL) {
		return NULL;
	}
	buf = talloc_array(mem_ctx, char, n + 1);
	while (buf && got < n) {
		r = mailstream_read(ss->stream, buf + got, n - got);
		if (r <= 0) {
			talloc_free(buf);
			return NULL;
		}
		got += r;
	}
	if (buf) {
		buf[n] = '\0';
	}
	return buf;
}

/* `{n}` or `{n+}` at the end of a line: the literal's size, or -1. */
static long literal_size(const char *line)
{
	const char	*open = strrchr(line, '{');
	char		*end = NULL;
	long		n;

	if (!open) {
		return -1;
	}
	errno = 0;
	n = strtol(open + 1, &end, 10);
	if (errno || end == open + 1 || n < 0) {
		return -1;
	}
	if (end[0] == '+') {
		end++;
	}
	return (end[0] == '}' && end[1] == '\0') ? n : -1;
}

/* Reads lines up to the final OK/NO/BYE. A GETSCRIPT literal goes to *data (when asked for);
   the text of a NO is logged. */
static enum sieve_status read_response(struct sieve_session *ss, TALLOC_CTX *mem_ctx, char **data, const char *what)
{
	const char	*l;
	char		*text;
	bool		missing, bye;
	long		n;

	if (data) {
		*data = NULL;
	}
	while ((l = mailstream_read_line_remove_eol(ss->stream, ss->line)) != NULL) {
		if (strncmp(l, "OK", 2) == 0 && (l[2] == '\0' || l[2] == ' ')) {
			return SIEVE_OK;
		}
		if ((strncmp(l, "NO", 2) == 0 || strncmp(l, "BYE", 3) == 0)) {
			/* l points into ss->line: decide before reading on. */
			missing = data && strstr(l, "(NONEXISTENT)");
			bye = l[0] == 'B';
			n = literal_size(l);
			text = (n >= 0) ? read_literal(ss, mem_ctx, n) : talloc_strdup(mem_ctx, l);
			if (n >= 0) {
				mailstream_read_line_remove_eol(ss->stream, ss->line);
			}
			if (missing) {
				talloc_free(text);
				return SIEVE_OK;	/* no script yet: *data stays NULL */
			}
			OC_DEBUG(1, "IMAP backend: ManageSieve %s refused: %s\n", what, text ? text : "?");
			talloc_free(text);
			ss->dead |= bye;
			return bye ? SIEVE_BAD : SIEVE_NO;
		}
		n = literal_size(l);
		if (n >= 0 && data && !*data) {
			*data = read_literal(ss, mem_ctx, n);
			if (!*data) {
				ss->dead = true;
				return SIEVE_BAD;
			}
			continue;	/* the CRLF after the literal comes as an empty line */
		}
		/* capability lines and the empty line after a literal */
	}
	OC_DEBUG(1, "IMAP backend: ManageSieve connection lost during %s\n", what);
	ss->dead = true;
	return SIEVE_BAD;
}

static bool has_capability(struct sieve_session *ss, const char *name, bool *found)
{
	const char	*l;
	size_t		len = strlen(name);

	*found = false;
	while ((l = mailstream_read_line_remove_eol(ss->stream, ss->line)) != NULL) {
		if (strncmp(l, "OK", 2) == 0) {
			return true;
		}
		if (strncmp(l, "NO", 2) == 0 || strncmp(l, "BYE", 3) == 0) {
			return false;
		}
		if (l[0] == '"' && strncasecmp(l + 1, name, len) == 0 && l[len + 1] == '"') {
			*found = true;
		}
	}
	return false;
}

static int starttls(struct sieve_session *ss)
{
	mailstream_low	*low, *tls;
	int		fd;

	if (send_str(ss, "STARTTLS\r\n", 10) || mailstream_flush(ss->stream) ||
	    read_response(ss, NULL, NULL, "STARTTLS") != SIEVE_OK) {
		return -1;
	}
	low = mailstream_get_low(ss->stream);
	fd = mailstream_low_get_fd(low);
	tls = mailstream_low_tls_open_timeout(fd, SIEVE_TIMEOUT_SECONDS);
	if (!tls) {
		return -1;
	}
	mailstream_low_free(low);
	mailstream_low_set_timeout(tls, SIEVE_TIMEOUT_SECONDS);
	mailstream_set_low(ss->stream, tls);
	return 0;
}

static int authenticate(struct sieve_session *ss, const struct imap_settings *s, const char *username)
{
	TALLOC_CTX	*tmp = talloc_new(NULL);
	DATA_BLOB	blob;
	char		*login, *b64, *cmd;
	size_t		ulen, plen;
	int		ret = -1;

	login = talloc_asprintf(tmp, "%s*%s", username, s->master_user);
	if (!login) {
		goto done;
	}
	/* PLAIN: empty authzid, then authcid and password (Dovecot reads "<user>*<master>"). */
	ulen = strlen(login);
	plen = s->master_password ? strlen(s->master_password) : 0;
	blob = data_blob_talloc(tmp, NULL, ulen + plen + 2);
	if (!blob.data) {
		goto done;
	}
	blob.data[0] = '\0';
	memcpy(blob.data + 1, login, ulen);
	blob.data[ulen + 1] = '\0';
	if (plen) {
		memcpy(blob.data + ulen + 2, s->master_password, plen);
	}
	b64 = base64_encode_data_blob(tmp, blob);
	cmd = b64 ? talloc_asprintf(tmp, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", b64) : NULL;
	if (cmd && !send_str(ss, cmd, strlen(cmd)) && !mailstream_flush(ss->stream) &&
	    read_response(ss, tmp, NULL, "AUTHENTICATE") == SIEVE_OK) {
		ret = 0;
	}
	memset(blob.data, 0, blob.length);
	if (cmd) {
		memset(cmd, 0, strlen(cmd));
	}
done:
	talloc_free(tmp);
	return ret;
}

static void session_close(struct sieve_session *ss)
{
	if (ss->stream && !ss->dead) {
		if (!send_str(ss, "LOGOUT\r\n", 8) && !mailstream_flush(ss->stream)) {
			read_response(ss, NULL, NULL, "LOGOUT");
		}
	}
	if (ss->stream) {
		mailstream_close(ss->stream);
		ss->stream = NULL;
	}
	if (ss->line) {
		mmap_string_free(ss->line);
		ss->line = NULL;
	}
	if (ss->pid > 0) {
		waitpid(ss->pid, NULL, 0);
		ss->pid = -1;
	}
}

static int session_open(struct sieve_session *ss, const struct imap_settings *s, const char *username)
{
	bool	tls = false;
	int	fd;

	memset(ss, 0, sizeof(*ss));
	ss->pid = -1;
	if (!s || !username || !username[0] || strpbrk(username, "\r\n\"*\\ ")) {
		return -1;
	}
	if (s->sieve_tunnel) {
		struct timeval tv = { SIEVE_TIMEOUT_SECONDS, 0 };

		fd = imap_tunnel_spawn(NULL, s->sieve_tunnel, username, &ss->pid);
		if (fd != -1) {
			setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		}
	} else {
		fd = tcp_connect(s->sieve_host, s->sieve_port);
	}
	ss->stream = (fd != -1) ? mailstream_socket_open(fd) : NULL;
	ss->line = mmap_string_new("");
	if (!ss->stream || !ss->line) {
		if (!ss->stream && fd != -1) {
			close(fd);
		}
		OC_DEBUG(1, "IMAP backend: ManageSieve connect failed\n");
		session_close(ss);
		return -1;
	}
	/* libetpan's default is 5 minutes, and it waits that long on a closed socket. */
	mailstream_low_set_timeout(mailstream_get_low(ss->stream), SIEVE_TIMEOUT_SECONDS);
	/* The PREAUTH tunnel (tests) sends no greeting and is already logged in. */
	if (s->sieve_tunnel) {
		return 0;
	}
	/* The master password never crosses a connection in clear text. */
	if (!has_capability(ss, "STARTTLS", &tls) || !tls || starttls(ss) ||
	    !has_capability(ss, "SASL", &tls) || authenticate(ss, s, username)) {
		OC_DEBUG(1, "IMAP backend: ManageSieve STARTTLS/AUTHENTICATE failed\n");
		session_close(ss);
		return -1;
	}
	return 0;
}

_PUBLIC_ int imap_sieve_get(const struct imap_settings *s, const char *username, TALLOC_CTX *mem_ctx, char **script)
{
	struct sieve_session	ss;
	static const char	cmd[] = "GETSCRIPT \"" SIEVE_SCRIPT_NAME "\"\r\n";
	int			ret = -1;

	*script = NULL;
	if (session_open(&ss, s, username)) {
		return -1;
	}
	if (!send_str(&ss, cmd, sizeof(cmd) - 1) && !mailstream_flush(ss.stream) &&
	    read_response(&ss, mem_ctx, script, "GETSCRIPT") == SIEVE_OK) {
		ret = 0;
	} else {
		talloc_free(*script);
		*script = NULL;
	}
	session_close(&ss);
	return ret;
}

_PUBLIC_ int imap_sieve_put(const struct imap_settings *s, const char *username, const char *script)
{
	struct sieve_session	ss;
	enum sieve_status	st = SIEVE_BAD;
	char			*cmd;
	int			ret;

	if (session_open(&ss, s, username)) {
		return -1;
	}
	if (script) {
		cmd = talloc_asprintf(NULL, "PUTSCRIPT \"" SIEVE_SCRIPT_NAME "\" {%zu+}\r\n", strlen(script));
		if (cmd && !send_str(&ss, cmd, strlen(cmd)) && !send_str(&ss, script, strlen(script)) &&
		    !send_str(&ss, "\r\n", 2) && !mailstream_flush(ss.stream)) {
			st = read_response(&ss, cmd, NULL, "PUTSCRIPT");
		}
		talloc_free(cmd);
	} else {
		static const char del[] = "DELETESCRIPT \"" SIEVE_SCRIPT_NAME "\"\r\n";
		char *ignored = NULL;

		/* Passing a data pointer makes a NONEXISTENT reply count as done. */
		if (!send_str(&ss, del, sizeof(del) - 1) && !mailstream_flush(ss.stream)) {
			st = read_response(&ss, NULL, &ignored, "DELETESCRIPT");
		}
		talloc_free(ignored);
	}
	ret = (st == SIEVE_OK) ? 0 : (st == SIEVE_NO ? -2 : -1);
	session_close(&ss);
	return ret;
}
