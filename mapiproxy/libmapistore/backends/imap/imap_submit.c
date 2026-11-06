/*
   OpenChange Storage Abstraction Layer library
   IMAP backend: submission (RFC 6409) of what Outlook sends

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
#include <sys/wait.h>
#include <unistd.h>

#include <libetpan/libetpan.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "imap_conn.h"

#define SMTP_TIMEOUT_SECONDS 10

/* Postfix decides who may send as whom (reject_sender_login_mismatch): the session logs in as its
   own user through the Dovecot master user, and the envelope sender is that user. */
_PUBLIC_ int imap_smtp_send(const struct imap_settings *s, const char *username, const char *from, const char **rcpts,
			    uint32_t count, const char *data, size_t len, int *smtp_code)
{
	mailsmtp	*smtp;
	mailstream	*stream;
	char		*login = NULL;
	pid_t		pid = -1;
	uint32_t	i;
	int		fd, r, ret = -2;

	*smtp_code = 0;
	if (!s || !username || !from || !rcpts || !count || !data || strpbrk(username, "\r\n")) {
		return -2;
	}
	smtp = mailsmtp_new(0, NULL);
	if (!smtp) {
		return -2;
	}
	mailsmtp_set_timeout(smtp, SMTP_TIMEOUT_SECONDS);
	if (s->smtp_tunnel) {
		fd = imap_tunnel_spawn(NULL, s->smtp_tunnel, username, &pid);
		stream = fd != -1 ? mailstream_socket_open(fd) : NULL;
		if (!stream && fd != -1) {
			close(fd);
		}
		r = stream ? mailsmtp_connect(smtp, stream) : MAILSMTP_ERROR_CONNECTION_REFUSED;
	} else {
		r = mailsmtp_socket_connect(smtp, s->smtp_host, s->smtp_port);
	}
	if (r != MAILSMTP_NO_ERROR) {
		OC_DEBUG(1, "IMAP backend: submission connect failed (%d)\n", r);
		goto done;
	}
	r = mailesmtp_ehlo(smtp);
	/* Credentials never cross a connection in clear text; only the test tunnel has no TLS. */
	if (r == MAILSMTP_NO_ERROR && !s->smtp_tunnel) {
		r = mailsmtp_socket_starttls(smtp);
		if (r == MAILSMTP_NO_ERROR) {
			r = mailesmtp_ehlo(smtp);
		}
	}
	if (r != MAILSMTP_NO_ERROR) {
		OC_DEBUG(1, "IMAP backend: submission EHLO/STARTTLS failed (%d)\n", r);
		goto done;
	}
	login = talloc_asprintf(NULL, "%s*%s", username, s->master_user);
	/* No authorization id: Dovecot reads "<user>*<master>" as the master login (lab-verified form). */
	r = login ? mailesmtp_auth_sasl(smtp, "PLAIN", s->smtp_host, NULL, NULL, "", login,
					s->master_password ? s->master_password : "", NULL) : MAILSMTP_ERROR_MEMORY;
	if (r != MAILSMTP_NO_ERROR) {
		*smtp_code = smtp->response_code;
		OC_DEBUG(1, "IMAP backend: submission AUTH refused (%d, %d)\n", r, smtp->response_code);
		goto done;
	}
	ret = -1;
	if ((smtp->esmtp & MAILSMTP_ESMTP_SIZE) && smtp->smtp_max_msg_size && len > smtp->smtp_max_msg_size) {
		*smtp_code = 552;
		OC_DEBUG(3, "IMAP backend: message of %zu bytes over the server's SIZE %zu\n", len, smtp->smtp_max_msg_size);
		goto done;
	}
	r = (smtp->esmtp & MAILSMTP_ESMTP_SIZE) ? mailesmtp_mail_size(smtp, from, 0, NULL, len)
						: mailesmtp_mail(smtp, from, 0, NULL);
	for (i = 0; r == MAILSMTP_NO_ERROR && i < count; i++) {
		r = mailesmtp_rcpt(smtp, rcpts[i], 0, NULL);
	}
	if (r == MAILSMTP_NO_ERROR) {
		r = mailsmtp_data(smtp);
	}
	if (r == MAILSMTP_NO_ERROR) {
		/* libetpan ends DATA with CRLF "." CRLF itself: the message's own final CRLF goes in there,
		   so the bytes delivered are the bytes filed in Sent. */
		r = mailsmtp_data_message(smtp, data, (len >= 2 && data[len - 2] == '\r' && data[len - 1] == '\n') ? len - 2 : len);
	}
	if (r != MAILSMTP_NO_ERROR) {
		*smtp_code = smtp->response_code;
		OC_DEBUG(3, "IMAP backend: submission refused (%d, reply %d, %u recipient(s))\n", r, smtp->response_code, count);
		mailsmtp_reset(smtp);
		goto done;
	}
	ret = 0;
	OC_DEBUG(5, "IMAP backend: submitted %zu bytes to %u recipient(s)\n", len, count);
done:
	if (smtp->stream) {
		mailsmtp_quit(smtp);
	}
	mailsmtp_free(smtp);
	talloc_free(login);
	if (pid > 0) {
		waitpid(pid, NULL, 0);
	}
	return ret;
}
