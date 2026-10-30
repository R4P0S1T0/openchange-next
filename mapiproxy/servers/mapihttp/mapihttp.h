/*
   OpenChange MAPI/HTTP service (MS-OXCMAPIHTTP)

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

#ifndef	__MAPIHTTP_H
#define	__MAPIHTTP_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>
#include <talloc.h>
#include <util/data_blob.h>

#define	MAPIHTTP_SERVER_APPLICATION	"Exchange/15.02.1544.004"
#define	MAPIHTTP_MAX_BODY		(16 * 1024 * 1024)

/* X-ResponseCode values, MS-OXCMAPIHTTP 2.2.3.3.3 */
#define	MAPIHTTP_SUCCESS		0
#define	MAPIHTTP_INVALID_VERB		2
#define	MAPIHTTP_INVALID_PATH		3
#define	MAPIHTTP_INVALID_HEADER		4
#define	MAPIHTTP_INVALID_REQUEST_TYPE	5
#define	MAPIHTTP_MISSING_HEADER		7
#define	MAPIHTTP_TOO_LARGE		9

/* authenticate() results */
#define	MAPIHTTP_AUTH_OK		0
#define	MAPIHTTP_AUTH_BAD		1
#define	MAPIHTTP_AUTH_TEMPFAIL		2

struct mapihttp_server {
	int	(*authenticate)(void *priv, const char *user, const char *password);
	void	*auth_priv;
};

struct mapihttp_request {
	const char	*method;
	const char	*path;
	const char	*request_type;
	const char	*request_id;
	const char	*content_type;
	const char	*cookie;
	const char	*authorization;
	const char	*client_info;
	const uint8_t	*body;
	size_t		body_len;
};

struct mapihttp_reply {
	unsigned	http_status;
	uint32_t	response_code;
	const char	*request_type;
	const char	*request_id;
	const char	*client_info;
	DATA_BLOB	body;
	const char	*set_cookie;
	uint32_t	expiration_ms;
	struct timeval	start;
};

void mapihttp_handle(struct mapihttp_server *, TALLOC_CTX *, const struct mapihttp_request *, struct mapihttp_reply *);
DATA_BLOB mapihttp_format_reply(TALLOC_CTX *, const struct mapihttp_reply *);

#endif /* __MAPIHTTP_H */
