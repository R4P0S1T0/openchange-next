/*
   OpenChange MAPI/HTTP service (MS-OXCMAPIHTTP)

   Request validation and routing, independent of the HTTP library.

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

#include <string.h>
#include <strings.h>
#include <util/time.h>
#include <ldb.h>
#include "mapiproxy/servers/mapihttp/mapihttp.h"
#include "libmapi/oc_log.h"

/**
   \details Check Basic credentials (RFC 7617) through the server's
   authenticate callback. Any other scheme is answered with 401 without
   calling it: Outlook sends Bearer first on every request.

   \return the HTTP status: 200, 401 or 503
 */
static unsigned mapihttp_check_auth(struct mapihttp_server *srv, TALLOC_CTX *mem_ctx,
				    const char *authorization)
{
	char		*decoded;
	char		*colon;
	int		len;
	int		ret;

	if (authorization == NULL) {
		return 401;
	}
	if (strncasecmp(authorization, "Basic ", 6) != 0) {
		OC_DEBUG(5, "non-Basic authorization scheme");
		return 401;
	}

	decoded = talloc_strdup(mem_ctx, authorization + 6 + strspn(authorization + 6, " "));
	if (decoded == NULL) {
		return 500;
	}
	len = ldb_base64_decode(decoded);
	colon = (len > 0) ? memchr(decoded, ':', len) : NULL;
	if (colon == NULL || memchr(decoded, '\0', len) != NULL) {
		ret = MAPIHTTP_AUTH_BAD;
	} else {
		*colon = '\0';
		ret = srv->authenticate(srv->auth_priv, decoded, colon + 1);
		if (ret == MAPIHTTP_AUTH_BAD) {
			oc_log(OC_LOG_WARNING, "mapihttp: failed login for '%s'", decoded);
		}
	}
	explicit_bzero(decoded, talloc_get_size(decoded));
	talloc_free(decoded);

	switch (ret) {
	case MAPIHTTP_AUTH_OK:
		return 200;
	case MAPIHTTP_AUTH_TEMPFAIL:
		return 503;
	default:
		return 401;
	}
}

/**
   \details Handle one MAPI/HTTP request. The reply strings either point
   into req or are allocated on mem_ctx.
 */
void mapihttp_handle(struct mapihttp_server *srv, TALLOC_CTX *mem_ctx,
		     const struct mapihttp_request *req, struct mapihttp_reply *rep)
{
	memset(rep, 0, sizeof (*rep));
	gettimeofday(&rep->start, NULL);
	rep->request_type = req->request_type;
	rep->request_id = req->request_id;
	rep->client_info = req->client_info;

	rep->http_status = mapihttp_check_auth(srv, mem_ctx, req->authorization);
	if (rep->http_status != 200) {
		return;
	}

	if (req->method == NULL || strcmp(req->method, "POST") != 0) {
		rep->response_code = MAPIHTTP_INVALID_VERB;
	} else if (req->path == NULL || (strcasecmp(req->path, "/mapi/emsmdb/") != 0 &&
					 strcasecmp(req->path, "/mapi/nspi/") != 0)) {
		rep->response_code = MAPIHTTP_INVALID_PATH;
	} else if (req->request_type == NULL || req->request_id == NULL || req->content_type == NULL) {
		rep->response_code = MAPIHTTP_MISSING_HEADER;
	} else if (strncasecmp(req->content_type, "application/mapi-http", 21) != 0) {
		rep->response_code = MAPIHTTP_INVALID_HEADER;
	} else if (strcasecmp(req->request_type, "PING") != 0) {
		/* shortcut: only PING is served so far, later tasks route the other request types */
		rep->response_code = MAPIHTTP_INVALID_REQUEST_TYPE;
	} else if (req->body_len > MAPIHTTP_MAX_BODY) {
		rep->response_code = MAPIHTTP_TOO_LARGE;
	}
}

/**
   \details Build the response body of a successful request: meta-tags,
   additional headers and the request type body (MS-OXCMAPIHTTP 3.2.5.2, 4.1).
 */
DATA_BLOB mapihttp_format_reply(TALLOC_CTX *mem_ctx, const struct mapihttp_reply *rep)
{
	DATA_BLOB	out = data_blob_null;
	struct timeval	now = timeval_current();
	char		*start;
	char		*head;

	start = http_timestring(mem_ctx, rep->start.tv_sec);
	head = talloc_asprintf(mem_ctx, "PROCESSING\r\nDONE\r\nX-ResponseCode: %u\r\n"
			       "X-ElapsedTime: %lld\r\nX-StartTime: %s\r\n\r\n", rep->response_code,
			       (long long)(usec_time_diff(&now, &rep->start) / 1000), start);
	if (start == NULL || head == NULL ||
	    !data_blob_append(mem_ctx, &out, head, strlen(head)) ||
	    (rep->body.length && !data_blob_append(mem_ctx, &out, rep->body.data, rep->body.length))) {
		data_blob_free(&out);
	}
	talloc_free(start);
	talloc_free(head);
	return out;
}
