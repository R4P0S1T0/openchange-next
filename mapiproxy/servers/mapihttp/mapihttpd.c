/*
   OpenChange MAPI/HTTP service (MS-OXCMAPIHTTP)

   libmicrohttpd glue. The service listens on 127.0.0.1 only, behind a
   TLS-terminating reverse proxy, and runs in a single thread.

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

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <microhttpd.h>
#include "mapiproxy/servers/mapihttp/mapihttp.h"
#include "libmapi/oc_log.h"

struct mapihttpd_call {
	DATA_BLOB	body;
	size_t		body_len;
};

/* shortcut: fixed user:pass credentials, replaced by the Dovecot authenticator in M1 Task 3 */
static int mapihttpd_fake_auth(void *priv, const char *user, const char *password)
{
	return (strcmp(user, "user") == 0 && strcmp(password, "pass") == 0) ? MAPIHTTP_AUTH_OK : MAPIHTTP_AUTH_BAD;
}

static bool mapihttpd_add_header(struct MHD_Response *response, const char *name, const char *value)
{
	return value == NULL || MHD_add_response_header(response, name, value) == MHD_YES;
}

static void mapihttpd_completed(void *cls, struct MHD_Connection *connection,
				void **con_cls, enum MHD_RequestTerminationCode toe)
{
	talloc_free(*con_cls);
	*con_cls = NULL;
}

static enum MHD_Result mapihttpd_access(void *cls, struct MHD_Connection *connection,
					const char *url, const char *method, const char *version,
					const char *upload_data, size_t *upload_data_size, void **con_cls)
{
	struct mapihttp_server	*srv = cls;
	struct mapihttpd_call	*call = *con_cls;
	struct mapihttp_request	req;
	struct mapihttp_reply	rep;
	struct MHD_Response	*response;
	DATA_BLOB		body = data_blob_null;
	char			code[16], expiration[16];
	bool			ok;
	enum MHD_Result		ret;

	if (call == NULL) {
		call = talloc_zero(NULL, struct mapihttpd_call);
		*con_cls = call;
		return call ? MHD_YES : MHD_NO;
	}

	if (*upload_data_size != 0) {
		/* Past the limit, keep counting but drop the data */
		if (call->body_len <= MAPIHTTP_MAX_BODY) {
			call->body_len += *upload_data_size;
			if (call->body_len <= MAPIHTTP_MAX_BODY &&
			    !data_blob_append(call, &call->body, upload_data, *upload_data_size)) {
				return MHD_NO;
			}
		}
		*upload_data_size = 0;
		return MHD_YES;
	}

	/* Headers are only read by name, so anything else the client sends is ignored */
	req = (struct mapihttp_request) {
		.method = method,
		.path = url,
		.request_type = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-RequestType"),
		.request_id = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-RequestId"),
		.content_type = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Content-Type"),
		.cookie = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Cookie"),
		.authorization = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization"),
		.client_info = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-ClientInfo"),
		.body = call->body_len <= MAPIHTTP_MAX_BODY ? call->body.data : NULL,
		.body_len = call->body_len,
	};
	mapihttp_handle(srv, call, &req, &rep);

	if (rep.http_status == 200 && rep.response_code == MAPIHTTP_SUCCESS) {
		body = mapihttp_format_reply(call, &rep);
		if (body.data == NULL) {
			return MHD_NO;
		}
	}
	response = MHD_create_response_from_buffer_copy(body.length, body.length ? body.data : (const void *)"");
	if (response == NULL) {
		return MHD_NO;
	}

	snprintf(code, sizeof(code), "%u", rep.response_code);
	snprintf(expiration, sizeof(expiration), "%u", rep.expiration_ms);
	ok = mapihttpd_add_header(response, "Content-Type", body.length ? "application/mapi-http" : "text/html") &&
		mapihttpd_add_header(response, "X-RequestType", rep.request_type) &&
		mapihttpd_add_header(response, "X-RequestId", rep.request_id) &&
		mapihttpd_add_header(response, "X-ClientInfo", rep.client_info) &&
		mapihttpd_add_header(response, "X-ServerApplication", MAPIHTTP_SERVER_APPLICATION) &&
		mapihttpd_add_header(response, "X-ResponseCode", rep.http_status == 200 ? code : NULL) &&
		mapihttpd_add_header(response, "X-PendingPeriod", body.length ? "15000" : NULL) &&
		mapihttpd_add_header(response, "X-ExpirationInfo", rep.expiration_ms ? expiration : NULL) &&
		mapihttpd_add_header(response, "Set-Cookie", rep.set_cookie) &&
		mapihttpd_add_header(response, "WWW-Authenticate",
				     rep.http_status == 401 ? "Basic realm=\"openchange\"" : NULL);

	ret = ok ? MHD_queue_response(connection, rep.http_status, response) : MHD_NO;
	MHD_destroy_response(response);
	return ret;
}

int main(void)
{
	struct mapihttp_server		srv = { .authenticate = mapihttpd_fake_auth };
	struct loadparm_context		*lp_ctx;
	struct sockaddr_in		addr = { .sin_family = AF_INET };
	struct MHD_Daemon		*daemon;
	int				port;

	oc_log_init_stderr();
	lp_ctx = loadparm_init_global(true);
	if (lp_ctx == NULL) {
		oc_log(OC_LOG_FATAL, "mapihttp: cannot load configuration");
		return 1;
	}
	port = lpcfg_parm_int(lp_ctx, NULL, "mapihttp", "port", 8080);
	if (port <= 0 || port > 65535) {
		oc_log(OC_LOG_FATAL, "mapihttp: invalid mapihttp:port %d", port);
		return 1;
	}

	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	/* No threading flag: requests are processed one at a time by MHD_run_wait() below */
	daemon = MHD_start_daemon(MHD_USE_ERROR_LOG, 0, NULL, NULL, mapihttpd_access, &srv,
				  MHD_OPTION_SOCK_ADDR, (struct sockaddr *)&addr,
				  MHD_OPTION_NOTIFY_COMPLETED, mapihttpd_completed, NULL,
				  MHD_OPTION_END);
	if (daemon == NULL) {
		oc_log(OC_LOG_FATAL, "mapihttp: cannot listen on 127.0.0.1:%d", port);
		return 1;
	}
	oc_log(OC_LOG_INFO, "mapihttp: listening on 127.0.0.1:%d", port);

	while (MHD_run_wait(daemon, -1) == MHD_YES);

	MHD_stop_daemon(daemon);
	return 1;
}
