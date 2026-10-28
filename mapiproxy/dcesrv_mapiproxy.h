/*
   MAPI Proxy

   OpenChange Project

   Copyright (C) Julien Kerihuel 2008

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

#ifndef	__DCESRV_MAPIPROXY_H__
#define	__DCESRV_MAPIPROXY_H__

#include "config.h"
#include "mapiproxy/samba_compat.h"

#include <sys/types.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <talloc.h>
#include <dcerpc.h>
#include <samba/session.h>

#include <dcerpc_server.h>
#include <param.h>
#include <credentials.h>

#include "gen_ndr/exchange.h"
#include "gen_ndr/ndr_exchange.h"
#include "mapiproxy/libmapiproxy/libmapiproxy.h"

/* Account names can collide across trusted domains; bind directory records to
 * the authenticated primary SID before accepting them as the session owner. */
static inline bool mapiproxy_call_owns_account(struct dcesrv_call_state *call,
                                              const struct ldb_message *record)
{
	struct auth_session_info *session;
	const struct dom_sid *sid;
	const struct ldb_val *stored;
	unsigned i;
	if (!dcesrv_call_authenticated(call)) return false;
	session = dcesrv_call_session_info(call);
	if (session == NULL || session->security_token == NULL ||
	    session->security_token->num_sids == 0) return false;
	sid = &session->security_token->sids[0];
	stored = ldb_msg_find_ldb_val(record, "objectSid");
	if (stored == NULL || stored->data == NULL || sid->sid_rev_num != 1 ||
	    sid->num_auths < 0 || (unsigned)sid->num_auths > sizeof(sid->sub_auths) / sizeof(sid->sub_auths[0]) ||
	    stored->length != 8 + 4 * (unsigned)sid->num_auths ||
	    stored->data[0] != sid->sid_rev_num || stored->data[1] != sid->num_auths ||
	    memcmp(stored->data + 2, sid->id_auth, 6) != 0) return false;
	/* SID subauthorities are 32-bit little-endian values in objectSid. */
	for (i = 0; i < (unsigned)sid->num_auths; i++) {
		const uint8_t *p = stored->data + 8 + 4 * i;
		uint32_t value = (uint32_t)p[0] | (uint32_t)p[1] << 8 |
			(uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
		if (value != sid->sub_auths[i]) return false;
	}
	return true;
}

static inline struct server_id mapiproxy_connection_server_id(struct dcesrv_connection *conn)
{
#if HAVE_DECL_DCESRV_SERVER_ID
	return dcesrv_server_id(conn);
#else
	return conn->server_id;
#endif
}

struct dcesrv_mapiproxy_private {
	struct dcerpc_pipe			*c_pipe;
	char					*exchname;
	bool					server_mode;
	bool					connected;
	bool					ndrdump;
};

/* Separate namespaces for authenticated connection and remote association state. */
#define MAPIPROXY_PRIVATE_MAGIC 0x6f636e70
#define MAPIPROXY_ASSOC_MAGIC 0x6f636e61

struct mapiproxy_remote_assoc {
	uint32_t id;
};

static inline struct dcesrv_mapiproxy_private *mapiproxy_private(struct dcesrv_call_state *call)
{
	return dcesrv_iface_state_find_conn(call, MAPIPROXY_PRIVATE_MAGIC,
		struct dcesrv_mapiproxy_private);
}

enum exchange_handle {
	EXCHANGE_HANDLE_NSP,
	EXCHANGE_HANDLE_EMSMDB,
	EXCHANGE_HANDLE_DS_RFR,
	EXCHANGE_HANDLE_ASYNCEMSMDB
};

/* Forward declarations */
struct composite_context;

#define MAXHOSTNAMELEN	255
#define	SERVERNAME      "/cn=Servers/cn="

#endif	/* !__DCESRV_MAPIPROXY_H__ */
