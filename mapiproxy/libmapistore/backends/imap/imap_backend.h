/*
   OpenChange Storage Abstraction Layer library
   Read-only IMAP backend: shared declarations

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

#ifndef __IMAP_BACKEND_H__
#define __IMAP_BACKEND_H__

#include "imap_conn.h"

#define IMAP_NAMESPACE "imap://"

#include "mapiproxy/libmapistore/mapistore_errors.h"

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include "gen_ndr/exchange.h"

struct mapistore_backend;
struct mapistore_contexts_list;
struct mapistore_connection_info;
struct mapistore_property_data;
struct indexing_context;
struct shared_conn;
struct imap_message_row;

/* First field of every backend object, so get_properties can dispatch. */
enum imap_object_type {
	IMAP_OBJ_FOLDER = 0x494D4631,
	IMAP_OBJ_TABLE,
	IMAP_OBJ_MESSAGE,
	IMAP_OBJ_ATTACHMENT,
	IMAP_OBJ_DRAFT_ATTACHMENT,	/* struct imap_draft_attachment */
};

struct imap_recipient {
	enum ulRecipClass	type;		/* MAPI_TO, MAPI_CC, MAPI_BCC */
	char			*name;		/* display name, or the address when unnamed */
	char			*address;
};

struct imap_attachment {
	uint32_t	type;			/* IMAP_OBJ_ATTACHMENT */
	uint32_t	number;
	char		*filename;
	char		*mime_type;
	char		*content_id;
	uint8_t		*data;
	uint32_t	size;
};

struct imap_folder;

/* One message of a message table, from UID FETCH (ENVELOPE FLAGS RFC822.SIZE INTERNALDATE BODYSTRUCTURE). */
struct imap_message_row {
	uint32_t	uid;
	uint32_t	uidvalidity;
	uint32_t	size;
	time_t		internal;	/* INTERNALDATE: delivery */
	time_t		date;		/* Date: header */
	bool		seen, flagged, answered, draft, has_attachments;
	char		*subject;	/* UTF-8, decoded */
	char		*from_name;
	char		*from_address;
	char		*display_to;
	char		*display_cc;
	char		*message_id;
	uint64_t	mid;
	struct imap_recipient	*recipients;	/* filled when a message is opened */
	uint32_t		recipient_count;
};

struct imap_message {
	uint32_t		type;		/* IMAP_OBJ_MESSAGE */
	struct imap_folder	*folder;
	struct imap_message_row	row;
	char			*body;		/* UTF-8 text (from the HTML part when there is no text part) */
	char			*html;		/* UTF-8 */
	char			*headers;	/* transport headers, UTF-8 */
	struct imap_attachment	*attachments;
	uint32_t		attachment_count;
	uint32_t		flags_add, flags_remove;	/* IMAP_FLAG_*, written by save */
	struct imap_draft	*draft;		/* set once Outlook writes to an unsent message */
};

/* An attachment of a draft by number: the draft's array moves as attachments are added. */
struct imap_draft_attachment {
	uint32_t		type;		/* IMAP_OBJ_DRAFT_ATTACHMENT */
	struct imap_message	*message;
	uint32_t		number;
};

/* A message Outlook is writing (drafts, Outbox): what imap_compose renders. */
struct imap_draft {
	char			*subject;	/* UTF-8 */
	char			*body;		/* PidTagBody, UTF-8 */
	uint8_t			*html;		/* PidTagHtml, in html_codepage */
	uint32_t		html_len;
	uint32_t		html_codepage;	/* PidTagInternetCodepage; 0 = UTF-8 */
	char			*message_id;	/* PidTagInternetMessageId */
	char			*in_reply_to;	/* PidTagInReplyToId */
	char			*references;	/* PidTagInternetReferences */
	char			*from_name;	/* PidTagSentRepresentingName or PidTagSenderName */
	bool			delete_after_submit;
	uint32_t		unresolved;	/* recipients without an SMTP address: submit refuses */
	struct imap_recipient	*recipients;
	uint32_t		recipient_count;
	struct imap_attachment	*attachments;	/* content_id set: inline in the HTML */
	uint32_t		attachment_count;
	bool			dirty;
};

struct openchangedb_context;

struct imap_context {
	char			*username;	/* the session's user; the only mailbox ever opened */
	struct indexing_context	*ictx;
	struct openchangedb_context *oc_ctx;	/* change numbers come from openchangedb */
	struct GUID		replica_guid;	/* of the mailbox, for change keys */
	struct shared_conn	*shared;
	struct imap_folder	*root;
};

struct imap_folder {
	uint32_t		type;		/* IMAP_OBJ_FOLDER */
	struct imap_context	*ctx;
	char			*mailbox;	/* modified UTF-7, as on the wire */
	uint64_t		fid;
	uint64_t		parent_fid;	/* 0 when the parent is not an IMAP folder of this context */
};

struct imap_table {
	uint32_t			type;	/* IMAP_OBJ_TABLE */
	struct imap_folder		*folder;
	enum mapistore_table_type	table_type;
	uint16_t			column_count;
	enum MAPITAGS			*columns;
	uint32_t			row_count;
	char				**children;	/* folder table */
	struct imap_message		*message;	/* attachment table */
	struct imap_message_row		*rows;		/* message table */
	uint32_t			uidvalidity;	/* of the mailbox when the rows were read */
	uint32_t			*view;		/* rows shown, in order (restriction and sort applied) */
	uint32_t			view_count;
	struct SSortOrder		*sort;		/* the last sort order, kept across restrictions */
	uint16_t			sort_count;
};

/* Entry point dlopen()ed by mapistore_backend_init. */
enum mapistore_error mapistore_init_backend(void);

/* Settings read by init(); NULL when the backend is not configured. */
const struct imap_settings *imap_backend_settings(void);

/* imap://<user>/<component>/.../ with each component %-encoded (see emsmdbp_compute_parent_uri). */
char *imap_uri(TALLOC_CTX *mem_ctx, const char *username, const char *mailbox, char delimiter);
int imap_uri_parse(TALLOC_CTX *mem_ctx, const char *uri, char delimiter, char **username, char **mailbox);
/* The leaf of `mailbox`, modified UTF-7 decoded to UTF-8 (raw when malformed). */
char *imap_display_name(TALLOC_CTX *mem_ctx, const char *mailbox, char delimiter);

/* One mailbox level from a UTF-8 display name, modified UTF-7; NULL when IMAP cannot hold it as one level. */
char *imap_mailbox_name(TALLOC_CTX *mem_ctx, const char *utf8, char delimiter);

/* Replaces the settings (tests; NULL with !broken = not configured). */
void imap_backend_set_state(const struct imap_settings *settings, bool broken);
bool imap_backend_broken(void);

/* Sets the context, folder, table, message and properties operations. */
void imap_backend_fill(struct mapistore_backend *backend);
void imap_message_fill(struct mapistore_backend *backend);

/* imap_folder.c */
struct imap_conn *imap_context_conn(struct imap_context *ctx);
char imap_context_delimiter(struct imap_context *ctx);
enum mapistore_error imap_fmid_for_uri(struct imap_context *ctx, const char *uri, uint64_t *fmid);
enum mapistore_error imap_list_contexts(const char *username, struct indexing_context *ictx, TALLOC_CTX *mem_ctx,
					struct mapistore_contexts_list **listp);
enum mapistore_error imap_create_context(TALLOC_CTX *mem_ctx, struct mapistore_connection_info *conn_info,
					 struct indexing_context *ictx, const char *uri, void **backend_object);
enum mapistore_error imap_create_root_folder(const char *username, enum mapistore_context_role role, uint64_t fid,
					     const char *name, TALLOC_CTX *mem_ctx, char **uri);
enum mapistore_error imap_folder_set_properties(struct imap_folder *f, struct SRow *row);
enum mapistore_error imap_folder_open_folder(void *parent, TALLOC_CTX *mem_ctx, uint64_t fid, void **child);
enum mapistore_error imap_folder_get_child_count(void *folder, enum mapistore_table_type type, uint32_t *count);
enum mapistore_error imap_folder_open_table(void *folder, TALLOC_CTX *mem_ctx, enum mapistore_table_type type,
					    uint32_t handle_id, void **table, uint32_t *row_count);
enum mapistore_error imap_table_set_columns(void *table, uint16_t count, enum MAPITAGS *columns);
enum mapistore_error imap_table_get_row(void *table, TALLOC_CTX *mem_ctx, enum mapistore_query_type type,
					uint32_t row, struct mapistore_property_data **data);
enum mapistore_error imap_table_get_row_count(void *table, enum mapistore_query_type type, uint32_t *count);
enum mapistore_error imap_table_set_restrictions(void *table, struct mapi_SRestriction *res, uint8_t *table_status);
enum mapistore_error imap_table_set_sort_order(void *table, struct SSortOrderSet *set, uint8_t *table_status);
enum mapistore_error imap_folder_properties(struct imap_folder *f, TALLOC_CTX *mem_ctx, uint16_t count,
					    enum MAPITAGS *tags, struct mapistore_property_data *data);
enum mapistore_error imap_table_available(void *table, TALLOC_CTX *mem_ctx, struct SPropTagArray **propsp);
enum mapistore_error imap_properties_available(void *object, TALLOC_CTX *mem_ctx, struct SPropTagArray **propsp);
enum mapistore_error imap_properties_get(void *object, TALLOC_CTX *mem_ctx, uint16_t count, enum MAPITAGS *tags,
					 struct mapistore_property_data *data);
uint32_t *imap_long(TALLOC_CTX *mem_ctx, uint32_t v);
uint8_t *imap_bool(TALLOC_CTX *mem_ctx, bool v);
uint64_t *imap_i8(TALLOC_CTX *mem_ctx, uint64_t v);

/* Change numbers (ICS): one per object URI, renewed when the object's state string changes. */
typedef enum mapistore_error (*imap_cn_source)(struct imap_context *ctx, uint64_t *cn);
void imap_backend_set_cn_source(imap_cn_source source);
enum mapistore_error imap_change_number(struct imap_context *ctx, const char *uri, const char *state, uint64_t *cn,
					time_t *when);
/* PidTagChangeNumber, PidTagChangeKey, PidTagPredecessorChangeList or PidTagLastModificationTime of a change. */
void *imap_change_value(TALLOC_CTX *mem_ctx, struct imap_context *ctx, uint64_t cn, time_t when, enum MAPITAGS tag);

/* imap_compose.c */
/* RFC 5322 + MIME, 7-bit; Bcc in the headers only with_bcc (stored drafts). NULL when an address
   is not a plain addr-spec. */
char *imap_compose(TALLOC_CTX *mem_ctx, const struct imap_draft *d, const char *from_address, const char *from_name,
		   time_t now, bool with_bcc, size_t *len);
/* To, Cc and Bcc addresses, without case-insensitive duplicates. */
uint32_t imap_draft_envelope(const struct imap_draft *d, TALLOC_CTX *mem_ctx, const char ***rcpts);

/* imap_message.c */
char *imap_utf8_clean(TALLOC_CTX *mem_ctx, const char *s, size_t len);
char *imap_decode_header(TALLOC_CTX *mem_ctx, const char *raw);
char *imap_message_uri(TALLOC_CTX *mem_ctx, struct imap_folder *f, uint32_t uidvalidity, uint32_t uid);
void *imap_row_value(TALLOC_CTX *mem_ctx, const struct imap_message_row *row, const struct imap_folder *f,
		     enum MAPITAGS tag);
enum mapistore_error imap_message_table_load(struct imap_table *t);
enum mapistore_error imap_message_row(struct imap_table *t, TALLOC_CTX *mem_ctx, uint32_t row,
				      struct mapistore_property_data *data);
enum mapistore_error imap_mid_uid(struct imap_folder *f, TALLOC_CTX *mem_ctx, uint64_t mid, uint32_t *uidvalidity,
				  uint32_t *uid);
enum mapistore_error imap_folder_open_message(void *folder, TALLOC_CTX *mem_ctx, uint64_t mid, bool read_write,
					      void **message);
enum mapistore_error imap_message_properties(void *message, TALLOC_CTX *mem_ctx, uint16_t count, enum MAPITAGS *tags,
					     struct mapistore_property_data *data);
enum mapistore_error imap_attachment_properties(struct imap_attachment *a, TALLOC_CTX *mem_ctx, uint16_t count,
						enum MAPITAGS *tags, struct mapistore_property_data *data);
enum mapistore_error imap_message_get_data(void *message, TALLOC_CTX *mem_ctx, struct mapistore_message **msg);
enum mapistore_error imap_message_get_attachment_table(void *message, TALLOC_CTX *mem_ctx, void **table,
						       uint32_t *row_count);
/* The attachment a draft attachment handle points at (NULL when gone). */
struct imap_attachment *imap_draft_attachment_get(void *handle);
enum mapistore_error imap_message_open_attachment(void *message, TALLOC_CTX *mem_ctx, uint32_t number,
						  void **attachment);

#endif /* __IMAP_BACKEND_H__ */
