/*
   OpenChange Storage Abstraction Layer library
   Optional CardDAV contacts backend (M6): SOGo address books for Outlook

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#ifndef	__DAV_BACKEND_H__
#define	__DAV_BACKEND_H__

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "dav_map.h"

#define DAV_NAMESPACE "dav://"
/* Context URIs: dav://contacts/<book segment>/; an item is <context URI><card segment>. */
#define DAV_CONTACTS_URI DAV_NAMESPACE "contacts/"

/* Process-wide settings from the smb.conf section [mapistore]. */
struct dav_settings {
	char		*url_template;	/* dav_url, "%u" is the mailbox user */
	uint8_t		*fp_key;	/* dav_fingerprint_key_file: 32+ random bytes, never logged */
	size_t		fp_key_len;
};

/* NULL when the backend is unconfigured or its configuration is unusable. */
const struct dav_settings *dav_backend_settings(void);
struct dav_settings *dav_settings_load(TALLOC_CTX *, struct loadparm_context *);
void dav_backend_fill(struct mapistore_backend *);
/* Entry point dlopen()ed by mapistore_backend_init. */
enum mapistore_error mapistore_init_backend(void);

/* Replaces the settings (tests; NULL = not configured). */
void dav_backend_set_settings(struct dav_settings *);
/* How long reads reuse a context's last sync and book listing, in seconds (default 10; tests: 0). */
void dav_backend_set_sync_window(int);

/* First field of every backend object, so get_properties can dispatch. */
enum dav_object_type {
	DAV_OBJ_FOLDER = 0x44415631,
	DAV_OBJ_TABLE,
	DAV_OBJ_MESSAGE,
	DAV_OBJ_ATTACHMENT,
};

/* One card of the book, as last listed. */
struct dav_item {
	char		*href;		/* server path, as the server spells it */
	char		*norm;		/* dav_href_norm(href): the item's identity on the server */
	char		*etag;
	uint64_t	mid;		/* from the indexing, on <context URI><last segment of norm> */
	struct dav_card	*card;		/* NULL until fetched; owned by the context, referenced by open messages */
	bool		listed;		/* in the current full listing */
};

/* One address book of the session's user. Everything here lives in session memory only. */
struct dav_context {
	char			*username;
	struct indexing_context	*ictx;
	struct GUID		replica_guid, mailbox_guid;
	struct dav_named_tags	tags;
	struct dav_fpstore	*fp;
	char			*home;		/* the user's address-book home URL */
	char			*book_href;	/* server path of the book, ending with '/' */
	char			*book_norm;
	char			*uri;		/* dav://contacts/<segment>/ */
	char			*displayname;
	char			*token;		/* sync token; NULL: the next listing is a full one */
	struct dav_item		*items;
	size_t			nitems;
	uint64_t		*deleted;	/* MIDs of cards gone, for ICS (emsmdb keeps those Outlook holds) */
	size_t			ndeleted;
	unsigned		deletions;	/* ever added to deleted: the state of the deletions' change */
	struct dav_folder	*root;
	/* R14: reads reuse these for the sync window, until a poll sees a change (see dav_folder.c) */
	time_t			synced_at, books_at;
	unsigned		synced_gen, books_gen;
	struct dav_book		*books;		/* the user's books, as last listed */
	size_t			nbooks;
	struct dav_context	**children;	/* personal: the other books' contexts, kept between opens */
	size_t			nchildren;
};

struct dav_folder {
	uint32_t		type;		/* DAV_OBJ_FOLDER */
	struct dav_context	*ctx;
	uint64_t		fid;
	uint64_t		parent_fid;	/* another book: personal's folder ID; 0 for a context's own root */
};

struct dav_message {
	uint32_t		type;		/* DAV_OBJ_MESSAGE */
	struct dav_folder	*folder;
	uint64_t		mid;
	char			*href, *etag;	/* href: normalized; both NULL for a message not saved yet */
	char			*path;		/* the card's server path, as the server spells it */
	struct dav_card		*card;		/* the version opened; NULL for a new message */
	/* Outlook's write */
	struct SRow		*props;		/* set since the last save */
	struct Binary_r		*client_ck, *client_pcl;
	/* the version Outlook had been given before this open, when the server's changed since: the base
	   of a save without PCL (Outlook reopens a contact to upload an offline edit) */
	uint64_t		given_fp[DAV_F_COUNT];
	bool			has_given;
	uint64_t		held_cn;	/* after a merged save without keys: the change Outlook holds */
	bool			full;		/* purged: the upload carries the whole message, absent = removed */
	struct dav_attachment	*photo;		/* the contact picture Outlook attached */
};

struct dav_attachment {
	uint32_t		type;		/* DAV_OBJ_ATTACHMENT: the contact picture */
	struct dav_message	*message;
	struct Binary_r		*data;		/* written by Outlook */
};

struct dav_table {
	uint32_t			type;	/* DAV_OBJ_TABLE */
	struct dav_folder		*folder;
	enum mapistore_table_type	table_type;
	uint16_t			column_count;
	enum MAPITAGS			*columns;
	uint32_t			row_count;
	uint64_t			*mids;		/* message table: rows by MID (items move on a sync) */
	struct dav_message		*message;	/* attachment table */
	struct dav_folder		**folders;	/* folder table: personal's other books */
};

/* dav_folder.c */
void dav_folder_fill(struct mapistore_backend *);
/* The session's HTTP client, with the password as it is now; NULL without credentials. */
struct dav_http *dav_context_http(struct dav_context *, TALLOC_CTX *);
/* Brings the item list up to date (sync-collection); a read within the sync window reuses the last one. */
enum mapistore_error dav_context_sync(struct dav_context *);
/* The same, now: after a write, or when an item the client names is missing. */
enum mapistore_error dav_context_resync(struct dav_context *);
struct dav_item *dav_item_by_mid(struct dav_context *, uint64_t mid);
/* Fetches the cards not cached yet (addressbook-multiget). */
enum mapistore_error dav_context_fetch(struct dav_context *);
char *dav_item_uri(TALLOC_CTX *, struct dav_context *, const char *norm);
/* A change property of the object at uri, renewed whenever state (an ETag) changes. */
void *dav_change_value(TALLOC_CTX *, struct dav_context *, const char *uri, const char *state, enum MAPITAGS);
/* When the card at norm reached this version: the first time this process saw its ETag. */
time_t dav_etag_time(struct dav_context *, const char *norm, const char *etag);
/* After a PUT of the card of mid at href: the item list and the indexing follow (a new href takes the MID). */
enum mapistore_error dav_item_put(struct dav_context *, uint64_t mid, const char *href, const char *etag, struct dav_card *);
/* The state at uri is Outlook's change (its keys), or a merge of it (a server change whose PCL includes it).
   Without keys (a save of an opened message) Outlook's change gets a number of its own; *held: the change
   Outlook now holds when the stored state is a later merge, else 0. */
void dav_change_record(struct dav_context *, const char *uri, const char *etag, const struct Binary_r *ck,
		       const struct Binary_r *pcl, bool merged, uint64_t *held);
enum mapistore_error dav_folder_set_properties(struct dav_folder *, struct SRow *);
uint64_t *dav_i8(TALLOC_CTX *, uint64_t);
uint32_t *dav_long(TALLOC_CTX *, uint32_t);
uint8_t *dav_bool(TALLOC_CTX *, bool);

/* dav_message.c */
void dav_message_fill(struct mapistore_backend *);
/* List members of folder f: a member card of the book <-> the Message EntryID of its contact. */
void dav_folder_resolver(struct dav_folder *, struct dav_member_resolver *);
/* One property of the card at norm shown in folder f; NULL when it has none. card may be NULL (not fetched). */
void *dav_item_value(TALLOC_CTX *, struct dav_folder *, uint64_t mid, const char *norm, const char *etag,
		     const struct dav_card *, enum MAPITAGS);
enum mapistore_error dav_message_properties(struct dav_message *, TALLOC_CTX *, uint16_t, enum MAPITAGS *,
					    struct mapistore_property_data *);
enum mapistore_error dav_attachment_properties(struct dav_message *, TALLOC_CTX *, uint16_t, enum MAPITAGS *,
					       struct mapistore_property_data *);

/* dav_merge.c */
bool dav_field_applies(const struct dav_card *, enum dav_field);
/* A members field (keys) with each mailto: key that names a CARD line of c (by EMAIL) as that line's key. */
char *dav_members_normalize(TALLOC_CTX *, const struct dav_card *c, const char *keys);
/* Outlook's values into the server's card (see dav_merge.c); base NULL: no fingerprint. today: YYYY-MM-DD. */
enum mapistore_error dav_merge(TALLOC_CTX *, struct dav_card *server, const char *outlook[DAV_F_COUNT],
			       const bool outlook_present[DAV_F_COUNT], const uint64_t base[DAV_F_COUNT],
			       time_t outlook_time, time_t server_time, const uint8_t *key, size_t key_len,
			       const char *today);

/* dav_cred.c: per-user password, reference counted by sessions. The result of get is valid only until the
   next dav_cred_set or dav_cred_forget of that user: fetch it for each HTTP client, never keep it. */
enum mapistore_error dav_cred_set(const char *, const char *);
enum mapistore_error dav_cred_forget(const char *);
const char *dav_cred_get(const char *);
/* Tests only: sees each password buffer after the wipe, right before free. */
void dav_cred_set_free_hook(void (*hook)(const char *buf, size_t len));

#endif /* ! __DAV_BACKEND_H__ */
