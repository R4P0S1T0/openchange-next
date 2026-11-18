/*
   CardDAV mapistore backend: vCard / VLIST <-> merge fields <-> MAPI contact and distribution list

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#ifndef	__DAV_MAP_H__
#define	__DAV_MAP_H__

#include <stdbool.h>
#include <stdint.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "dav_vcard.h"

/* Largest picture (decoded bytes) taken from Outlook: SOGo and phones choke on huge PHOTOs. */
#define DAV_PHOTO_MAX (1024 * 1024)

/* One value per row of the spec's mapping table; the unit of the field-level merge. */
enum dav_field {
	DAV_F_FN, DAV_F_N_FAMILY, DAV_F_N_GIVEN, DAV_F_N_MIDDLE, DAV_F_N_PREFIX, DAV_F_N_SUFFIX,
	DAV_F_EMAIL1, DAV_F_EMAIL2, DAV_F_EMAIL3,
	DAV_F_TEL_WORK, DAV_F_TEL_HOME, DAV_F_TEL_CELL, DAV_F_TEL_FAX,
	DAV_F_ORG, DAV_F_ORG_UNIT, DAV_F_TITLE, DAV_F_ADR_WORK, DAV_F_ADR_HOME,
	DAV_F_NOTE, DAV_F_BDAY, DAV_F_URL, DAV_F_PHOTO, DAV_F_LIST_NAME, DAV_F_LIST_MEMBERS,
	DAV_F_COUNT
};

/* Full property tags (mapped id << 16 | type) of the PidLid properties used. */
struct dav_named_tags {
	uint32_t	email_address[3], email_display_name[3], email_address_type[3];
	uint32_t	file_under, has_picture;
	uint32_t	work_street, work_city, work_state, work_postal_code, work_country, work_po_box;
	uint32_t	dl_name, dl_members, dl_one_off_members, dl_checksum;
	/* read-only, derived from the e-mails: what Outlook's contacts address book lists */
	uint32_t	email_original_display_name[3], email_original_entryid[3], abp_email_list, abp_array_type;
};

/* Maps a list member's card UID to the Message EntryID of that contact and back (NULL: unknown). */
struct dav_member_resolver {
	void		*ctx;
	struct Binary_r	*(*entryid_for_uid)(void *ctx, TALLOC_CTX *, const char *uid);
	char		*(*uid_for_entryid)(void *ctx, TALLOC_CTX *, const struct Binary_r *);
};

/* key: member card UID, or "mailto:<lowercase email>" for an address with no card. */
struct dav_member {
	char	*key;
	char	*name;
	char	*email;
};

enum mapistore_error dav_named_tags_resolve(struct namedprops_context *, struct dav_named_tags *);

/* Normalized value (NULL when absent or empty). ADR: the 7 components, each still
   vCard-escaped so the "\n" separator is unambiguous, extended address always empty. */
char *dav_field_get(TALLOC_CTX *, const struct dav_card *, enum dav_field);
/* value NULL removes; untrusted input is escaped/neutralized, never a line break. */
void dav_field_set(struct dav_card *, enum dav_field, const char *value);
/* Set merge: a mailto: key keeps a line with that EMAIL; lines Outlook was never shown (r cannot
   resolve them and they have no EMAIL; r may be NULL) are kept. */
void dav_list_set_members(struct dav_card *, const struct dav_member_resolver *r,
			  const struct dav_member *, size_t count);

/* Parameter NAME of a line, quotes removed; NULL when absent. */
char *dav_line_param(TALLOC_CTX *, const struct dav_line *, const char *name);
/* CARD lines without EMAIL or FN take them from the member of m that names them. */
void dav_list_complete(struct dav_card *, const struct dav_member *m, size_t count);

enum mapistore_error dav_card_get_prop(TALLOC_CTX *, const struct dav_card *, const struct dav_named_tags *,
				       const struct dav_member_resolver *, enum MAPITAGS, void **value);
/* props may hold PidTagAttachDataBinary = the contact picture attachment's bytes.
   base (may be NULL) supplies the address components Outlook did not send. */
void dav_props_to_fields(TALLOC_CTX *, struct SRow *props, const struct dav_named_tags *,
			 const struct dav_member_resolver *, const struct dav_card *base,
			 char *values[DAV_F_COUNT], bool present[DAV_F_COUNT]);
/* Members of a distribution list in Outlook's properties; false when the row has none. */
bool dav_props_members(TALLOC_CTX *, struct SRow *props, const struct dav_named_tags *,
		       const struct dav_member_resolver *, struct dav_member **, size_t *count);

#endif /* ! __DAV_MAP_H__ */
