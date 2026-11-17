/*
   CardDAV mapistore backend: contacts and distribution lists as Outlook messages (read side)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <string.h>
#include <strings.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "gen_ndr/ndr_property.h"
#include "dav_backend.h"
#include "dav_http.h"
#include "dav_fpstore.h"

/* Outlook shows a contact's picture from this attachment (MS-OXOCNTC 2.2.1.8). */
#define CONTACT_PICTURE "ContactPicture.jpg"

void dav_fp_card(const uint8_t *key, size_t key_len, const struct dav_card *c, uint64_t fp[DAV_F_COUNT])
{
	TALLOC_CTX	*tmp = talloc_new(NULL);
	int		f;

	for (f = 0; f < DAV_F_COUNT; f++) {
		fp[f] = dav_fp(key, key_len, f, tmp ? dav_field_get(tmp, c, f) : NULL);
	}
	talloc_free(tmp);
}

/* The listed card whose href ends with name. */
static struct dav_item *item_by_segment(struct dav_context *ctx, const char *name)
{
	size_t i;

	for (i = 0; i < ctx->nitems; i++) {
		if (strcmp(strrchr(ctx->items[i].norm, '/') + 1, name) == 0) return &ctx->items[i];
	}
	return NULL;
}

/* A list member names its card by "<UID>.vcf", the card's href in SOGo: the Message EntryID of
   that card in this folder (MS-OXCDATA 2.2.4.2), or NULL when the book has no such card. */
static struct Binary_r *entryid_for_uid(void *p, TALLOC_CTX *mem_ctx, const char *uid)
{
	struct dav_folder	*f = p;
	struct dav_item		*it = item_by_segment(f->ctx, talloc_asprintf(mem_ctx, "%s.vcf", uid));
	struct MessageEntryId	e;
	struct Binary_r		*b;
	DATA_BLOB		blob;

	if (!it && !(it = item_by_segment(f->ctx, uid))) return NULL;
	memset(&e, 0, sizeof e);
	e.ProviderUID = f->ctx->mailbox_guid;
	e.MessageType = eitLTPPrivateMessage;
	e.FolderDatabaseGuid = f->ctx->replica_guid;
	e.FolderGlobalCounter.value = f->fid >> 16;
	e.MessageDatabaseGuid = f->ctx->replica_guid;
	e.MessageGlobalCounter.value = it->mid >> 16;
	if (ndr_push_struct_blob(&blob, mem_ctx, &e, (ndr_push_flags_fn_t) ndr_push_MessageEntryId) != NDR_ERR_SUCCESS ||
	    !(b = talloc_zero(mem_ctx, struct Binary_r))) {
		return NULL;
	}
	b->cb = blob.length;
	b->lpb = talloc_steal(b, blob.data);
	return b;
}

static char *uid_for_entryid(void *p, TALLOC_CTX *mem_ctx, const struct Binary_r *bin)
{
	struct dav_folder	*f = p;
	struct MessageEntryId	*e = get_MessageEntryId(mem_ctx, discard_const_p(struct Binary_r, bin));
	uint64_t		counter;
	char			*name;
	size_t			i, n;

	if (!e || e->MessageType != eitLTPPrivateMessage || !GUID_equal(&e->ProviderUID, &f->ctx->mailbox_guid)) {
		return NULL;
	}
	counter = (uint64_t) e->MessageGlobalCounter.value & 0xFFFFFFFFFFFFULL;
	for (i = 0; i < f->ctx->nitems; i++) {
		if ((f->ctx->items[i].mid >> 16) != counter) continue;
		name = talloc_strdup(mem_ctx, strrchr(f->ctx->items[i].norm, '/') + 1);
		n = name ? strlen(name) : 0;
		if (n > 4 && strcasecmp(name + n - 4, ".vcf") == 0) name[n - 4] = '\0';
		return name;
	}
	return NULL;
}

void dav_folder_resolver(struct dav_folder *f, struct dav_member_resolver *r)
{
	r->ctx = f;
	r->entryid_for_uid = entryid_for_uid;
	r->uid_for_entryid = uid_for_entryid;
}

static bool has_photo(TALLOC_CTX *mem_ctx, struct dav_folder *f, const struct dav_card *card)
{
	void *v;

	return card && dav_card_get_prop(mem_ctx, card, &f->ctx->tags, NULL, PidTagAttachDataBinary, &v) == MAPISTORE_SUCCESS;
}

void *dav_item_value(TALLOC_CTX *mem_ctx, struct dav_folder *f, uint64_t mid, const char *norm, const char *etag,
		     const struct dav_card *card, enum MAPITAGS tag)
{
	struct dav_member_resolver	r;
	void				*v;

	dav_folder_resolver(f, &r);

	switch (tag) {
	case PidTagMid:
		return dav_i8(mem_ctx, mid);
	case PidTagFolderId:
	case PidTagParentFolderId:
		return dav_i8(mem_ctx, f->fid);
	case PidTagChangeNumber:
	case PidTagChangeKey:
	case PidTagPredecessorChangeList:
	case PidTagLastModificationTime:
		/* the ETag is the card's version */
		return dav_change_value(mem_ctx, f->ctx, dav_item_uri(mem_ctx, f->ctx, norm), etag, tag);
	case PidTagMessageFlags:
		return dav_long(mem_ctx, MSGFLAG_READ | (has_photo(mem_ctx, f, card) ? MSGFLAG_HASATTACH : 0));
	case PidTagRead:
		return dav_bool(mem_ctx, true);
	case PidTagHasAttachments:
		return dav_bool(mem_ctx, has_photo(mem_ctx, f, card));
	case PidTagAttachDataBinary:
		return NULL;	/* the picture's bytes belong to its attachment */
	default:
		return card && dav_card_get_prop(mem_ctx, card, &f->ctx->tags, &r, tag, &v) == MAPISTORE_SUCCESS ? v : NULL;
	}
}

/* Fingerprints of the version Outlook now holds: the base of the field merge on its next upload. */
static void record_fingerprints(struct dav_context *ctx, const struct dav_item *it)
{
	const struct dav_settings	*settings = dav_backend_settings();
	uint64_t			fp[DAV_F_COUNT];
	enum mapistore_error		ret;

	dav_fp_card(settings->fp_key, settings->fp_key_len, it->card, fp);
	ret = dav_fp_put(ctx->fp, ctx->username, it->norm, fp, it->etag);
	if (ret != MAPISTORE_SUCCESS) {
		OC_DEBUG(1, "DAV backend: fingerprints not stored (%s)\n", mapistore_errstr(ret));
	}
}

static enum mapistore_error open_message(void *folder, TALLOC_CTX *mem_ctx, uint64_t mid, bool read_write,
					 void **messagep)
{
	struct dav_folder	*f = folder;
	struct dav_context	*ctx;
	struct dav_message	*m;
	struct dav_item		*it;
	struct dav_http		*h;
	char			*body = NULL, *etag = NULL;
	enum mapistore_error	ret;

	if (!f || f->type != DAV_OBJ_FOLDER || !messagep) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	ctx = f->ctx;
	if (!(it = dav_item_by_mid(ctx, mid))) {
		ret = dav_context_sync(ctx);
		if (ret != MAPISTORE_SUCCESS) return ret;
		if (!(it = dav_item_by_mid(ctx, mid))) return MAPISTORE_ERR_NOT_FOUND;
	}
	if (!it->card) {
		h = dav_context_http(ctx, ctx);
		ret = h ? dav_get(h, ctx, it->href, &body, &etag) : MAPISTORE_ERR_CONN_REFUSED;
		talloc_free(h);
		if (ret == MAPISTORE_SUCCESS && !(it->card = dav_card_parse(ctx, body, strlen(body)))) {
			ret = MAPISTORE_ERR_INVALID_DATA;
		}
		talloc_free(body);
		if (ret == MAPISTORE_SUCCESS && etag && strcmp(etag, it->etag) != 0) {
			talloc_free(it->etag);
			it->etag = talloc_steal(ctx, etag);
			etag = NULL;
		}
		talloc_free(etag);
		if (ret != MAPISTORE_SUCCESS) return ret;
	}
	m = talloc_zero(mem_ctx, struct dav_message);
	if (!m || !(m->href = talloc_strdup(m, it->norm)) || !(m->etag = talloc_strdup(m, it->etag)) ||
	    !talloc_reference(m, it->card)) {
		talloc_free(m);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	m->type = DAV_OBJ_MESSAGE;
	m->folder = f;
	m->mid = mid;
	m->card = it->card;
	record_fingerprints(ctx, it);
	*messagep = m;
	return MAPISTORE_SUCCESS;
}

enum mapistore_error dav_message_properties(struct dav_message *m, TALLOC_CTX *mem_ctx, uint16_t count,
					    enum MAPITAGS *tags, struct mapistore_property_data *data)
{
	uint16_t i;

	for (i = 0; i < count; i++) {
		data[i].data = dav_item_value(mem_ctx, m->folder, m->mid, m->href, m->etag, m->card, tags[i]);
		data[i].error = data[i].data ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NOT_FOUND;
	}
	return MAPISTORE_SUCCESS;
}

enum mapistore_error dav_attachment_properties(struct dav_message *m, TALLOC_CTX *mem_ctx, uint16_t count,
					       enum MAPITAGS *tags, struct mapistore_property_data *data)
{
	struct Binary_r	*photo = NULL;
	uint16_t	i;

	dav_card_get_prop(mem_ctx, m->card, &m->folder->ctx->tags, NULL, PidTagAttachDataBinary, (void **) &photo);
	for (i = 0; i < count; i++) {
		void *v;

		switch (tags[i]) {
		case PidTagAttachNumber:		v = dav_long(mem_ctx, 0); break;
		case PidTagAttachMethod:		v = dav_long(mem_ctx, 1); break; /* afByValue */
		case PidTagAttachSize:			v = photo ? dav_long(mem_ctx, photo->cb) : NULL; break;
		case PidTagRenderingPosition:		v = dav_long(mem_ctx, 0xFFFFFFFF); break;
		case PidTagAttachFlags:			v = dav_long(mem_ctx, 0); break;
		case PidTagAttachmentHidden:
		case PidTagAttachmentContactPhoto:	v = dav_bool(mem_ctx, true); break;
		case PidTagAttachLongFilename:
		case PidTagAttachFilename:
		case PidTagDisplayName:			v = talloc_strdup(mem_ctx, CONTACT_PICTURE); break;
		case PidTagAttachExtension:		v = talloc_strdup(mem_ctx, ".jpg"); break;
		case PidTagAttachDataBinary:		v = photo; break;
		default:				v = NULL; break;
		}
		data[i].data = v;
		data[i].error = v ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NOT_FOUND;
	}
	return MAPISTORE_SUCCESS;
}

/* Contacts carry no recipients. */
static enum mapistore_error get_message_data(void *object, TALLOC_CTX *mem_ctx, struct mapistore_message **msgp)
{
	struct dav_message		*m = object;
	struct mapistore_message	*msg;
	void				*name;

	if (!m || m->type != DAV_OBJ_MESSAGE || !msgp) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	msg = talloc_zero(mem_ctx, struct mapistore_message);
	name = msg ? dav_item_value(msg, m->folder, m->mid, m->href, m->etag, m->card, PidTagDisplayName) : NULL;
	if (!msg || !(msg->subject_prefix = talloc_strdup(msg, "")) ||
	    !(msg->normalized_subject = name ? name : talloc_strdup(msg, "")) || !(msg->columns = talloc_zero(msg, struct SPropTagArray))) {
		talloc_free(msg);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	*msgp = msg;
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error get_attachment_table(void *object, TALLOC_CTX *mem_ctx, void **tablep, uint32_t *row_count)
{
	struct dav_message	*m = object;
	struct dav_table	*t;

	if (!m || m->type != DAV_OBJ_MESSAGE || !tablep || !row_count) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	t = talloc_zero(mem_ctx, struct dav_table);
	if (!t) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	t->type = DAV_OBJ_TABLE;
	t->folder = m->folder;
	t->message = m;
	t->table_type = MAPISTORE_ATTACHMENT_TABLE;
	t->row_count = has_photo(t, m->folder, m->card) ? 1 : 0;
	*tablep = t;
	*row_count = t->row_count;
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error open_attachment(void *object, TALLOC_CTX *mem_ctx, uint32_t number, void **attachment)
{
	struct dav_message	*m = object;
	struct dav_attachment	*a;

	if (!m || m->type != DAV_OBJ_MESSAGE || !attachment) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (number != 0 || !has_photo(m, m->folder, m->card)) {
		return MAPISTORE_ERR_NOT_FOUND;
	}
	a = talloc_zero(mem_ctx, struct dav_attachment);
	if (!a) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	a->type = DAV_OBJ_ATTACHMENT;
	a->message = m;
	*attachment = a;
	return MAPISTORE_SUCCESS;
}

void dav_message_fill(struct mapistore_backend *backend)
{
	backend->folder.open_message = open_message;
	backend->message.get_message_data = get_message_data;
	backend->message.get_attachment_table = get_attachment_table;
	backend->message.open_attachment = open_attachment;
}
