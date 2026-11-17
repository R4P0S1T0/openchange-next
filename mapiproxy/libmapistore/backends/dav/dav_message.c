/*
   CardDAV mapistore backend: contacts and distribution lists as Outlook messages (read side)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <time.h>

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

/* Fingerprints of the version Outlook is now shown: the last one shown (what a delete names) and one of the
   versions an upload's PredecessorChangeList can name as its base. */
static void record_fingerprints(struct dav_context *ctx, const char *norm, const char *etag, const struct dav_card *card)
{
	const struct dav_settings	*settings = dav_backend_settings();
	TALLOC_CTX			*tmp = talloc_new(NULL);
	uint64_t			fp[DAV_F_COUNT];
	struct Binary_r			*ck;
	enum mapistore_error		ret;

	dav_fp_card(settings->fp_key, settings->fp_key_len, card, fp);
	ret = dav_fp_put(ctx->fp, ctx->username, norm, fp, etag);
	ck = tmp ? dav_change_value(tmp, ctx, dav_item_uri(tmp, ctx, norm), etag, PidTagChangeKey) : NULL;
	if (ret == MAPISTORE_SUCCESS) {
		ret = ck ? dav_fp_version_put(ctx->fp, ctx->username, norm, ck, fp, etag) : MAPISTORE_ERR_NO_MEMORY;
	}
	if (ret != MAPISTORE_SUCCESS) {
		OC_DEBUG(1, "DAV backend: fingerprints not stored (%s)\n", mapistore_errstr(ret));
	}
	talloc_free(tmp);
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
	    !(m->path = talloc_strdup(m, it->href)) || !talloc_reference(m, it->card)) {
		talloc_free(m);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	m->type = DAV_OBJ_MESSAGE;
	m->folder = f;
	m->mid = mid;
	m->card = it->card;
	record_fingerprints(ctx, it->norm, it->etag, it->card);
	*messagep = m;
	return MAPISTORE_SUCCESS;
}

enum mapistore_error dav_message_properties(struct dav_message *m, TALLOC_CTX *mem_ctx, uint16_t count,
					    enum MAPITAGS *tags, struct mapistore_property_data *data)
{
	uint16_t i;
	uint32_t j;

	for (i = 0; i < count; i++) {
		data[i].data = NULL;
		/* not saved yet: what Outlook set */
		for (j = 0; !m->href && m->props && j < m->props->cValues; j++) {
			if ((enum MAPITAGS) m->props->lpProps[j].ulPropTag == tags[i]) {
				data[i].data = (void *) get_SPropValue_data(&m->props->lpProps[j]);
			}
		}
		if (m->href) data[i].data = dav_item_value(mem_ctx, m->folder, m->mid, m->href, m->etag, m->card, tags[i]);
		data[i].error = data[i].data ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NOT_FOUND;
	}
	return MAPISTORE_SUCCESS;
}

enum mapistore_error dav_attachment_properties(struct dav_message *m, TALLOC_CTX *mem_ctx, uint16_t count,
					       enum MAPITAGS *tags, struct mapistore_property_data *data)
{
	struct Binary_r	*photo = NULL;
	uint16_t	i;

	if (m->card) dav_card_get_prop(mem_ctx, m->card, &m->folder->ctx->tags, NULL, PidTagAttachDataBinary, (void **) &photo);
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

/* ---- write ---- */

static enum mapistore_error create_message(void *folder, TALLOC_CTX *mem_ctx, uint64_t mid, uint8_t associated,
					   void **messagep)
{
	struct dav_folder	*f = folder;
	struct dav_message	*m;

	if (!f || f->type != DAV_OBJ_FOLDER || !messagep) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (associated) {
		return MAPISTORE_ERR_DENIED;	/* FAI (views, rules) have no vCard form */
	}
	m = talloc_zero(mem_ctx, struct dav_message);
	if (!m) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	m->type = DAV_OBJ_MESSAGE;
	m->folder = f;
	m->mid = mid;
	*messagep = m;
	return MAPISTORE_SUCCESS;
}

static bool row_has(const struct SRow *row, uint32_t tag)
{
	uint32_t i;

	for (i = 0; i < row->cValues; i++) if ((uint32_t) row->lpProps[i].ulPropTag == tag) return true;
	return false;
}

/* Outlook's properties so far, a later value of a tag replacing the earlier one. */
static enum mapistore_error message_set_properties(struct dav_message *m, struct SRow *row)
{
	uint32_t	n = m->props ? m->props->cValues : 0, i;
	struct SRow	*props = talloc_zero(m, struct SRow);

	if (!props || !(props->lpProps = talloc_array(props, struct SPropValue, n + row->cValues))) {
		talloc_free(props);
		return MAPISTORE_ERR_NO_MEMORY;
	}
	for (i = 0; i < n; i++) {
		if (row_has(row, m->props->lpProps[i].ulPropTag)) continue;
		mapi_copy_spropvalues(props, &m->props->lpProps[i], &props->lpProps[props->cValues++], 1);
	}
	mapi_copy_spropvalues(props, row->lpProps, &props->lpProps[props->cValues], row->cValues);
	props->cValues += row->cValues;
	talloc_free(m->props);
	m->props = props;
	/* ICS uploads carry Outlook's change key and PCL: kept for the change it is making. */
	for (i = 0; i < row->cValues; i++) {
		const struct SPropValue *p = &row->lpProps[i];
		struct Binary_r **dst = p->ulPropTag == PidTagChangeKey ? &m->client_ck
					: p->ulPropTag == PidTagPredecessorChangeList ? &m->client_pcl : NULL;

		if (!dst) continue;
		talloc_free(*dst);
		if (!(*dst = mapistore_binary_dup(m, &p->value.bin))) return MAPISTORE_ERR_NO_MEMORY;
	}
	return MAPISTORE_SUCCESS;
}

/* Only the contact picture is kept (PidTagAttachmentContactPhoto); other attachments have no vCard form. */
static enum mapistore_error attachment_set_properties(struct dav_attachment *a, struct SRow *row)
{
	uint32_t i;

	for (i = 0; i < row->cValues; i++) {
		const struct SPropValue *p = &row->lpProps[i];

		if (p->ulPropTag == PidTagAttachDataBinary) {
			talloc_free(a->data);
			if (!(a->data = mapistore_binary_dup(a, &p->value.bin))) return MAPISTORE_ERR_NO_MEMORY;
		} else if (p->ulPropTag == PidTagAttachmentContactPhoto && p->value.b) {
			a->message->photo = a;
		}
	}
	return MAPISTORE_SUCCESS;
}

static enum mapistore_error set_properties(void *object, struct SRow *row)
{
	uint32_t type = object ? *(uint32_t *) object : 0;

	if (!row) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	switch (type) {
	case DAV_OBJ_MESSAGE:		return message_set_properties(object, row);
	case DAV_OBJ_ATTACHMENT:	return attachment_set_properties(object, row);
	case DAV_OBJ_FOLDER:		return dav_folder_set_properties(object, row);
	default:			return MAPISTORE_ERR_INVALID_PARAMETER;
	}
}

static enum mapistore_error create_attachment(void *object, TALLOC_CTX *mem_ctx, void **attachment, uint32_t *aid)
{
	struct dav_message	*m = object;
	struct dav_attachment	*a;

	if (!m || m->type != DAV_OBJ_MESSAGE || !attachment || !aid) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	if (!(a = talloc_zero(m, struct dav_attachment))) {
		return MAPISTORE_ERR_NO_MEMORY;
	}
	a->type = DAV_OBJ_ATTACHMENT;
	a->message = m;
	*attachment = a;
	*aid = 0;
	return MAPISTORE_SUCCESS;
}

/* ICS upload (MS-OXCFXICS 2.2.3.2.4.2): the properties that follow are the whole message. */
static enum mapistore_error purge(void *object)
{
	struct dav_message *m = object;

	if (!m || m->type != DAV_OBJ_MESSAGE) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	m->full = true;
	m->photo = NULL;
	return MAPISTORE_SUCCESS;
}

static bool same(const char *a, const char *b)
{
	return !a || !*a ? !b || !*b : b && strcmp(a, b) == 0;
}

static char *new_uid(TALLOC_CTX *mem_ctx)
{
	struct GUID g = GUID_random();

	return GUID_string(mem_ctx, &g);
}

/* What Outlook wrote, the picture's bytes as PidTagAttachDataBinary. */
static struct SRow *outlook_row(TALLOC_CTX *mem_ctx, struct dav_message *m)
{
	struct SRow	*row = talloc_zero(mem_ctx, struct SRow);
	uint32_t	n = m->props ? m->props->cValues : 0;

	if (!row || !(row->lpProps = talloc_array(row, struct SPropValue, n + 1))) {
		talloc_free(row);
		return NULL;
	}
	if (n) memcpy(row->lpProps, m->props->lpProps, n * sizeof *row->lpProps);
	row->cValues = n;
	if (m->photo && m->photo->data) {
		set_SPropValue_proptag(&row->lpProps[row->cValues++], PidTagAttachDataBinary, m->photo->data);
	}
	return row;
}

static void outlook_fields(TALLOC_CTX *mem_ctx, struct dav_message *m, struct SRow *row, const struct dav_card *server,
			   char *v[DAV_F_COUNT], bool p[DAV_F_COUNT])
{
	struct dav_member_resolver	r;
	int				f;

	dav_folder_resolver(m->folder, &r);
	dav_props_to_fields(mem_ctx, row, &m->folder->ctx->tags, &r, server, v, p);
	for (f = 0; m->full && f < DAV_F_COUNT; f++) {
		/* a whole message: what it lacks, Outlook removed (a picture too big to sync is no removal) */
		if (!p[f] && !(f == DAV_F_PHOTO && row_has(row, PidTagAttachDataBinary))) {
			p[f] = true;
			v[f] = NULL;
		}
	}
}

static time_t outlook_time(struct SRow *row, time_t now)
{
	uint32_t i;

	for (i = 0; i < row->cValues; i++) {
		const struct FILETIME *ft = &row->lpProps[i].value.ft;
		uint64_t nt = ((uint64_t) ft->dwHighDateTime << 32) | ft->dwLowDateTime;

		if (row->lpProps[i].ulPropTag == PidTagLastModificationTime && nt / 10000000ULL > 11644473600ULL) {
			return (time_t) (nt / 10000000ULL - 11644473600ULL);
		}
	}
	return now;
}

/* When the server's version was made: its REV (UTC), else when this process first saw its ETag. */
static time_t server_time(struct dav_context *ctx, const struct dav_card *c, const char *norm, const char *etag)
{
	struct dav_line	*l = dav_card_find(c, "REV", NULL, 0);
	char		d[15];
	const char	*s;
	size_t		k = 0;
	struct tm	tm;

	for (s = l ? l->value : ""; *s && k < 14; s++) if (*s >= '0' && *s <= '9') d[k++] = *s;
	d[k] = '\0';
	memset(&tm, 0, sizeof tm);
	if (k >= 8 && sscanf(d, "%4d%2d%2d%2d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) >= 3) {
		tm.tm_year -= 1900;
		tm.tm_mon -= 1;
		return timegm(&tm);
	}
	return dav_etag_time(ctx, norm, etag);
}

/* Members Outlook added: EMAIL and FN on their CARD line, and for a free address the stub card SOGo's web
   UI makes (FN + EMAIL), which the line then names. stubs (email, uid pairs) survive a retried merge. */
static enum mapistore_error complete_members(struct dav_message *m, struct dav_http *h, TALLOC_CTX *mem_ctx,
					     struct dav_card *c, struct SRow *row, char ***stubs, size_t *nstubs)
{
	struct dav_context		*ctx = m->folder->ctx;
	struct dav_member_resolver	r;
	struct dav_member		*mem;
	struct dav_line			*l;
	struct dav_card			*stub;
	size_t				n, i, j;
	char				*email, *fn, *body;
	enum mapistore_error		ret;

	if (strcmp(dav_card_kind(c), "VLIST") != 0) return MAPISTORE_SUCCESS;
	dav_folder_resolver(m->folder, &r);
	if (dav_props_members(mem_ctx, row, &ctx->tags, &r, &mem, &n)) dav_list_complete(c, mem, n);
	for (i = 0; (l = dav_card_find(c, "CARD", NULL, i)); i++) {
		if (*l->value || !(email = dav_line_param(mem_ctx, l, "EMAIL")) || !*email) continue;
		for (j = 0; j < *nstubs && strcasecmp((*stubs)[2 * j], email) != 0; j++);
		if (j == *nstubs) {
			fn = dav_line_param(mem_ctx, l, "FN");
			*stubs = talloc_realloc(mem_ctx, *stubs, char *, 2 * j + 2);
			if (!*stubs || !((*stubs)[2 * j] = email) || !((*stubs)[2 * j + 1] = new_uid(mem_ctx))) return MAPISTORE_ERR_NO_MEMORY;
			body = talloc_asprintf(mem_ctx, "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:%s\r\nEND:VCARD\r\n", (*stubs)[2 * j + 1]);
			if (!body || !(stub = dav_card_parse(mem_ctx, body, strlen(body)))) return MAPISTORE_ERR_NO_MEMORY;
			dav_field_set(stub, DAV_F_FN, fn && *fn ? fn : email);
			dav_card_set(stub, "EMAIL", "work", 0, dav_text_escape(mem_ctx, email));
			ret = dav_put(h, mem_ctx, talloc_asprintf(mem_ctx, "%s%s.vcf", ctx->book_href, (*stubs)[2 * j + 1]),
				      dav_card_render(mem_ctx, stub), NULL, NULL, true, NULL);
			if (ret != MAPISTORE_SUCCESS) return ret;
			(*nstubs)++;
		}
		talloc_free(l->value);
		if (!(l->value = talloc_asprintf(c, "%s.vcf", (*stubs)[2 * j + 1]))) return MAPISTORE_ERR_NO_MEMORY;
		l->touched = true;
	}
	return MAPISTORE_SUCCESS;
}

/* PUT with If-Match, or as a new card; REV, when the card keeps one, tells when. */
static enum mapistore_error put_card(struct dav_http *h, TALLOC_CTX *mem_ctx, const char *path, struct dav_card *c,
				     const char *if_match, time_t now, char **etag)
{
	char		rev[32];
	struct tm	tm;
	char		*body;

	if (dav_card_find(c, "REV", NULL, 0) && gmtime_r(&now, &tm) && strftime(rev, sizeof rev, "%Y%m%dT%H%M%SZ", &tm)) {
		dav_card_set(c, "REV", NULL, 0, rev);
	}
	if (!(body = dav_card_render(mem_ctx, c))) return MAPISTORE_ERR_NO_MEMORY;
	return dav_put(h, mem_ctx, path, body, NULL, if_match, !if_match, etag);
}

static const char *message_class(struct SRow *row)
{
	uint32_t i;

	for (i = 0; i < row->cValues; i++) {
		if (row->lpProps[i].ulPropTag == PidTagMessageClass) return row->lpProps[i].value.lpszW;
		if (row->lpProps[i].ulPropTag == PidTagMessageClass_string8) return row->lpProps[i].value.lpszA;
	}
	return NULL;
}

/* A new card, or Outlook's version again after another client deleted it: at a fresh href (SOGo ignores
   If-None-Match and would overwrite), the UID kept. */
static enum mapistore_error create_put(struct dav_message *m, struct dav_http *h, TALLOC_CTX *mem_ctx, struct SRow *row,
				       char *v[DAV_F_COUNT], bool p[DAV_F_COUNT], char ***stubs, size_t *nstubs,
				       time_t now, struct dav_card **cardp, char **pathp, char **etag)
{
	const char	*klass = message_class(row);
	struct dav_line	*uid = m->card ? dav_card_find(m->card, "UID", NULL, 0) : NULL;
	char		*name = new_uid(mem_ctx), *body;
	struct dav_card	*c;
	int		f;
	enum mapistore_error ret;

	if (!name) return MAPISTORE_ERR_NO_MEMORY;
	if (m->card) body = dav_card_render(mem_ctx, m->card);
	else if (klass && strncasecmp(klass, "IPM.DistList", 12) == 0) body = talloc_asprintf(mem_ctx, "BEGIN:VLIST\r\nUID:%s\r\nVERSION:1.0\r\nEND:VLIST\r\n", name);
	else body = talloc_asprintf(mem_ctx, "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:%s\r\nN:;;;;\r\nEND:VCARD\r\n", name);
	if (!body || !(c = dav_card_parse(mem_ctx, body, strlen(body)))) return MAPISTORE_ERR_NO_MEMORY;
	if (!uid) dav_card_set(c, "UID", NULL, 0, name);
	outlook_fields(mem_ctx, m, row, c, v, p);
	for (f = 0; f < DAV_F_COUNT; f++) {
		if (p[f] && dav_field_applies(c, f)) dav_field_set(c, f, v[f]);
	}
	ret = complete_members(m, h, mem_ctx, c, row, stubs, nstubs);
	*pathp = talloc_asprintf(mem_ctx, "%s%s.vcf", m->folder->ctx->book_href, name);
	if (ret == MAPISTORE_SUCCESS) ret = *pathp ? put_card(h, mem_ctx, *pathp, c, NULL, now, etag) : MAPISTORE_ERR_NO_MEMORY;
	*cardp = c;
	return ret;
}

/* GET the current card, merge Outlook's write into it, PUT it back if it did not change meanwhile. */
static enum mapistore_error merge_put(struct dav_message *m, struct dav_http *h, TALLOC_CTX *mem_ctx, struct SRow *row,
				      char *v[DAV_F_COUNT], bool p[DAV_F_COUNT], char ***stubs, size_t *nstubs,
				      time_t now, struct dav_card **cardp, char **etag)
{
	const struct dav_settings	*st = dav_backend_settings();
	uint64_t			fp[DAV_F_COUNT];
	const uint64_t			*base = NULL;
	char				*body, *current, *base_etag, today[11];
	struct dav_card			*c;
	struct tm			tm;
	enum mapistore_error		ret;

	ret = dav_get(h, mem_ctx, m->path, &body, &current);
	if (ret != MAPISTORE_SUCCESS) return ret;
	if (!current || !(c = dav_card_parse(mem_ctx, body, strlen(body)))) return MAPISTORE_ERR_INVALID_DATA;
	outlook_fields(mem_ctx, m, row, c, v, p);
	/* The base: the newest version the upload's PredecessorChangeList names (none: no base, so a stale
	   client never silently reverts another's synced edit); online without one, the version opened. */
	if (m->client_pcl) {
		if (dav_fp_version_get(m->folder->ctx->fp, mem_ctx, m->folder->ctx->username, m->href, m->client_pcl, fp,
				       &base_etag) == MAPISTORE_SUCCESS) {
			base = fp;
		}
	} else if (!m->full && m->card) {
		dav_fp_card(st->fp_key, st->fp_key_len, m->card, fp);
		base = fp;
	}
	strftime(today, sizeof today, "%Y-%m-%d", localtime_r(&now, &tm));
	ret = dav_merge(mem_ctx, c, (const char **) v, p, base, outlook_time(row, now),
			server_time(m->folder->ctx, c, m->href, current), st->fp_key, st->fp_key_len, today);
	if (ret == MAPISTORE_SUCCESS) ret = complete_members(m, h, mem_ctx, c, row, stubs, nstubs);
	if (ret == MAPISTORE_SUCCESS) ret = put_card(h, mem_ctx, m->path, c, current, now, etag);
	*cardp = c;
	return ret;
}

/* Whether the stored card is what Outlook holds: then Outlook's own change keys stand for it. */
static bool outlook_holds(TALLOC_CTX *mem_ctx, const struct dav_card *stored, const struct dav_card *opened,
			  char *v[DAV_F_COUNT], bool p[DAV_F_COUNT])
{
	char	*a;
	int	f;

	for (f = 0; f < DAV_F_COUNT; f++) {
		if (!dav_field_applies(stored, f)) continue;
		a = p[f] ? v[f] : opened ? dav_field_get(mem_ctx, opened, f) : NULL;
		if (f == DAV_F_LIST_MEMBERS && p[f]) a = dav_members_normalize(mem_ctx, stored, a);
		if (!same(a, dav_field_get(mem_ctx, stored, f))) return false;
	}
	return true;
}

/* Outlook's write into SOGo, merged field by field with what other clients wrote (see dav_merge.c). */
static enum mapistore_error save(void *message, TALLOC_CTX *mem_ctx)
{
	struct dav_message		*m = message;
	const struct dav_settings	*st = dav_backend_settings();
	struct dav_context		*ctx;
	struct dav_http			*h;
	struct dav_card			*c = NULL, *got;
	struct SRow			*row;
	TALLOC_CTX			*tmp;
	char				*v[DAV_F_COUNT], *path, *etag = NULL, *body, *norm, **stubs = NULL;
	bool				p[DAV_F_COUNT];
	size_t				nstubs = 0;
	time_t				now = time(NULL);
	int				attempt;
	enum mapistore_error		ret = MAPISTORE_ERR_NOT_FOUND;

	if (!m || m->type != DAV_OBJ_MESSAGE || !st) {
		return MAPISTORE_ERR_INVALID_PARAMETER;
	}
	ctx = m->folder->ctx;
	tmp = talloc_new(NULL);
	row = tmp ? outlook_row(tmp, m) : NULL;
	h = row ? dav_context_http(ctx, tmp) : NULL;
	if (!h) {
		talloc_free(tmp);
		return row ? MAPISTORE_ERR_CONN_REFUSED : MAPISTORE_ERR_NO_MEMORY;
	}
	path = m->path;
	if (path && !m->props && !m->photo && !m->full) {
		talloc_free(tmp);
		return MAPISTORE_SUCCESS;	/* nothing written since the last save */
	}
	/* changed again meanwhile (412): merged again, at most 3 times */
	for (attempt = 0; path && attempt < 4; attempt++) {
		ret = merge_put(m, h, tmp, row, v, p, &stubs, &nstubs, now, &c, &etag);
		if (ret != MAPISTORE_ERR_CONFLICT) break;
	}
	if (ret == MAPISTORE_ERR_NOT_FOUND) {
		ret = create_put(m, h, tmp, row, v, p, &stubs, &nstubs, now, &c, &path, &etag);
	}
	if (ret != MAPISTORE_SUCCESS) {
		OC_DEBUG(1, "DAV backend: mid 0x%"PRIx64" not saved (%s)\n", m->mid, mapistore_errstr(ret));
		talloc_free(tmp);
		return ret;
	}
	/* no ETag in the answer: the stored version tells it */
	if (!etag && dav_get(h, tmp, path, &body, &etag) == MAPISTORE_SUCCESS && (got = dav_card_parse(tmp, body, strlen(body)))) {
		c = got;
	}
	norm = dav_href_norm(tmp, path);
	if (!etag || !norm) {
		OC_DEBUG(1, "DAV backend: mid 0x%"PRIx64" saved without an ETag; the next sync shows it\n", m->mid);
		dav_context_sync(ctx);
		talloc_free(tmp);
		return MAPISTORE_SUCCESS;
	}
	dav_change_record(ctx, dav_item_uri(tmp, ctx, norm), etag, m->client_ck, m->client_pcl,
			  !outlook_holds(tmp, c, m->card, v, p));
	ret = dav_item_put(ctx, m->mid, path, etag, c);
	if (ret != MAPISTORE_SUCCESS) {
		OC_DEBUG(1, "DAV backend: index of mid 0x%"PRIx64" not updated (%s)\n", m->mid, mapistore_errstr(ret));
	}
	record_fingerprints(ctx, norm, etag, c);
	/* the message is now the stored version: a later save merges from it */
	path = talloc_strdup(m, path);	/* may be m->path */
	talloc_free(m->href);
	talloc_free(m->etag);
	talloc_free(m->path);
	if (m->card) talloc_unlink(m, m->card);
	m->href = talloc_strdup(m, norm);
	m->etag = talloc_strdup(m, etag);
	m->path = path;
	m->card = talloc_reference(m, c) ? c : NULL;
	m->full = false;
	m->photo = NULL;
	TALLOC_FREE(m->props);
	TALLOC_FREE(m->client_ck);
	TALLOC_FREE(m->client_pcl);
	talloc_free(tmp);
	return m->href && m->etag && m->path && m->card ? MAPISTORE_SUCCESS : MAPISTORE_ERR_NO_MEMORY;
}

void dav_message_fill(struct mapistore_backend *backend)
{
	backend->folder.open_message = open_message;
	backend->folder.create_message = create_message;
	backend->message.save = save;
	backend->message.purge = purge;
	backend->message.create_attachment = create_attachment;
	backend->properties.set_properties = set_properties;
	backend->message.get_message_data = get_message_data;
	backend->message.get_attachment_table = get_attachment_table;
	backend->message.open_attachment = open_attachment;
}
