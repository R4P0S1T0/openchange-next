/*
   CardDAV mapistore backend: no network, no server.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <curl/curl.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "dav_backend.h"
#include "dav_vcard.h"
#include "dav_map.h"
#include "dav_http.h"
#include "gen_ndr/ndr_property.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "dav backend check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

enum mapistore_error mapistore_init_backend(void);
enum mapistore_error mapistore_backend_registered(const char *);

static TALLOC_CTX *root;
static const char *fixture, *vcf_dir, *carddav_fake;

static int write_file(const char *path, size_t len, mode_t mode)
{
    FILE *f = fopen(path, "w");
    size_t i;
    if (!f) return 1;
    for (i = 0; i < len; i++) fputc('A' + (int)(i % 26), f);
    fclose(f);
    return chmod(path, mode);
}

static int test_inert_when_unconfigured(void)
{
    struct mapistore_backend b;
    struct mapistore_contexts_list *l = (void *)1;
    void *ctx = NULL;
    memset(&b, 0, sizeof b);
    CHECK(mapistore_backend_init_defaults(&b) == MAPISTORE_SUCCESS);
    dav_backend_fill(&b);
    CHECK(b.backend.init() == MAPISTORE_SUCCESS);
    CHECK(dav_backend_settings() == NULL);
    CHECK(b.backend.list_contexts("u", NULL, root, &l) == MAPISTORE_SUCCESS && l == NULL);
    CHECK(b.backend.create_context(root, NULL, NULL, "dav://u/", &ctx) == MAPISTORE_ERR_NOT_AVAILABLE);
    return 0;
}

static int test_settings_key_file(void)
{
    char *path = talloc_asprintf(root, "%s/fp.key", fixture);
    struct loadparm_context *lp = loadparm_init(root);
    struct dav_settings *s;
    CHECK(path && lp);
    CHECK(dav_settings_load(root, lp) == NULL); /* no dav_url */
    CHECK(lpcfg_set_cmdline(lp, "mapistore:dav_url", "https://sogo.invalid/dav/%u/Contacts/"));
    CHECK(dav_settings_load(root, lp) == NULL); /* no key file configured */
    CHECK(lpcfg_set_cmdline(lp, "mapistore:dav_fingerprint_key_file", path));
    CHECK(dav_settings_load(root, lp) == NULL); /* missing */
    if (write_file(path, 32, 0644)) return 1;
    CHECK(dav_settings_load(root, lp) == NULL); /* group/world readable */
    CHECK(chmod(path, 0600) == 0);
    if (write_file(path, 31, 0600)) return 1;
    CHECK(dav_settings_load(root, lp) == NULL); /* too short */
    if (write_file(path, 40, 0600)) return 1;
    CHECK((s = dav_settings_load(root, lp)) != NULL);
    CHECK(strcmp(s->url_template, "https://sogo.invalid/dav/%u/Contacts/") == 0);
    CHECK(s->fp_key_len == 40 && memcmp(s->fp_key, "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMN", 40) == 0);
    return 0;
}

static int test_backend_registers(void)
{
    CHECK(mapistore_init_backend() == MAPISTORE_SUCCESS);
    CHECK(mapistore_backend_registered("dav") == MAPISTORE_SUCCESS);
    return 0;
}


static char *slurp(const char *name, size_t *len)
{
    char *path = talloc_asprintf(root, "%s/%s", vcf_dir, name), *buf;
    FILE *f = path ? fopen(path, "rb") : NULL;
    size_t n;
    if (!f) return NULL;
    buf = talloc_array(root, char, 65536);
    n = fread(buf, 1, 65535, f);
    fclose(f);
    buf[n] = '\0';
    *len = n;
    return buf;
}

static int roundtrip(const char *name, const char *kind)
{
    size_t len, i;
    char *in = slurp(name, &len), *lf, *out;
    struct dav_card *c;
    CHECK(in);
    c = dav_card_parse(root, in, len);
    CHECK(c && strcmp(dav_card_kind(c), kind) == 0);
    out = dav_card_render(root, c);
    CHECK(out && strcmp(out, in) == 0);
    /* same card with bare LF endings renders as CRLF */
    lf = talloc_array(root, char, len + 1);
    for (i = 0, len = 0; in[i]; i++) if (in[i] != '\r') lf[len++] = in[i];
    c = dav_card_parse(root, lf, len);
    CHECK(c && (out = dav_card_render(root, c)) && strcmp(out, in) == 0);
    return 0;
}

static int test_vcard_roundtrip_untouched(void)
{
    CHECK(roundtrip("contact_full.vcf", "VCARD") == 0);
    CHECK(roundtrip("list.vlf", "VLIST") == 0);
    CHECK(dav_card_parse(root, "BEGIN:VEVENT\r\nEND:VEVENT\r\n", 26) == NULL);
    CHECK(dav_card_parse(root, "hello", 5) == NULL);
    CHECK(dav_card_parse(root, "BEGIN:VCARD\r\nFN:x\r\n", 19) == NULL); /* no END */
    return 0;
}

static int test_vcard_folding_utf8(void)
{
    char note[512] = "NOTE:", *out, *p, *card;
    struct dav_card *c;
    struct dav_line *l;
    int i;
    for (i = 0; i < 100; i++) strcat(note, i % 2 ? "\xc3\xa7" : "\xc3\xa3"); /* 200 octets of ç/ã */
    c = dav_card_parse(root, "BEGIN:VCARD\r\nFN:x\r\nEND:VCARD\r\n", 30);
    CHECK(c);
    dav_card_set(c, "NOTE", NULL, 0, note + 5);
    out = dav_card_render(root, c);
    CHECK(out);
    for (p = out; *p; ) {
        char *e = strstr(p, "\r\n");
        CHECK(e && e - p <= 75);
        /* a fold must start on a character boundary */
        if (*p == ' ') CHECK(((unsigned char)p[1] & 0xC0) != 0x80);
        p = e + 2;
    }
    card = talloc_strdup(root, out);
    c = dav_card_parse(root, card, strlen(card));
    CHECK(c && (l = dav_card_find(c, "NOTE", NULL, 0)) && strcmp(l->value, note + 5) == 0);
    return 0;
}

static int test_vcard_escape(void)
{
    char *u = dav_text_unescape(root, "a\\,b\\;c\\nd\\\\e"), *e;
    CHECK(strcmp(u, "a,b;c\nd\\e") == 0);
    e = dav_text_escape(root, u);
    CHECK(strcmp(e, "a\\,b\\;c\\nd\\\\e") == 0);
    return 0;
}

static int test_vcard_set_keeps_unknown(void)
{
    size_t len;
    char *in = slurp("contact_full.vcf", &len), *out;
    struct dav_card *c = dav_card_parse(root, in, len);
    struct dav_line *l;
    CHECK(c);
    CHECK((l = dav_card_find(c, "TEL", "cell", 0)) && strcmp(l->value, "+55 11 90000-0001") == 0);
    CHECK((l = dav_card_find(c, "tel", "WORK", 0)) && strstr(l->value, "0002"));
    CHECK(dav_card_find(c, "TEL", "fax", 1) == NULL);
    dav_card_set(c, "TEL", "cell", 0, "+55 11 98888-7777");
    dav_card_set(c, "TEL", "pager", 0, "123");              /* new line */
    dav_card_set(c, "EMAIL", "OTHER", 0, NULL);             /* remove */
    out = dav_card_render(root, c);
    CHECK(strstr(out, "TEL;TYPE=CELL,VOICE,pref:+55 11 98888-7777\r\n"));
    CHECK(strstr(out, "TEL;TYPE=pager:123\r\n"));
    CHECK(!strstr(out, "outra@exemplo.test"));
    CHECK(strstr(out, "X-PHONE-CUSTOM;X-FOO=bar:valor desconhecido\r\n"));
    CHECK(strstr(out, "X-ABUID:11111111-2222-3333-4444-555555555555:ABPerson\r\n"));
    CHECK(strstr(out, "ITEM1.X-ABLABEL:Ramal Custom\r\n"));
    CHECK(strstr(out, "PHOTO;TYPE=PNG;ENCODING=b:iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAD\r\n UlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==\r\n"));
    CHECK(strstr(out, "NOTE:Linha um\\nLinha dois com acentua\xc3\xa7\xc3\xa3o: \xc3\xa7\xc3\xa3o\\, \xc3\xa3\\; fim.\\nLinha tres\r\n"));
    return 0;
}

static int test_vlist_parse(void)
{
    size_t len;
    char *in = slurp("list.vlf", &len);
    struct dav_card *c = dav_card_parse(root, in, len);
    struct dav_line *l;
    CHECK(c && strcmp(dav_card_kind(c), "VLIST") == 0);
    CHECK((l = dav_card_find(c, "CARD", NULL, 0)));
    CHECK(l->nparams == 2 && strcmp(l->params[0], "EMAIL=conceicao@exemplo.test") == 0 && strncmp(l->params[1], "FN=Dra.", 7) == 0);
    CHECK(strcmp(l->value, "16F4F4-6AFC4800-5-3CFB6140.vcf") == 0); /* unfolded */
    CHECK((l = dav_card_find(c, "CARD", NULL, 2)) && strcmp(l->value, "16F4F4-6AFC4800-9-3CFB6140.vcf") == 0);
    CHECK(dav_card_find(c, "CARD", NULL, 3) == NULL);
    CHECK((l = dav_card_find(c, "FN", NULL, 0)) && strcmp(l->value, "Lista Exemplo") == 0);
    CHECK(dav_card_find(c, "VERSION", NULL, 0));
    return 0;
}

static int test_vcard_trailing_data_rejected(void)
{
    const char *two = "BEGIN:VCARD\r\nFN:a\r\nEND:VCARD\r\nBEGIN:VCARD\r\nFN:b\r\nEND:VCARD\r\n";
    const char *blank = "BEGIN:VCARD\r\nFN:a\r\nEND:VCARD\r\n\r\n\n";
    const char *junk = "BEGIN:VCARD\r\nFN:a\r\nEND:VCARD\r\nX-JUNK:1";
    CHECK(dav_card_parse(root, two, strlen(two)) == NULL);
    CHECK(dav_card_parse(root, junk, strlen(junk)) == NULL);
    CHECK(dav_card_parse(root, blank, strlen(blank)) != NULL);
    return 0;
}

/* Fake mapped ids for the PidLid properties. */
static const struct dav_named_tags fake_tags = {
    .email_address = { 0x81000000 | PT_UNICODE, 0x81010000 | PT_UNICODE, 0x81020000 | PT_UNICODE },
    .email_display_name = { 0x81030000 | PT_UNICODE, 0x81040000 | PT_UNICODE, 0x81050000 | PT_UNICODE },
    .email_address_type = { 0x81060000 | PT_UNICODE, 0x81070000 | PT_UNICODE, 0x81080000 | PT_UNICODE },
    .file_under = 0x81090000 | PT_UNICODE, .has_picture = 0x810A0000 | PT_BOOLEAN,
    .work_street = 0x810B0000 | PT_UNICODE, .work_city = 0x810C0000 | PT_UNICODE,
    .work_state = 0x810D0000 | PT_UNICODE, .work_postal_code = 0x810E0000 | PT_UNICODE,
    .work_country = 0x810F0000 | PT_UNICODE, .work_po_box = 0x81100000 | PT_UNICODE,
    .dl_name = 0x81110000 | PT_UNICODE, .dl_members = 0x81120000 | PT_MV_BINARY,
    .dl_one_off_members = 0x81130000 | PT_MV_BINARY, .dl_checksum = 0x81140000 | PT_LONG,
};

#define M5 "16F4F4-6AFC4800-5-3CFB6140"
#define M7 "16F4F4-6AFC4800-7-3CFB6140"
#define M9 "16F4F4-6AFC4800-9-3CFB6140"

/* ctx: number of known members (2: the free address -9 has no contact, 3: all known). */
static struct Binary_r *fake_eid(void *ctx, TALLOC_CTX *mem, const char *uid)
{
    const char *known[] = { M5, M7, M9 };
    int i, n = *(int *)ctx;
    for (i = 0; i < n; i++) {
        if (strcmp(uid, known[i]) == 0) {
            struct Binary_r *b = talloc(mem, struct Binary_r);
            b->lpb = (uint8_t *)talloc_asprintf(b, "EID-%s", uid);
            b->cb = strlen((char *)b->lpb);
            return b;
        }
    }
    return NULL;
}

static char *fake_uid(void *ctx, TALLOC_CTX *mem, const struct Binary_r *b)
{
    if (b->cb < 5 || memcmp(b->lpb, "EID-", 4) != 0) return NULL;
    return talloc_strndup(mem, (char *)b->lpb + 4, b->cb - 4);
}

static struct dav_card *load_card(const char *name)
{
    size_t len;
    char *in = slurp(name, &len);
    return in ? dav_card_parse(root, in, len) : NULL;
}

static const char *str_prop(const struct dav_card *c, const struct dav_member_resolver *r, uint32_t tag)
{
    void *v = NULL;
    if (dav_card_get_prop(root, c, &fake_tags, r, tag, &v) != MAPISTORE_SUCCESS) return NULL;
    return v;
}

static uint32_t contact_tags[] = {
    PidTagMessageClass, PidTagDisplayName, PidTagSurname, PidTagGivenName, PidTagMiddleName,
    PidTagDisplayNamePrefix, PidTagGeneration, PidTagBusinessTelephoneNumber, PidTagHomeTelephoneNumber,
    PidTagMobileTelephoneNumber, PidTagBusinessFaxNumber, PidTagCompanyName, PidTagDepartmentName, PidTagTitle,
    PidTagHomeAddressStreet, PidTagHomeAddressCity, PidTagHomeAddressStateOrProvince, PidTagHomeAddressPostalCode,
    PidTagHomeAddressCountry, PidTagHomeAddressPostOfficeBox, PidTagBody, PidTagBirthday, PidTagBusinessHomePage,
    PidTagAttachDataBinary, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/* Every property the card yields, as an SRow (what Outlook would send back unchanged). */
static struct SRow *card_row(const struct dav_card *c, const struct dav_member_resolver *r)
{
    const struct dav_named_tags *t = &fake_tags;
    uint32_t named[] = { t->email_address[0], t->email_address[1], t->email_address[2], t->email_display_name[0],
                         t->email_address_type[0], t->file_under, t->has_picture, t->work_street, t->work_city,
                         t->work_state, t->work_postal_code, t->work_country, t->work_po_box, t->dl_name,
                         t->dl_members, t->dl_one_off_members, t->dl_checksum };
    struct SRow *row = talloc_zero(root, struct SRow);
    size_t i, n = 24;
    memcpy(contact_tags + n, named, sizeof named);
    n += sizeof named / sizeof named[0];
    row->lpProps = talloc_zero_array(row, struct SPropValue, n);
    for (i = 0; i < n; i++) {
        void *v = NULL;
        if (dav_card_get_prop(row, c, t, r, contact_tags[i], &v) != MAPISTORE_SUCCESS) continue;
        set_SPropValue_proptag(&row->lpProps[row->cValues++], contact_tags[i], v);
    }
    return row;
}

static int test_map_contact_full(void)
{
    struct dav_card *c = load_card("contact_full.vcf");
    struct FILETIME *ft;
    struct Binary_r *photo;
    uint8_t *b;
    void *v;
    uint64_t nt;
    struct tm tm = { .tm_year = 85, .tm_mon = 2, .tm_mday = 27 };
    CHECK(c);
    CHECK(!strcmp(str_prop(c, NULL, PidTagMessageClass), "IPM.Contact"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagDisplayName), "Dra. Concei\xc3\xa7\xc3\xa3o \xc3\x82ngela Exemplo"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagSurname), "Exemplo"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagGivenName), "Concei\xc3\xa7\xc3\xa3o \xc3\x82ngela"));
    CHECK(str_prop(c, NULL, PidTagMiddleName) == NULL);
    CHECK(!strcmp(str_prop(c, NULL, PidTagDisplayNamePrefix), "Dra."));
    CHECK(str_prop(c, NULL, PidTagGeneration) == NULL);
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.file_under), "Exemplo, Concei\xc3\xa7\xc3\xa3o \xc3\x82ngela"));
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.email_address[0]), "conceicao@exemplo.test"));
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.email_address[1]), "conceicao.casa@exemplo.test"));
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.email_address[2]), "outra@exemplo.test"));
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.email_display_name[0]),
                  "Dra. Concei\xc3\xa7\xc3\xa3o \xc3\x82ngela Exemplo (conceicao@exemplo.test)"));
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.email_address_type[2]), "SMTP"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagBusinessTelephoneNumber), "+55 11 3000-0002"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagHomeTelephoneNumber), "+55 11 3000-0003"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagMobileTelephoneNumber), "+55 11 90000-0001"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagBusinessFaxNumber), "+55 11 3000-0004"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagCompanyName), "Empresa Exemplo Ltda"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagDepartmentName), "Diretoria"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagTitle), "Diretora"));
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.work_street), "Rua das Palmeiras, 100"));
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.work_city), "S\xc3\xa3o Paulo"));
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.work_state), "SP"));
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.work_postal_code), "01000-000"));
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.work_country), "Brasil"));
    CHECK(str_prop(c, NULL, fake_tags.work_po_box) == NULL);
    CHECK(!strcmp(str_prop(c, NULL, PidTagHomeAddressStreet), "Avenida A\xc3\xa7\x61\xc3\xad 200\nFundos"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagHomeAddressCity), "Curitiba"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagBody),
                  "Linha um\nLinha dois com acentua\xc3\xa7\xc3\xa3o: \xc3\xa7\xc3\xa3o, \xc3\xa3; fim.\nLinha tres"));
    CHECK(!strcmp(str_prop(c, NULL, PidTagBusinessHomePage), "https://exemplo.test/"));
    CHECK(dav_card_get_prop(root, c, &fake_tags, NULL, PidTagBirthday, &v) == MAPISTORE_SUCCESS);
    ft = v;
    nt = ((uint64_t)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
    CHECK(nt == ((uint64_t)timegm(&tm) + 11644473600ULL) * 10000000ULL);
    CHECK(dav_card_get_prop(root, c, &fake_tags, NULL, fake_tags.has_picture, &v) == MAPISTORE_SUCCESS);
    b = v;
    CHECK(*b == 1);
    CHECK(dav_card_get_prop(root, c, &fake_tags, NULL, PidTagAttachDataBinary, &v) == MAPISTORE_SUCCESS);
    photo = v;
    CHECK(photo->cb == 70 && !memcmp(photo->lpb, "\x89PNG\r\n\x1a\n", 8) && !memcmp(photo->lpb + 62, "IEND", 4));
    CHECK(dav_card_get_prop(root, c, &fake_tags, NULL, fake_tags.dl_members, &v) == MAPISTORE_ERR_NOT_FOUND);
    CHECK(dav_card_get_prop(root, c, &fake_tags, NULL, PidTagSubjectPrefix, &v) == MAPISTORE_ERR_NOT_FOUND);
    return 0;
}

static int same_fields(char *a[DAV_F_COUNT], char *b[DAV_F_COUNT])
{
    int f;
    for (f = 0; f < DAV_F_COUNT; f++) {
        if (!a[f] != !b[f] || (a[f] && strcmp(a[f], b[f]))) {
            fprintf(stderr, "field %d: [%s] vs [%s]\n", f, a[f] ? a[f] : "(null)", b[f] ? b[f] : "(null)");
            return 1;
        }
    }
    return 0;
}

static int test_map_props_to_fields_roundtrip(void)
{
    struct dav_card *c = load_card("contact_full.vcf"), *n;
    char *orig[DAV_F_COUNT], *again[DAV_F_COUNT], *props[DAV_F_COUNT], *out;
    bool present[DAV_F_COUNT];
    int f;
    CHECK(c);
    for (f = 0; f < DAV_F_COUNT; f++) orig[f] = dav_field_get(root, c, f);
    CHECK(orig[DAV_F_ADR_WORK] && !strcmp(orig[DAV_F_ADR_WORK], "\n\nRua das Palmeiras\\, 100\nS\xc3\xa3o Paulo\nSP\n01000-000\nBrasil"));
    CHECK(orig[DAV_F_BDAY] && !strcmp(orig[DAV_F_BDAY], "1985-03-27"));
    CHECK(orig[DAV_F_PHOTO] && orig[DAV_F_LIST_NAME] == NULL);
    /* fields -> new card -> fields */
    n = dav_card_parse(root, "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:x\r\nEND:VCARD\r\n", 44);
    CHECK(n);
    for (f = 0; f < DAV_F_COUNT; f++) dav_field_set(n, f, orig[f]);
    out = dav_card_render(root, n);
    CHECK(out && (n = dav_card_parse(root, out, strlen(out))));
    for (f = 0; f < DAV_F_COUNT; f++) again[f] = dav_field_get(root, n, f);
    CHECK(same_fields(orig, again) == 0);
    /* card -> MAPI properties -> fields: what Outlook sends back unchanged maps to the same fields */
    dav_props_to_fields(root, card_row(c, NULL), &fake_tags, NULL, NULL, props, present);
    CHECK(present[DAV_F_FN] && present[DAV_F_ADR_HOME] && present[DAV_F_PHOTO] && !present[DAV_F_LIST_MEMBERS]);
    CHECK(same_fields(orig, props) == 0);
    /* a partial address from Outlook keeps the components it did not send */
    {
        struct SPropValue p;
        struct SRow row = { .cValues = 1, .lpProps = &p };
        set_SPropValue_proptag(&p, fake_tags.work_city, "Campinas");
        dav_props_to_fields(root, &row, &fake_tags, NULL, c, props, present);
        CHECK(present[DAV_F_ADR_WORK] && !present[DAV_F_FN]);
        CHECK(!strcmp(props[DAV_F_ADR_WORK], "\n\nRua das Palmeiras\\, 100\nCampinas\nSP\n01000-000\nBrasil"));
    }
    return 0;
}

static int test_field_set_no_line_injection(void)
{
    struct dav_card *c = dav_card_parse(root, "BEGIN:VCARD\r\nVERSION:3.0\r\nEND:VCARD\r\n", 37);
    struct dav_member m = { "mailto:a@b.test", "x\r\nTEL:evil", "a@b.test\r\nTEL:evil" };
    struct dav_card *l = dav_card_parse(root, "BEGIN:VLIST\r\nEND:VLIST\r\n", 24);
    char *out;
    int f;
    CHECK(c && l);
    for (f = 0; f < DAV_F_COUNT; f++) {
        if (f == DAV_F_PHOTO) continue;
        dav_field_set(c, f, "x\r\nTEL:evil");
    }
    dav_field_set(c, DAV_F_PHOTO, "AAAA\r\nTEL:evil");
    out = dav_card_render(root, c);
    CHECK(out && (c = dav_card_parse(root, out, strlen(out))));
    CHECK(dav_card_find(c, "TEL", NULL, 4) == NULL); /* only the 4 mapped TEL lines */
    for (f = 0; f < (int)c->nlines; f++) CHECK(strcasecmp(c->lines[f].name, "TEL") || !strstr(c->lines[f].value, "evil") || strstr(c->lines[f].value, "\\n"));
    dav_list_set_members(l, NULL, &m, 1);
    dav_field_set(l, DAV_F_LIST_MEMBERS, "uid1\r\nTEL:evil");
    out = dav_card_render(root, l);
    CHECK(out && (l = dav_card_parse(root, out, strlen(out))));
    CHECK(dav_card_find(l, "TEL", NULL, 0) == NULL);
    return 0;
}

/* MS-OXOCNTC 4.x example list: PidLidDistributionListMembers (a one-off and a wrapped contact EntryID)
   with PidLidDistributionListChecksum 0xD4B0223A (algorithm of 3.1.5.11: polynomial 0xEDB88320, seed 0). */
static int dist_list_crc_vector(void)
{
    static const char *hex =
        "00000000812b1fa4bea310199d6e00dd010f540200000180540068006f006d00610073002000480061006d0062006f00720067"
        "00000053004d005400500000007500730065007200310040006500780061006d0070006c0065002e0063006f006d000000"
        "00000000c091add3519dcf11a4a900aa0047faa4c300000000c242428260001647ada95c0777b74be20700612a7bab49f64e"
        "4b9c52dbfb5a53aa1c000000f04ea60000612a7bab49f64e4b9c52dbfb5a53aa1c000000f0d5b00000";
    uint8_t buf[256];
    size_t i, n = strlen(hex) / 2;
    unsigned x;
    CHECK(n == 191);
    for (i = 0; i < n; i++) { CHECK(sscanf(hex + 2 * i, "%2x", &x) == 1); buf[i] = x; }
    CHECK(calculateCRC(buf, 0, n) == 0xD4B0223A);
    return 0;
}

static int test_map_list_members(void)
{
    struct dav_card *c = load_card("list.vlf"), *e;
    int two = 2, three = 3;
    struct dav_member_resolver r = { &two, fake_eid, fake_uid };
    struct BinaryArray_r *m, *o;
    struct OneOffEntryId *oo;
    struct dav_member *mem;
    char *fields[DAV_F_COUNT], *in, *out;
    bool present[DAV_F_COUNT];
    size_t n, i, len, total = 0;
    uint8_t *cat;
    void *v;
    static const uint8_t wrap[] = { 0, 0, 0, 0, 0xC0, 0x91, 0xAD, 0xD3, 0x51, 0x9D, 0xCF, 0x11, 0xA4, 0xA9, 0x00,
                                    0xAA, 0x00, 0x47, 0xFA, 0xA4, 0xC3 };
    static const uint8_t oneoff[] = { 0, 0, 0, 0, 0x81, 0x2B, 0x1F, 0xA4, 0xBE, 0xA3, 0x10, 0x19, 0x9D, 0x6E, 0x00,
                                      0xDD, 0x01, 0x0F, 0x54, 0x02 };
    CHECK(c);
    CHECK(!strcmp(str_prop(c, &r, PidTagMessageClass), "IPM.DistList"));
    CHECK(!strcmp(str_prop(c, &r, fake_tags.dl_name), "Lista Exemplo"));
    CHECK(!strcmp(str_prop(c, &r, PidTagDisplayName), "Lista Exemplo"));
    CHECK(!strcmp(dav_field_get(root, c, DAV_F_LIST_MEMBERS), M5 "\n" M7 "\n" M9));
    CHECK(dav_card_get_prop(root, c, &fake_tags, &r, fake_tags.dl_members, &v) == MAPISTORE_SUCCESS);
    m = v;
    CHECK(m->cValues == 3);
    CHECK(m->lpbin[0].cb == sizeof wrap + 4 + strlen(M5) && !memcmp(m->lpbin[0].lpb, wrap, sizeof wrap)
          && !memcmp(m->lpbin[0].lpb + sizeof wrap, "EID-" M5, 4 + strlen(M5)));
    CHECK(!memcmp(m->lpbin[1].lpb + sizeof wrap, "EID-" M7, 4 + strlen(M7)));
    /* free address (no contact): one-off entry with its name and address */
    CHECK(!memcmp(m->lpbin[2].lpb, oneoff, sizeof oneoff));
    CHECK((oo = get_OneOffEntryId(root, &m->lpbin[2])));
    CHECK(!strcmp(oo->DisplayName.lpszW, "Livre Exemplo") && !strcmp(oo->EmailAddress.lpszW, "livre@exemplo.test")
          && !strcmp(oo->AddressType.lpszW, "SMTP"));
    CHECK(dav_card_get_prop(root, c, &fake_tags, &r, fake_tags.dl_one_off_members, &v) == MAPISTORE_SUCCESS);
    o = v;
    CHECK(o->cValues == 3 && (oo = get_OneOffEntryId(root, &o->lpbin[1])));
    CHECK(!strcmp(oo->EmailAddress.lpszW, "conceicao.casa@exemplo.test"));
    for (i = 0; i < 3; i++) total += m->lpbin[i].cb;
    cat = talloc_array(root, uint8_t, total);
    for (i = 0, total = 0; i < 3; i++) { memcpy(cat + total, m->lpbin[i].lpb, m->lpbin[i].cb); total += m->lpbin[i].cb; }
    CHECK(dav_card_get_prop(root, c, &fake_tags, &r, fake_tags.dl_checksum, &v) == MAPISTORE_SUCCESS);
    CHECK(*(uint32_t *)v == calculateCRC(cat, 0, total));
    CHECK(dist_list_crc_vector() == 0);
    /* MAPI -> members: the free address comes back as mailto: (Task 7 makes its stub card) */
    CHECK(dav_props_members(root, card_row(c, &r), &fake_tags, &r, &mem, &n) && n == 3);
    CHECK(!strcmp(mem[0].key, M5) && !strcmp(mem[0].email, "conceicao@exemplo.test"));
    CHECK(!strcmp(mem[2].key, "mailto:livre@exemplo.test") && !strcmp(mem[2].name, "Livre Exemplo"));
    dav_props_to_fields(root, card_row(c, &r), &fake_tags, &r, NULL, fields, present);
    CHECK(present[DAV_F_LIST_MEMBERS] && !strcmp(fields[DAV_F_LIST_MEMBERS], M5 "\n" M7 "\nmailto:livre@exemplo.test"));
    CHECK(present[DAV_F_LIST_NAME] && !strcmp(fields[DAV_F_LIST_NAME], "Lista Exemplo"));
    /* the mailto: member Outlook sends back is SOGo's -9 line (same EMAIL): kept verbatim, nothing added */
    in = slurp("list.vlf", &len);
    dav_list_set_members(c, &r, mem, n);
    CHECK(!strcmp(dav_card_render(root, c), in));
    /* a new free address from Outlook becomes a CARD line with an empty value (Task 7 makes the stub);
       a member Outlook removed goes */
    mem[1].key = "mailto:nova@exemplo.test";
    mem[1].email = "nova@exemplo.test";
    mem[1].name = "Nova";
    dav_list_set_members(c, &r, mem, n);
    out = dav_card_render(root, c);
    CHECK(strstr(out, "CARD;EMAIL=nova@exemplo.test;FN=Nova:\r\n") && !strstr(out, "-7-") && strstr(out, "-9-")
          && strstr(out, "-5-"));
    /* a member Outlook was never shown (no contact, no EMAIL) survives an Outlook write */
    in = talloc_asprintf(root, "BEGIN:VLIST\r\nCARD:unseen-uid.vcf\r\nCARD;EMAIL=a@b.test:gone.vcf\r\nFN:L\r\nEND:VLIST\r\n");
    c = dav_card_parse(root, in, strlen(in));
    CHECK(c);
    CHECK(dav_card_get_prop(root, c, &fake_tags, &r, fake_tags.dl_members, &v) == MAPISTORE_SUCCESS
          && ((struct BinaryArray_r *)v)->cValues == 1);
    dav_list_set_members(c, &r, mem, 0);
    out = dav_card_render(root, c);
    CHECK(strstr(out, "CARD:unseen-uid.vcf\r\n") && !strstr(out, "gone"));
    /* every member known: Outlook's list gives back exactly SOGo's member lines */
    r.ctx = &three;
    c = load_card("list.vlf");
    in = slurp("list.vlf", &len);
    CHECK(dav_props_members(root, card_row(c, &r), &fake_tags, &r, &mem, &n) && n == 3);
    dav_list_set_members(c, &r, mem, n);
    CHECK(!strcmp(dav_card_render(root, c), in));
    e = dav_card_parse(root, "BEGIN:VLIST\r\nEND:VLIST\r\n", 24);
    dav_list_set_members(e, &r, mem, n);
    for (i = 0; i < 3; i++) {
        struct dav_line *a = dav_card_find(c, "CARD", NULL, i), *b = dav_card_find(e, "CARD", NULL, i);
        CHECK(a && b && !strcmp(a->value, b->value) && a->nparams == 2 && b->nparams == 2
              && !strcmp(a->params[0], b->params[0]) && !strcmp(a->params[1], b->params[1]));
    }
    return 0;
}

static int test_photo_cap(void)
{
    struct SPropValue p[2];
    struct SRow row = { .cValues = 2, .lpProps = p };
    struct Binary_r big = { .cb = 2 * 1024 * 1024 };
    char *fields[DAV_F_COUNT];
    bool present[DAV_F_COUNT];
    big.lpb = talloc_zero_array(root, uint8_t, big.cb);
    set_SPropValue_proptag(&p[0], PidTagDisplayName, "Foto Grande");
    set_SPropValue_proptag(&p[1], PidTagAttachDataBinary, &big);
    dav_props_to_fields(root, &row, &fake_tags, NULL, NULL, fields, present);
    CHECK(!present[DAV_F_PHOTO] && present[DAV_F_FN] && !strcmp(fields[DAV_F_FN], "Foto Grande"));
    big.cb = DAV_PHOTO_MAX;
    set_SPropValue_proptag(&p[1], PidTagAttachDataBinary, &big); /* copies the Binary_r */
    dav_props_to_fields(root, &row, &fake_tags, NULL, NULL, fields, present);
    CHECK(present[DAV_F_PHOTO] && fields[DAV_F_PHOTO]);
    return 0;
}

/* ---- CardDAV client against carddav_fake.py on 127.0.0.1 ---- */

static pid_t fake_pid;
static char fake_base[128];

static void fake_stop(void)
{
    if (fake_pid > 0) {
        kill(fake_pid, SIGTERM);
        waitpid(fake_pid, NULL, 0);
        fake_pid = 0;
    }
}

static int fake_start(void)
{
    char *portfile = talloc_asprintf(root, "%s/fake.port", fixture);
    char *state = talloc_asprintf(root, "%s/fake.state", fixture);
    int i, port = 0;
    FILE *f;

    unlink(portfile);
    fake_pid = fork();
    if (fake_pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        execl("/usr/bin/python3", "python3", "-I", carddav_fake, portfile, state, (char *)NULL);
        _exit(127);
    }
    for (i = 0; i < 100 && !port; i++) {
        usleep(50000);
        if ((f = fopen(portfile, "r"))) {
            if (fscanf(f, "%d", &port) != 1) port = 0;
            fclose(f);
        }
    }
    if (!port) return 1;
    snprintf(fake_base, sizeof fake_base, "http://127.0.0.1:%d/dav/u/Contacts/", port);
    return 0;
}

/* POST to a test-control endpoint of the fake. */
static int ctl(const char *what)
{
    CURL *c = curl_easy_init();
    char url[256];
    long st = 0;

    snprintf(url, sizeof url, "%.*s/_ctl/%s", (int)(strstr(fake_base, "/dav/") - fake_base), fake_base, what);
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, fopen("/dev/null", "w"));
    curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &st);
    curl_easy_cleanup(c);
    return st == 200 ? 0 : 1;
}

#define BOOK "/dav/u/Contacts/personal/"
#define VC(n) "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:" n "\r\nFN:" n "\r\nEND:VCARD\r\n"

static struct dav_http *client(const char *pw)
{
    return dav_http_new(root, fake_base, "u", pw);
}

static int test_http_list_books(void)
{
    struct dav_http *h;
    struct dav_book *b;
    size_t n;

    CHECK(!fake_start());
    h = client("p");
    CHECK(dav_list_books(h, root, &b, &n) == MAPISTORE_SUCCESS && n == 1);
    CHECK(!strcmp(b[0].href, BOOK) && !strcmp(b[0].segment, "personal"));
    CHECK(!strcmp(b[0].displayname, "Personal") && b[0].sync_token);
    CHECK(dav_mkcol_book(h, "/dav/u/Contacts/work/", "Trab & Co") == MAPISTORE_SUCCESS);
    CHECK(dav_mkcol_book(h, "/dav/u/Contacts/work/", "x") == MAPISTORE_ERR_EXIST);
    CHECK(dav_rename_book(h, "/dav/u/Contacts/work/", "Trabalho") == MAPISTORE_SUCCESS);
    CHECK(dav_list_books(h, root, &b, &n) == MAPISTORE_SUCCESS && n == 2 && !strcmp(b[1].displayname, "Trabalho"));
    CHECK(dav_delete_book(h, "/dav/u/Contacts/work/") == MAPISTORE_SUCCESS);
    CHECK(dav_list_books(h, root, &b, &n) == MAPISTORE_SUCCESS && n == 1);
    talloc_free(h);
    fake_stop();
    return 0;
}

static int test_http_sync_incremental(void)
{
    struct dav_http *h;
    struct dav_change *ch;
    char *etag_a, *etag_b, *tok, *tok2, *tok3, *body, *e2;
    size_t n;
    bool full;

    CHECK(!fake_start());
    h = client("p");
    CHECK(dav_put(h, BOOK "a.vcf", VC("a"), "text/vcard; charset=utf-8", NULL, true, &etag_a) == MAPISTORE_SUCCESS && etag_a);
    etag_a = talloc_strdup(root, etag_a);
    CHECK(dav_put(h, BOOK "b.vcf", VC("b"), "text/vcard; charset=utf-8", NULL, true, &etag_b) == MAPISTORE_SUCCESS);
    CHECK(dav_sync(h, root, BOOK, NULL, &ch, &n, &tok, &full) == MAPISTORE_SUCCESS);
    CHECK(n == 2 && full && tok && ch[0].etag && ch[1].etag);
    CHECK(!ctl("edit?path=" BOOK "a.vcf"));
    CHECK(dav_sync(h, root, BOOK, tok, &ch, &n, &tok2, &full) == MAPISTORE_SUCCESS);
    CHECK(n == 1 && !full && !strcmp(ch[0].href, BOOK "a.vcf") && ch[0].etag && strcmp(ch[0].etag, etag_a));
    CHECK(strcmp(tok, tok2));
    CHECK(!ctl("delete?path=" BOOK "b.vcf"));
    CHECK(dav_sync(h, root, BOOK, tok2, &ch, &n, &tok3, &full) == MAPISTORE_SUCCESS);
    CHECK(n == 1 && !strcmp(ch[0].href, BOOK "b.vcf") && ch[0].etag == NULL);
    /* GET and multiget */
    CHECK(dav_get(h, root, BOOK "a.vcf", &body, &e2) == MAPISTORE_SUCCESS && strstr(body, "X-EDITED") && e2);
    {
        char *hrefs[2] = { BOOK "a.vcf", BOOK "zz.vcf" };
        char **bodies, **etags;
        CHECK(dav_multiget(h, root, BOOK, hrefs, 2, &bodies, &etags) == MAPISTORE_SUCCESS);
        CHECK(bodies[0] && strstr(bodies[0], "UID:a") && etags[0] && !strcmp(etags[0], e2) && !bodies[1] && !etags[1]);
    }
    CHECK(dav_get(h, root, BOOK "b.vcf", &body, NULL) == MAPISTORE_ERR_NOT_FOUND);
    talloc_free(h);
    fake_stop();
    return 0;
}

static int test_http_sync_invalid_token_full(void)
{
    struct dav_http *h;
    struct dav_change *ch;
    char *tok, *tok2;
    size_t n;
    bool full;

    CHECK(!fake_start());
    h = client("p");
    CHECK(dav_put(h, BOOK "a.vcf", VC("a"), NULL, NULL, true, NULL) == MAPISTORE_SUCCESS);
    CHECK(dav_sync(h, root, BOOK, NULL, &ch, &n, &tok, &full) == MAPISTORE_SUCCESS);
    CHECK(!ctl("invalidate_token"));
    CHECK(dav_sync(h, root, BOOK, tok, &ch, &n, &tok2, &full) == MAPISTORE_SUCCESS);
    CHECK(full && n == 1 && ch[0].etag && tok2);
    /* SOGo answers an unknown token with 207: no error, tombstones for what is gone */
    CHECK(dav_sync(h, root, BOOK, "bogus", &ch, &n, &tok2, &full) == MAPISTORE_SUCCESS && !full);
    talloc_free(h);
    fake_stop();
    return 0;
}

static int test_http_put_if_match_412(void)
{
    struct dav_http *h;
    char *etag, *e2;

    CHECK(!fake_start());
    h = client("p");
    CHECK(dav_put(h, BOOK "a.vcf", VC("a"), NULL, NULL, true, &etag) == MAPISTORE_SUCCESS);
    etag = talloc_strdup(root, etag);
    CHECK(dav_put(h, BOOK "a.vcf", VC("a2"), NULL, "\"nope\"", false, NULL) == MAPISTORE_ERR_CONFLICT);
    CHECK(dav_put(h, BOOK "a.vcf", VC("a2"), NULL, etag, false, &e2) == MAPISTORE_SUCCESS && e2 && strcmp(e2, etag));
    e2 = talloc_strdup(root, e2);
    CHECK(dav_delete(h, BOOK "a.vcf", etag) == MAPISTORE_ERR_CONFLICT);
    CHECK(dav_delete(h, BOOK "a.vcf", e2) == MAPISTORE_SUCCESS);
    CHECK(dav_delete(h, BOOK "a.vcf", NULL) == MAPISTORE_ERR_NOT_FOUND);
    CHECK(dav_put(h, BOOK "a.vcf", "x", "text/x\r\nX: y", NULL, false, NULL) == MAPISTORE_ERR_INVALID_PARAMETER);
    talloc_free(h);
    fake_stop();
    return 0;
}

static int test_http_put_if_none_match_exists(void)
{
    struct dav_http *h;

    CHECK(!fake_start());
    h = client("p");
    CHECK(dav_put(h, BOOK "a.vcf", VC("a"), NULL, NULL, true, NULL) == MAPISTORE_SUCCESS);
    CHECK(dav_put(h, BOOK "a.vcf", VC("a"), NULL, NULL, true, NULL) == MAPISTORE_ERR_CONFLICT);
    talloc_free(h);
    fake_stop();
    return 0;
}

static int test_http_401_denied(void)
{
    struct dav_http *h;
    struct dav_book *b;
    size_t n;

    CHECK(!fake_start());
    h = client("wrong");
    CHECK(dav_list_books(h, root, &b, &n) == MAPISTORE_ERR_DENIED);
    CHECK(!dav_http_new(root, "ftp://127.0.0.1/", "u", "p"));
    talloc_free(h);
    fake_stop();
    return 0;
}

static int test_http_timeout_conn_refused(void)
{
    struct dav_http *h;
    struct dav_book *b;
    size_t n;
    time_t t0;

    CHECK(!fake_start());
    h = client("p");
    CHECK(!ctl("fail?code=503"));
    CHECK(dav_list_books(h, root, &b, &n) == MAPISTORE_ERR_CONN_REFUSED);
    CHECK(!ctl("fail?code=0") && !ctl("slow?secs=20"));
    t0 = time(NULL);
    CHECK(dav_list_books(h, root, &b, &n) == MAPISTORE_ERR_CONN_REFUSED);
    CHECK(time(NULL) - t0 <= 17);
    talloc_free(h);
    fake_stop();
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <fixture dir> <vcf dir> <carddav_fake.py>\n", argv[0]);
        return 2;
    }
    root = talloc_new(NULL);
    fixture = argv[1];
    vcf_dir = argv[2];
    carddav_fake = argv[3];
    if (mkdir(fixture, 0700) && access(fixture, W_OK)) return 2;
    if (test_inert_when_unconfigured() || test_settings_key_file() || test_backend_registers()
        || test_vcard_roundtrip_untouched() || test_vcard_folding_utf8() || test_vcard_escape()
        || test_vcard_set_keeps_unknown() || test_vlist_parse()
        || test_vcard_trailing_data_rejected() || test_map_contact_full() || test_map_props_to_fields_roundtrip()
        || test_field_set_no_line_injection() || test_map_list_members() || test_photo_cap()
        || test_http_list_books() || test_http_sync_incremental() || test_http_sync_invalid_token_full()
        || test_http_put_if_match_412() || test_http_put_if_none_match_exists() || test_http_401_denied()
        || test_http_timeout_conn_refused()) { fake_stop(); return 1; }
    printf("dav backend smoke: ok\n");
    talloc_free(root);
    return 0;
}
