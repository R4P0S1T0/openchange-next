/*
   CardDAV mapistore backend: no network, no server.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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
#include "dav_fpstore.h"
#include "mapiproxy/libmapistore/backends/namedprops_backend.h"
#include "gen_ndr/ndr_property.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "dav backend check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

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
    CHECK(lpcfg_set_cmdline(lp, "mapistore:dav_url", ""));
    CHECK(dav_settings_load(root, lp) == NULL); /* empty = unset: inert */
    return 0;
}

static int test_backend_registers(void)
{
    CHECK(mapistore_init_backend() == MAPISTORE_SUCCESS);
    CHECK(mapistore_backend_registered("dav") == MAPISTORE_SUCCESS);
    return 0;
}

static int freed_calls, freed_zero;

static void cred_free_hook(const char *buf, size_t len)
{
    size_t i;
    freed_calls++;
    freed_zero = len > 0;
    for (i = 0; i < len; i++) if (buf[i]) freed_zero = 0;
}

static int test_cred_refcount(void)
{
    struct mapistore_backend b;

    memset(&b, 0, sizeof b);
    CHECK(mapistore_backend_init_defaults(&b) == MAPISTORE_SUCCESS);
    CHECK(b.backend.set_credentials("other", "x") == MAPISTORE_SUCCESS);	/* defaults: no-op */
    CHECK(b.backend.forget_credentials("other") == MAPISTORE_SUCCESS);
    dav_backend_fill(&b);
    dav_cred_set_free_hook(cred_free_hook);
    CHECK(dav_cred_get("alice") == NULL);
    CHECK(b.backend.set_credentials("alice", "s3cret") == MAPISTORE_SUCCESS);
    CHECK(b.backend.set_credentials("alice", "s3cret") == MAPISTORE_SUCCESS);
    CHECK(b.backend.set_credentials("bob", "other") == MAPISTORE_SUCCESS);
    CHECK(b.backend.forget_credentials("alice") == MAPISTORE_SUCCESS);
    CHECK(freed_calls == 0);
    CHECK(dav_cred_get("alice") && strcmp(dav_cred_get("alice"), "s3cret") == 0);
    CHECK(b.backend.forget_credentials("alice") == MAPISTORE_SUCCESS);
    CHECK(freed_calls == 1 && freed_zero);
    CHECK(dav_cred_get("alice") == NULL);
    CHECK(strcmp(dav_cred_get("bob"), "other") == 0);
    CHECK(b.backend.set_credentials("bob", "changed") == MAPISTORE_SUCCESS);	/* newest verified password wins */
    CHECK(freed_calls == 2 && freed_zero && strcmp(dav_cred_get("bob"), "changed") == 0);
    CHECK(b.backend.forget_credentials("bob") == MAPISTORE_SUCCESS);
    CHECK(freed_calls == 2 && dav_cred_get("bob"));
    CHECK(b.backend.forget_credentials("alice") == MAPISTORE_SUCCESS);	/* unknown: nothing to do */
    CHECK(freed_calls == 2);
    CHECK(b.backend.forget_credentials("bob") == MAPISTORE_SUCCESS);
    CHECK(freed_calls == 3 && freed_zero && dav_cred_get("bob") == NULL);
    dav_cred_set_free_hook(NULL);
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
    .email_original_display_name = { 0x81150000 | PT_UNICODE, 0x81160000 | PT_UNICODE, 0x81170000 | PT_UNICODE },
    .email_original_entryid = { 0x81180000 | PT_BINARY, 0x81190000 | PT_BINARY, 0x811A0000 | PT_BINARY },
    .abp_email_list = 0x811B0000 | PT_MV_LONG, .abp_array_type = 0x811C0000 | PT_LONG,
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
    /* what Outlook's contacts address book and the form title need (MS-OXOCNTC 2.2.1.2.x) */
    CHECK(!strcmp(str_prop(c, NULL, PidTagSubject), "Dra. Concei\xc3\xa7\xc3\xa3o \xc3\x82ngela Exemplo"));
    CHECK(!strcmp(str_prop(c, NULL, fake_tags.email_original_display_name[1]), "conceicao.casa@exemplo.test"));
    CHECK(dav_card_get_prop(root, c, &fake_tags, NULL, fake_tags.email_original_entryid[0], &v) == MAPISTORE_SUCCESS
          && ((struct Binary_r *) v)->cb > 20);
    CHECK(dav_card_get_prop(root, c, &fake_tags, NULL, fake_tags.abp_array_type, &v) == MAPISTORE_SUCCESS
          && *(uint32_t *) v == 7);
    CHECK(dav_card_get_prop(root, c, &fake_tags, NULL, fake_tags.abp_email_list, &v) == MAPISTORE_SUCCESS
          && ((struct LongArray_r *) v)->cValues == 3 && ((struct LongArray_r *) v)->lpl[2] == 2);
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

/* A list with no members (Outlook saves one): no member properties at all, as Exchange gives; an empty
   multivalued property makes Outlook fail the whole folder's sync (E_INVALIDARG). */
static int test_map_list_empty(void)
{
    static const char in[] = "BEGIN:VLIST\r\nUID:e\r\nVERSION:1.0\r\nFN:Vazia\r\nEND:VLIST\r\n";
    struct dav_card *c = dav_card_parse(root, in, strlen(in));
    int two = 2;
    struct dav_member_resolver r = { &two, fake_eid, fake_uid };
    void *v;

    CHECK(c);
    CHECK(!strcmp(str_prop(c, &r, PidTagMessageClass), "IPM.DistList"));
    CHECK(dav_card_get_prop(root, c, &fake_tags, &r, fake_tags.dl_members, &v) == MAPISTORE_ERR_NOT_FOUND);
    CHECK(dav_card_get_prop(root, c, &fake_tags, &r, fake_tags.dl_one_off_members, &v) == MAPISTORE_ERR_NOT_FOUND);
    CHECK(dav_card_get_prop(root, c, &fake_tags, &r, fake_tags.dl_checksum, &v) == MAPISTORE_SUCCESS && *(uint32_t *)v == 0);
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
    CHECK(dav_put(h, root, BOOK "a.vcf", VC("a"), "text/vcard; charset=utf-8", NULL, true, &etag_a) == MAPISTORE_SUCCESS && etag_a);
    CHECK(dav_put(h, root, BOOK "b.vcf", VC("b"), "text/vcard; charset=utf-8", NULL, true, &etag_b) == MAPISTORE_SUCCESS);
    CHECK(etag_b && strcmp(etag_a, etag_b)); /* still valid after the next request */
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
    CHECK(dav_put(h, root, BOOK "a.vcf", VC("a"), NULL, NULL, true, NULL) == MAPISTORE_SUCCESS);
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
    CHECK(dav_put(h, root, BOOK "a.vcf", VC("a"), NULL, NULL, true, &etag) == MAPISTORE_SUCCESS);
    CHECK(dav_put(h, root, BOOK "a.vcf", VC("a2"), NULL, "\"nope\"", false, NULL) == MAPISTORE_ERR_CONFLICT);
    CHECK(dav_put(h, root, BOOK "a.vcf", VC("a2"), NULL, etag, false, &e2) == MAPISTORE_SUCCESS && e2 && strcmp(e2, etag));
    CHECK(dav_delete(h, BOOK "a.vcf", etag) == MAPISTORE_ERR_CONFLICT);
    CHECK(dav_delete(h, BOOK "a.vcf", e2) == MAPISTORE_SUCCESS);
    CHECK(dav_delete(h, BOOK "a.vcf", NULL) == MAPISTORE_ERR_NOT_FOUND);
    CHECK(dav_put(h, root, BOOK "a.vcf", "x", "text/x\r\nX: y", NULL, false, NULL) == MAPISTORE_ERR_INVALID_PARAMETER);
    talloc_free(h);
    fake_stop();
    return 0;
}

static int test_http_put_if_none_match_exists(void)
{
    struct dav_http *h;

    CHECK(!fake_start());
    h = client("p");
    CHECK(dav_put(h, root, BOOK "a.vcf", VC("a"), NULL, NULL, true, NULL) == MAPISTORE_SUCCESS);
    CHECK(dav_put(h, root, BOOK "a.vcf", VC("a"), NULL, NULL, true, NULL) == MAPISTORE_ERR_CONFLICT);
    talloc_free(h);
    fake_stop();
    return 0;
}

/* The captured SOGo responses (anonymized) served by the fake. */
static int test_http_sogo_fixtures(void)
{
    struct dav_http *h;
    struct dav_book *b;
    struct dav_change *ch;
    char *tok, **bodies, **etags, *hrefs[2] = { "/SOGo/dav/u/Contacts/personal/c1.vcf", "/SOGo/dav/u/Contacts/personal/c9.vcf" };
    char q[512];
    size_t n;
    bool full;

    CHECK(!fake_start());
    /* the captured paths are SOGo's: the client's home must be the one they live under */
    snprintf(q, sizeof q, "%.*s/SOGo/dav/u/Contacts/", (int)(strstr(fake_base, "/dav/") - fake_base), fake_base);
    h = dav_http_new(root, q, "u", "p");
    snprintf(q, sizeof q, "serve?file=%s/propfind_books.xml", vcf_dir);
    CHECK(!ctl(q));
    CHECK(dav_list_books(h, root, &b, &n) == MAPISTORE_SUCCESS && n == 1);	/* the GAL directory is left out */
    CHECK(!strcmp(b[0].segment, "personal") && !strcmp(b[0].displayname, "Personal") && !strcmp(b[0].sync_token, "1794920267"));
    snprintf(q, sizeof q, "serve?file=%s/sync_incr.xml", vcf_dir);
    CHECK(!ctl(q));
    CHECK(dav_sync(h, root, "/SOGo/dav/u/Contacts/personal/", "1794920281", &ch, &n, &tok, &full) == MAPISTORE_SUCCESS);
    CHECK(n == 2 && !full && !strcmp(tok, "1794920281"));
    CHECK(!strcmp(ch[0].etag, "\"gcs00000002\"") && ch[1].etag == NULL);
    snprintf(q, sizeof q, "serve?file=%s/multiget.xml", vcf_dir);
    CHECK(!ctl(q));
    CHECK(dav_multiget(h, root, "/SOGo/dav/u/Contacts/personal/", hrefs, 2, &bodies, &etags) == MAPISTORE_SUCCESS);
    CHECK(strstr(bodies[0], "UID:c1") && strstr(bodies[0], "END:VCARD") && !strcmp(etags[0], "\"gcs00000002\"") && !bodies[1]);
    talloc_free(h);
    fake_stop();
    return 0;
}

static int test_href_norm(void)
{
    CHECK(!strcmp(dav_href_norm(root, "/a/b%40c/"), "/a/b@c"));
    CHECK(!strcmp(dav_href_norm(root, "http://h:1/a/%62.vcf"), "/a/b.vcf"));
    CHECK(!strcmp(dav_href_norm(root, "/a/x%2fy"), "/a/x%2Fy"));	/* an encoded slash stays one segment */
    CHECK(!strcmp(dav_href_norm(root, "/"), "/"));
    CHECK(dav_href_norm(root, "/a/../b") == NULL && dav_href_norm(root, "/a/%2e%2E/b") == NULL);
    CHECK(dav_href_norm(root, "/a/./b") == NULL && dav_href_norm(root, "/a/%00") == NULL);
    return 0;
}

/* A card named like its book is a card; hrefs outside the book, or escaping it, are ignored. */
static int test_http_hrefs_under_book(void)
{
    static const char sync_xml[] = "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\">"
        "<D:response><D:href>/dav/u/Contacts/personal/</D:href><D:propstat><D:prop><D:getetag>\"b\"</D:getetag></D:prop>"
        "<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
        "<D:response><D:href>/dav/u/Contacts/personal/personal</D:href><D:propstat><D:prop><D:getetag>\"1\"</D:getetag></D:prop>"
        "<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
        "<D:response><D:href>/dav/u/Contacts/other/x.vcf</D:href><D:propstat><D:prop><D:getetag>\"2\"</D:getetag></D:prop>"
        "<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
        "<D:response><D:href>/dav/u/Contacts/personal/../other/y.vcf</D:href><D:propstat><D:prop><D:getetag>\"3\"</D:getetag></D:prop>"
        "<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
        "<D:response><D:href>/dav/u/Contacts/personal/a%20b.vcf</D:href><D:propstat><D:prop><D:getetag>\"4\"</D:getetag>"
        "<C:address-data xmlns:C=\"urn:ietf:params:xml:ns:carddav\">BEGIN:VCARD</C:address-data></D:prop>"
        "<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
        "<D:sync-token>9</D:sync-token></D:multistatus>";
    char *path = talloc_asprintf(root, "%s/hrefs.xml", fixture), q[512], *tok, **bodies, **etags;
    char *want[2] = { BOOK "a b.vcf", BOOK "other.vcf" };
    struct dav_http *h;
    struct dav_change *ch;
    size_t n;
    bool full;
    FILE *f = fopen(path, "w");

    CHECK(f && fputs(sync_xml, f) >= 0 && fclose(f) == 0);
    CHECK(!fake_start());
    h = client("p");
    snprintf(q, sizeof q, "serve?file=%s", path);
    CHECK(!ctl(q));
    CHECK(dav_sync(h, root, BOOK, "1", &ch, &n, &tok, &full) == MAPISTORE_SUCCESS);
    CHECK(n == 2 && !strcmp(ch[0].href, BOOK "personal") && !strcmp(ch[1].href, BOOK "a%20b.vcf"));
    CHECK(dav_multiget(h, root, BOOK, want, 2, &bodies, &etags) == MAPISTORE_SUCCESS);
    CHECK(bodies[0] && !strcmp(etags[0], "\"4\"") && !bodies[1]);
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

/* ---- the backend through the mapistore API, against the fake ---- */

/* In-memory mapistore indexing: fmid <-> URI, as the TDB/MySQL backends keep it. */
struct fake_index { uint64_t fmid[512]; char *uri[512]; size_t n; uint64_t next; };
static struct fake_index fidx = { .next = 0x100 };

static enum mapistore_error fi_get_fmid(struct indexing_context *c, const char *u, const char *uri, bool partial,
                                        uint64_t *fmid, bool *soft)
{
    size_t i;
    for (i = 0; i < fidx.n; i++) {
        if (strcmp(fidx.uri[i], uri) == 0) { *fmid = fidx.fmid[i]; *soft = false; return MAPISTORE_SUCCESS; }
    }
    return MAPISTORE_ERR_NOT_FOUND;
}
static enum mapistore_error fi_get_uri(struct indexing_context *c, const char *u, TALLOC_CTX *mem, uint64_t fmid,
                                       char **uri, bool *soft)
{
    size_t i;
    for (i = 0; i < fidx.n; i++) {
        if (fidx.fmid[i] == fmid) { *uri = talloc_strdup(mem, fidx.uri[i]); *soft = false; return MAPISTORE_SUCCESS; }
    }
    return MAPISTORE_ERR_NOT_FOUND;
}
static enum mapistore_error fi_add_fmid(struct indexing_context *c, const char *u, uint64_t fmid, const char *uri)
{
    if (fidx.n == 512) return MAPISTORE_ERR_NO_MEMORY;
    fidx.fmid[fidx.n] = fmid;
    fidx.uri[fidx.n++] = talloc_strdup(root, uri);
    return MAPISTORE_SUCCESS;
}
static enum mapistore_error fi_update_fmid(struct indexing_context *c, const char *u, uint64_t fmid, const char *uri)
{
    size_t i;
    for (i = 0; i < fidx.n; i++) {
        if (fidx.fmid[i] == fmid) { fidx.uri[i] = talloc_strdup(root, uri); return MAPISTORE_SUCCESS; }
    }
    return MAPISTORE_ERR_NOT_FOUND;
}
static enum mapistore_error fi_list_folders(struct indexing_context *c, const char *u, TALLOC_CTX *mem, uint32_t *n,
                                           uint64_t **fmids, char ***uris)
{
    size_t i;
    *n = 0;
    *fmids = talloc_array(mem, uint64_t, fidx.n + 1);
    *uris = talloc_array(mem, char *, fidx.n + 1);
    for (i = 0; i < fidx.n; i++) {
        if (fidx.uri[i][strlen(fidx.uri[i]) - 1] != '/') continue;
        (*fmids)[*n] = fidx.fmid[i];
        (*uris)[(*n)++] = fidx.uri[i];
    }
    return MAPISTORE_SUCCESS;
}
static enum mapistore_error fi_allocate(struct indexing_context *c, const char *u, uint64_t *fmid)
{
    *fmid = fidx.next++;
    return MAPISTORE_SUCCESS;
}
static enum mapistore_error fi_del_fmid(struct indexing_context *c, const char *u, uint64_t fmid, uint8_t flags)
{
    size_t i;
    for (i = 0; i < fidx.n; i++) {
        if (fidx.fmid[i] == fmid) {
            fidx.fmid[i] = fidx.fmid[--fidx.n];
            fidx.uri[i] = fidx.uri[fidx.n];
            return MAPISTORE_SUCCESS;
        }
    }
    return MAPISTORE_SUCCESS;
}
static struct indexing_context ictx = { .add_fmid = fi_add_fmid, .del_fmid = fi_del_fmid, .update_fmid = fi_update_fmid, .list_folders = fi_list_folders, .get_uri = fi_get_uri, .get_fmid = fi_get_fmid,
                                        .allocate_fmid = fi_allocate };

/* Named properties: the mapped ID of a PSETID_Address LID is the LID itself. */
static enum mapistore_error np_get_mapped_id(struct namedprops_context *np, struct MAPINAMEID nameid, uint16_t *id)
{
    *id = nameid.kind.lid;
    return MAPISTORE_SUCCESS;
}
static struct namedprops_context fake_np = { .get_mapped_id = np_get_mapped_id };
static struct mapistore_context fake_mstore = { .nprops_ctx = &fake_np };
static struct mapistore_connection_info dav_conn = { .username = "u", .mstore_ctx = &fake_mstore,
    .replica_guid = { .time_low = 0x11223344, .time_mid = 0x5566, .time_hi_and_version = 0x7788 } };
static struct mapistore_backend B;
static struct dav_settings test_settings;
static uint8_t test_key[32] = "0123456789abcdef0123456789abcdef";

#define EMAIL1 ((0x8083u << 16) | PT_UNICODE)
#define HAS_PICTURE ((0x8015u << 16) | PT_BOOLEAN)
#define DL_MEMBERS ((0x8055u << 16) | PT_MV_BINARY)

/* The fake running, the backend configured for it and the user's password known. */
static int backend_up(void)
{
    CHECK(!fake_start());
    test_settings.url_template = talloc_asprintf(root, "%.*s/dav/%%u/Contacts/",
                                                 (int)(strstr(fake_base, "/dav/") - fake_base), fake_base);
    test_settings.fp_key = test_key;
    test_settings.fp_key_len = sizeof test_key;
    dav_backend_set_settings(&test_settings);
    dav_backend_set_sync_window(0);	/* each read sees the fake's latest state */
    memset(&B, 0, sizeof B);
    CHECK(mapistore_backend_init_defaults(&B) == MAPISTORE_SUCCESS);
    dav_backend_fill(&B);
    CHECK(dav_cred_set("u", "p") == MAPISTORE_SUCCESS);
    return 0;
}

static void backend_down(void)
{
    dav_cred_forget("u");
    dav_backend_set_settings(NULL);
    fake_stop();
}

static int put(const char *name, const char *body)
{
    struct dav_http *h = client("p");
    char *href = talloc_asprintf(root, BOOK "%s", name);
    CHECK(dav_put(h, root, href, body, NULL, NULL, false, NULL) == MAPISTORE_SUCCESS);
    talloc_free(h);
    return 0;
}

static int put_fixture(const char *name, const char *fixture_name)
{
    size_t len;
    char *body = slurp(fixture_name, &len);
    CHECK(body);
    return put(name, body);
}

static struct dav_folder *book(const char *segment)
{
    void *folder = NULL;
    char *uri = talloc_asprintf(root, "dav://contacts/%s/", segment);
    return B.backend.create_context(root, &dav_conn, &ictx, uri, &folder) == MAPISTORE_SUCCESS ? folder : NULL;
}

/* MID and change number of the row named name (0 when absent); the row count in *count. */
static int row_of(struct dav_folder *f, const char *name, uint64_t *mid, uint64_t *cn, uint32_t *count)
{
    enum MAPITAGS cols[] = { PidTagDisplayName, PidTagMid, PidTagChangeNumber, PidTagMessageClass };
    struct mapistore_property_data *d;
    void *t;
    uint32_t n, i;
    *mid = *cn = 0;
    CHECK(B.folder.open_table(f, root, MAPISTORE_MESSAGE_TABLE, 1, &t, &n) == MAPISTORE_SUCCESS);
    CHECK(B.table.set_columns(t, 4, cols) == MAPISTORE_SUCCESS);
    for (i = 0; i < n; i++) {
        CHECK(B.table.get_row(t, root, MAPISTORE_PREFILTERED_QUERY, i, &d) == MAPISTORE_SUCCESS);
        CHECK(d[1].error == MAPISTORE_SUCCESS && d[2].error == MAPISTORE_SUCCESS);
        if (d[0].error == MAPISTORE_SUCCESS && !strcmp(d[0].data, name)) {
            *mid = *(uint64_t *)d[1].data;
            *cn = *(uint64_t *)d[2].data;
        }
    }
    if (count) *count = n;
    return 0;
}

static bool has_id(const struct UI8Array_r *ids, uint64_t id)
{
    uint32_t i;
    for (i = 0; i < ids->cValues; i++) if (ids->lpui8[i] == id) return true;
    return false;
}

static int test_list_contexts_books(void)
{
    struct mapistore_contexts_list *l = NULL, *e;
    struct dav_http *h;
    int seen = 0;

    CHECK(!backend_up());
    h = client("p");
    CHECK(dav_mkcol_book(h, "/dav/u/Contacts/work/", "Trabalho") == MAPISTORE_SUCCESS);
    CHECK(dav_mkcol_book(h, "/dav/u/Contacts/fam/", "Fam\xc3\xadlia") == MAPISTORE_SUCCESS);
    /* only personal: the other books are its subfolders (test_books_are_subfolders) */
    CHECK(B.backend.list_contexts("u", &ictx, root, &l) == MAPISTORE_SUCCESS);
    for (e = l; e; e = e->next) {
        CHECK(e->role == MAPISTORE_CONTACTS_ROLE);
        if (!strcmp(e->url, "dav://contacts/personal/")) { CHECK(e->main_folder && !strcmp(e->name, "Personal")); seen |= 1; }
    }
    CHECK(seen == 1 && !l->next);
    /* a user whose password the backend does not hold: an error, never an empty list */
    CHECK(B.backend.list_contexts("nobody", &ictx, root, &l) == MAPISTORE_ERR_CONN_REFUSED && l == NULL);
    talloc_free(h);
    backend_down();
    return 0;
}

/* Review Focus 2: SOGo down or refusing the password at logon keeps the contacts folders. */
static int test_list_contexts_sogo_down_keeps(void)
{
    struct mapistore_contexts_list *l = NULL;
    struct dav_folder *f;
    void *t;
    uint32_t n;

    CHECK(!backend_up());
    CHECK(!ctl("fail?code=503"));
    CHECK(B.backend.list_contexts("u", &ictx, root, &l) == MAPISTORE_ERR_CONN_REFUSED && l == NULL);
    CHECK(!ctl("fail?code=0"));
    dav_cred_forget("u");
    CHECK(dav_cred_set("u", "changed") == MAPISTORE_SUCCESS);
    CHECK(B.backend.list_contexts("u", &ictx, root, &l) == MAPISTORE_ERR_CONN_REFUSED && l == NULL);
    dav_cred_forget("u");
    CHECK(dav_cred_set("u", "p") == MAPISTORE_SUCCESS);
    CHECK((f = book("personal")) != NULL);
    fake_stop();
    CHECK(B.backend.list_contexts("u", &ictx, root, &l) == MAPISTORE_ERR_CONN_REFUSED && l == NULL);
    /* the folder answers with an error, not with an empty book */
    CHECK(B.folder.open_table(f, root, MAPISTORE_MESSAGE_TABLE, 1, &t, &n) == MAPISTORE_ERR_CONN_REFUSED);
    backend_down();
    return 0;
}

static int test_contents_table_contacts_and_lists(void)
{
    struct dav_folder *f;
    enum MAPITAGS ftags[] = { PidTagDisplayName, PidTagContainerClass, PidTagContentCount };
    struct mapistore_property_data fd[3];
    uint64_t mid_c, mid_l, cn;
    uint32_t n;

    CHECK(!backend_up());
    if (put_fixture(M5 ".vcf", "contact_full.vcf") || put_fixture("16F4F4-6AFC4800-3-3CFB6140.vcf", "list.vlf")) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "Dra. Concei\xc3\xa7\xc3\xa3o \xc3\x82ngela Exemplo", &mid_c, &cn, &n)) return 1;
    CHECK(n == 2 && mid_c && cn);
    if (row_of(f, "Lista Exemplo", &mid_l, &cn, NULL)) return 1;
    CHECK(mid_l && mid_l != mid_c);
    {
        enum MAPITAGS cols[] = { PidTagMessageClass, PidTagMid };
        struct mapistore_property_data *d;
        void *t;
        uint32_t i, contacts = 0, lists = 0;
        CHECK(B.folder.open_table(f, root, MAPISTORE_MESSAGE_TABLE, 1, &t, &n) == MAPISTORE_SUCCESS);
        CHECK(B.table.set_columns(t, 2, cols) == MAPISTORE_SUCCESS);
        for (i = 0; i < n; i++) {
            CHECK(B.table.get_row(t, root, MAPISTORE_PREFILTERED_QUERY, i, &d) == MAPISTORE_SUCCESS);
            contacts += !strcmp(d[0].data, "IPM.Contact") && *(uint64_t *)d[1].data == mid_c;
            lists += !strcmp(d[0].data, "IPM.DistList") && *(uint64_t *)d[1].data == mid_l;
        }
        CHECK(contacts == 1 && lists == 1);
    }
    CHECK(B.folder.get_child_count(f, MAPISTORE_MESSAGE_TABLE, &n) == MAPISTORE_SUCCESS && n == 2);
    CHECK(B.folder.get_child_count(f, MAPISTORE_FOLDER_TABLE, &n) == MAPISTORE_SUCCESS && n == 0);
    CHECK(B.properties.get_properties(f, root, 3, ftags, fd) == MAPISTORE_SUCCESS);
    CHECK(fd[0].error == 0 && !strcmp(fd[0].data, "Personal"));
    CHECK(fd[1].error == 0 && !strcmp(fd[1].data, "IPF.Contact"));
    CHECK(fd[2].error == 0 && *(uint32_t *)fd[2].data == 2);
    backend_down();
    return 0;
}

static int test_open_contact_props_and_photo(void)
{
    enum MAPITAGS tags[] = { PidTagDisplayName, EMAIL1, HAS_PICTURE, PidTagHasAttachments, PidTagMessageFlags,
                             PidTagAttachDataBinary, PidTagMid };
    enum MAPITAGS atags[] = { PidTagAttachLongFilename, PidTagAttachmentContactPhoto, PidTagAttachDataBinary,
                              PidTagAttachMethod };
    struct mapistore_property_data d[7], ad[4];
    struct dav_folder *f;
    struct dav_card *c = load_card("contact_full.vcf");
    struct Binary_r *photo;
    void *msg, *list, *at, *att, *v;
    uint64_t mid_c, mid_l, cn;
    uint32_t n;

    CHECK(c && dav_card_get_prop(root, c, &fake_tags, NULL, PidTagAttachDataBinary, &v) == MAPISTORE_SUCCESS);
    photo = v;
    CHECK(!backend_up());
    if (put_fixture(M5 ".vcf", "contact_full.vcf") || put_fixture("16F4F4-6AFC4800-3-3CFB6140.vcf", "list.vlf")) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "Dra. Concei\xc3\xa7\xc3\xa3o \xc3\x82ngela Exemplo", &mid_c, &cn, NULL)) return 1;
    if (row_of(f, "Lista Exemplo", &mid_l, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid_c, false, &msg) == MAPISTORE_SUCCESS);
    CHECK(B.properties.get_properties(msg, root, 7, tags, d) == MAPISTORE_SUCCESS);
    CHECK(d[0].error == 0 && !strcmp(d[0].data, "Dra. Concei\xc3\xa7\xc3\xa3o \xc3\x82ngela Exemplo"));
    CHECK(d[1].error == 0 && !strcmp(d[1].data, "conceicao@exemplo.test"));
    CHECK(d[2].error == 0 && *(uint8_t *)d[2].data == 1);
    CHECK(d[3].error == 0 && *(uint8_t *)d[3].data == 1);
    CHECK(d[4].error == 0 && (*(uint32_t *)d[4].data & MSGFLAG_HASATTACH));
    CHECK(d[5].error == MAPISTORE_ERR_NOT_FOUND);	/* the picture is the attachment's, not the message's */
    CHECK(d[6].error == 0 && *(uint64_t *)d[6].data == mid_c);
    CHECK(B.message.get_attachment_table(msg, root, &at, &n) == MAPISTORE_SUCCESS && n == 1);
    CHECK(B.message.open_attachment(msg, root, 1, &att) == MAPISTORE_ERR_NOT_FOUND);
    CHECK(B.message.open_attachment(msg, root, 0, &att) == MAPISTORE_SUCCESS);
    CHECK(B.properties.get_properties(att, root, 4, atags, ad) == MAPISTORE_SUCCESS);
    CHECK(ad[0].error == 0 && !strcmp(ad[0].data, "ContactPicture.jpg"));
    CHECK(ad[1].error == 0 && *(uint8_t *)ad[1].data == 1);
    CHECK(ad[2].error == 0 && ((struct Binary_r *)ad[2].data)->cb == photo->cb);
    CHECK(!memcmp(((struct Binary_r *)ad[2].data)->lpb, photo->lpb, photo->cb));
    CHECK(ad[3].error == 0 && *(uint32_t *)ad[3].data == 1);
    /* the list: its member card in this book is the wrapped EntryID of that contact's message */
    CHECK(B.folder.open_message(f, root, mid_l, false, &list) == MAPISTORE_SUCCESS);
    {
        enum MAPITAGS lt[] = { DL_MEMBERS, PidTagMessageClass };
        struct mapistore_property_data ld[2];
        struct BinaryArray_r *m;
        struct Binary_r inner;
        struct MessageEntryId *e;
        CHECK(B.properties.get_properties(list, root, 2, lt, ld) == MAPISTORE_SUCCESS);
        CHECK(ld[1].error == 0 && !strcmp(ld[1].data, "IPM.DistList"));
        CHECK(ld[0].error == 0 && (m = ld[0].data)->cValues == 3);
        CHECK(m->lpbin[0].cb > 21 && m->lpbin[0].lpb[20] == 0xC3);
        inner.cb = m->lpbin[0].cb - 21;
        inner.lpb = m->lpbin[0].lpb + 21;
        CHECK((e = get_MessageEntryId(root, &inner)) != NULL);
        CHECK(e->MessageType == eitLTPPrivateMessage && (uint64_t)e->MessageGlobalCounter.value == mid_c >> 16);
        CHECK((uint64_t)e->FolderGlobalCounter.value == f->fid >> 16);
        CHECK(m->lpbin[1].lpb[20] != 0xC3 && m->lpbin[2].lpb[20] != 0xC3);	/* not in the book: one-off */
        {
            /* and back: what Outlook sends names the same members */
            struct SPropValue p;
            struct SRow row = { .cValues = 1, .lpProps = &p };
            struct dav_member_resolver r;
            struct dav_member *mem;
            size_t k;
            dav_folder_resolver(f, &r);
            set_SPropValue_proptag(&p, DL_MEMBERS, m);
            CHECK(dav_props_members(root, &row, &f->ctx->tags, &r, &mem, &k) && k == 3);
            CHECK(!strcmp(mem[0].key, M5) && !strcmp(mem[1].key, "mailto:conceicao.casa@exemplo.test"));
            CHECK(!strcmp(mem[2].key, "mailto:livre@exemplo.test"));
            inner.lpb[4] ^= 1;	/* another store's entry is not resolved */
            CHECK(r.uid_for_entryid(r.ctx, root, &inner) == NULL);
        }
    }
    backend_down();
    return 0;
}

static int test_ics_incremental(void)
{
    struct dav_folder *f;
    struct UI8Array_r *ids;
    uint64_t mid_a, mid_b, cn_a, cn_b, mid, cn, dcn0, dcn1;
    uint32_t n;

    CHECK(!backend_up());
    if (put("a.vcf", VC("a")) || put("b.vcf", VC("b"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "a", &mid_a, &cn_a, NULL) || row_of(f, "b", &mid_b, &cn_b, NULL)) return 1;
    CHECK(mid_a && mid_b && cn_a && cn_b);
    CHECK(B.folder.get_deleted_fmids(f, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn0) == MAPISTORE_SUCCESS);
    CHECK(!has_id(ids, mid_a) && !has_id(ids, mid_b) && dcn0);
    /* edited by another client: a new change number for that card only */
    CHECK(!ctl("edit?path=" BOOK "a.vcf"));
    if (row_of(f, "a", &mid, &cn, NULL)) return 1;
    CHECK(mid == mid_a && cn != cn_a);
    if (row_of(f, "b", &mid, &cn, NULL)) return 1;
    CHECK(mid == mid_b && cn == cn_b);
    /* deleted by another client: in get_deleted_fmids, with a new change */
    CHECK(!ctl("delete?path=" BOOK "b.vcf"));
    CHECK(B.folder.get_deleted_fmids(f, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn1) == MAPISTORE_SUCCESS);
    CHECK(has_id(ids, mid_b) && !has_id(ids, mid_a) && dcn1 != dcn0);
    if (row_of(f, "a", &mid, &cn, &n)) return 1;
    CHECK(n == 1);
    CHECK(B.folder.get_deleted_fmids(f, root, MAPISTORE_FOLDER_TABLE, 0, &ids, &dcn1) == MAPISTORE_SUCCESS && ids->cValues == 0);
    backend_down();
    return 0;
}

/* Review Focus 5: an unusable sync token never mints a second MID, and deletions are still seen. */
static int test_ics_token_invalid_no_dup_mids(void)
{
    struct dav_folder *f, *f2;
    struct UI8Array_r *ids;
    uint64_t mid_a, mid_b, mid, cn, dcn;
    uint32_t n;
    void *msg;

    CHECK(!backend_up());
    if (put("ta.vcf", VC("ta")) || put("tb.vcf", VC("tb"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "ta", &mid_a, &cn, NULL) || row_of(f, "tb", &mid_b, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid_a, false, &msg) == MAPISTORE_SUCCESS);
    CHECK(B.folder.open_message(f, root, mid_b, false, &msg) == MAPISTORE_SUCCESS);
    /* RFC 6578 servers refuse the token: full listing */
    CHECK(!ctl("delete?path=" BOOK "tb.vcf") && !ctl("invalidate_token"));
    if (row_of(f, "ta", &mid, &cn, &n)) return 1;
    CHECK(n == 1 && mid == mid_a);
    CHECK(B.folder.get_deleted_fmids(f, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS);
    CHECK(has_id(ids, mid_b) && !has_id(ids, mid_a));
    /* SOGo answers an unknown token with every card plus tombstones */
    talloc_free(f->ctx->token);
    f->ctx->token = talloc_strdup(f->ctx, "1");
    CHECK(!ctl("edit?path=" BOOK "ta.vcf"));
    if (row_of(f, "ta", &mid, &cn, &n)) return 1;
    CHECK(n == 1 && mid == mid_a && f->ctx->nitems == 1);
    /* a new session lists everything: same MID, and a card it was given that went away is reported */
    CHECK(B.folder.open_message(f, root, mid_a, false, &msg) == MAPISTORE_SUCCESS);
    CHECK(!ctl("delete?path=" BOOK "ta.vcf") && put("tc.vcf", VC("tc")) == 0);
    CHECK((f2 = book("personal")) != NULL);
    CHECK(B.folder.get_deleted_fmids(f2, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS);
    CHECK(has_id(ids, mid_a));
    if (row_of(f2, "tc", &mid, &cn, &n)) return 1;
    CHECK(n == 1 && mid && mid != mid_a && mid != mid_b);
    backend_down();
    return 0;
}

/* A card deleted while every client is away: each later session of the user reports it, until it is back. */
static int test_deletion_reaches_every_client(void)
{
    struct dav_folder *a, *b, *c;
    struct UI8Array_r *ids;
    uint64_t mid_x, cn, dcn;
    void *msg;

    CHECK(!backend_up());
    if (put("dx.vcf", VC("dx"))) return 1;
    CHECK((a = book("personal")) != NULL);
    if (row_of(a, "dx", &mid_x, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(a, root, mid_x, false, &msg) == MAPISTORE_SUCCESS);	/* PC1 and PC2 hold it */
    CHECK(!ctl("delete?path=" BOOK "dx.vcf"));
    CHECK((a = book("personal")) != NULL);	/* PC1 logs on */
    CHECK(B.folder.get_deleted_fmids(a, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS && has_id(ids, mid_x));
    CHECK((b = book("personal")) != NULL);	/* PC2 logs on later */
    CHECK(B.folder.get_deleted_fmids(b, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS && has_id(ids, mid_x));
    /* put back at the same href: no longer deleted, same MID */
    if (put("dx.vcf", VC("dx"))) return 1;
    CHECK((c = book("personal")) != NULL);
    CHECK(B.folder.get_deleted_fmids(c, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS && !has_id(ids, mid_x));
    if (row_of(c, "dx", &cn, &dcn, NULL)) return 1;
    CHECK(cn == mid_x);
    CHECK((c = book("personal")) != NULL);
    CHECK(B.folder.get_deleted_fmids(c, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS && !has_id(ids, mid_x));
    backend_down();
    return 0;
}

static int test_fp_written_on_read(void)
{
    struct dav_folder *f;
    uint64_t fp[DAV_F_COUNT], mid, cn;
    char *etag, *norm = "/dav/u/Contacts/personal/fp1.vcf";
    struct dav_item *it;
    void *msg;

    CHECK(!backend_up());
    if (put("fp1.vcf", VC("fp1"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "fp1", &mid, &cn, NULL)) return 1;
    CHECK(dav_fp_get(f->ctx->fp, root, "u", norm, fp, &etag) == MAPISTORE_ERR_NOT_FOUND);
    CHECK(B.folder.open_message(f, root, mid, false, &msg) == MAPISTORE_SUCCESS);
    CHECK((it = dav_item_by_mid(f->ctx, mid)) != NULL);
    CHECK(dav_fp_get(f->ctx->fp, root, "u", norm, fp, &etag) == MAPISTORE_SUCCESS && !strcmp(etag, it->etag));
    CHECK(fp[DAV_F_FN] == dav_fp(test_key, sizeof test_key, DAV_F_FN, "fp1"));
    CHECK(fp[DAV_F_NOTE] == dav_fp(test_key, sizeof test_key, DAV_F_NOTE, NULL));
    CHECK(fp[DAV_F_FN] != dav_fp((const uint8_t *)"another key, also 32 bytes long!", 32, DAV_F_FN, "fp1"));
    /* the next read after an edit elsewhere records the new version */
    CHECK(!ctl("edit?path=" BOOK "fp1.vcf"));
    if (row_of(f, "fp1", &mid, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid, false, &msg) == MAPISTORE_SUCCESS);
    CHECK(dav_fp_get(f->ctx->fp, root, "u", norm, fp, &etag) == MAPISTORE_SUCCESS && !strcmp(etag, dav_item_by_mid(f->ctx, mid)->etag));
    backend_down();
    return 0;
}

static int test_fpstore_memory(void)
{
    struct dav_fpstore *s = dav_fpstore_open(root, NULL);
    uint64_t fp[DAV_F_COUNT] = { 1, 2, 3 }, got[DAV_F_COUNT];
    char *etag, **gone, *live[] = { "/b/x" };
    size_t n;

    CHECK(s);
    CHECK(dav_fp_put(s, "u", "/b/x", fp, "\"1\"") == MAPISTORE_SUCCESS);
    CHECK(dav_fp_put(s, "u", "/b/y", fp, "\"2\"") == MAPISTORE_SUCCESS);
    CHECK(dav_fp_put(s, "u", "/c/z", fp, "\"3\"") == MAPISTORE_SUCCESS);
    CHECK(dav_fp_put(s, "v", "/b/y", fp, "\"4\"") == MAPISTORE_SUCCESS);
    fp[0] = 9;
    CHECK(dav_fp_put(s, "u", "/b/x", fp, "\"5\"") == MAPISTORE_SUCCESS);
    CHECK(dav_fp_get(s, root, "u", "/b/x", got, &etag) == MAPISTORE_SUCCESS && !strcmp(etag, "\"5\"") && got[0] == 9 && got[2] == 3);
    CHECK(dav_fp_get(s, root, "w", "/b/x", got, &etag) == MAPISTORE_ERR_NOT_FOUND);
    /* prune: only this user's rows of this book that are not live */
    CHECK(dav_fp_prune(s, "u", "/b", live, 1, root, &gone, &n) == MAPISTORE_SUCCESS && n == 1 && !strcmp(gone[0], "/b/y"));
    CHECK(dav_fp_get(s, root, "u", "/b/y", got, &etag) == MAPISTORE_ERR_NOT_FOUND);
    /* a tombstone: reported again on the next prune (another client of the user may not know yet) */
    CHECK(dav_fp_prune(s, "u", "/b", live, 1, root, &gone, &n) == MAPISTORE_SUCCESS && n == 1 && !strcmp(gone[0], "/b/y"));
    {
        char *both[] = { "/b/x", "/b/y" };
        /* listed again (put back): the tombstone goes */
        CHECK(dav_fp_prune(s, "u", "/b", both, 2, root, &gone, &n) == MAPISTORE_SUCCESS && n == 0);
        CHECK(dav_fp_prune(s, "u", "/b", live, 1, root, &gone, &n) == MAPISTORE_SUCCESS && n == 0);
    }
    CHECK(dav_fp_get(s, root, "v", "/b/y", got, &etag) == MAPISTORE_SUCCESS);
    CHECK(dav_fp_get(s, root, "u", "/c/z", got, &etag) == MAPISTORE_SUCCESS);
    CHECK(dav_fp_delete(s, "u", "/b/x") == MAPISTORE_SUCCESS);
    CHECK(dav_fp_get(s, root, "u", "/b/x", got, &etag) == MAPISTORE_ERR_NOT_FOUND);
    /* tombstone: no longer read, reported gone */
    CHECK(dav_fp_tombstone(s, "u", "/c/z") == MAPISTORE_SUCCESS);
    CHECK(dav_fp_get(s, root, "u", "/c/z", got, &etag) == MAPISTORE_ERR_NOT_FOUND);
    CHECK(dav_fp_prune(s, "u", "/c", NULL, 0, root, &gone, &n) == MAPISTORE_SUCCESS && n == 1 && !strcmp(gone[0], "/c/z"));
    /* versions: the newest the PCL names; only the last DAV_FP_VERSIONS kept */
    {
        uint8_t x[11][22], pcl[2 * 23];
        struct Binary_r ck = { .cb = 22 }, p = { .cb = 46, .lpb = pcl };
        int i;
        for (i = 0; i < 11; i++) {
            memset(x[i], 0xEE, 22);
            x[i][21] = i;
            ck.lpb = x[i];
            fp[0] = 100 + i;
            CHECK(dav_fp_version_put(s, "u", "/b/v", &ck, fp, talloc_asprintf(root, "\"%d\"", i)) == MAPISTORE_SUCCESS);
        }
        ck.lpb = x[5];
        fp[0] = 105;
        CHECK(dav_fp_version_put(s, "u", "/b/v", &ck, fp, "\"5\"") == MAPISTORE_SUCCESS);	/* again: one row */
        pcl[0] = pcl[23] = 22;
        memcpy(pcl + 1, x[3], 22);
        memcpy(pcl + 24, x[5], 22);
        CHECK(dav_fp_version_get(s, root, "u", "/b/v", &p, got, &etag) == MAPISTORE_SUCCESS && got[0] == 105 && !strcmp(etag, "\"5\""));
        memcpy(pcl + 24, x[0], 22);	/* the oldest went: the next named one */
        CHECK(dav_fp_version_get(s, root, "u", "/b/v", &p, got, &etag) == MAPISTORE_SUCCESS && got[0] == 103);
        p.cb = 23;
        memcpy(pcl + 1, x[0], 22);
        CHECK(dav_fp_version_get(s, root, "u", "/b/v", &p, got, &etag) == MAPISTORE_ERR_NOT_FOUND);
        CHECK(dav_fp_version_get(s, root, "w", "/b/v", &p, got, &etag) == MAPISTORE_ERR_NOT_FOUND);
        CHECK(dav_fp_delete(s, "u", "/b/v") == MAPISTORE_SUCCESS);
        memcpy(pcl + 1, x[10], 22);
        CHECK(dav_fp_version_get(s, root, "u", "/b/v", &p, got, &etag) == MAPISTORE_ERR_NOT_FOUND);
    }
    talloc_free(s);
    return 0;
}


/* ---- field merge (no server) ---- */

static const char *TODAY = "2026-11-17";

static struct dav_card *card_of(const char *text)
{
    return dav_card_parse(root, text, strlen(text));
}

static void no_outlook(char *v[DAV_F_COUNT], bool p[DAV_F_COUNT])
{
    int f;
    for (f = 0; f < DAV_F_COUNT; f++) { v[f] = NULL; p[f] = false; }
}

#define MCARD(fn, cell) "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:m1\r\nFN:" fn "\r\nTEL;TYPE=CELL:" cell "\r\nEND:VCARD\r\n"

static int merge(struct dav_card *server, char *v[DAV_F_COUNT], bool p[DAV_F_COUNT], const uint64_t *base,
                 time_t ot, time_t st)
{
    return dav_merge(root, server, (const char **)v, p, base, ot, st, test_key, sizeof test_key, TODAY) != MAPISTORE_SUCCESS;
}

static int test_merge_only_outlook(void)
{
    struct dav_card *base = card_of(MCARD("Ana", "111")), *server = card_of(MCARD("Ana", "111"));
    uint64_t fp[DAV_F_COUNT];
    char *v[DAV_F_COUNT];
    bool p[DAV_F_COUNT];
    CHECK(base && server);
    dav_fp_card(test_key, sizeof test_key, base, fp);
    no_outlook(v, p);
    v[DAV_F_FN] = "Ana Maria"; p[DAV_F_FN] = true;
    v[DAV_F_TEL_CELL] = "111"; p[DAV_F_TEL_CELL] = true;
    CHECK(!merge(server, v, p, fp, 100, 200));	/* only Outlook changed it: Outlook's, whatever the times */
    CHECK(!strcmp(dav_field_get(root, server, DAV_F_FN), "Ana Maria"));
    CHECK(!strcmp(dav_field_get(root, server, DAV_F_TEL_CELL), "111"));
    CHECK(dav_field_get(root, server, DAV_F_NOTE) == NULL);
    return 0;
}

static int test_merge_only_server(void)
{
    struct dav_card *base = card_of(MCARD("Ana", "111")), *server = card_of(MCARD("Ana", "999"));
    uint64_t fp[DAV_F_COUNT];
    char *v[DAV_F_COUNT];
    bool p[DAV_F_COUNT];
    dav_fp_card(test_key, sizeof test_key, base, fp);
    no_outlook(v, p);
    v[DAV_F_FN] = "Ana"; p[DAV_F_FN] = true;
    v[DAV_F_TEL_CELL] = "111"; p[DAV_F_TEL_CELL] = true;	/* Outlook still has the old number */
    CHECK(!merge(server, v, p, fp, 300, 200));
    CHECK(!strcmp(dav_field_get(root, server, DAV_F_TEL_CELL), "999"));
    CHECK(dav_field_get(root, server, DAV_F_NOTE) == NULL);
    /* neither side changed it, Outlook did not send it: kept */
    no_outlook(v, p);
    CHECK(!merge(server, v, p, fp, 300, 200) && !strcmp(dav_field_get(root, server, DAV_F_FN), "Ana"));
    return 0;
}

static int test_merge_both_outlook_newer_note(void)
{
    struct dav_card *base = card_of(MCARD("Ana", "111")), *server = card_of(MCARD("Ana", "222"));
    uint64_t fp[DAV_F_COUNT];
    char *v[DAV_F_COUNT], *note;
    bool p[DAV_F_COUNT];
    dav_fp_card(test_key, sizeof test_key, base, fp);
    no_outlook(v, p);
    v[DAV_F_TEL_CELL] = "333"; p[DAV_F_TEL_CELL] = true;
    CHECK(!merge(server, v, p, fp, 300, 200));
    CHECK(!strcmp(dav_field_get(root, server, DAV_F_TEL_CELL), "333"));
    CHECK((note = dav_field_get(root, server, DAV_F_NOTE)) && !strcmp(note, "[2026-11-17 conflito] celular: 222"));
    return 0;
}

static int test_merge_both_server_newer_note(void)
{
    struct dav_card *base = card_of(MCARD("Ana", "111")), *server;
    uint64_t fp[DAV_F_COUNT];
    char *v[DAV_F_COUNT], *note;
    bool p[DAV_F_COUNT];
    server = card_of("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:m1\r\nFN:Ana\r\nTEL;TYPE=CELL:222\r\nNOTE:antes\r\n"
                     "PHOTO;ENCODING=b;TYPE=JPEG:QUJD\r\nEND:VCARD\r\n");
    dav_fp_card(test_key, sizeof test_key, base, fp);
    no_outlook(v, p);
    v[DAV_F_TEL_CELL] = "333"; p[DAV_F_TEL_CELL] = true;
    v[DAV_F_PHOTO] = "WFla"; p[DAV_F_PHOTO] = true;
    CHECK(!merge(server, v, p, fp, 200, 300));
    CHECK(!strcmp(dav_field_get(root, server, DAV_F_TEL_CELL), "222"));
    CHECK(!strcmp(dav_field_get(root, server, DAV_F_PHOTO), "QUJD"));
    note = dav_field_get(root, server, DAV_F_NOTE);
    CHECK(note && !strcmp(note, "antes\n[2026-11-17 conflito] celular: 333\n[2026-11-17 conflito] foto substitu\xc3\xad" "da"));
    /* a tie keeps the stored value */
    server = card_of(MCARD("Ana", "222"));
    CHECK(!merge(server, v, p, fp, 300, 300) && !strcmp(dav_field_get(root, server, DAV_F_TEL_CELL), "222"));
    return 0;
}

static int test_merge_no_base_note(void)
{
    struct dav_card *server = card_of("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:m1\r\nFN:Ana\r\nTEL;TYPE=CELL:111\r\n"
                                      "ADR;TYPE=WORK:;;Rua A\\, 1;Cidade;;;\r\nEND:VCARD\r\n");
    char *v[DAV_F_COUNT], *note;
    bool p[DAV_F_COUNT];
    no_outlook(v, p);
    v[DAV_F_FN] = "Ana"; p[DAV_F_FN] = true;	/* same value: nothing to say */
    v[DAV_F_TEL_CELL] = "222"; p[DAV_F_TEL_CELL] = true;
    v[DAV_F_ADR_WORK] = "\n\nRua B\nCidade\n\n\n"; p[DAV_F_ADR_WORK] = true;
    CHECK(!merge(server, v, p, NULL, 300, 200));
    CHECK(!strcmp(dav_field_get(root, server, DAV_F_TEL_CELL), "222"));
    note = dav_field_get(root, server, DAV_F_NOTE);
    CHECK(note && !strcmp(note, "[2026-11-17 conflito] celular: 111\n"
                                "[2026-11-17 conflito] endere\xc3\xa7o comercial: Rua A, 1, Cidade"));
    return 0;
}

#define MLIST(lines) "BEGIN:VLIST\r\nUID:l1\r\nVERSION:1.0\r\nFN:L\r\n" lines "END:VLIST\r\n"
#define LA "CARD;EMAIL=a@x.test;FN=A:ua.vcf\r\n"
#define LB "CARD;EMAIL=b@x.test;FN=B:ub.vcf\r\n"
#define LC "CARD;EMAIL=c@x.test;FN=C:uc.vcf\r\n"
#define LD "CARD;EMAIL=d@x.test;FN=D:ud.vcf\r\n"

static int test_merge_members_sets(void)
{
    struct dav_card *base = card_of(MLIST(LA LB LC)), *server = card_of(MLIST(LA LB LC LD));
    uint64_t fp[DAV_F_COUNT];
    char *v[DAV_F_COUNT];
    bool p[DAV_F_COUNT];
    dav_fp_card(test_key, sizeof test_key, base, fp);
    /* SOGo added D, Outlook removed B (and knows C only as a free address): both apply */
    no_outlook(v, p);
    v[DAV_F_LIST_MEMBERS] = "mailto:c@x.test\nua"; p[DAV_F_LIST_MEMBERS] = true;
    CHECK(!merge(server, v, p, fp, 100, 200));
    CHECK(!strcmp(dav_field_get(root, server, DAV_F_LIST_MEMBERS), "ua\nuc\nud"));
    CHECK(strstr(dav_card_render(root, server), LC) && dav_field_get(root, server, DAV_F_NOTE) == NULL);
    /* Outlook unchanged (mailto: of a member line is that line): nothing removed */
    server = card_of(MLIST(LA LB LC LD));
    v[DAV_F_LIST_MEMBERS] = "mailto:b@x.test\nua\nuc";
    CHECK(!merge(server, v, p, fp, 300, 200) && !strcmp(dav_field_get(root, server, DAV_F_LIST_MEMBERS), "ua\nub\nuc\nud"));
    /* only Outlook changed: its set, a new free address as a CARD line with its EMAIL */
    server = card_of(MLIST(LA LB LC));
    v[DAV_F_LIST_MEMBERS] = "mailto:new@x.test\nua";
    CHECK(!merge(server, v, p, fp, 100, 200));
    CHECK(!strcmp(dav_field_get(root, server, DAV_F_LIST_MEMBERS), "mailto:new@x.test\nua"));
    /* no fingerprint: the union, nothing removed */
    server = card_of(MLIST(LA LB));
    v[DAV_F_LIST_MEMBERS] = "uc";
    CHECK(!merge(server, v, p, NULL, 300, 200) && !strcmp(dav_field_get(root, server, DAV_F_LIST_MEMBERS), "ua\nub\nuc"));
    return 0;
}

static int test_merge_keeps_unknown_lines(void)
{
    const char *in = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:m1\r\nFN:Ana\r\nX-PHONE-CUSTOM;X-LABEL=obra:555\r\n"
                     "item1.TEL:777\r\nitem1.X-ABLabel:portaria\r\nTEL;TYPE=CELL:111\r\nEND:VCARD\r\n";
    struct dav_card *server = card_of(in);
    uint64_t fp[DAV_F_COUNT];
    char *v[DAV_F_COUNT], *out;
    bool p[DAV_F_COUNT];
    dav_fp_card(test_key, sizeof test_key, server, fp);
    no_outlook(v, p);
    v[DAV_F_TEL_CELL] = "222"; p[DAV_F_TEL_CELL] = true;
    v[DAV_F_FN] = "Ana"; p[DAV_F_FN] = true;
    CHECK(!merge(server, v, p, fp, 300, 200));
    out = dav_card_render(root, server);
    CHECK(strstr(out, "X-PHONE-CUSTOM;X-LABEL=obra:555\r\nitem1.TEL:777\r\nitem1.X-ABLabel:portaria\r\nTEL;TYPE=CELL:222\r\n"));
    return 0;
}

static int test_fp_keyed(void)
{
    const uint8_t other[32] = "another key, also 32 bytes long!";
    CHECK(dav_fp(test_key, sizeof test_key, DAV_F_TEL_CELL, "1234") != dav_fp(other, sizeof other, DAV_F_TEL_CELL, "1234"));
    CHECK(dav_fp(test_key, sizeof test_key, DAV_F_TEL_CELL, "1234") == dav_fp(test_key, sizeof test_key, DAV_F_TEL_CELL, "1234"));
    CHECK(dav_fp(test_key, sizeof test_key, DAV_F_TEL_CELL, "1234") != dav_fp(test_key, sizeof test_key, DAV_F_TEL_HOME, "1234"));
    CHECK(dav_fp(test_key, sizeof test_key, DAV_F_NOTE, "") != dav_fp(test_key, sizeof test_key, DAV_F_NOTE, NULL));
    return 0;
}

/* ---- write path against the fake ---- */

#define WBOOK "/dav/u/Contacts/personal/"

static struct SRow *props(int n, ...)
{
    struct SRow *row = talloc_zero(root, struct SRow);
    va_list ap;
    int i;
    row->lpProps = talloc_zero_array(row, struct SPropValue, n);
    va_start(ap, n);
    for (i = 0; i < n; i++) {
        uint32_t tag = va_arg(ap, uint32_t);
        const void *val = va_arg(ap, const void *);
        set_SPropValue_proptag(&row->lpProps[row->cValues++], tag, val);
    }
    va_end(ap);
    return row;
}

/* The stored card, unfolded. */
static char *stored(const char *name)
{
    struct dav_http *h = client("p");
    char *body = NULL, *etag, *o, *i;
    if (dav_get(h, root, talloc_asprintf(root, WBOOK "%s", name), &body, &etag) != MAPISTORE_SUCCESS) body = NULL;
    talloc_free(h);
    for (o = i = body; i && *i; ) {
        if (!strncmp(i, "\r\n ", 3)) i += 3;
        else *o++ = *i++;
    }
    if (o) *o = '\0';
    return body;
}

/* Name of the one card of the book whose body has needle (NULL if none). */
static char *stored_with(const char *needle)
{
    struct dav_http *h = client("p");
    struct dav_change *ch;
    char *tok, *body, *etag, *found = NULL;
    size_t n, i;
    bool full;
    if (dav_sync(h, root, WBOOK, NULL, &ch, &n, &tok, &full) != MAPISTORE_SUCCESS) n = 0;
    for (i = 0; i < n; i++) {
        if (ch[i].etag && dav_get(h, root, ch[i].href, &body, &etag) == MAPISTORE_SUCCESS && strstr(body, needle)) {
            found = talloc_strdup(root, strrchr(ch[i].href, '/') + 1);
        }
    }
    talloc_free(h);
    return found;
}

static int test_save_new_contact_put(void)
{
    struct dav_folder *f;
    void *msg, *att;
    uint32_t aid, n;
    uint64_t mid, cn, fp[DAV_F_COUNT];
    char *name, *body, *etag;
    uint8_t yes = 1;
    struct Binary_r pic = { .cb = 3, .lpb = (uint8_t *)"JPG" };
    struct dav_member_resolver r;

    CHECK(!backend_up());
    CHECK((f = book("personal")) != NULL);
    CHECK(B.folder.create_message(f, root, 0x77770001, 1, &msg) == MAPISTORE_ERR_DENIED);	/* FAI */
    CHECK(B.folder.create_message(f, root, 0x77770001, 0, &msg) == MAPISTORE_SUCCESS);
    CHECK(B.properties.set_properties(msg, props(4, PidTagMessageClass, "IPM.Contact", PidTagDisplayName, "Nova Pessoa",
                                                 PidTagSurname, "Pessoa", EMAIL1, "nova@exemplo.test")) == MAPISTORE_SUCCESS);
    CHECK(B.message.create_attachment(msg, root, &att, &aid) == MAPISTORE_SUCCESS);
    CHECK(B.properties.set_properties(att, props(2, PidTagAttachDataBinary, &pic, PidTagAttachmentContactPhoto, &yes)) == MAPISTORE_SUCCESS);
    CHECK(B.message.save(msg, root) == MAPISTORE_SUCCESS);
    CHECK((name = stored_with("FN:Nova Pessoa")) != NULL);
    body = stored(name);
    CHECK(strstr(body, "BEGIN:VCARD\r\nVERSION:3.0\r\n") && strstr(body, "N:Pessoa;;;;\r\n") && strstr(body, "nova@exemplo.test")
          && strstr(body, "PHOTO;ENCODING=b;TYPE=JPEG:SlBH\r\n"));
    /* <UID>.vcf */
    CHECK(strstr(body, talloc_asprintf(root, "UID:%.*s\r\n", (int)(strlen(name) - 4), name)));
    /* the row keeps Outlook's MID; fingerprints of the stored version */
    if (row_of(f, "Nova Pessoa", &mid, &cn, &n)) return 1;
    CHECK(mid == 0x77770001 && n == 1);
    CHECK(dav_fp_get(f->ctx->fp, root, "u", talloc_asprintf(root, WBOOK "%s", name), fp, &etag) == MAPISTORE_SUCCESS);
    CHECK(fp[DAV_F_FN] == dav_fp(test_key, sizeof test_key, DAV_F_FN, "Nova Pessoa"));
    /* a new list with a free address: a stub card (FN + EMAIL) the CARD line names, as SOGo's web UI does */
    {
        const char *src = "BEGIN:VLIST\r\nFN:x\r\nCARD;EMAIL=Livre2@Exemplo.test;FN=Livre Dois:not-in-book.vcf\r\nEND:VLIST\r\n";
        struct dav_card *c = card_of(src);
        const struct dav_named_tags *t = &f->ctx->tags;
        void *mv, *oo;
        char *list, *stub;
        dav_folder_resolver(f, &r);
        CHECK(dav_card_get_prop(root, c, t, &r, t->dl_members, &mv) == MAPISTORE_SUCCESS);
        CHECK(dav_card_get_prop(root, c, t, &r, t->dl_one_off_members, &oo) == MAPISTORE_SUCCESS);
        CHECK(B.folder.create_message(f, root, 0x77780001, 0, &msg) == MAPISTORE_SUCCESS);
        CHECK(B.properties.set_properties(msg, props(4, PidTagMessageClass, "IPM.DistList", t->dl_name, "Nova Lista",
                                                     t->dl_members, mv, t->dl_one_off_members, oo)) == MAPISTORE_SUCCESS);
        CHECK(B.message.save(msg, root) == MAPISTORE_SUCCESS);
        CHECK((list = stored_with("BEGIN:VLIST")) && (body = stored(list)));
        CHECK(strstr(body, "FN:Nova Lista\r\n") && strstr(body, "VERSION:1.0\r\n"));
        CHECK((stub = stored_with("FN:Livre Dois")) && strcmp(stub, list) != 0);
        CHECK(strstr(stored(stub), "EMAIL;TYPE=work:livre2@exemplo.test\r\n"));
        CHECK(strstr(body, talloc_asprintf(root, "CARD;EMAIL=livre2@exemplo.test;FN=Livre Dois:%s\r\n", stub)));
    }
    backend_down();
    return 0;
}

/* Cached mode: Outlook uploads the whole contact (ICS: open to write, purge, every property, save). */
static int upload(struct dav_folder *f, uint64_t mid, struct SRow *row, enum mapistore_error expect)
{
    void *msg;
    CHECK(B.folder.open_message(f, root, mid, true, &msg) == MAPISTORE_SUCCESS);
    CHECK(B.message.purge(msg) == MAPISTORE_SUCCESS);
    CHECK(B.properties.set_properties(msg, row) == MAPISTORE_SUCCESS);
    CHECK(B.message.save(msg, root) == expect);
    return 0;
}

#define WCARD(n, email, cell) "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:" n "\r\nN:" n ";;;;\r\nFN:" n "\r\nEMAIL;TYPE=INTERNET:" email \
    "\r\nTEL;TYPE=CELL:" cell "\r\nX-PHONE-ONLY:keep\r\nEND:VCARD\r\n"

static int test_save_concurrent_edit_merged(void)
{
    struct dav_folder *f;
    uint64_t mid, cn, cn2;
    void *msg;
    char *body;
    /* Outlook's own replica (another GUID) */
    uint8_t ckb[22] = { 0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0, 0, 7 }, pclb[23];
    uint8_t pcl2b[46];
    struct Binary_r ck = { .cb = 22, .lpb = ckb }, pcl = { .cb = 23, .lpb = pclb }, pcl2 = { .cb = 46, .lpb = pcl2b }, *got;
    enum MAPITAGS kt[] = { PidTagChangeKey, PidTagPredecessorChangeList };
    struct mapistore_property_data kd[2];
    pclb[0] = 22;
    memcpy(pclb + 1, ckb, 22);

    CHECK(!backend_up());
    if (put("ce.vcf", WCARD("ce", "old@x.test", "111"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "ce", &mid, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid, false, &msg) == MAPISTORE_SUCCESS);	/* Outlook downloads it */
    CHECK(B.properties.get_properties(msg, root, 1, kt, kd) == MAPISTORE_SUCCESS && kd[0].error == 0);
    pcl2.lpb[0] = 22;
    memcpy(pcl2.lpb + 1, ((struct Binary_r *)kd[0].data)->lpb, 22);	/* the version Outlook was given */
    memcpy(pcl2.lpb + 23, pclb, 23);
    CHECK(!ctl("edit?path=" WBOOK "ce.vcf&set=TEL;TYPE=CELL:999"));	/* the phone, on webmail */
    /* Outlook offline changed the e-mail; its upload still carries the old phone */
    if (upload(f, mid, props(7, PidTagDisplayName, "ce", PidTagSurname, "ce", EMAIL1, "new@x.test",
                             PidTagMobileTelephoneNumber, "111", PidTagMessageClass, "IPM.Contact",
                             PidTagChangeKey, &ck, PidTagPredecessorChangeList, &pcl2), MAPISTORE_SUCCESS)) return 1;
    body = stored("ce.vcf");
    CHECK(strstr(body, "new@x.test") && strstr(body, "TEL;TYPE=CELL:999\r\n") && strstr(body, "X-PHONE-ONLY:keep\r\n")
          && !strstr(body, "conflito"));
    /* Outlook gets the merged version on its next sync: a new change, which follows Outlook's (no conflict) */
    if (row_of(f, "ce", &mid, &cn2, NULL)) return 1;
    CHECK(cn2 != cn);
    CHECK(B.folder.open_message(f, root, mid, false, &msg) == MAPISTORE_SUCCESS);
    CHECK(B.properties.get_properties(msg, root, 2, kt, kd) == MAPISTORE_SUCCESS && kd[0].error == 0 && kd[1].error == 0);
    got = kd[1].data;
    CHECK(((struct Binary_r *)kd[0].data)->cb == 22 && memcmp(((struct Binary_r *)kd[0].data)->lpb, ck.lpb, 16) != 0);
    /* Outlook's XID kept, the older server XID replaced by the new one */
    CHECK(got->cb == 23 + 23 && !memcmp(got->lpb, pcl.lpb, 23) && !memcmp(got->lpb + 24, ((struct Binary_r *)kd[0].data)->lpb, 22));
    /* an upload nothing else touched: Outlook's own keys stand for it, no change bounces back */
    ck.lpb[21] = 8;
    pcl.lpb = talloc_memdup(root, got->lpb, got->cb);	/* what Outlook now holds, plus its new change */
    pcl.cb = got->cb;
    pcl.lpb[22] = 8;
    if (upload(f, mid, props(7, PidTagDisplayName, "ce", PidTagSurname, "ce", EMAIL1, "new@x.test",
                             PidTagMobileTelephoneNumber, "999", PidTagMessageClass, "IPM.Contact",
                             PidTagChangeKey, &ck, PidTagPredecessorChangeList, &pcl), MAPISTORE_SUCCESS)) return 1;
    CHECK(B.folder.open_message(f, root, mid, false, &msg) == MAPISTORE_SUCCESS);
    CHECK(B.properties.get_properties(msg, root, 2, kt, kd) == MAPISTORE_SUCCESS && kd[0].error == 0);
    CHECK(((struct Binary_r *)kd[0].data)->cb == 22 && !memcmp(((struct Binary_r *)kd[0].data)->lpb, ck.lpb, 22));
    backend_down();
    return 0;
}

static int test_save_412_three_times_conflict(void)
{
    struct dav_folder *f;
    uint64_t mid, cn;
    void *msg;

    CHECK(!backend_up());
    if (put("cf.vcf", WCARD("cf", "a@x.test", "111"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "cf", &mid, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid, true, &msg) == MAPISTORE_SUCCESS);	/* online edit */
    CHECK(B.properties.set_properties(msg, props(1, PidTagMobileTelephoneNumber, "222")) == MAPISTORE_SUCCESS);
    CHECK(!ctl("conflict?n=4"));	/* one try and three redos, all refused */
    CHECK(B.message.save(msg, root) == MAPISTORE_ERR_CONFLICT);
    CHECK(mapistore_error_to_mapi(MAPISTORE_ERR_CONFLICT) == MAPI_E_OBJECT_CHANGED);
    /* SOGo down: a network error, so Outlook keeps the upload and retries instead of filing it under Local Failures */
    CHECK(mapistore_error_to_mapi(MAPISTORE_ERR_CONN_REFUSED) == ecRpcFailed);
    CHECK(strstr(stored("cf.vcf"), "TEL;TYPE=CELL:111\r\n"));
    /* changed three times meanwhile: merged again, saved */
    CHECK(!ctl("conflict?n=3"));
    CHECK(B.message.save(msg, root) == MAPISTORE_SUCCESS);
    CHECK(strstr(stored("cf.vcf"), "TEL;TYPE=CELL:222\r\n"));
    /* saved again on the same handle with nothing new: the server's later edit stays, no conflict line */
    CHECK(!ctl("edit?path=" WBOOK "cf.vcf&set=TEL;TYPE=CELL:555"));
    CHECK(B.message.save(msg, root) == MAPISTORE_SUCCESS);
    CHECK(strstr(stored("cf.vcf"), "TEL;TYPE=CELL:555\r\n") && !strstr(stored("cf.vcf"), "conflito"));
    backend_down();
    return 0;
}

static int test_save_after_remote_delete_recreates(void)
{
    struct dav_folder *f;
    struct UI8Array_r *ids;
    uint64_t mid, mid2, cn, dcn;
    uint32_t n;
    void *msg;
    char *name, *body;

    CHECK(!backend_up());
    if (put("rd.vcf", WCARD("rd", "a@x.test", "111"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "rd", &mid, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid, false, &msg) == MAPISTORE_SUCCESS);
    CHECK(!ctl("delete?path=" WBOOK "rd.vcf"));
    if (upload(f, mid, props(4, PidTagDisplayName, "rd", PidTagSurname, "rd", EMAIL1, "a@x.test",
                             PidTagMobileTelephoneNumber, "333"), MAPISTORE_SUCCESS)) return 1;
    CHECK(stored("rd.vcf") == NULL);
    CHECK((name = stored_with("UID:rd\r\n")) && strcmp(name, "rd.vcf") != 0);	/* a fresh href, the same UID */
    body = stored(name);
    CHECK(strstr(body, "TEL;TYPE=CELL:333\r\n") && strstr(body, "X-PHONE-ONLY:keep\r\n"));
    /* same MID, not reported deleted */
    if (row_of(f, "rd", &mid2, &cn, &n)) return 1;
    CHECK(mid2 == mid && n == 1);
    CHECK(B.folder.get_deleted_fmids(f, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS && !has_id(ids, mid));
    backend_down();
    return 0;
}

static int test_delete_after_remote_edit_survives(void)
{
    struct dav_folder *f, *f2;
    struct UI8Array_r *ids;
    uint64_t mid, mid2, mid_g, cn, cn2, dcn, fp[DAV_F_COUNT];
    char *etag;
    void *msg;

    CHECK(!backend_up());
    if (put("ds.vcf", VC("ds")) || put("dg.vcf", VC("dg"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "ds", &mid, &cn, NULL) || row_of(f, "dg", &mid_g, &cn2, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid, false, &msg) == MAPISTORE_SUCCESS);
    CHECK(B.folder.open_message(f, root, mid_g, false, &msg) == MAPISTORE_SUCCESS);
    CHECK(!ctl("edit?path=" WBOOK "ds.vcf&set=NOTE:editado%20no%20celular"));
    /* Outlook deletes the version it saw: dropped, the newer one comes back under a new ID (Outlook never
       shows again an ID it deleted, whatever its change number) */
    CHECK(B.folder.delete_message(f, mid, 0) == MAPISTORE_SUCCESS);
    CHECK(stored("ds.vcf") && strstr(stored("ds.vcf"), "NOTE:editado no celular"));
    if (row_of(f, "ds", &mid2, &cn2, NULL)) return 1;
    CHECK(mid2 && mid2 != mid && cn2 != cn);
    CHECK(dav_fp_get(f->ctx->fp, root, "u", WBOOK "ds.vcf", fp, &etag) == MAPISTORE_SUCCESS);
    CHECK(B.folder.get_deleted_fmids(f, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS && has_id(ids, mid));
    CHECK(!has_id(ids, mid2));
    /* unchanged elsewhere: deleted; its row a tombstone, so a later session of the user (another PC) learns it */
    CHECK(B.folder.delete_message(f, mid_g, 0) == MAPISTORE_SUCCESS);
    CHECK(stored("dg.vcf") == NULL);
    CHECK(dav_fp_get(f->ctx->fp, root, "u", WBOOK "dg.vcf", fp, &etag) == MAPISTORE_ERR_NOT_FOUND);
    CHECK(B.folder.delete_message(f, mid_g, 0) == MAPISTORE_SUCCESS);	/* already gone */
    CHECK((f2 = book("personal")) != NULL);
    CHECK(B.folder.get_deleted_fmids(f2, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS && has_id(ids, mid_g));
    /* online: edited elsewhere before Outlook opened it to write, then deleted: the version it was shown goes */
    if (put("do.vcf", VC("do"))) return 1;
    if (row_of(f, "do", &mid, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid, false, &msg) == MAPISTORE_SUCCESS);
    CHECK(!ctl("edit?path=" WBOOK "do.vcf&set=NOTE:outro"));
    if (row_of(f, "do", &mid, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid, true, &msg) == MAPISTORE_SUCCESS);
    CHECK(B.folder.delete_message(f, mid, 0) == MAPISTORE_SUCCESS);
    CHECK(stored("do.vcf") == NULL);
    backend_down();
    return 0;
}

static int poll_has(struct mapistore_connection_info *s, size_t want, const char *uri, int kind);

/* The change key Outlook holds for an opened message, as the PCL it sends with a move. */
static struct Binary_r *pcl_of(void *msg)
{
    enum MAPITAGS kt[] = { PidTagChangeKey };
    struct mapistore_property_data d[1];
    struct Binary_r *ck, *pcl;
    if (B.properties.get_properties(msg, root, 1, kt, d) != MAPISTORE_SUCCESS || d[0].error) return NULL;
    ck = d[0].data;
    if (!(pcl = talloc_zero(root, struct Binary_r)) || !(pcl->lpb = talloc_array(pcl, uint8_t, ck->cb + 1))) return NULL;
    pcl->cb = ck->cb + 1;
    pcl->lpb[0] = ck->cb;
    memcpy(pcl->lpb + 1, ck->lpb, ck->cb);
    return pcl;
}

/* What Outlook deleted offline it moves, once back, to Deleted Items: another store, which refuses it, so emsmdb
   tells this one the messages left (no target). The move's PCL names the version Outlook deleted: unchanged since,
   the card goes; edited elsewhere since, it stays, under a new ID, since Outlook already took the edit and dropped
   it for its pending delete. */
static int test_move_out_after_offline_delete(void)
{
    struct dav_folder *f, *f2;
    struct UI8Array_r *ids;
    struct Binary_r *pl, *pk;
    uint64_t ml, mk, mk2, cn, cnk, dcn, dst = 0x9999;
    struct mapistore_connection_info *s = talloc_zero(root, struct mapistore_connection_info);
    void *msg;

    CHECK(!backend_up());
    if (put("ml.vcf", VC("ml")) || put("mk.vcf", VC("mk"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "ml", &ml, &cn, NULL) || row_of(f, "mk", &mk, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, ml, false, &msg) == MAPISTORE_SUCCESS && (pl = pcl_of(msg)));
    CHECK(B.folder.open_message(f, root, mk, false, &msg) == MAPISTORE_SUCCESS && (pk = pcl_of(msg)));
    CHECK(!ctl("edit?path=" WBOOK "mk.vcf&set=NOTE:editado%20no%20webmail"));	/* while Outlook is offline */
    /* back online, Outlook downloads first: it is given the edit */
    if (row_of(f, "mk", &mk2, &cnk, NULL)) return 1;
    CHECK(mk2 == mk && B.folder.open_message(f, root, mk, false, &msg) == MAPISTORE_SUCCESS);
    CHECK(B.folder.move_copy_messages(NULL, f, root, 1, &ml, &dst, NULL, &pl, false) == MAPISTORE_SUCCESS);
    CHECK(stored("ml.vcf") == NULL);
    s->username = talloc_strdup(s, "u");
    if (poll_has(s, 0, NULL, 0)) return 1;
    CHECK(B.folder.move_copy_messages(NULL, f, root, 1, &mk, &dst, NULL, &pk, false) == MAPISTORE_SUCCESS);
    CHECK(stored("mk.vcf") && strstr(stored("mk.vcf"), "NOTE:editado no webmail"));
    if (row_of(f, "mk", &mk2, &cn, NULL)) return 1;
    CHECK(mk2 && mk2 != mk && cn != cnk);
    CHECK(B.folder.get_deleted_fmids(f, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS);
    CHECK(has_id(ids, mk) && has_id(ids, ml) && !has_id(ids, mk2));
    /* nothing changed on the server, yet the card is new to Outlook: the session is told to sync the book */
    if (poll_has(s, 1, "dav://contacts/personal/", MAPISTORE_CHANGE_CONTENTS) || poll_has(s, 0, NULL, 0)) return 1;
    /* the new ID holds in the next session; a message already gone is no error */
    CHECK((f2 = book("personal")) != NULL);
    if (row_of(f2, "mk", &mk, &cn, NULL)) return 1;
    CHECK(mk == mk2);
    CHECK(B.folder.move_copy_messages(NULL, f2, root, 1, &ml, &dst, NULL, &pl, false) == MAPISTORE_SUCCESS);
    /* moves within the store and copies are not handled here */
    CHECK(B.folder.move_copy_messages(f2, f, root, 1, &mk, &dst, NULL, NULL, false) == MAPISTORE_ERR_DENIED);
    CHECK(B.folder.move_copy_messages(NULL, f, root, 1, &mk, &dst, NULL, NULL, true) == MAPISTORE_ERR_DENIED);
    CHECK(stored("mk.vcf") != NULL);
    /* a move naming no version we gave Outlook keeps the card */
    if (row_of(f2, "mk", &mk, &cn, NULL)) return 1;
    CHECK(B.folder.move_copy_messages(NULL, f2, root, 1, &mk, &dst, NULL, NULL, false) == MAPISTORE_SUCCESS);
    CHECK(stored("mk.vcf") != NULL);
    if (row_of(f2, "mk", &mk2, &cn, NULL)) return 1;
    CHECK(mk2 && mk2 != mk);
    backend_down();
    return 0;
}

static bool book_named(const char *displayname)
{
    struct dav_http *h = client("p");
    struct dav_book *b;
    size_t n, i;
    bool found = false;
    if (dav_list_books(h, root, &b, &n) == MAPISTORE_SUCCESS) {
        for (i = 0; i < n; i++) if (b[i].displayname && !strcmp(b[i].displayname, displayname)) found = true;
    }
    talloc_free(h);
    return found;
}

static int test_folder_create_rename_delete(void)
{
    struct dav_folder *f, *child, *again, *w;
    enum MAPITAGS tags[] = { PidTagDisplayName, PidTagContainerClass };
    struct mapistore_property_data d[2];
    void *c;

    CHECK(!backend_up());
    CHECK((f = book("personal")) != NULL);
    CHECK(B.folder.create_folder(f, root, 0x88880001, props(2, PidTagDisplayName, "Notas", PidTagContainerClass, "IPF.Note"), &c)
          == MAPISTORE_ERR_DENIED);
    CHECK(B.folder.create_folder(f, root, 0x88880001, props(2, PidTagDisplayName, "Clientes", PidTagContainerClass, "IPF.Contact"), &c)
          == MAPISTORE_SUCCESS);
    child = c;
    CHECK(child->fid == 0x88880001 && book_named("Clientes"));
    CHECK(B.properties.get_properties(child, root, 2, tags, d) == MAPISTORE_SUCCESS);
    CHECK(d[0].error == 0 && !strcmp(d[0].data, "Clientes") && d[1].error == 0 && !strcmp(d[1].data, "IPF.Contact"));
    /* opened again through Contacts; books are flat: nothing below another book */
    CHECK(B.folder.open_folder(f, root, 0x88880001, &c) == MAPISTORE_SUCCESS);
    again = c;
    CHECK(again->fid == 0x88880001 && !strcmp(again->ctx->book_href, child->ctx->book_href));
    CHECK(B.folder.create_folder(child, root, 0x88880002, props(1, PidTagDisplayName, "Sub"), &c) == MAPISTORE_ERR_DENIED);
    /* a contact in it */
    CHECK(B.folder.create_message(child, root, 0x88880003, 0, &c) == MAPISTORE_SUCCESS);
    CHECK(B.properties.set_properties(c, props(1, PidTagDisplayName, "Cliente Um")) == MAPISTORE_SUCCESS);
    CHECK(B.message.save(c, root) == MAPISTORE_SUCCESS);
    CHECK(B.properties.set_properties(child, props(1, PidTagDisplayName, "Clientes VIP")) == MAPISTORE_SUCCESS);
    CHECK(book_named("Clientes VIP") && !book_named("Clientes"));
    w = book(strrchr(talloc_strndup(root, child->ctx->uri, strlen(child->ctx->uri) - 1), '/') + 1);
    CHECK(w && w->fid == 0x88880001);
    CHECK(B.folder.delete(child) == MAPISTORE_SUCCESS);
    CHECK(!book_named("Clientes VIP"));
    backend_down();
    return 0;
}

static int test_delete_personal_denied(void)
{
    struct dav_folder *f;

    CHECK(!backend_up());
    CHECK((f = book("personal")) != NULL);
    CHECK(B.folder.delete(f) == MAPISTORE_ERR_DENIED);
    CHECK(book_named("Personal"));
    backend_down();
    return 0;
}

/* R11: PC A and PC B both hold v1; A saves v2 (one field); B, offline, uploads an edit of another field
   naming only v1: both edits stay, B's stale copy of A's field reverts nothing, no NOTE. */
static int test_stale_client_never_reverts(void)
{
    struct dav_folder *f;
    enum MAPITAGS kt[] = { PidTagChangeKey };
    struct mapistore_property_data kd[1];
    uint8_t xa[22] = { 0xA1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0, 0, 1 }, xb[22];
    uint8_t pa[46], pb[46];
    struct Binary_r cka = { .cb = 22, .lpb = xa }, ckb = { .cb = 22, .lpb = xb };
    struct Binary_r pcla = { .cb = 46, .lpb = pa }, pclb = { .cb = 46, .lpb = pb };
    uint64_t mid, cn;
    void *msg;
    char *body;

    CHECK(!backend_up());
    if (put("st.vcf", WCARD("st", "v1@x.test", "111"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "st", &mid, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid, false, &msg) == MAPISTORE_SUCCESS);	/* A and B download v1 */
    CHECK(B.properties.get_properties(msg, root, 1, kt, kd) == MAPISTORE_SUCCESS && kd[0].error == 0);
    memcpy(xb, xa, 22);
    xb[0] = 0xB1;
    pa[0] = pb[0] = 22;
    memcpy(pa + 1, ((struct Binary_r *)kd[0].data)->lpb, 22);
    memcpy(pb + 1, pa + 1, 22);
    pa[23] = pb[23] = 22;
    memcpy(pa + 24, xa, 22);
    memcpy(pb + 24, xb, 22);
    /* A: the e-mail */
    if (upload(f, mid, props(6, PidTagDisplayName, "st", PidTagSurname, "st", EMAIL1, "a@x.test",
                             PidTagMobileTelephoneNumber, "111", PidTagChangeKey, &cka, PidTagPredecessorChangeList, &pcla),
               MAPISTORE_SUCCESS)) return 1;
    CHECK(B.folder.open_message(f, root, mid, false, &msg) == MAPISTORE_SUCCESS);	/* the poll shows v2 to someone */
    /* B: the phone, its e-mail still v1's */
    if (upload(f, mid, props(6, PidTagDisplayName, "st", PidTagSurname, "st", EMAIL1, "v1@x.test",
                             PidTagMobileTelephoneNumber, "222", PidTagChangeKey, &ckb, PidTagPredecessorChangeList, &pclb),
               MAPISTORE_SUCCESS)) return 1;
    body = stored("st.vcf");
    CHECK(strstr(body, "a@x.test") && !strstr(body, "v1@x.test") && strstr(body, "TEL;TYPE=CELL:222\r\n")
          && !strstr(body, "conflito"));
    backend_down();
    return 0;
}

/* R9: the other books are subfolders of personal, with the same IDs in every session. */
static int test_books_are_subfolders(void)
{
    struct dav_folder *f, *g;
    struct dav_http *h;
    enum MAPITAGS cols[] = { PidTagFolderId, PidTagDisplayName, PidTagParentFolderId, PidTagContainerClass };
    enum MAPITAGS sub[] = { PidTagSubfolders };
    struct mapistore_property_data *d, sd[1], sd3[3];
    struct UI8Array_r *ids;
    uint64_t fid_work, dcn;
    uint32_t n;
    void *t, *c;

    CHECK(!backend_up());
    h = client("p");
    CHECK(dav_mkcol_book(h, "/dav/u/Contacts/work/", "Trabalho") == MAPISTORE_SUCCESS);
    CHECK((f = book("personal")) != NULL);
    CHECK(B.folder.get_child_count(f, MAPISTORE_FOLDER_TABLE, &n) == MAPISTORE_SUCCESS && n == 1);
    CHECK(B.properties.get_properties(f, root, 1, sub, sd) == MAPISTORE_SUCCESS && sd[0].error == 0 && *(uint8_t *)sd[0].data);
    CHECK(B.folder.open_table(f, root, MAPISTORE_FOLDER_TABLE, 1, &t, &n) == MAPISTORE_SUCCESS && n == 1);
    CHECK(B.table.set_columns(t, 4, cols) == MAPISTORE_SUCCESS);
    CHECK(B.table.get_row(t, root, MAPISTORE_PREFILTERED_QUERY, 0, &d) == MAPISTORE_SUCCESS);
    CHECK(d[0].error == 0 && d[1].error == 0 && !strcmp(d[1].data, "Trabalho") && d[2].error == 0
          && *(uint64_t *)d[2].data == f->fid && d[3].error == 0 && !strcmp(d[3].data, "IPF.Contact"));
    fid_work = *(uint64_t *)d[0].data;
    /* a contact in it, through personal */
    CHECK(B.folder.open_folder(f, root, fid_work, &c) == MAPISTORE_SUCCESS);
    g = c;
    CHECK(g->fid == fid_work && g->parent_fid == f->fid);
    CHECK(dav_put(h, root, "/dav/u/Contacts/work/w1.vcf", VC("w1"), NULL, NULL, false, NULL) == MAPISTORE_SUCCESS);
    CHECK(B.folder.get_child_count(g, MAPISTORE_MESSAGE_TABLE, &n) == MAPISTORE_SUCCESS && n == 1);
    CHECK(B.folder.get_child_count(g, MAPISTORE_FOLDER_TABLE, &n) == MAPISTORE_SUCCESS && n == 0);
    /* opened on its own (emsmdb opening it by ID from the store): personal is still its parent */
    CHECK((g = book("work")) != NULL && g->fid == fid_work);
    CHECK(B.properties.get_properties(g, root, 3, cols, sd3) == MAPISTORE_SUCCESS && sd3[2].error == 0
          && *(uint64_t *)sd3[2].data == f->fid);
    /* a new session: the same ID */
    CHECK((f = book("personal")) != NULL);
    CHECK(B.folder.open_table(f, root, MAPISTORE_FOLDER_TABLE, 1, &t, &n) == MAPISTORE_SUCCESS && n == 1);
    CHECK(B.table.set_columns(t, 1, cols) == MAPISTORE_SUCCESS);
    CHECK(B.table.get_row(t, root, MAPISTORE_PREFILTERED_QUERY, 0, &d) == MAPISTORE_SUCCESS && *(uint64_t *)d[0].data == fid_work);
    CHECK(B.folder.get_deleted_fmids(f, root, MAPISTORE_FOLDER_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS && !has_id(ids, fid_work));
    /* deleted in webmail: reported as a deleted folder */
    CHECK(dav_delete_book(h, "/dav/u/Contacts/work/") == MAPISTORE_SUCCESS);
    CHECK(B.folder.get_child_count(f, MAPISTORE_FOLDER_TABLE, &n) == MAPISTORE_SUCCESS && n == 0);
    CHECK(B.folder.get_deleted_fmids(f, root, MAPISTORE_FOLDER_TABLE, 0, &ids, &dcn) == MAPISTORE_SUCCESS && has_id(ids, fid_work) && dcn);
    talloc_free(h);
    backend_down();
    return 0;
}

/* Online, Outlook keeps the item open and saves again: nothing it did not set again is re-applied. */
static int test_second_save_same_handle(void)
{
    struct dav_folder *f;
    uint64_t mid, cn;
    void *msg;
    char *body;

    CHECK(!backend_up());
    if (put("ss.vcf", WCARD("ss", "a@x.test", "111"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "ss", &mid, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid, true, &msg) == MAPISTORE_SUCCESS);
    CHECK(!ctl("edit?path=" WBOOK "ss.vcf&set=TEL;TYPE=CELL:999"));
    CHECK(B.properties.set_properties(msg, props(1, PidTagMobileTelephoneNumber, "222")) == MAPISTORE_SUCCESS);
    CHECK(B.message.save(msg, root) == MAPISTORE_SUCCESS);	/* both changed, the server's is not older: kept */
    body = stored("ss.vcf");
    CHECK(strstr(body, "TEL;TYPE=CELL:999\r\n") && strstr(body, "conflito] celular: 222"));
    CHECK(B.message.save(msg, root) == MAPISTORE_SUCCESS);
    body = stored("ss.vcf");
    CHECK(strstr(body, "TEL;TYPE=CELL:999\r\n") && strstr(body, "conflito] celular: 222"));
    backend_down();
    return 0;
}

/* Lab 18/11: Outlook uploads an offline edit by opening the contact again (OpenMessage, no PCL) after
   webmail changed the same field: the base is what Outlook was given before, so neither value is lost. */
static int test_offline_save_reopened_without_pcl(void)
{
    struct dav_folder *f;
    uint64_t mid, cn;
    void *msg;
    char *body;

    CHECK(!backend_up());
    if (put("op.vcf", WCARD("op", "a@x.test", "111"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (row_of(f, "op", &mid, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid, false, &msg) == MAPISTORE_SUCCESS);	/* Outlook syncs it */
    CHECK(!ctl("edit?path=" WBOOK "op.vcf&set=TEL;TYPE=CELL:999"));	/* webmail, while Outlook is offline */
    if (row_of(f, "op", &mid, &cn, NULL)) return 1;
    CHECK(B.folder.open_message(f, root, mid, true, &msg) == MAPISTORE_SUCCESS);	/* Outlook back online */
    CHECK(B.properties.set_properties(msg, props(1, PidTagMobileTelephoneNumber, "222")) == MAPISTORE_SUCCESS);
    CHECK(B.message.save(msg, root) == MAPISTORE_SUCCESS);
    body = stored("op.vcf");
    CHECK(strstr(body, "conflito] celular:") && strstr(body, "999") && strstr(body, "222"));
    {
        /* the merge added what Outlook does not hold: what Outlook reads back after the save is its own
           change, and the stored version a later one, so its next sync brings the merged card */
        enum MAPITAGS kt[] = { PidTagChangeNumber, PidTagChangeKey };
        struct mapistore_property_data held[2], now[2];
        void *fresh;
        CHECK(B.properties.get_properties(msg, root, 2, kt, held) == MAPISTORE_SUCCESS && !held[0].error && !held[1].error);
        CHECK(B.folder.open_message(f, root, mid, false, &fresh) == MAPISTORE_SUCCESS);
        CHECK(B.properties.get_properties(fresh, root, 2, kt, now) == MAPISTORE_SUCCESS && !now[0].error && !now[1].error);
        CHECK(*(uint64_t *) now[0].data > *(uint64_t *) held[0].data);
        CHECK(memcmp(((struct Binary_r *) now[1].data)->lpb, ((struct Binary_r *) held[1].data)->lpb, 22) != 0);
    }
    backend_down();
    return 0;
}

/* Task 8: a session's poll reports what changed since that session's last poll (its first only learns the
   state), so every session of the user hears of a change. */
static int poll_has(struct mapistore_connection_info *s, size_t want, const char *uri, int kind)
{
    struct mapistore_change *ch;
    size_t n, i;
    bool found = !uri;
    CHECK(B.backend.poll_changes(s, root, &ch, &n) == MAPISTORE_SUCCESS);
    for (i = 0; i < n; i++) if (uri && !strcmp(ch[i].uri, uri) && (int)ch[i].kind == kind) found = true;
    if (n != want || !found) { fprintf(stderr, "poll: %zu changes, want %zu with %s/%d\n", n, want, uri ? uri : "-", kind); return 1; }
    return 0;
}

/* Name and change number of personal's only subfolder, as its folder table shows them. */
static int child_row(struct dav_folder *f, char **name, uint64_t *cn)
{
    enum MAPITAGS cols[] = { PidTagDisplayName, PidTagChangeNumber };
    struct mapistore_property_data *d;
    void *t;
    uint32_t n;
    CHECK(B.folder.open_table(f, root, MAPISTORE_FOLDER_TABLE, 1, &t, &n) == MAPISTORE_SUCCESS && n == 1);
    CHECK(B.table.set_columns(t, 2, cols) == MAPISTORE_SUCCESS);
    CHECK(B.table.get_row(t, root, MAPISTORE_PREFILTERED_QUERY, 0, &d) == MAPISTORE_SUCCESS);
    CHECK(d[0].error == 0 && d[1].error == 0);
    *name = talloc_strdup(root, d[0].data);
    *cn = *(uint64_t *)d[1].data;
    return 0;
}

static int test_poll_reports_contents_and_books(void)
{
    struct mapistore_connection_info *s1 = talloc_zero(root, struct mapistore_connection_info);
    struct mapistore_connection_info *s2 = talloc_zero(root, struct mapistore_connection_info);
    struct dav_http *h;
    struct dav_folder *f;
    char *name;
    uint64_t cn0, cn;

    CHECK(!backend_up());
    s1->username = talloc_strdup(s1, "u");
    s2->username = talloc_strdup(s2, "u");
    if (put("pa.vcf", VC("pa"))) return 1;
    if (poll_has(s1, 0, NULL, 0) || poll_has(s2, 0, NULL, 0) || poll_has(s1, 0, NULL, 0)) return 1;
    /* webmail edits a card and creates a book */
    CHECK(!ctl("edit?path=" BOOK "pa.vcf"));
    h = client("p");
    CHECK(dav_mkcol_book(h, "/dav/u/Contacts/work/", "Trabalho") == MAPISTORE_SUCCESS);
    if (poll_has(s1, 2, "dav://contacts/personal/", MAPISTORE_CHANGE_CONTENTS) ||
        poll_has(s2, 2, "dav://contacts/personal/", MAPISTORE_CHANGE_FOLDER_ADDED) || poll_has(s1, 0, NULL, 0)) return 1;
    /* a card in the new book, a rename, then the book goes */
    CHECK(dav_put(h, root, "/dav/u/Contacts/work/w.vcf", VC("w"), NULL, NULL, false, NULL) == MAPISTORE_SUCCESS);
    if (poll_has(s1, 1, "dav://contacts/work/", MAPISTORE_CHANGE_CONTENTS)) return 1;
    /* renamed in webmail: reported on personal (Outlook resyncs the hierarchy on its newer PidTagHierRev), and
       the book's row then shows the new name with a new change number, even within the read window */
    CHECK((f = book("personal")) != NULL);
    dav_backend_set_sync_window(10);
    if (child_row(f, &name, &cn0)) return 1;
    CHECK(!strcmp(name, "Trabalho"));
    CHECK(dav_rename_book(h, "/dav/u/Contacts/work/", "Trabalho 2") == MAPISTORE_SUCCESS);
    if (poll_has(s1, 1, "dav://contacts/personal/", MAPISTORE_CHANGE_FOLDER_RENAMED)) return 1;
    if (child_row(f, &name, &cn)) return 1;
    CHECK(!strcmp(name, "Trabalho 2") && cn != cn0);
    dav_backend_set_sync_window(0);
    CHECK(dav_delete_book(h, "/dav/u/Contacts/work/") == MAPISTORE_SUCCESS);
    if (poll_has(s1, 1, "dav://contacts/personal/", MAPISTORE_CHANGE_FOLDER_DELETED)) return 1;
    /* s2 missed nothing: the card, the rename and the deletion fold into the book's deletion */
    if (poll_has(s2, 1, "dav://contacts/personal/", MAPISTORE_CHANGE_FOLDER_DELETED)) return 1;
    talloc_free(h);
    /* a session's poll state goes with it */
    talloc_free(s1);
    talloc_free(s2);
    backend_down();
    return 0;
}

/* R14: reads reuse a context's last sync for a while; a poll that saw a change ends that at once. */
static int test_sync_throttled_until_poll(void)
{
    struct mapistore_connection_info *s = talloc_zero(root, struct mapistore_connection_info);
    struct dav_folder *f;
    uint64_t mid, cn0, cn;
    uint32_t n;

    CHECK(!backend_up());
    s->username = talloc_strdup(s, "u");
    dav_backend_set_sync_window(10);
    if (put("th.vcf", VC("th"))) return 1;
    CHECK((f = book("personal")) != NULL);
    if (poll_has(s, 0, NULL, 0) || row_of(f, "th", &mid, &cn0, NULL)) return 1;
    CHECK(!ctl("edit?path=" BOOK "th.vcf") && put("th2.vcf", VC("th2")) == 0);
    if (row_of(f, "th", &mid, &cn, &n)) return 1;
    CHECK(cn == cn0 && n == 1);	/* within the window: the last listing */
    if (poll_has(s, 1, "dav://contacts/personal/", MAPISTORE_CHANGE_CONTENTS)) return 1;
    if (row_of(f, "th", &mid, &cn, &n)) return 1;
    CHECK(cn != cn0 && n == 2);
    dav_backend_set_sync_window(0);
    talloc_free(s);
    backend_down();
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
    if (test_inert_when_unconfigured() || test_settings_key_file() || test_backend_registers() || test_cred_refcount()
        || test_vcard_roundtrip_untouched() || test_vcard_folding_utf8() || test_vcard_escape()
        || test_vcard_set_keeps_unknown() || test_vlist_parse()
        || test_vcard_trailing_data_rejected() || test_map_contact_full() || test_map_props_to_fields_roundtrip()
        || test_field_set_no_line_injection() || test_map_list_members() || test_map_list_empty() || test_photo_cap()
        || test_http_list_books() || test_http_sync_incremental() || test_http_sync_invalid_token_full()
        || test_http_put_if_match_412() || test_http_put_if_none_match_exists() || test_http_sogo_fixtures() || test_href_norm()
        || test_http_hrefs_under_book() || test_http_401_denied()
        || test_http_timeout_conn_refused() || test_fpstore_memory() || test_list_contexts_books()
        || test_list_contexts_sogo_down_keeps() || test_contents_table_contacts_and_lists()
        || test_open_contact_props_and_photo() || test_ics_incremental() || test_ics_token_invalid_no_dup_mids()
        || test_fp_written_on_read() || test_deletion_reaches_every_client()
        || test_merge_only_outlook() || test_merge_only_server() || test_merge_both_outlook_newer_note()
        || test_merge_both_server_newer_note() || test_merge_no_base_note() || test_merge_members_sets()
        || test_merge_keeps_unknown_lines() || test_fp_keyed() || test_save_new_contact_put()
        || test_save_concurrent_edit_merged() || test_save_412_three_times_conflict()
        || test_save_after_remote_delete_recreates() || test_delete_after_remote_edit_survives()
        || test_move_out_after_offline_delete()
        || test_folder_create_rename_delete() || test_delete_personal_denied() || test_stale_client_never_reverts()
        || test_books_are_subfolders() || test_second_save_same_handle() || test_offline_save_reopened_without_pcl()
        || test_poll_reports_contents_and_books() || test_sync_throttled_until_poll()) { fake_stop(); return 1; }
    printf("dav backend smoke: ok\n");
    talloc_free(root);
    return 0;
}
