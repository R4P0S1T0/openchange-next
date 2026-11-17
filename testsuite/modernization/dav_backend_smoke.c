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

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "dav_backend.h"
#include "dav_vcard.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "dav backend check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

enum mapistore_error mapistore_init_backend(void);
enum mapistore_error mapistore_backend_registered(const char *);

static TALLOC_CTX *root;
static const char *fixture, *vcf_dir;

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

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <fixture dir> <vcf dir>\n", argv[0]);
        return 2;
    }
    root = talloc_new(NULL);
    fixture = argv[1];
    vcf_dir = argv[2];
    if (mkdir(fixture, 0700) && access(fixture, W_OK)) return 2;
    if (test_inert_when_unconfigured() || test_settings_key_file() || test_backend_registers()
        || test_vcard_roundtrip_untouched() || test_vcard_folding_utf8() || test_vcard_escape()
        || test_vcard_set_keeps_unknown() || test_vlist_parse()) return 1;
    printf("dav backend smoke: ok\n");
    talloc_free(root);
    return 0;
}
