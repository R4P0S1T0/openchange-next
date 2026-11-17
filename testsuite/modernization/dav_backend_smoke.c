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

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "dav backend check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

enum mapistore_error mapistore_init_backend(void);
enum mapistore_error mapistore_backend_registered(const char *);

static TALLOC_CTX *root;
static const char *fixture;

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

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <fixture dir>\n", argv[0]);
        return 2;
    }
    root = talloc_new(NULL);
    fixture = argv[1];
    if (mkdir(fixture, 0700) && access(fixture, W_OK)) return 2;
    if (test_inert_when_unconfigured() || test_settings_key_file() || test_backend_registers()) return 1;
    printf("dav backend smoke: ok\n");
    talloc_free(root);
    return 0;
}
