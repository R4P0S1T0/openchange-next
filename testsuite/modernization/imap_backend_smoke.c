/*
   Read-only IMAP mapistore backend against Dovecot's imap binary in PREAUTH mode
   (mapistore:imap_tunnel): a throwaway Maildir, no root, no network.

   Usage: imap-backend-test /usr/lib/dovecot/imap <fixture dir>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libetpan/libetpan.h>

#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "libmapi/libmapi_private.h"
#include "imap_backend.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "imap backend check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

enum mapistore_error mapistore_backend_registered(const char *);

static TALLOC_CTX *root;
static const char *fixture;
static struct imap_settings tunnel;

static const char plain_message[] =
    "From: Ana <ana@example.invalid>\r\n"
    "To: Alice <alice@example.invalid>\r\n"
    "Subject: Plain hello\r\n"
    "Date: Tue, 03 Nov 2026 10:00:00 -0300\r\n"
    "Message-ID: <plain@example.invalid>\r\n"
    "\r\n"
    "Hello from the fixture.\r\n";

static const char second_message[] =
    "From: Bruno <bruno@example.invalid>\r\n"
    "To: Alice <alice@example.invalid>\r\n"
    "Subject: Second\r\n"
    "Date: Tue, 03 Nov 2026 11:00:00 -0300\r\n"
    "\r\n"
    "Second body.\r\n";

static int write_file(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    CHECK(fputs(text, f) >= 0);
    CHECK(fclose(f) == 0);
    CHECK(chmod(path, mode) == 0);
    return 0;
}

/* A Dovecot configuration for one user's Maildir under the fixture directory. */
static int setup_fixture(const char *imap_binary)
{
    char *conf = talloc_asprintf(root, "%s/dovecot.conf", fixture);
    char *text = talloc_asprintf(root,
        "dovecot_config_version = 2.4.0\n"
        "dovecot_storage_version = 2.4.0\n"
        "base_dir = %s/run\n"
        "state_dir = %s/state\n"
        "log_path = %s/dovecot.log\n"
        "mail_driver = maildir\n"
        "mail_home = %s/home/%%{user}\n"
        "mail_path = ~/Maildir\n"
        "namespace inbox {\n"
        "  inbox = yes\n"
        "  separator = /\n"
        "  mailbox Sent {\n    special_use = \\Sent\n    auto = create\n  }\n"
        "  mailbox Drafts {\n    special_use = \\Drafts\n    auto = create\n  }\n"
        "  mailbox Trash {\n    special_use = \\Trash\n    auto = create\n  }\n"
        "  mailbox Junk {\n    special_use = \\Junk\n    auto = create\n  }\n"
        "}\n", fixture, fixture, fixture, fixture);
    CHECK(conf && text);
    CHECK(mkdir(fixture, 0700) == 0 || errno == EEXIST);
    if (write_file(conf, text, 0600)) return 1;
    tunnel.host = "127.0.0.1";
    tunnel.port = 143;
    tunnel.master_user = "openchange";
    tunnel.tunnel = talloc_asprintf(root, "%s -c %s", imap_binary, conf);
    CHECK(tunnel.tunnel != NULL);
    return 0;
}

static int append(mailimap *imap, const char *mailbox, const char *message)
{
    CHECK(mailimap_append_simple(imap, mailbox, message, strlen(message)) == MAILIMAP_NO_ERROR);
    return 0;
}

/* INBOX with two messages, and Projects/Sub created as a webmail user would. */
static int populate(void)
{
    struct imap_conn *conn = imap_conn_open(root, &tunnel, "alice@example.invalid");
    mailimap *imap;
    CHECK(conn != NULL);
    imap = imap_conn_session(conn);
    CHECK(mailimap_create(imap, "Projects") == MAILIMAP_NO_ERROR);
    CHECK(mailimap_create(imap, "Projects/Sub") == MAILIMAP_NO_ERROR);
    if (append(imap, "INBOX", plain_message) || append(imap, "INBOX", second_message)) return 1;
    talloc_free(conn);
    return 0;
}

static const struct imap_mailbox *find(const struct imap_mailbox *list, size_t n, const char *name)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (strcmp(list[i].name, name) == 0) return &list[i];
    }
    return NULL;
}

static int test_list_fixture(void)
{
    struct imap_conn *conn = imap_conn_open(root, &tunnel, "alice@example.invalid");
    struct imap_mailbox *list;
    const struct imap_mailbox *mb;
    size_t n;
    CHECK(conn != NULL);
    CHECK(imap_list(conn, conn, &list, &n) == MAPISTORE_SUCCESS);
    CHECK((mb = find(list, n, "INBOX")) != NULL && mb->delimiter == '/');
    CHECK((mb = find(list, n, "Sent")) != NULL && (mb->flags & IMAP_MB_SENT));
    CHECK((mb = find(list, n, "Drafts")) != NULL && (mb->flags & IMAP_MB_DRAFTS));
    CHECK((mb = find(list, n, "Trash")) != NULL && (mb->flags & IMAP_MB_TRASH));
    CHECK((mb = find(list, n, "Junk")) != NULL && (mb->flags & IMAP_MB_JUNK));
    CHECK((mb = find(list, n, "Projects")) != NULL && (mb->flags & IMAP_MB_HASCHILDREN));
    CHECK(find(list, n, "Projects/Sub") != NULL);
    talloc_free(conn);
    return 0;
}

static int test_examine_counts(void)
{
    struct imap_conn *conn = imap_conn_open(root, &tunnel, "alice@example.invalid");
    struct imap_status st, again;
    CHECK(conn != NULL);
    CHECK(imap_examine(conn, "INBOX", &st) == MAPISTORE_SUCCESS);
    CHECK(st.messages == 2 && st.uidvalidity != 0 && st.uidnext == 3);
    CHECK(imap_status(conn, "INBOX", &again) == MAPISTORE_SUCCESS);
    CHECK(again.messages == 2 && again.unseen == 2 && again.uidvalidity == st.uidvalidity);
    CHECK(imap_examine(conn, "Nonexistent", &st) == MAPISTORE_ERR_NOT_FOUND);
    talloc_free(conn);
    return 0;
}

/* Only the session's own user is ever used, and it cannot smuggle IMAP syntax. */
static int test_username_is_checked(void)
{
    CHECK(imap_conn_open(root, &tunnel, "bob@example.invalid\r\nA LOGOUT") == NULL);
    CHECK(imap_conn_open(root, &tunnel, "") == NULL);
    CHECK(imap_conn_open(root, &tunnel, "a*b@example.invalid") == NULL);
    return 0;
}

static int test_settings_password_file(void)
{
    char *path = talloc_asprintf(root, "%s/master.pw", fixture);
    struct loadparm_context *lp = loadparm_init(root);
    struct imap_settings *s;
    CHECK(path && lp);
    CHECK(imap_settings_load(root, lp) == NULL); /* neither password file nor tunnel */
    CHECK(lpcfg_set_cmdline(lp, "mapistore:imap_master_password_file", path));
    CHECK(imap_settings_load(root, lp) == NULL); /* missing */
    if (write_file(path, "s3cret\n", 0644)) return 1;
    CHECK(imap_settings_load(root, lp) == NULL); /* group/world readable */
    CHECK(chmod(path, 0600) == 0);
    CHECK((s = imap_settings_load(root, lp)) != NULL);
    CHECK(strcmp(s->master_password, "s3cret") == 0 && strcmp(s->host, "127.0.0.1") == 0 && s->port == 143);
    CHECK(strcmp(s->master_user, "openchange") == 0 && s->tunnel == NULL);
    if (write_file(path, "", 0600)) return 1;
    CHECK(imap_settings_load(root, lp) == NULL); /* empty */
    return 0;
}

static int test_backend_registers(void)
{
    CHECK(mapistore_init_backend() == MAPISTORE_SUCCESS);
    CHECK(mapistore_backend_registered("imap") == MAPISTORE_SUCCESS);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <dovecot imap binary> <fixture dir>\n", argv[0]);
        return 2;
    }
    root = talloc_new(NULL);
    fixture = argv[2];
    if (setup_fixture(argv[1]) || populate() || test_list_fixture() || test_examine_counts() ||
        test_username_is_checked() || test_settings_password_file() || test_backend_registers()) {
        return 1;
    }
    talloc_free(root);
    printf("IMAP backend connection, listing, status and settings: OK\n");
    return 0;
}
