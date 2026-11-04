/*
   Read-only IMAP mapistore backend against Dovecot's imap binary in PREAUTH mode
   (mapistore:imap_tunnel): a throwaway Maildir, no root, no network.

   Usage: imap-backend-test /usr/lib/dovecot/imap <fixture dir>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 */

#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
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

static const char latin1_message[] =
    "From: =?ISO-8859-1?Q?Jos=E9?= <jose@example.invalid>\r\n"
    "To: Alice <alice@example.invalid>, bob@example.invalid\r\n"
    "Cc: Carol <carol@example.invalid>\r\n"
    "Subject: =?ISO-8859-1?Q?Ol=E1?=\r\n"
    "Date: Mon, 02 Nov 2026 09:30:00 +0000\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: text/plain; charset=ISO-8859-1\r\n"
    "Content-Transfer-Encoding: quoted-printable\r\n"
    "\r\n"
    "Ol=E1, tudo bem?\r\n";

static const char attachment_message[] =
    "From: Ana <ana@example.invalid>\r\n"
    "To: Alice <alice@example.invalid>\r\n"
    "Subject: With attachment\r\n"
    "Date: Tue, 03 Nov 2026 12:00:00 -0300\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"b1\"\r\n"
    "\r\n"
    "--b1\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "\r\n"
    "<p>See <b>attached</b>.</p>\r\n"
    "--b1\r\n"
    "Content-Type: application/octet-stream; name=\"report.bin\"\r\n"
    "Content-Disposition: attachment; filename=\"report.bin\"\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "AAECAwQ=\r\n"
    "--b1--\r\n";

/* Odd MIME the backend must still open: no closing boundary, an unknown charset, a forwarded
   message, raw 8-bit bytes in the subject. */
static const char odd_messages[][600] = {
    "From: x@example.invalid\r\nSubject: Unclosed\r\nMIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"zz\"\r\n\r\n--zz\r\nContent-Type: text/plain\r\n\r\nPart one\r\n",
    "From: x@example.invalid\r\nSubject: Charset\r\nMIME-Version: 1.0\r\n"
    "Content-Type: text/plain; charset=x-no-such-charset\r\n\r\nCaf\xe9 bytes\r\n",
    "From: x@example.invalid\r\nSubject: Forward\r\nMIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"f\"\r\n\r\n--f\r\nContent-Type: text/plain\r\n\r\nSee below\r\n"
    "--f\r\nContent-Type: message/rfc822\r\n\r\nFrom: y@example.invalid\r\nSubject: Inner\r\n\r\nInner body\r\n--f--\r\n",
    "From: x@example.invalid\r\nSubject: Raw \xff\xfe bytes\r\n\r\nBody\r\n",
};

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
    tunnel.max_message_size = 32 * 1024 * 1024;
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
    {
        struct mailimap_flag_list *seen = mailimap_flag_list_new_empty();
        CHECK(seen && mailimap_flag_list_add(seen, mailimap_flag_new_seen()) == MAILIMAP_NO_ERROR);
        CHECK(mailimap_append(imap, "Projects", seen, NULL, latin1_message, strlen(latin1_message)) == MAILIMAP_NO_ERROR);
        mailimap_flag_list_free(seen);
    }
    if (append(imap, "Projects", attachment_message)) return 1;
    CHECK(mailimap_create(imap, "Odd") == MAILIMAP_NO_ERROR);
    {
        size_t i;
        for (i = 0; i < sizeof odd_messages / sizeof odd_messages[0]; i++) {
            if (append(imap, "Odd", odd_messages[i])) return 1;
        }
    }
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
    /* STARTTLS does not verify certificates: the master password stays on loopback (M3). */
    if (write_file(path, "s3cret\n", 0600)) return 1;
    CHECK(lpcfg_set_cmdline(lp, "mapistore:imap_host", "192.0.2.1"));
    CHECK(imap_settings_load(root, lp) == NULL);
    CHECK(lpcfg_set_cmdline(lp, "mapistore:imap_host", "::1"));
    CHECK(imap_settings_load(root, lp) != NULL);
    return 0;
}

static int test_mailbox_name_round_trip(void)
{
    static const char *names[] = { "INBOX", "Projects/Sub", "a%b", "Caf&AOk-", "with space", "Quote\"d", "&-and", "x/y/z/w" };
    size_t i;
    char *user, *mailbox, *uri;
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        uri = imap_uri(root, "alice@example.invalid", names[i], '/');
        CHECK(uri != NULL && strncmp(uri, "imap://alice%40example.invalid/", 31) == 0 && uri[strlen(uri) - 1] == '/');
        CHECK(imap_uri_parse(root, uri, '/', &user, &mailbox) == 0);
        CHECK(strcmp(user, "alice@example.invalid") == 0 && strcmp(mailbox, names[i]) == 0);
    }
    /* One path segment per hierarchy level: the parent is the URI without its last segment. */
    CHECK(strcmp(imap_uri(root, "u", "Projects/Sub", '/'), "imap://u/Projects/Sub/") == 0);
    CHECK(strcmp(imap_uri(root, "u", "a%b", '/'), "imap://u/a%25b/") == 0);
    CHECK(strcmp(imap_uri(root, "u", "P.Sub", '.'), "imap://u/P/Sub/") == 0);
    CHECK(imap_uri_parse(root, "imap://u/P/Sub/", '.', &user, &mailbox) == 0 && strcmp(mailbox, "P.Sub") == 0);
    CHECK(imap_uri_parse(root, "imap://u/a%2/", '/', &user, &mailbox) != 0);
    CHECK(imap_uri_parse(root, "imap://u/a%00b/", '/', &user, &mailbox) != 0);
    CHECK(imap_uri_parse(root, "imap://u/a%0D%0Ab/", '/', &user, &mailbox) != 0); /* no IMAP line breaks */
    CHECK(imap_uri_parse(root, "imap://u//", '/', &user, &mailbox) != 0);
    CHECK(imap_uri_parse(root, "sogo://u/INBOX/", '/', &user, &mailbox) != 0);
    CHECK(strcmp(imap_display_name(root, "Caf&AOk-", '/'), "Caf\xc3\xa9") == 0);
    CHECK(strcmp(imap_display_name(root, "Projects/Sub", '/'), "Sub") == 0);
    CHECK(strcmp(imap_display_name(root, "&-and", '/'), "&and") == 0);
    CHECK(strcmp(imap_display_name(root, "bad&AOk", '/'), "bad&AOk") == 0);   /* unterminated: shown raw */
    CHECK(strcmp(imap_display_name(root, "&2D3eAA-", '/'), "\xf0\x9f\x98\x80") == 0); /* surrogate pair */
    CHECK(strcmp(imap_display_name(root, "&2D0-", '/'), "&2D0-") == 0);       /* lone surrogate: shown raw */
    return 0;
}

/* In-memory mapistore indexing: fmid <-> URI, as the TDB/MySQL backends keep it. */
struct fake_index { uint64_t fmid[256]; char *uri[256]; size_t n; uint64_t next; };
static struct fake_index fidx;
static struct indexing_context ictx;

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
    if (fidx.n == 256) return MAPISTORE_ERR_NO_MEMORY;
    fidx.fmid[fidx.n] = fmid;
    fidx.uri[fidx.n++] = talloc_strdup(root, uri);
    return MAPISTORE_SUCCESS;
}
static enum mapistore_error fi_allocate(struct indexing_context *c, const char *u, uint64_t *fmid)
{
    *fmid = fidx.next++;
    return MAPISTORE_SUCCESS;
}

static struct mapistore_connection_info conn_info = { .username = "alice@example.invalid",
    .replica_guid = { .time_low = 0x11223344, .time_mid = 0x5566, .time_hi_and_version = 0x7788 } };

static void *context_for(const char *mailbox)
{
    void *folder = NULL;
    char *uri = imap_uri(root, "alice@example.invalid", mailbox, '/');
    if (!uri || imap_create_context(root, &conn_info, &ictx, uri, &folder) != MAPISTORE_SUCCESS) return NULL;
    return folder;
}

static const struct mapistore_contexts_list *entry(const struct mapistore_contexts_list *l, const char *name)
{
    for (; l; l = l->next) {
        if (strcmp(l->name, name) == 0) return l;
    }
    return NULL;
}

static int test_list_contexts_roles(void)
{
    struct mapistore_contexts_list *list = NULL;
    const struct mapistore_contexts_list *e;
    CHECK(imap_list_contexts("alice@example.invalid", &ictx, root, &list) == MAPISTORE_SUCCESS && list);
    CHECK((e = entry(list, "Inbox")) && e->main_folder && e->role == MAPISTORE_MAIL_ROLE);
    CHECK(strcmp(e->url, "imap://alice%40example.invalid/INBOX/") == 0);
    CHECK((e = entry(list, "Sent")) && e->main_folder && e->role == MAPISTORE_SENTITEMS_ROLE);
    CHECK((e = entry(list, "Drafts")) && e->main_folder && e->role == MAPISTORE_DRAFTS_ROLE);
    CHECK((e = entry(list, "Trash")) && e->main_folder && e->role == MAPISTORE_DELETEDITEMS_ROLE);
    CHECK((e = entry(list, "Junk")) && !e->main_folder && e->role == MAPISTORE_MAIL_ROLE);
    CHECK((e = entry(list, "Projects")) && !e->main_folder && e->role == MAPISTORE_MAIL_ROLE);
    CHECK(entry(list, "Sub") == NULL); /* subfolders come from the hierarchy table */
    CHECK(list->prev != NULL);         /* a DLIST head: prev is the tail */
    return 0;
}

/* mapistore_add_context strips "imap://" before calling create_context. */
static int test_create_context_without_namespace(void)
{
    void *folder = NULL;
    CHECK(imap_create_context(root, &conn_info, &ictx, "alice%40example.invalid/INBOX/", &folder) == MAPISTORE_SUCCESS);
    CHECK(folder != NULL && strcmp(((struct imap_folder *) folder)->mailbox, "INBOX") == 0);
    folder = NULL;
    CHECK(imap_create_context(root, &conn_info, &ictx, "bob%40example.invalid/INBOX/", &folder) == MAPISTORE_ERR_DENIED);
    return 0;
}

static int test_uri_user_must_match(void)
{
    void *folder = NULL;
    char *uri = imap_uri(root, "bob@example.invalid", "INBOX", '/');
    CHECK(imap_create_context(root, &conn_info, &ictx, uri, &folder) == MAPISTORE_ERR_DENIED && folder == NULL);
    CHECK(imap_create_context(root, &conn_info, &ictx, "imap://alice%40example.invalid/", &folder) != MAPISTORE_SUCCESS);
    return 0;
}

static enum MAPITAGS hierarchy_columns[] = { PidTagFolderId, PidTagDisplayName, PidTagContentCount,
    PidTagSubfolders, PidTagContainerClass, PidTagParentFolderId };

static int test_hierarchy_table_rows(void)
{
    void *projects = context_for("Projects"), *table = NULL, *sub = NULL;
    struct mapistore_property_data *row = NULL;
    uint32_t count = 99;
    uint64_t fid;
    CHECK(projects != NULL);
    CHECK(imap_folder_get_child_count(projects, MAPISTORE_FOLDER_TABLE, &count) == MAPISTORE_SUCCESS && count == 1);
    CHECK(imap_folder_open_table(projects, root, MAPISTORE_FOLDER_TABLE, 1, &table, &count) == MAPISTORE_SUCCESS);
    CHECK(count == 1);
    CHECK(imap_table_set_columns(table, 6, hierarchy_columns) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &row) == MAPISTORE_SUCCESS);
    CHECK(row[0].error == MAPISTORE_SUCCESS && (fid = *(uint64_t *) row[0].data) != 0);
    CHECK(row[1].error == MAPISTORE_SUCCESS && strcmp(row[1].data, "Sub") == 0);
    CHECK(row[2].error == MAPISTORE_SUCCESS && *(uint32_t *) row[2].data == 0);
    CHECK(row[3].error == MAPISTORE_SUCCESS && *(uint8_t *) row[3].data == 0);
    CHECK(row[4].error == MAPISTORE_SUCCESS && strcmp(row[4].data, "IPF.Note") == 0);
    /* ICS hierarchy sync dereferences it for every row below the top level (oxcfxics_push_folderChange). */
    CHECK(row[5].error == MAPISTORE_SUCCESS && *(uint64_t *) row[5].data == ((struct imap_folder *) projects)->fid);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 1, &row) == MAPISTORE_ERR_NOT_FOUND);
    /* The row's folder ID opens the child; the same ID is returned on the next listing. */
    CHECK(imap_folder_open_folder(projects, root, fid, &sub) == MAPISTORE_SUCCESS && sub);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &row) == MAPISTORE_SUCCESS);
    CHECK(*(uint64_t *) row[0].data == fid);
    CHECK((fid & 0xFFFF) == 0x0001); /* replica ID 1, as mapistore_indexing_get_new_folderID_as_user */
    /* A known folder outside the subtree (INBOX) does not open through Projects. */
    {
        struct imap_folder *inbox = context_for("INBOX");
        void *outside = NULL;
        CHECK(inbox != NULL);
        CHECK(imap_folder_open_folder(projects, root, inbox->fid, &outside) == MAPISTORE_ERR_NOT_FOUND && !outside);
    }
    return 0;
}

static int test_folder_properties(void)
{
    void *inbox = context_for("INBOX"), *other = NULL, *fai = NULL;
    enum MAPITAGS tags[] = { PidTagContentCount, PidTagContentUnreadCount, PidTagSubfolders, PidTagDisplayName,
        PidTagAttachDataBinary };
    struct mapistore_property_data data[5];
    uint32_t count = 99;
    CHECK(inbox != NULL);
    CHECK(imap_properties_get(inbox, root, 5, tags, data) == MAPISTORE_SUCCESS);
    CHECK(data[0].error == MAPISTORE_SUCCESS && *(uint32_t *) data[0].data == 2);
    CHECK(data[1].error == MAPISTORE_SUCCESS && *(uint32_t *) data[1].data == 2);
    CHECK(data[2].error == MAPISTORE_SUCCESS && *(uint8_t *) data[2].data == 0);
    CHECK(data[3].error == MAPISTORE_SUCCESS && strcmp(data[3].data, "Inbox") == 0);
    CHECK(data[4].error == MAPISTORE_ERR_NOT_FOUND);
    CHECK(imap_folder_get_child_count(inbox, MAPISTORE_FAI_TABLE, &count) == MAPISTORE_SUCCESS && count == 0);
    CHECK(imap_folder_open_table(inbox, root, MAPISTORE_FAI_TABLE, 2, &fai, &count) == MAPISTORE_SUCCESS && count == 0);
    /* A folder ID that is not below this folder does not open through it. */
    CHECK(imap_folder_open_folder(inbox, root, 0xDEAD0001, &other) == MAPISTORE_ERR_NOT_FOUND);
    return 0;
}

static int test_create_root_folder_not_found(void)
{
    char *uri = NULL;
    /* NOT_FOUND lets emsmdb create the folder natively (emsmdbp_object_folder_commit_creation). */
    CHECK(imap_create_root_folder("alice@example.invalid", MAPISTORE_MAIL_ROLE, 0x1234, "New", root, &uri)
        == MAPISTORE_ERR_NOT_FOUND && uri == NULL);
    return 0;
}

/* A server that accepts but never answers (overloaded, stopped) fails the logon in seconds; the
   worker serving every user must not block for libetpan's default five minutes. */
static int test_silent_server_times_out(void)
{
    struct imap_settings silent = { .host = "127.0.0.1", .master_user = "openchange", .master_password = "x" };
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof a;
    time_t start;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s >= 0 && bind(s, (struct sockaddr *) &a, sizeof a) == 0 && listen(s, 1) == 0);
    CHECK(getsockname(s, (struct sockaddr *) &a, &len) == 0);
    silent.port = ntohs(a.sin_port);
    start = time(NULL);
    CHECK(imap_conn_open(root, &silent, "alice@example.invalid") == NULL);
    CHECK(time(NULL) - start < 30);
    close(s);
    return 0;
}

static int test_imap_down_is_an_error(void)
{
    struct imap_settings down = tunnel;
    struct mapistore_contexts_list *list = NULL;
    down.tunnel = "/nonexistent/imap";
    imap_backend_set_state(&down, false);
    CHECK(imap_list_contexts("alice@example.invalid", &ictx, root, &list) == MAPISTORE_ERR_CONN_REFUSED);
    imap_backend_set_state(NULL, false);
    CHECK(imap_list_contexts("alice@example.invalid", &ictx, root, &list) == MAPISTORE_SUCCESS && list == NULL);
    imap_backend_set_state(&tunnel, false);
    return 0;
}

static enum MAPITAGS message_columns[] = { PidTagSubject, PidTagSenderName, PidTagSenderSmtpAddress,
    PidTagDisplayTo, PidTagDisplayCc, PidTagMessageDeliveryTime, PidTagMessageSize, PidTagMessageFlags,
    PidTagHasAttachments, PidTagMessageClass, PidTagMid, PidTagClientSubmitTime, PidTagInternetMessageId };
#define N_MESSAGE_COLUMNS (sizeof message_columns / sizeof message_columns[0])

static int message_rows(const char *mailbox, void **tablep, uint32_t *count)
{
    void *folder = context_for(mailbox);
    CHECK(folder != NULL);
    CHECK(imap_folder_open_table(folder, root, MAPISTORE_MESSAGE_TABLE, 3, tablep, count) == MAPISTORE_SUCCESS);
    CHECK(imap_table_set_columns(*tablep, N_MESSAGE_COLUMNS, message_columns) == MAPISTORE_SUCCESS);
    return 0;
}

/* 2026-11-02 09:30:00 UTC as FILETIME (100 ns since 1601). */
#define NOV2_0930 ((uint64_t) (1793611800LL + 11644473600LL) * 10000000ULL)

static uint64_t filetime(const struct mapistore_property_data *d)
{
    const struct FILETIME *ft = d->data;
    return ((uint64_t) ft->dwHighDateTime << 32) | ft->dwLowDateTime;
}

static int test_message_table_columns(void)
{
    void *table;
    struct mapistore_property_data *r;
    uint32_t count = 0, flags;
    CHECK(!message_rows("Projects", &table, &count) && count == 2);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &r) == MAPISTORE_SUCCESS);
    CHECK(r[0].error == 0 && strcmp(r[0].data, "Ol\xc3\xa1") == 0);
    CHECK(r[1].error == 0 && strcmp(r[1].data, "Jos\xc3\xa9") == 0);
    CHECK(r[2].error == 0 && strcmp(r[2].data, "jose@example.invalid") == 0);
    CHECK(r[3].error == 0 && strcmp(r[3].data, "Alice; bob@example.invalid") == 0);
    CHECK(r[4].error == 0 && strcmp(r[4].data, "Carol") == 0);
    CHECK(r[5].error == 0 && filetime(&r[5]) != 0);               /* INTERNALDATE: the time of the APPEND */
    CHECK(r[6].error == 0 && *(uint32_t *) r[6].data == strlen(latin1_message));
    flags = *(uint32_t *) r[7].data;
    CHECK(r[7].error == 0 && (flags & 0x1) && !(flags & 0x10)); /* MSGFLAG_READ, no MSGFLAG_HASATTACH */
    CHECK(r[8].error == 0 && *(uint8_t *) r[8].data == 0);
    CHECK(r[9].error == 0 && strcmp(r[9].data, "IPM.Note") == 0);
    CHECK(r[10].error == 0 && (*(uint64_t *) r[10].data & 0xFFFF) == 1);
    CHECK(r[11].error == 0 && filetime(&r[11]) == NOV2_0930);    /* Date: header */
    CHECK(r[12].error == MAPISTORE_ERR_NOT_FOUND);                /* no Message-ID header */
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 1, &r) == MAPISTORE_SUCCESS);
    CHECK(strcmp(r[0].data, "With attachment") == 0);
    flags = *(uint32_t *) r[7].data;
    CHECK(!(flags & 0x1) && (flags & 0x10) && *(uint8_t *) r[8].data == 1);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 2, &r) == MAPISTORE_ERR_NOT_FOUND);
    return 0;
}

static int test_message_ids_stable(void)
{
    void *table, *again;
    struct mapistore_property_data *r;
    uint32_t count;
    uint64_t mid;
    CHECK(!message_rows("INBOX", &table, &count) && count == 2);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &r) == MAPISTORE_SUCCESS);
    mid = *(uint64_t *) r[10].data;
    CHECK(r[12].error == 0 && strcmp(r[12].data, "<plain@example.invalid>") == 0);
    CHECK(!message_rows("INBOX", &again, &count));
    CHECK(imap_table_get_row(again, root, MAPISTORE_PREFILTERED_QUERY, 0, &r) == MAPISTORE_SUCCESS);
    CHECK(*(uint64_t *) r[10].data == mid);
    return 0;
}

/* A mailbox deleted and recreated in webmail has a new UIDVALIDITY: its messages get new MIDs. */
static int test_uidvalidity_change_new_mids(void)
{
    struct imap_conn *conn = imap_conn_open(root, &tunnel, "alice@example.invalid");
    mailimap *imap = imap_conn_session(conn);
    void *table;
    struct mapistore_property_data *r;
    uint32_t count;
    uint64_t before;
    CHECK(conn != NULL);
    CHECK(mailimap_create(imap, "Temp") == MAILIMAP_NO_ERROR);
    if (append(imap, "Temp", plain_message)) return 1;
    CHECK(!message_rows("Temp", &table, &count) && count == 1);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &r) == MAPISTORE_SUCCESS);
    before = *(uint64_t *) r[10].data;
    CHECK(mailimap_delete(imap, "Temp") == MAILIMAP_NO_ERROR);
    CHECK(mailimap_create(imap, "Temp") == MAILIMAP_NO_ERROR);
    if (append(imap, "Temp", plain_message)) return 1;
    CHECK(!message_rows("Temp", &table, &count) && count == 1);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &r) == MAPISTORE_SUCCESS);
    CHECK(*(uint64_t *) r[10].data != before);
    CHECK(mailimap_delete(imap, "Temp") == MAILIMAP_NO_ERROR);
    talloc_free(conn);
    return 0;
}

/* The message ID of row `row` of `mailbox`'s message table. */
static uint64_t row_mid(const char *mailbox, uint32_t row, void **folderp)
{
    void *table;
    struct mapistore_property_data *r;
    uint32_t count;
    *folderp = context_for(mailbox);
    if (!*folderp || imap_folder_open_table(*folderp, root, MAPISTORE_MESSAGE_TABLE, 9, &table, &count) != MAPISTORE_SUCCESS ||
        imap_table_set_columns(table, N_MESSAGE_COLUMNS, message_columns) != MAPISTORE_SUCCESS ||
        imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, row, &r) != MAPISTORE_SUCCESS || r[10].error) {
        return 0;
    }
    return *(uint64_t *) r[10].data;
}

static enum MAPITAGS body_tags[] = { PidTagBody, PidTagHtml, PidTagNativeBody, PidTagSubject, PidTagInternetCodepage,
    PidTagMessageFlags };

static int open_message(const char *mailbox, uint32_t row, void **msgp, struct mapistore_property_data *data)
{
    void *folder;
    uint64_t mid = row_mid(mailbox, row, &folder);
    CHECK(mid != 0);
    CHECK(imap_folder_open_message(folder, root, mid, false, msgp) == MAPISTORE_SUCCESS && *msgp);
    CHECK(imap_properties_get(*msgp, root, 6, body_tags, data) == MAPISTORE_SUCCESS);
    return 0;
}

static int recipient(struct mapistore_message *m, uint32_t i, const char *column_name, uint32_t tag, const char **value)
{
    uint32_t c;
    for (c = 0; c < m->columns->cValues; c++) {
        if (m->columns->aulPropTag[c] == tag) {
            *value = m->recipients[i].data[c];
            return 0;
        }
    }
    fprintf(stderr, "no recipient column %s\n", column_name);
    return 1;
}

static int test_open_plain_message_body(void)
{
    void *msg;
    struct mapistore_property_data d[6];
    struct mapistore_message *m;
    const char *v;
    if (open_message("INBOX", 0, &msg, d)) return 1;
    CHECK(d[0].error == 0 && strcmp(d[0].data, "Hello from the fixture.\r\n") == 0);
    CHECK(d[1].error == MAPISTORE_ERR_NOT_FOUND);
    CHECK(d[2].error == 0 && *(uint32_t *) d[2].data == 1); /* plain text */
    CHECK(d[3].error == 0 && strcmp(d[3].data, "Plain hello") == 0);
    CHECK(imap_message_get_data(msg, root, &m) == MAPISTORE_SUCCESS);
    CHECK(strcmp(m->normalized_subject, "Plain hello") == 0 && m->recipients_count == 1);
    CHECK(m->recipients[0].type == MAPI_TO && m->recipients[0].username == NULL); /* SMTP, no directory lookup */
    if (recipient(m, 0, "PidTagDisplayName", PidTagDisplayName, &v)) return 1;
    CHECK(v && strcmp(v, "Alice") == 0);
    if (recipient(m, 0, "PidTagEmailAddress", PidTagEmailAddress, &v)) return 1;
    CHECK(v && strcmp(v, "alice@example.invalid") == 0);
    if (recipient(m, 0, "PidTagAddressType", PidTagAddressType, &v)) return 1;
    CHECK(v && strcmp(v, "SMTP") == 0);
    return 0;
}

static int test_charset_and_recipients(void)
{
    void *msg;
    struct mapistore_property_data d[6];
    struct mapistore_message *m;
    if (open_message("Projects", 0, &msg, d)) return 1;
    CHECK(d[0].error == 0 && strcmp(d[0].data, "Ol\xc3\xa1, tudo bem?\r\n") == 0); /* QP + ISO-8859-1 */
    CHECK(imap_message_get_data(msg, root, &m) == MAPISTORE_SUCCESS && m->recipients_count == 3);
    CHECK(m->recipients[0].type == MAPI_TO && m->recipients[1].type == MAPI_TO && m->recipients[2].type == MAPI_CC);
    return 0;
}

static int test_open_html_message_and_attachment(void)
{
    void *msg, *table, *att;
    struct mapistore_property_data d[6], *r, a[2];
    const struct Binary_r *bin;
    enum MAPITAGS att_columns[] = { PidTagAttachNumber, PidTagAttachLongFilename, PidTagAttachSize,
        PidTagAttachMimeTag, PidTagAttachMethod };
    enum MAPITAGS att_data[] = { PidTagAttachDataBinary, PidTagAttachLongFilename };
    uint32_t count = 0;
    if (open_message("Projects", 1, &msg, d)) return 1;
    bin = d[1].data;
    /* RFC 2046: the CRLF before a boundary belongs to the boundary, not to the part. */
    CHECK(d[1].error == 0 && bin->cb == strlen("<p>See <b>attached</b>.</p>"));
    CHECK(memcmp(bin->lpb, "<p>See <b>attached</b>.</p>", 27) == 0);
    CHECK(d[0].error == 0 && strcmp(d[0].data, "See attached.") == 0); /* text from the HTML */
    CHECK(*(uint32_t *) d[2].data == 3 && *(uint32_t *) d[4].data == 65001); /* HTML, UTF-8 */
    CHECK(imap_message_get_attachment_table(msg, root, &table, &count) == MAPISTORE_SUCCESS && count == 1);
    CHECK(imap_table_set_columns(table, 5, att_columns) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &r) == MAPISTORE_SUCCESS);
    CHECK(*(uint32_t *) r[0].data == 0 && strcmp(r[1].data, "report.bin") == 0 && *(uint32_t *) r[2].data == 5);
    CHECK(strcmp(r[3].data, "application/octet-stream") == 0 && *(uint32_t *) r[4].data == 1); /* by value */
    CHECK(imap_message_open_attachment(msg, root, 0, &att) == MAPISTORE_SUCCESS);
    CHECK(imap_properties_get(att, root, 2, att_data, a) == MAPISTORE_SUCCESS && a[0].error == 0);
    bin = a[0].data;
    CHECK(bin->cb == 5 && memcmp(bin->lpb, "\0\1\2\3\4", 5) == 0);
    CHECK(imap_message_open_attachment(msg, root, 1, &att) == MAPISTORE_ERR_NOT_FOUND);
    return 0;
}

static int test_malformed_mime_opens(void)
{
    void *msg, *table;
    struct mapistore_property_data d[6];
    uint32_t i, count;
    for (i = 0; i < sizeof odd_messages / sizeof odd_messages[0]; i++) {
        if (open_message("Odd", i, &msg, d)) return 1;
        CHECK(d[0].error == 0 && d[0].data && d[3].error == 0); /* some body text, a subject */
        CHECK(imap_message_get_attachment_table(msg, root, &table, &count) == MAPISTORE_SUCCESS);
        if (i == 2) CHECK(count == 1); /* the forwarded message */
    }
    CHECK(open_message("Odd", 3, &msg, d) == 0 && strcmp(d[3].data, "Raw \xef\xbf\xbd\xef\xbf\xbd bytes") == 0);
    return 0;
}

/* Deleted in webmail (\Deleted + EXPUNGE) while Outlook keeps the ID: NOT_FOUND, not another message. */
static int test_expunged_mid_not_found(void)
{
    struct imap_conn *conn = imap_conn_open(root, &tunnel, "alice@example.invalid");
    mailimap *imap = imap_conn_session(conn);
    struct mailimap_flag_list *deleted;
    struct mailimap_store_att_flags *store;
    struct mailimap_set *set;
    void *folder, *msg = NULL;
    uint64_t gone;
    CHECK(conn != NULL);
    CHECK(mailimap_create(imap, "Gone") == MAILIMAP_NO_ERROR);
    if (append(imap, "Gone", plain_message) || append(imap, "Gone", second_message)) return 1;
    gone = row_mid("Gone", 0, &folder);
    CHECK(gone != 0);
    CHECK(mailimap_select(imap, "Gone") == MAILIMAP_NO_ERROR);
    deleted = mailimap_flag_list_new_empty();
    CHECK(deleted && mailimap_flag_list_add(deleted, mailimap_flag_new_deleted()) == MAILIMAP_NO_ERROR);
    store = mailimap_store_att_flags_new_add_flags_silent(deleted);
    set = mailimap_set_new_single(1);
    CHECK(store && set && mailimap_store(imap, set, store) == MAILIMAP_NO_ERROR);
    mailimap_set_free(set);
    mailimap_store_att_flags_free(store);
    CHECK(mailimap_expunge(imap) == MAILIMAP_NO_ERROR);
    CHECK(imap_folder_open_message(folder, root, gone, false, &msg) == MAPISTORE_ERR_NOT_FOUND && msg == NULL);
    /* ICS reports it as deleted (a move out of the folder in webmail), and only it. */
    {
        struct mapistore_backend b;
        struct UI8Array_r *ids = NULL;
        uint64_t cn = 0;
        memset(&b, 0, sizeof b);
        CHECK(mapistore_backend_init_defaults(&b) == MAPISTORE_SUCCESS);
        imap_backend_fill(&b);
        CHECK(b.folder.get_deleted_fmids(folder, root, MAPISTORE_MESSAGE_TABLE, 0, &ids, &cn) == MAPISTORE_SUCCESS);
        CHECK(ids && ids->cValues == 1 && ids->lpui8[0] == gone && cn != 0);
        CHECK(b.folder.get_deleted_fmids(folder, root, MAPISTORE_FOLDER_TABLE, 0, &ids, &cn) == MAPISTORE_SUCCESS);
        CHECK(ids && ids->cValues == 0);
    }
    CHECK(mailimap_delete(imap, "Gone") == MAILIMAP_NO_ERROR);
    talloc_free(conn);
    return 0;
}

static int test_oversize_message_notice(void)
{
    struct imap_settings small = tunnel;
    void *msg, *table;
    struct mapistore_property_data d[6];
    uint32_t count = 9;
    small.max_message_size = 100;
    imap_backend_set_state(&small, false);
    if (open_message("Projects", 1, &msg, d)) return 1;
    CHECK(d[0].error == 0 && strstr(d[0].data, "too large") != NULL && d[1].error == MAPISTORE_ERR_NOT_FOUND);
    CHECK(imap_message_get_attachment_table(msg, root, &table, &count) == MAPISTORE_SUCCESS && count == 0);
    imap_backend_set_state(&tunnel, false);
    return 0;
}

/* Configured but unusable (password file mode, typo): an error, never an empty list that would
   make provisioning drop every IMAP folder. */
static int test_broken_config_is_an_error(void)
{
    struct mapistore_contexts_list *list = NULL;
    imap_backend_set_state(NULL, true);
    CHECK(imap_list_contexts("alice@example.invalid", &ictx, root, &list) == MAPISTORE_ERR_CONN_REFUSED);
    imap_backend_set_state(&tunnel, false);
    return 0;
}

/* Bodies are not cut at the header limit. */
static int test_large_body_complete(void)
{
    struct imap_conn *conn = imap_conn_open(root, &tunnel, "alice@example.invalid");
    char *big = talloc_asprintf(root, "From: x@example.invalid\r\nSubject: Big\r\n\r\n");
    void *msg;
    struct mapistore_property_data d[6];
    size_t i;
    CHECK(conn && big);
    for (i = 0; i < 2000; i++) big = talloc_asprintf_append_buffer(big, "line %04zu of a long body\r\n", i);
    CHECK(mailimap_create(imap_conn_session(conn), "Big") == MAILIMAP_NO_ERROR);
    if (append(imap_conn_session(conn), "Big", big)) return 1;
    if (open_message("Big", 0, &msg, d)) return 1;
    CHECK(d[0].error == 0 && strlen(d[0].data) == 2000 * strlen("line 0000 of a long body\r\n"));
    CHECK(mailimap_delete(imap_conn_session(conn), "Big") == MAILIMAP_NO_ERROR);
    talloc_free(conn);
    return 0;
}

/* Dovecot restarted under a live session: the next call reconnects instead of failing for good. */
static int test_reconnect_after_drop(void)
{
    struct imap_folder *inbox = context_for("INBOX");
    struct imap_conn *conn;
    uint32_t count = 0;
    CHECK(inbox != NULL && (conn = imap_context_conn(inbox->ctx)) != NULL);
    CHECK(imap_conn_pid(conn) > 0 && kill(imap_conn_pid(conn), SIGKILL) == 0);
    waitpid(imap_conn_pid(conn), NULL, 0);
    imap_folder_get_child_count(inbox, MAPISTORE_MESSAGE_TABLE, &count); /* fails: the server is gone */
    CHECK(imap_folder_get_child_count(inbox, MAPISTORE_MESSAGE_TABLE, &count) == MAPISTORE_SUCCESS && count == 2);
    return 0;
}

/* Outlook sorts (by delivery time) and restricts (unread only, ICS change numbers) before
   QueryRows; without them the table answered nothing. */
static int test_sort_and_restrict(void)
{
    enum MAPITAGS cols[] = { PidTagSubject };
    struct SSortOrder asc = { PidTagSubject, TABLE_SORT_ASCEND }, desc = { PidTagSubject, TABLE_SORT_DESCEND };
    struct SSortOrderSet by_subject = { .cSorts = 1, .aSort = &asc };
    struct mapi_SRestriction unread = { .rt = RES_BITMASK };
    struct mapi_SRestriction has_id = { .rt = RES_EXIST };
    struct mapi_SRestriction prefix = { .rt = RES_CONTENT };
    struct mapistore_property_data *r;
    void *table;
    uint32_t count;
    uint8_t status = 0xFF;
    CHECK(imap_folder_open_table(context_for("Projects"), root, MAPISTORE_MESSAGE_TABLE, 6, &table, &count) == MAPISTORE_SUCCESS && count == 2);
    CHECK(imap_table_set_columns(table, 1, cols) == MAPISTORE_SUCCESS);
    CHECK(imap_table_set_sort_order(table, &by_subject, &status) == MAPISTORE_SUCCESS && status == 0);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &r) == MAPISTORE_SUCCESS);
    CHECK(strcmp(r[0].data, "Ol\xc3\xa1") == 0);
    by_subject.aSort = &desc;
    CHECK(imap_table_set_sort_order(table, &by_subject, &status) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &r) == MAPISTORE_SUCCESS);
    CHECK(strcmp(r[0].data, "With attachment") == 0);
    /* "Unread": MSGFLAG_READ clear. */
    unread.res.resBitmask.relMBR = BMR_EQZ;
    unread.res.resBitmask.ulPropTag = PidTagMessageFlags;
    unread.res.resBitmask.ulMask = 0x1;
    CHECK(imap_table_set_restrictions(table, &unread, &status) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row_count(table, MAPISTORE_PREFILTERED_QUERY, &count) == MAPISTORE_SUCCESS && count == 1);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &r) == MAPISTORE_SUCCESS);
    CHECK(strcmp(r[0].data, "With attachment") == 0);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 1, &r) == MAPISTORE_ERR_NOT_FOUND);
    has_id.res.resExist.ulPropTag = PidTagInternetMessageId;
    CHECK(imap_table_set_restrictions(table, &has_id, &status) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row_count(table, MAPISTORE_PREFILTERED_QUERY, &count) == MAPISTORE_SUCCESS && count == 0);
    prefix.res.resContent.fuzzy = 0x00010002; /* FL_PREFIX | FL_IGNORECASE */
    prefix.res.resContent.ulPropTag = PidTagSubject;
    prefix.res.resContent.lpProp.ulPropTag = PidTagSubject;
    prefix.res.resContent.lpProp.value.lpszW = "with";
    CHECK(imap_table_set_restrictions(table, &prefix, &status) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row_count(table, MAPISTORE_PREFILTERED_QUERY, &count) == MAPISTORE_SUCCESS && count == 1);
    CHECK(imap_table_set_restrictions(table, NULL, &status) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row_count(table, MAPISTORE_PREFILTERED_QUERY, &count) == MAPISTORE_SUCCESS && count == 2);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &r) == MAPISTORE_SUCCESS);
    CHECK(strcmp(r[0].data, "With attachment") == 0); /* the sort order stays */
    return 0;
}

/* A client restriction whose value type disagrees with its tag, or a string restriction on a
   binary column, is unsupported (rows pass), never a read through the wrong union member. */
static int test_mistyped_restriction_ignored(void)
{
    struct mapi_SRestriction r = { .rt = RES_PROPERTY };
    void *table;
    uint32_t count;
    uint8_t status = 0xFF;
    CHECK(imap_folder_open_table(context_for("Projects"), root, MAPISTORE_MESSAGE_TABLE, 7, &table, &count) == MAPISTORE_SUCCESS && count == 2);
    r.res.resProperty.relop = 4; /* RELOP_EQ */
    r.res.resProperty.ulPropTag = PidTagChangeKey;
    r.res.resProperty.lpProp.ulPropTag = PidTagMessageFlags;
    r.res.resProperty.lpProp.value.l = 5;
    CHECK(imap_table_set_restrictions(table, &r, &status) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row_count(table, MAPISTORE_PREFILTERED_QUERY, &count) == MAPISTORE_SUCCESS && count == 2);
    r.rt = RES_CONTENT;
    r.res.resContent.fuzzy = 1; /* FL_SUBSTRING */
    r.res.resContent.ulPropTag = PidTagChangeKey;
    r.res.resContent.lpProp.ulPropTag = PidTagSubject;
    r.res.resContent.lpProp.value.lpszW = "x";
    CHECK(imap_table_set_restrictions(table, &r, &status) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row_count(table, MAPISTORE_PREFILTERED_QUERY, &count) == MAPISTORE_SUCCESS && count == 2);
    r.res.resContent.ulPropTag = PidTagSubject;
    r.res.resContent.lpProp.value.lpszW = NULL;
    CHECK(imap_table_set_restrictions(table, &r, &status) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row_count(table, MAPISTORE_PREFILTERED_QUERY, &count) == MAPISTORE_SUCCESS && count == 2);
    return 0;
}

static uint64_t next_cn = 0x5000;
static enum mapistore_error fake_cn(struct imap_context *ctx, uint64_t *cn)
{
    *cn = (exchange_globcnt(next_cn++) << 16) | 0x0001;
    return MAPISTORE_SUCCESS;
}

/* ICS (cached mode) aborts without PidTagChangeNumber on folders, and without the change number,
   change key and predecessor list on messages (oxcfxics.c). */
static int test_change_numbers(void)
{
    enum MAPITAGS tags[] = { PidTagChangeNumber, PidTagChangeKey, PidTagPredecessorChangeList, PidTagLastModificationTime };
    struct mapistore_property_data d[6], again[4], *r; /* open_message fills 6 */
    struct imap_folder *folder;
    void *table, *msg;
    const struct Binary_r *key, *pcl;
    uint64_t folder_cn, message_cn;
    uint32_t count;
    imap_backend_set_cn_source(fake_cn);
    CHECK((folder = context_for("Projects")) != NULL);
    CHECK(imap_properties_get(folder, root, 4, tags, d) == MAPISTORE_SUCCESS);
    CHECK(d[0].error == 0 && d[1].error == 0 && d[2].error == 0 && d[3].error == 0);
    folder_cn = *(uint64_t *) d[0].data;
    key = d[1].data;
    pcl = d[2].data;
    CHECK((folder_cn & 0xFFFF) == 1 && key->cb == 22 && pcl->cb == 23 && pcl->lpb[0] == 22);
    CHECK(memcmp(key->lpb, "\x44\x33\x22\x11\x66\x55\x88\x77", 8) == 0); /* replica GUID, NDR */
    CHECK(memcmp(pcl->lpb + 1, key->lpb, 22) == 0);
    CHECK(imap_properties_get(context_for("Projects"), root, 4, tags, again) == MAPISTORE_SUCCESS);
    CHECK(*(uint64_t *) again[0].data == folder_cn); /* unchanged folder, same change number */
    /* Messages carry their own, stable while their flags do not change. */
    CHECK(imap_folder_open_table(folder, root, MAPISTORE_MESSAGE_TABLE, 4, &table, &count) == MAPISTORE_SUCCESS && count == 2);
    CHECK(imap_table_set_columns(table, 4, tags) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &r) == MAPISTORE_SUCCESS);
    CHECK(r[0].error == 0 && r[1].error == 0 && r[2].error == 0);
    message_cn = *(uint64_t *) r[0].data;
    CHECK(message_cn != folder_cn && ((const struct Binary_r *) r[1].data)->cb == 22);
    CHECK(open_message("Projects", 0, &msg, d) == 0);
    CHECK(imap_properties_get(msg, root, 4, tags, again) == MAPISTORE_SUCCESS);
    CHECK(again[0].error == 0 && *(uint64_t *) again[0].data == message_cn);
    /* New mail in the folder changes the folder's change number. */
    {
        struct imap_conn *conn = imap_conn_open(root, &tunnel, "alice@example.invalid");
        CHECK(conn && !append(imap_conn_session(conn), "Projects", second_message));
        CHECK(imap_properties_get(context_for("Projects"), root, 4, tags, again) == MAPISTORE_SUCCESS);
        CHECK(*(uint64_t *) again[0].data != folder_cn);
        talloc_free(conn);
    }
    return 0;
}

/* Every operation gets a default: emsmdb calls preload_message_bodies during cached-mode sync,
   and an unset pointer in a stack-allocated backend crashed the daemon. */
static int test_defaults_cover_every_operation(void)
{
    struct mapistore_backend b;
    memset(&b, 0xA5, sizeof b);
    CHECK(mapistore_backend_init_defaults(&b) == MAPISTORE_SUCCESS);
    CHECK((void *) b.folder.preload_message_bodies != (void *) 0xA5A5A5A5A5A5A5A5ULL);
    CHECK((void *) b.folder.move_folder != (void *) 0xA5A5A5A5A5A5A5A5ULL);
    CHECK((void *) b.folder.copy_folder != (void *) 0xA5A5A5A5A5A5A5A5ULL);
    CHECK((void *) b.message.create_embedded_message != (void *) 0xA5A5A5A5A5A5A5A5ULL);
    CHECK(b.folder.preload_message_bodies(NULL, MAPISTORE_MESSAGE_TABLE, NULL) == MAPISTORE_SUCCESS);
    return 0;
}

static bool has_tag(const struct SPropTagArray *a, enum MAPITAGS tag)
{
    uint32_t i;
    for (i = 0; a && i < a->cValues; i++) {
        if (a->aulPropTag[i] == tag) return true;
    }
    return false;
}

/* ICS full sync and GetPropertiesAll send what get_available_properties lists: without it,
   cached-mode Outlook receives messages with no subject, sender or body and hides them. */
static int test_available_properties(void)
{
    struct SPropTagArray *props = NULL;
    void *msg, *att;
    struct mapistore_property_data d[6];
    CHECK(imap_properties_available(context_for("INBOX"), root, &props) == MAPISTORE_SUCCESS);
    CHECK(has_tag(props, PidTagDisplayName) && has_tag(props, PidTagContentCount) && has_tag(props, PidTagChangeNumber));
    CHECK(open_message("Projects", 1, &msg, d) == 0);
    CHECK(imap_properties_available(msg, root, &props) == MAPISTORE_SUCCESS);
    CHECK(has_tag(props, PidTagSubject) && has_tag(props, PidTagSenderName) && has_tag(props, PidTagMessageClass));
    CHECK(has_tag(props, PidTagBody) && has_tag(props, PidTagHtml) && has_tag(props, PidTagMessageDeliveryTime));
    CHECK(has_tag(props, PidTagChangeNumber) && has_tag(props, PidTagChangeKey) && has_tag(props, PidTagPredecessorChangeList));
    CHECK(!has_tag(props, PidTagInternetMessageId)); /* this message has no Message-ID header */
    CHECK(imap_message_open_attachment(msg, root, 0, &att) == MAPISTORE_SUCCESS);
    CHECK(imap_properties_available(att, root, &props) == MAPISTORE_SUCCESS);
    CHECK(has_tag(props, PidTagAttachDataBinary) && has_tag(props, PidTagAttachLongFilename));
    /* ICS contents sync takes the message properties from the message table (RopSyncConfigure). */
    {
        void *table;
        uint32_t count;
        CHECK(imap_folder_open_table(context_for("INBOX"), root, MAPISTORE_MESSAGE_TABLE, 5, &table, &count) == MAPISTORE_SUCCESS);
        CHECK(imap_table_available(table, root, &props) == MAPISTORE_SUCCESS);
        CHECK(has_tag(props, PidTagSubject) && has_tag(props, PidTagBody) && has_tag(props, PidTagMessageClass));
    }
    return 0;
}

/* emsmdb knows a context root by the folder ID it provisioned, not by the one the indexing
   holds for the URI: children must name that ID as parent, or Outlook orphans them. */
static int test_root_folder_takes_core_fid(void)
{
    struct mapistore_backend b;
    void *inbox = context_for("Projects"), *rootf = NULL, *table = NULL;
    struct mapistore_property_data *row = NULL;
    enum MAPITAGS tags[] = { PidTagFolderId, PidTagParentFolderId };
    struct mapistore_property_data d[1];
    uint32_t count = 0;
    const uint64_t core_fid = 0xf503000000000001ULL;
    memset(&b, 0, sizeof b);
    CHECK(inbox != NULL && mapistore_backend_init_defaults(&b) == MAPISTORE_SUCCESS);
    imap_backend_fill(&b);
    CHECK(b.context.get_root_folder(inbox, root, core_fid, &rootf) == MAPISTORE_SUCCESS && rootf);
    CHECK(imap_properties_get(rootf, root, 1, tags, d) == MAPISTORE_SUCCESS);
    CHECK(d[0].error == MAPISTORE_SUCCESS && *(uint64_t *) d[0].data == core_fid);
    CHECK(imap_folder_open_table(rootf, root, MAPISTORE_FOLDER_TABLE, 1, &table, &count) == MAPISTORE_SUCCESS && count >= 1);
    CHECK(imap_table_set_columns(table, 2, tags) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &row) == MAPISTORE_SUCCESS);
    CHECK(row[1].error == MAPISTORE_SUCCESS && *(uint64_t *) row[1].data == core_fid);
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
    signal(SIGPIPE, SIG_IGN); /* as openchange-mapihttpd (Rust ignores SIGPIPE) */
    root = talloc_new(NULL);
    fixture = argv[2];
    ictx.get_fmid = fi_get_fmid;
    ictx.get_uri = fi_get_uri;
    ictx.add_fmid = fi_add_fmid;
    ictx.allocate_fmid = fi_allocate;
    fidx.next = 0x2000;
    imap_backend_set_cn_source(fake_cn); /* no openchangedb here */
    if (setup_fixture(argv[1]) || populate() || test_list_fixture() || test_examine_counts() ||
        test_username_is_checked() || test_settings_password_file() || test_mailbox_name_round_trip() ||
        (imap_backend_set_state(&tunnel, false), 0) || test_list_contexts_roles() || test_create_context_without_namespace() || test_uri_user_must_match() ||
        test_hierarchy_table_rows() || test_folder_properties() || test_create_root_folder_not_found() ||
        test_imap_down_is_an_error() || test_message_table_columns() || test_message_ids_stable() ||
        test_uidvalidity_change_new_mids() || test_open_plain_message_body() || test_charset_and_recipients() ||
        test_open_html_message_and_attachment() || test_malformed_mime_opens() || test_expunged_mid_not_found() ||
        test_oversize_message_notice() || test_broken_config_is_an_error() || test_large_body_complete() ||
        test_reconnect_after_drop() || test_sort_and_restrict() || test_mistyped_restriction_ignored() || test_silent_server_times_out() || test_change_numbers() || test_defaults_cover_every_operation() || test_available_properties() || test_root_folder_takes_core_fid() || test_backend_registers()) {
        return 1;
    }
    talloc_free(root);
    printf("IMAP backend connection, listing, status and settings: OK\n");
    return 0;
}
