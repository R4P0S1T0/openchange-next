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
#include <signal.h>
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

static struct mapistore_connection_info conn_info = { .username = "alice@example.invalid" };

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

static int test_uri_user_must_match(void)
{
    void *folder = NULL;
    char *uri = imap_uri(root, "bob@example.invalid", "INBOX", '/');
    CHECK(imap_create_context(root, &conn_info, &ictx, uri, &folder) == MAPISTORE_ERR_DENIED && folder == NULL);
    CHECK(imap_create_context(root, &conn_info, &ictx, "imap://alice%40example.invalid/", &folder) != MAPISTORE_SUCCESS);
    return 0;
}

static enum MAPITAGS hierarchy_columns[] = { PidTagFolderId, PidTagDisplayName, PidTagContentCount,
    PidTagSubfolders, PidTagContainerClass };

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
    CHECK(imap_table_set_columns(table, 5, hierarchy_columns) == MAPISTORE_SUCCESS);
    CHECK(imap_table_get_row(table, root, MAPISTORE_PREFILTERED_QUERY, 0, &row) == MAPISTORE_SUCCESS);
    CHECK(row[0].error == MAPISTORE_SUCCESS && (fid = *(uint64_t *) row[0].data) != 0);
    CHECK(row[1].error == MAPISTORE_SUCCESS && strcmp(row[1].data, "Sub") == 0);
    CHECK(row[2].error == MAPISTORE_SUCCESS && *(uint32_t *) row[2].data == 0);
    CHECK(row[3].error == MAPISTORE_SUCCESS && *(uint8_t *) row[3].data == 0);
    CHECK(row[4].error == MAPISTORE_SUCCESS && strcmp(row[4].data, "IPF.Note") == 0);
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

static int test_imap_down_is_an_error(void)
{
    struct imap_settings down = tunnel;
    struct mapistore_contexts_list *list = NULL;
    down.tunnel = "/nonexistent/imap";
    imap_backend_set_settings(&down);
    CHECK(imap_list_contexts("alice@example.invalid", &ictx, root, &list) == MAPISTORE_ERR_CONN_REFUSED);
    imap_backend_set_settings(NULL);
    CHECK(imap_list_contexts("alice@example.invalid", &ictx, root, &list) == MAPISTORE_SUCCESS && list == NULL);
    imap_backend_set_settings(&tunnel);
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
    if (setup_fixture(argv[1]) || populate() || test_list_fixture() || test_examine_counts() ||
        test_username_is_checked() || test_settings_password_file() || test_mailbox_name_round_trip() ||
        (imap_backend_set_settings(&tunnel), 0) || test_list_contexts_roles() || test_uri_user_must_match() ||
        test_hierarchy_table_rows() || test_folder_properties() || test_create_root_folder_not_found() ||
        test_imap_down_is_an_error() || test_backend_registers()) {
        return 1;
    }
    talloc_free(root);
    printf("IMAP backend connection, listing, status and settings: OK\n");
    return 0;
}
