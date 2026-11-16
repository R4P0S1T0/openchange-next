# M5 Notifications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** cached-mode Outlook picks up every IMAP mail-folder change (new, flags, moves, deletes, folders) within about a minute, without a restart.

**Architecture:** mapihttpd (Rust) watches each online user's mailbox with IMAP NOTIFY (LIST-STATUS poll as fallback) and turns events into "mailbox X changed"; a new FFI call runs on the existing C worker and queues TableModified ROW_MODIFIED/ADDED/DELETED RopNotify blocks on the deep hierarchy tables the session keeps open; the session's NotificationWait wakes and the next Execute carries them. Outlook then runs ICS (M3/M4) on that folder because the row brings a newer PidTagLocalCommitTimeMax.

**Tech Stack:** C (emsmdb, libmapistore IMAP backend, libetpan), Rust (mapihttpd, tokio), Dovecot 2.4 (NOTIFY, CONDSTORE, LIST-STATUS).

**Spec:** `docs/superpowers/specs/2026-11-13-m5-notifications-design.md`

## Global Constraints

- The lab Outlook runs on a shared terminal server (TS-167): acceptance acts only inside our own session (`RenanMorano_Testes`); no machine-wide commands, no process kills by name, no logoff of other sessions.
- No new Rust crate dependencies (vendored, offline build); IMAP client code is hand-written on `tokio::net::TcpStream`.
- The IMAP master credentials stay where they are (smb.conf `mapistore:imap_*` options read by C); Rust obtains them only through the new FFI call, never logs them.
- One C worker thread serves every session: `oc_emsmdb_folder_changed` does at most one folder property read per tracked table.
- Spike code on branch `m5` (marked `SPIKE (M5, throwaway)`) is discarded first; the two real fixes are re-applied from `/srv/build/m5-patches/m5-real-fixes.patch` (lab) as part of Task 1.
- Out of scope here: the spec's nice-to-have NewMail 0x8002 alert (needs the new message's MID); ROW_MODIFIED alone drives the sync. Revisit after acceptance.
- Lab build: `labmake.sh` (scratchpad `lab/`) then `/tmp/deploy-m2c.sh`; after a sync, `./configure --prefix=/usr/local --enable-mapihttp` on the lab tree if `config.mk` lost `OC_MAPIHTTP`.

## Review Focus

- Outlook releases the hierarchy table (RopRelease or session end) and a change arrives afterwards: no use of the freed table, nothing queued (Task 2 test `test_notify_after_table_release`).
- A change arrives before Outlook opened any deep hierarchy table: nothing queued, no error (Task 2 test `test_notify_without_table`).
- More queued notifications than fit in one Execute reply: the rest stays queued for the next Execute, none lost (Task 2 test `test_notify_overflow_kept`).
- Mailbox names with non-ASCII characters (modified UTF-7 on the wire, e.g. `Lixo Eletr&APQ-nico`): mapped to the right FID (Task 2 test `test_fid_for_mailbox_utf7`).
- The NOTIFY connection drops or Dovecot rejects NOTIFY: the watcher falls back to polling and reconnects with backoff, never a busy loop (Task 5 tests `test_watch_falls_back_to_poll`, `test_watch_reconnect_backoff`).

---

### Task 1: IMAP folder state and properties Outlook compares

**Files:**
- Modify: `mapiproxy/libmapistore/backends/imap/imap_conn.c` (`imap_status`: STATUS adds `HIGHESTMODSEQ`)
- Modify: `mapiproxy/libmapistore/backends/imap/imap_conn.h` (`struct imap_status` gains `uint64_t highestmodseq`)
- Modify: `mapiproxy/libmapistore/backends/imap/imap_folder.c` (state string, `PidTagLocalCommitTimeMax`)
- Modify: `mapiproxy/servers/default/emsmdb/emsmdbp_object.c` (`PR_CONTENT_UNREAD` from the backend, 0 as fallback)
- Test: `testsuite/modernization/imap_backend_smoke.c`

**Interfaces:**
- Produces: folder property `PidTagLocalCommitTimeMax` (PT_SYSTIME) = time of the folder's last state change; folder state string `"%u:%u:%u:%u:%llu"` (uidvalidity, messages, unseen, uidnext, highestmodseq).

- [ ] **Step 1:** Discard the spike: `git checkout -- mapihttpd mapiproxy` in the worktree; then `git apply /path/to/m5-real-fixes.patch` (copied from the lab).
- [ ] **Step 2: Failing tests** in `imap_backend_smoke.c`:
  - `test_folder_commit_time_on_flag_change`: read `PidTagLocalCommitTimeMax` of INBOX; set `\Flagged` on one message through a second IMAP connection (no count changes); sleep 1 s; read again → strictly greater.
  - `test_folder_commit_time_present`: `PidTagLocalCommitTimeMax` returns `MAPISTORE_SUCCESS` and equals `PidTagLastModificationTime`.
- [ ] **Step 3:** `labmake.sh check-imap-backend` → the flag test fails (state ignores modseq).
- [ ] **Step 4: Implement** HIGHESTMODSEQ in `imap_status` (`MAILIMAP_STATUS_ATT_HIGHESTMODSEQ`; 0 when the server has no CONDSTORE) and in the state string.
- [ ] **Step 5:** `labmake.sh check-imap-backend` → PASS.
- [ ] **Step 6: Commit** `fix(mapistore/imap): folder commit time and unread count Outlook compares`.

### Task 2: Notification queue on deep hierarchy tables (C, emsmdb)

**Files:**
- Create: `mapiproxy/servers/default/emsmdb/emsmdbp_notify.c`
- Modify: `mapiproxy/servers/default/emsmdb/dcesrv_exchange_emsmdb.h` (context fields, prototypes)
- Modify: `mapiproxy/servers/default/emsmdb/oxcfold.c` (`EcDoRpc_RopGetHierarchyTable` tracks Depth tables without `TableFlags_NoNotifications`)
- Modify: `mapiproxy/servers/default/emsmdb/emsmdbp_object.c` (table destructor untracks)
- Modify: `mapiproxy/servers/default/emsmdb/emsmdb_execute.c` (append queued blobs after the replies, within the size limit; keep the rest)
- Modify: `Makefile` (new object in liboc_emsmdb and exchange_emsmdb)
- Test: `testsuite/modernization/oc_emsmdb_smoke.c`

**Interfaces:**
- Produces:
  - `enum emsmdbp_folder_change { EMSMDBP_FOLDER_MODIFIED, EMSMDBP_FOLDER_ADDED, EMSMDBP_FOLDER_DELETED };`
  - `int emsmdbp_notify_folder_changed(struct emsmdbp_context *ctx, uint64_t fid, enum emsmdbp_folder_change kind);` → number of RopNotify blocks queued (0 when no tracked table holds the folder).
  - `enum MAPISTATUS emsmdbp_fid_for_mailbox(struct emsmdbp_context *ctx, const char *mailbox, uint64_t *fid);` → openchangedb system folder whose MAPIStoreURI is that mailbox (Inbox, Sent, Deleted Items, ...), else the mapistore indexing FID of `imap://<user>/<mailbox>/`; `MAPI_E_NOT_FOUND` otherwise. `mailbox` is modified UTF-7 as IMAP sends it.
  - `bool emsmdbp_notify_pending(struct emsmdbp_context *ctx);`
- Row content: the folder's properties in the tracked table's columns via `emsmdbp_object_get_properties` + `emsmdbp_fill_table_row_blob` (what QueryRows sends); ROW_MODIFIED/ROW_ADDED carry `InsertAfterFID` = previous sibling in the table order, or 0; ROW_DELETED carries the FID only. Notification type 0x0100 (`fnevTableModified`), handle = the table's handle, LogonId = the GetHierarchyTable request's.

- [ ] **Step 1: Failing tests** in `oc_emsmdb_smoke.c` (native mailbox from `test_provision_native_mailbox`, ROP frames built like `get_status_request`):
  - `test_notify_row_modified`: Logon, OpenFolder(mailbox root), GetHierarchyTable(TableFlags 0x84), SetColumns(FolderId, DisplayName, ContentCount); `emsmdbp_notify_folder_changed(ctx, inbox_fid, EMSMDBP_FOLDER_MODIFIED)` == 1; next Execute(GetStatus) reply contains one RopNotify with NotificationType 0x0100, TableEvent 5, FID = inbox, columns decoding to the Inbox row.
  - `test_notify_without_table`: no hierarchy table → returns 0, Execute reply has no RopNotify.
  - `test_notify_after_table_release`: table released by RopRelease → returns 0.
  - `test_notify_overflow_kept`: 200 changes queued, Execute with a small `rop_out_cap` → reply holds what fits, the next Execute the rest; total RopNotify count 200.
  - `test_fid_for_mailbox_utf7`: provisioned folder whose MAPIStoreURI is `imap://u/Lixo%20Eletr%C3%B4nico/` resolves from `Lixo Eletr&APQ-nico`.
- [ ] **Step 2:** `labmake.sh check-oc-emsmdb` → the new tests fail to link.
- [ ] **Step 3: Implement** `emsmdbp_notify.c` and the hooks; the queue lives on `emsmdbp_context` (talloc list of DATA_BLOBs), the memcached "deliver" path stays as is.
- [ ] **Step 4:** `labmake.sh check-oc-emsmdb` and `check-imap-backend` → PASS.
- [ ] **Step 5: Commit** `feat(emsmdb): notify Outlook's hierarchy tables when a folder changes`.

### Task 3: FFI for folder changes and IMAP watch parameters (C)

**Files:**
- Modify: `mapiproxy/servers/default/emsmdb/oc_emsmdb.h`, `oc_emsmdb.c`
- Test: `testsuite/modernization/oc_emsmdb_smoke.c`

**Interfaces:**
- Produces:
  - `uint32_t oc_emsmdb_folder_changed(oc_emsmdb_session *session, const char *mailbox, uint32_t kind, uint32_t *pending);` kind 0 modified, 1 added, 2 deleted; `*pending` = 1 when the session has queued notifications after the call. Unknown mailbox → returns 0 with `*pending` unchanged.
  - `uint32_t oc_emsmdb_imap_watch_params(char **host, uint16_t *port, char **master_user, char **master_password);` strings malloc'ed (caller frees with `oc_emsmdb_free`); `MAPI_E_NOT_FOUND` when the IMAP backend is not configured.
  - `void oc_emsmdb_free(void *p);`
  - `const char *oc_emsmdb_username(oc_emsmdb_session *session);`
- [ ] **Step 1: Failing tests**: `test_ffi_folder_changed` (session from `test_connect_success`, table opened as in Task 2 → `*pending` 1); `test_ffi_watch_params` (fixture smb.conf with `mapistore:imap_host = 127.0.0.1`, port 143, master user `openchange`, password file → values returned, password equal to the file's first line).
- [ ] **Step 2:** run → fail. **Step 3:** implement over Task 2 and `imap_backend_settings()`. **Step 4:** run → PASS.
- [ ] **Step 5: Commit** `feat(emsmdb): FFI to report folder changes and IMAP watch parameters`.

### Task 4: Backend call and NotificationWait wake-up (Rust)

**Files:**
- Modify: `mapihttpd/src/ffi.rs`, `mapihttpd/src/backend.rs` (trait method, `Job::FolderChanged`, `FakeBackend`/`Call`)
- Modify: `mapihttpd/src/session.rs` (per-session `pending: AtomicBool` + `tokio::sync::Notify`; user name per session)
- Modify: `mapihttpd/src/emsmdb.rs` (`notification_wait` waits on the session's Notify or the deadline; EventPending = 1 when pending)

**Interfaces:**
- Consumes: Task 3 FFI.
- Produces:
  - `Backend::folder_changed(&self, id: SessionId, mailbox: String, kind: FolderChange) -> impl Future<Output = bool>` (true = notifications pending).
  - `pub enum FolderChange { Modified, Added, Deleted }`
  - `SessionTable::sessions_of(&self, user: &str) -> Vec<(SessionId, Arc<SessionSignal>)>`; `SessionSignal { pending: AtomicBool, notify: Notify }` with `fn raise(&self)`.
  - `Backend::watch_params(&self) -> impl Future<Output = Option<WatchParams>>`; `pub struct WatchParams { host: String, port: u16, master_user: String, master_password: Password }`.
- [ ] **Step 1: Failing tests** (`emsmdb.rs` tests, FakeBackend): `test_notification_wait_wakes_on_raise` (wait set to 300 s, raise after 100 ms → reply within 1 s with EventPending 1); `test_notification_wait_pending_before_wait` (raise first → immediate EventPending 1); `test_notification_wait_timeout_unchanged` (no raise, wait 1 s → EventPending 0).
- [ ] **Step 2:** `cargo test -p mapihttpd` → fail. **Step 3:** implement. **Step 4:** PASS (also `cargo clippy -- -D warnings`).
- [ ] **Step 5: Commit** `feat(mapihttpd): wake NotificationWait when a session has notifications`.

### Task 5: IMAP watcher per online user (Rust)

**Files:**
- Create: `mapihttpd/src/imapwatch.rs` (client, parser, watcher, manager)
- Modify: `mapihttpd/src/main.rs`, `mapihttpd/src/emsmdb.rs` (start on Connect, stop with the user's last session)

**Interfaces:**
- Consumes: Task 4 (`folder_changed`, `sessions_of`, `watch_params`).
- Produces: `pub struct WatchManager` with `fn session_started(&self, user: &str)`, `fn session_ended(&self, user: &str)`; events `enum MailboxEvent { Changed(String), ListChanged }`.
- Behaviour fixed by the spec: AUTHENTICATE PLAIN `<user>*<master>` over loopback; `NOTIFY SET STATUS (personal (MessageNew MessageExpunge FlagChange MailboxName))`; untagged STATUS/LIST name the mailbox; coalesce per mailbox for 1 s; on NOTIFY refusal or connection loss: reconnect with backoff 1 s doubling to 60 s, and poll `LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN UIDNEXT HIGHESTMODSEQ))` every 60 s while down plus once after each reconnect; a mailbox that appears → `Added`, disappears → `Deleted`, differs → `Modified`.
- [ ] **Step 1: Failing tests** against a scripted fake IMAP server (`tokio::net::TcpListener` in the test): `test_parse_status_event` (untagged `* STATUS "Lixo Eletr&APQ-nico" (MESSAGES 3)` → `Changed("Lixo Eletr&APQ-nico")`); `test_watch_coalesces` (5 events for INBOX within 200 ms → one `folder_changed`); `test_watch_falls_back_to_poll` (server answers NOTIFY with `NO` → LIST-STATUS issued, a changed snapshot yields `Modified`, a new mailbox `Added`, a removed one `Deleted`); `test_watch_reconnect_backoff` (server closes → reconnect attempts spaced ≥1 s, ≥2 s); `test_watch_stops_with_last_session`; `test_password_not_logged` (log capture contains no password).
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** `cargo test`, `cargo clippy -- -D warnings` → PASS.
- [ ] **Step 5: Commit** `feat(mapihttpd): watch online users' mailboxes and notify Outlook`.

### Task 6: Lab acceptance, docs, cleanup

- [x] **Step 1:** Build without sanitizers (`labmake.sh all mapiproxy/servers/liboc_emsmdb.so bin/openchange-mapihttpd`), deploy, restart; reopen Outlook (default profile, our session only).
- [x] **Step 2:** Acceptance per spec (each must appear within about a minute, Outlook not restarted): new mail by SMTP; mail filed by a Sieve rule (`ana@` → Archive); read/unread and flag changed in SOGo; move and delete in SOGo; folder created, renamed, deleted in SOGo. Then kill the watcher's IMAP connection on the lab (`doveadm kick` of the master session for `teste`) and repeat one case (fallback poll).
- [x] **Step 3:** Record in `doc/MODERNIZATION.md` ("M5: notifications"): mechanism, timings, limits.
- [x] **Step 4:** Cleanup: stop and remove the `grommunio` container (`machinectl poweroff grommunio`, remove `/srv/machines/grommunio`, the `/var/lib/machines` link, `/etc/systemd/nspawn/grommunio.nspawn`), `/etc/nginx/conf.d/m5-gromox-route.conf`, restore `proxy_pass http://127.0.0.1:8080;` and drop the `m5-route` log in the `mail` site (backup `/root/nginx-mail.pre-m5-gromox`), remove the `grommunio-test` site and CA, `ip addr del` of the veth address; in Outlook (our session) remove the `ref@` account from profile "Outlook" and delete profile "Referencia"; remove `/var/lib/openchange/spike-notify` if present.
- [x] **Step 5: Commit** `docs: record M5 acceptance`; then superpowers:finishing-a-development-branch.
