# M4: IMAP writes and sending from Outlook — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** What a person does in Outlook (move, copy, delete, read state, flags, drafts, folders, send) reaches Dovecot and Postfix.

**Architecture:** The M3 IMAP mapistore backend gains IMAP mutations (`imap_write.c`), a MAPI→MIME composer (`imap_compose.c`) and a submission client (`imap_submit.c`); the mapistore indexing gains a URI-prefix rewrite for folder renames. emsmdb already routes the cached-mode imports to mapistore; it changes only where it ignores backend errors and at submit.

**Tech Stack:** C, libetpan 1.9.4 (IMAP UIDPLUS/MOVE, MIME writer, ESMTP + SASL), talloc, Dovecot 2.4 (test harness in PREAUTH), Postfix submission 587.

**Spec:** `docs/specs/2026-11-04-m4-imap-writes-design.md` (maintainer decisions of 2026-11-04 and lab facts inside).

## Global Constraints

- Logs never carry addresses, subjects, bodies or the master password (M3 rule). `OC_DEBUG` lines name UIDs, mids, counts and error codes only.
- The fmid index changes only after the IMAP server confirmed the write (tagged OK).
- Permanent delete is `UID STORE +FLAGS (\Deleted)` + `UID EXPUNGE <those uids>`; never a bare `EXPUNGE`. Without UIDPLUS: refuse (`MAPISTORE_ERR_NOT_IMPLEMENTED`).
- Only messages with MSGFLAG_UNSENT (0x8) are ever re-rendered/re-appended; on any other message `save` writes flags only.
- Submission: `mapistore:smtp_host` default `127.0.0.1`, `mapistore:smtp_port` default `587`; STARTTLS always; certificate verification off only when the host is loopback (reuse `is_loopback` from `imap_conn.c`); AUTH PLAIN as `<user>*<master_user>` with the master password; MAIL FROM = the session user's primary address (the IMAP login name).
- IMAP and SMTP network timeout 10 s (`IMAP_TIMEOUT_SECONDS`, M3).
- Default folders (Inbox, Sent, Drafts, Trash, Junk, Archive, Outbox) cannot be deleted or renamed from Outlook: `MAPISTORE_ERR_DENIED`.
- Outbox is the IMAP mailbox `Outbox`, created unsubscribed.
- Tests run on the lab VM through the scratchpad `m1-lab/labmake.sh` (sync + make); C suites `check-imap-backend`, `check-oc-emsmdb`, `check-emsmdb`; Python suite as in M3 (43 tests).
- Commits in English, trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Another message already `\Deleted` by webmail in the same folder when Outlook hard-deletes one:** only Outlook's UID disappears. Pinned by `test_expunge_only_given_uid` (Task 1).
2. **Folder rename with messages and subfolders below:** every mid under it still opens after the rename, no new mids. Pinned by `test_rename_keeps_mids` (Task 4).
3. **IMAP refuses a write (quota, mailbox gone, read-only):** the index is untouched and the error reaches emsmdb. Pinned by `test_refused_move_keeps_index` (Task 3).
4. **Non-ASCII subject/display names and a binary attachment in a sent message:** the MIME parses back to the same strings and bytes; Bcc never appears in headers. Pinned by `test_compose_round_trip` (Task 5).
5. **Postfix refuses the sender or a recipient:** nothing is sent, the message stays in Outbox, submit returns an error. Pinned by `test_submit_refusal_keeps_outbox` (Task 7).

---

### Task 1: IMAP mutations on the wire

**Files:**
- Create: `mapiproxy/libmapistore/backends/imap/imap_write.c`
- Modify: `mapiproxy/libmapistore/backends/imap/imap_conn.h` (declarations), `Makefile` (object list of `mapistore_imap.so`, next to `imap_message.po`)
- Test: `testsuite/modernization/imap_backend_smoke.c`

**Interfaces:**
- Produces (all return 0 on tagged OK, -1 otherwise; each SELECTs the mailbox read-write first, so later EXAMINEs by M3 code must not assume a selected state):
  - `#define IMAP_FLAG_SEEN 0x01, IMAP_FLAG_FLAGGED 0x02, IMAP_FLAG_ANSWERED 0x04, IMAP_FLAG_DELETED 0x08, IMAP_FLAG_FORWARDED 0x10 /* $Forwarded */, IMAP_FLAG_DRAFT 0x20`
  - `int imap_uid_move(struct imap_conn *conn, const char *from, const uint32_t *uids, uint32_t count, const char *to, bool copy, uint32_t *dest_uidvalidity, uint32_t *dest_uids);` — `mailimap_uidplus_uid_move`/`_uid_copy`; `dest_uids[i]` is the COPYUID UID of `uids[i]` (map through the source/dest sets, not by position in the reply).
  - `int imap_uid_set_flags(struct imap_conn *conn, const char *mailbox, uint32_t uid, uint32_t add, uint32_t remove);`
  - `int imap_uid_expunge(struct imap_conn *conn, const char *mailbox, const uint32_t *uids, uint32_t count);` — needs UIDPLUS in the capability list, else -1 without sending anything.
  - `int imap_append(struct imap_conn *conn, const char *mailbox, const char *data, size_t len, uint32_t flags, uint32_t *uidvalidity, uint32_t *uid);` — `mailimap_uidplus_append`.
  - `int imap_create_mailbox(struct imap_conn *conn, const char *name, bool subscribe);`, `int imap_rename_mailbox(struct imap_conn *conn, const char *from, const char *to);`, `int imap_delete_mailbox(struct imap_conn *conn, const char *name);`
  Names are modified UTF-7, as on the wire (M3 `struct imap_folder.mailbox`).

- [ ] **Step 1: Write the failing tests** `test_uid_move_copy` (move one fixture message Projects→Archive: source count −1, dest +1, returned dest UID fetches the same Message-ID; copy leaves the source), `test_expunge_only_given_uid` (two messages in a scratch mailbox, both `\Deleted` via `imap_uid_set_flags`, expunge one UID → the other still exists with `\Deleted`), `test_append_and_flags` (append 3-line message with `IMAP_FLAG_SEEN|IMAP_FLAG_DRAFT` → returned UID's FLAGS contain both; `imap_uid_set_flags(…, IMAP_FLAG_FLAGGED|IMAP_FLAG_FORWARDED, IMAP_FLAG_SEEN)` → `\Flagged $Forwarded`, no `\Seen`), `test_mailbox_lifecycle` (create "Tmp" subscribed → LSUB lists it; rename to "Tmp2"; delete; LIST lacks both). Each test works on mailboxes it creates, so fixture counts used by M3 tests stay valid; register them after the M3 tests in `main`.
- [ ] **Step 2: Run** `labmake.sh check-imap-backend` — Expected: build failure (undefined `imap_uid_move` …).
- [ ] **Step 3: Implement** the functions above in `imap_write.c` with libetpan's calls named in the interface; `imap_conn_check()` on every result (reconnect logic of M3).
- [ ] **Step 4: Run** `labmake.sh check-imap-backend` — Expected: `IMAP backend …: OK`; Dovecot log lines show `expunged=1` only for the expunge test.
- [ ] **Step 5: Commit** `feat(mapistore/imap): IMAP mutations (move, copy, flags, expunge, append, mailboxes)`.

### Task 2: Indexing URI-prefix rewrite

**Files:**
- Modify: `mapiproxy/libmapistore/mapistore.h` (`struct indexing_context`), `mapiproxy/libmapistore/backends/indexing_mysql.c`, `mapiproxy/libmapistore/backends/indexing_tdb.c`, `mapiproxy/libmapistore/mapistore_indexing.c` (default stub)
- Test: `testsuite/libmapistore/mapistore_indexing.c`

**Interfaces:**
- Produces: `enum mapistore_error (*update_uri_prefix)(struct indexing_context *ictx, const char *username, const char *old_prefix, const char *new_prefix);` — every record of `username` whose URI starts with `old_prefix` gets `new_prefix` + the rest; fmids unchanged; soft-deleted flags unchanged. MySQL: one `UPDATE … SET url = CONCAT(?, SUBSTRING(url, CHAR_LENGTH(?)+1)) WHERE username=? AND url LIKE ?` with `old_prefix` LIKE-escaped (`%`, `_`, `\`). TDB: traverse.

- [ ] **Step 1: Failing tests** `test_update_uri_prefix` in both the mysql and tdb suites: add `imap://u/A/` (fmid 1), `imap://u/A/B/` (2), `imap://u/A/B/7_1` (3), `imap://u/AB/` (4), `imap://u/A_/` (5); rewrite `imap://u/A/`→`imap://u/Z/` → `get_uri(2)=="imap://u/Z/B/"`, `get_uri(3)=="imap://u/Z/B/7_1"`, `get_uri(4)` and `get_uri(5)` unchanged; `get_fmid("imap://u/Z/B/")==2`.
- [ ] **Step 2: Run** the libcheck runner on the lab (`make bin/openchange-testsuite` then the runner as `make check`'s recipe at Makefile:1542 does, with the M3 MySQL test socket) — Expected: build failure on the missing member. If the runner cannot reach a test MySQL on the lab, run the tdb suite only and record a ruling.
- [ ] **Step 3: Implement** both backends and the stub (`MAPISTORE_ERR_NOT_IMPLEMENTED`).
- [ ] **Step 4: Run** — Expected: both new tests pass, existing indexing tests pass.
- [ ] **Step 5: Commit** `feat(mapistore): indexing rewrites a URI prefix`.

### Task 3: Message writes in the backend (move, copy, delete, read, flags)

**Files:**
- Modify: `mapiproxy/libmapistore/backends/imap/imap_folder.c` (`move_copy_messages`, `delete_message`), `imap_message.c` (`set_read_flag`, message `set_properties`, `save` for received mail), `imap_backend.h`
- Test: `testsuite/modernization/imap_backend_smoke.c`

**Interfaces:**
- Consumes: Task 1 functions; `imap_message_uri(mem_ctx, folder, uidvalidity, uid)` (M3); `ictx->update_fmid`/`add_fmid`/`del_fmid`.
- Produces: backend ops registered in `imap_backend_fill`/`imap_message_fill`:
  - `move_copy_messages(target_folder, source_folder, mem_ctx, count, src_mids, t_mids, target_change_keys, target_predecessor_change_lists, want_copy)` — same context only, else `MAPISTORE_ERR_DENIED` (emsmdb turns cross-store into NO_SUPPORT). Move: `update_fmid(t_mids[i] or src_mids[i])` to the dest URI; emsmdb passes the target mids it allocated — bind those (`add_fmid`) and `del_fmid(src, MAPISTORE_PERMANENT_DELETE)` on move; copy binds only the targets.
  - `delete_message(folder, mid, flags)` — any flag value: `imap_uid_expunge`, then `del_fmid(mid, MAPISTORE_PERMANENT_DELETE)`.
  - `set_read_flag(message, flag)` — `SUPPRESS_RECEIPT|CLEAR_READ_FLAG` bits per MS-OXCMSG RopSetMessageReadFlag: clear → remove `\Seen`, else add.
  - On a message without MSGFLAG_UNSENT: `set_properties` records PidTagFlagStatus (2 → `\Flagged`, else clear), PidTagLastVerbExecuted (102/103 → `\Answered`, 104 → `$Forwarded`), PidTagMessageFlags MSGFLAG_READ (→ `\Seen`); everything else ignored with one level-5 log line; `save` applies the pending flag diff with one `imap_uid_set_flags`.

- [ ] **Step 1: Failing tests** `test_backend_move_binds_target_mid` (move mid of "With attachment" to Archive with t_mid 0x9001 → `open_message(archive, 0x9001)` succeeds with the same subject; `open_message(projects, old mid)` → NOT_FOUND; copy keeps both), `test_backend_hard_delete` (delete mid → NOT_FOUND on open, IMAP count −1), `test_read_and_follow_up_flags` (set_read_flag clear → FLAGS lack `\Seen`; set PidTagFlagStatus=2 + LastVerbExecuted=102, save → `\Flagged \Answered`; a PidTagSubject change on that received message leaves the IMAP message's Subject header unchanged), `test_refused_move_keeps_index` (move to a mailbox deleted behind the backend's back → error, `get_uri(src mid)` unchanged).
- [ ] **Step 2: Run** `labmake.sh check-imap-backend` — Expected: FAIL (ops are the M3 NOT_IMPLEMENTED defaults).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: OK.
- [ ] **Step 5: Commit** `feat(mapistore/imap): move, copy, delete and flags reach IMAP`.

### Task 4: Folder writes (create, rename, move, delete)

**Files:**
- Modify: `mapiproxy/libmapistore/backends/imap/imap_folder.c`, `imap_backend.h`
- Test: `testsuite/modernization/imap_backend_smoke.c`

**Interfaces:**
- Consumes: Task 1 mailbox calls; Task 2 `update_uri_prefix`; M3 `imap_uri`, `imap_display_name` (and its inverse: encode a UTF-8 display name to modified UTF-7 — add `char *imap_mailbox_name(TALLOC_CTX *, const char *utf8)` in `imap_names.c`; `/`, the delimiter and `%`/`*` in a display name are refused with `MAPISTORE_ERR_INVALID_PARAMETER`).
- Produces: `create_folder(parent, mem_ctx, fid, aRow, &child)` (PidTagDisplayName from aRow → `<parent mailbox><delim><name>`, CREATE + SUBSCRIBE, `add_fmid(fid, uri)`); folder `set_properties` with PidTagDisplayName → rename in place; `move_folder(folder, target_parent, mem_ctx, new_name)` → RENAME under the target; both call `update_uri_prefix(old folder URI, new folder URI)` after the server's OK; `delete(folder)` → `imap_delete_mailbox` only when the mailbox has no messages and no children, else `MAPISTORE_ERR_EXIST`; default folders (`\Inbox`, SPECIAL-USE ones, `Outbox`) → `MAPISTORE_ERR_DENIED` for rename/move/delete.

- [ ] **Step 1: Failing tests** `test_create_folder_named_utf8` ("Relatórios" → LIST shows `Relat&APM-rios`, subscribed; reopening by fid gives the display name back), `test_rename_keeps_mids` (folder with one message and one subfolder: rename → message mid and subfolder fid open under the new name; no new fmids allocated: `fidx.next` unchanged), `test_delete_folder_rules` (non-empty → EXIST; empty → gone; Inbox → DENIED; name with `/` → INVALID_PARAMETER).
- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: OK.
- [ ] **Step 5: Commit** `feat(mapistore/imap): Outlook creates, renames and deletes IMAP folders`.

### Task 5: MAPI→MIME composer

**Files:**
- Create: `mapiproxy/libmapistore/backends/imap/imap_compose.c`
- Modify: `imap_backend.h`, `Makefile`
- Test: `testsuite/modernization/imap_backend_smoke.c`

**Interfaces:**
- Produces:
  - `struct imap_draft` — talloc child of the message: `props` (`struct SRow`-like list of the PidTag values Outlook set), `recipients` (`struct imap_recipient *`, count), `attachments` (`struct imap_attachment *`, count, plus `bool inline_`/content id), `bool dirty`.
  - `char *imap_compose(TALLOC_CTX *mem_ctx, const struct imap_draft *d, const char *from_address, const char *from_name, time_t now, size_t *len);` — RFC 5322 + MIME via libetpan (`mailimf_fields`, `mailmime_*`, `mailmime_write_mem`): From, To, Cc (never Bcc), Subject (RFC 2047 UTF-8 B when non-ASCII), Date, Message-ID `<random hex@domain of from_address>` unless PidTagInternetMessageId is set, In-Reply-To/References from PidTagInReplyToId/PidTagInternetReferences; body: text only → `text/plain; charset=utf-8` QP; text+HTML → `multipart/alternative`; attachments → `multipart/mixed` (inline ones with Content-ID under `multipart/related` with the HTML); attachment bytes base64; filenames RFC 2231 UTF-8. Body source: PidTagBody, PidTagHtml; PidTagRtfCompressed alone → convert with the existing `lzfu` decompressor and send as text (`shortcut:` comment: RTF formatting is dropped, upgrade when a client needs it).
  - `uint32_t imap_draft_envelope(const struct imap_draft *d, TALLOC_CTX *mem_ctx, const char ***rcpts);` — all To/Cc/Bcc addresses, de-duplicated case-insensitively.

- [ ] **Step 1: Failing test** `test_compose_round_trip`: draft with Subject "Relatório de março ✓", To "Ana Souza" <ana@example.invalid>, Cc one, Bcc "x@example.invalid", PidTagBody "Olá\r\n", PidTagHtml "<p>Olá</p>", attachment "relatório.pdf" with bytes 0x00..0xFF; compose, parse the result with M3's parser (the same path `imap_folder_open_message` uses, fed from memory) → subject, To/Cc display, body, HTML and attachment bytes/filename equal; the raw text has no "x@example.invalid"; `imap_draft_envelope` returns 3 addresses. Second case: text only → single `text/plain` part.
- [ ] **Step 2: Run** — Expected: build failure.
- [ ] **Step 3: Implement.** If M3's parser cannot be fed from memory, add `enum mapistore_error imap_message_parse(TALLOC_CTX *, const char *data, size_t len, struct imap_message *out)` in `imap_message.c` by extracting the existing parse body (no behaviour change; M3 tests stay green).
- [ ] **Step 4: Run** — Expected: OK, also under the ASan/UBSan build used in M3.
- [ ] **Step 5: Commit** `feat(mapistore/imap): compose MIME from MAPI messages`.

### Task 6: Drafts and Outbox (create, edit, save)

**Files:**
- Modify: `imap_message.c` (`create_message`, `set_properties`/`modify_recipients`/`create_attachment`/attachment `set_properties` and stream writes on drafts, `save`), `imap_folder.c` (`list_contexts`/provisioning: Outbox), `imap_backend.h`
- Test: `testsuite/modernization/imap_backend_smoke.c`, `testsuite/modernization/oc_emsmdb_smoke.c` (Outbox provisioning)

**Interfaces:**
- Consumes: Task 5 `struct imap_draft`, `imap_compose`; Task 1 `imap_append`, `imap_uid_expunge`.
- Produces:
  - `create_message(folder, mem_ctx, mid, associated, &msg)` — associated (FAI) → `MAPISTORE_ERR_DENIED`; else an in-memory message with an `imap_draft`, MSGFLAG_UNSENT set, no IMAP traffic.
  - `open_message(…, read_write=true)` on an MSGFLAG_UNSENT (IMAP `\Draft`) message loads its parsed content into an `imap_draft`.
  - `save(msg)` on a draft: compose, `imap_append` with `IMAP_FLAG_DRAFT|IMAP_FLAG_SEEN` to the message's folder; if it replaced an older version, `imap_uid_expunge` the old UID; then `update_fmid`/`add_fmid(mid, new uri)`. APPEND failure → error, old version and index untouched.
  - Outbox: `list_contexts` creates `Outbox` unsubscribed when missing and offers it with role `MAPISTORE_OUTBOX_ROLE`, so the M3 takeover maps the existing openchangedb Outbox fid to it (same path as Drafts in M3).

- [ ] **Step 1: Failing tests** `test_draft_save_and_edit` (create in Drafts with mid 0x9101, subject "v1", save → IMAP Drafts +1 with `\Draft`; open read-write, subject "v2", save → still +1 (old expunged), `open_message(0x9101)` shows "v2"), `test_fai_create_denied`, `test_outbox_provisioned` (list_contexts on a fixture without Outbox creates it, LSUB lacks it, the list has an Outbox-role entry) and in `oc_emsmdb_smoke.c` `test_outbox_taken_over` (logon after provisioning maps the Outbox fid to `imap://<user>/Outbox/`).
- [ ] **Step 2: Run** `labmake.sh check-imap-backend check-oc-emsmdb` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: OK.
- [ ] **Step 5: Commit** `feat(mapistore/imap): Outlook drafts and Outbox live in IMAP`.

### Task 7: Submission and Sent

**Files:**
- Create: `mapiproxy/libmapistore/backends/imap/imap_submit.c`
- Modify: `imap_conn.c`/`imap_conn.h` (`smtp_host`, `smtp_port`, `smtp_tunnel` in `struct imap_settings`, loaded from `mapistore:smtp_host`/`mapistore:smtp_port`), `imap_message.c` (`submit`), `mapiproxy/servers/default/emsmdb/oxomsg.c` (relocation through the backend), `Makefile`, `doc/MODERNIZATION.md` (parameters)
- Test: `testsuite/modernization/imap_backend_smoke.c`

**Interfaces:**
- Consumes: Task 5 `imap_compose`, `imap_draft_envelope`; Task 1 `imap_uid_move`, `imap_uid_expunge`.
- Produces:
  - `int imap_smtp_send(const struct imap_settings *s, const char *username, const char *from, const char **rcpts, uint32_t count, const char *data, size_t len, int *smtp_code);` — libetpan `mailsmtp`: connect, EHLO, STARTTLS (always; verify unless loopback), EHLO, AUTH PLAIN via `mailesmtp_auth_sasl`, `mailesmtp_mail_size` when EHLO SIZE is present (refuse locally above it), RCPT each (any failure → RSET, return -1), DATA, QUIT. `settings->smtp_tunnel` (test only, like `imap_tunnel`): a command whose stdio is an SMTP server without TLS; STARTTLS is skipped only on the tunnel.
  - backend `submit(msg, flags)`: message must be saved in Outbox (else `MAPISTORE_ERR_INVALID_OBJECT`); compose (from the saved draft), send; on success clear MSGFLAG_UNSENT and move: PidTagDeleteAfterSubmit → `imap_uid_expunge`; else `imap_uid_move` Outbox→Sent (the `\Sent` SPECIAL-USE mailbox), rebind the mid, flags `\Seen`. On failure: message stays in Outbox, error returned (`MAPISTORE_ERR_DENIED` for 5xx, `MAPISTORE_ERR_CONN_REFUSED` for connect/TLS/auth failures).
  - The backend files the exact bytes it sent (`UID MOVE`), instead of emsmdb's `oxomsg_mapistore_handle_message_relocation`, which would create and re-compose a second message. After a successful submit the message no longer reports PidTagTargetEntryId or PidTagSentMailSvrEID (dropped from the draft's properties), so that function finds nothing to do; emsmdb needs no IMAP branch.
  - `oxomsg.c`: RopSubmitMessage returns `mapistore_error_to_mapi(ret)` of `mapistore_message_submit` instead of ignoring it, and skips relocation and `record_add_mid` when it failed.

- [ ] **Step 1: Failing tests** (plus, in `test_submit_sends_and_files`, `imap_message_properties` of the submitted message answers NOT_FOUND for PidTagTargetEntryId and PidTagSentMailSvrEID although the draft had both) with a fake SMTP server (a small C helper `bin/imap-backend-smtp-fake`, built by the test target, scripted by argv: replies per command, writes the received envelope and DATA to a file): `test_submit_sends_and_files` (draft in Outbox → submit → fake got AUTH PLAIN with `alice@example.invalid*openchange`, MAIL FROM alice, 3 RCPTs, DATA equal to `imap_compose` output; Outbox −1, Sent +1 `\Seen`; mid opens in Sent), `test_submit_refusal_keeps_outbox` (fake answers 553 to RCPT → submit error DENIED, Outbox unchanged, no DATA in the file), `test_submit_delete_after` (PidTagDeleteAfterSubmit → Sent unchanged, Outbox −1), `test_submit_size_refused` (EHLO SIZE 100 → error before MAIL).
- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement.** The real Postfix 587 is exercised in Task 8 with Outlook.
- [ ] **Step 4: Run** `labmake.sh all check-imap-backend check-oc-emsmdb check-emsmdb` — Expected: all OK.
- [ ] **Step 5: Commit** `feat(mapistore/imap): Outlook sends through submission and files in Sent`.

### Task 8: emsmdb error propagation, lab acceptance, docs

**Files:**
- Modify: `mapiproxy/servers/default/emsmdb/oxcfxics.c` (ImportMessageMove: return `mapistore_error_to_mapi` of `mapistore_folder_move_copy_messages`; ImportReadStateChanges: log and keep going per message, reply error only when every message failed), `doc/MODERNIZATION.md` ("M4 lab setup and result")
- Test: lab with Outlook (no ROP-level harness exists; M3 ruling)

- [ ] **Step 1:** Implement the two oxcfxics changes; `labmake.sh all check-oc-emsmdb check-emsmdb` — Expected: OK.
- [ ] **Step 2:** Deploy to the lab; set `mapistore:smtp_host`/`smtp_port` in the lab smb.conf (edit with sed on those keys only; never print the file).
- [ ] **Step 3: Outlook acceptance** (user at PC 192.168.0.162, cached mode), each checked in SOGo and with `doveadm` (counts/flags only, addresses sanitized): move Inbox→teste; Delete → Trash; Shift+Delete one message while webmail has another `\Deleted` in the same folder (that one survives); read/unread; follow-up flag; reply (→ `\Answered`); create folder "Relatórios", rename, delete; save a draft, edit it, discard; send to another lab account with an attachment and accents → arrives (doveadm), `DKIM-Signature` header present, copy in Sent; send with a From of another account (if Outlook allows choosing it) → error shown, message stays in Outbox. Expected: every item as described; journal has no SIGSEGV/SIGABRT.
- [ ] **Step 4:** Record results in `doc/MODERNIZATION.md`; commit `docs: record M4 Outlook acceptance`.
