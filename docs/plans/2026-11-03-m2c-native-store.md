# M2c: native openchangedb mailbox so the Outlook profile opens — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** RopLogon succeeds for a directory mailbox with no mapistore backend installed, so Outlook opens the server mailbox (empty folders) instead of looping and falling back to a local data file.

**Architecture:** `emsmdbp_mailbox_provision` already creates part of the mailbox (Reminders … Top of Information Store) as native openchangedb folders (no mapistore URI). When no backend offers a fallback context, the remaining system folders (Deferred Action … Views) and the special folders (Inbox, Outbox, Sent, Deleted, Calendar, Contacts, …) are created the same way. openchangedb, on MariaDB through its existing MySQL backend, then holds folders, FAI messages and properties until M3's IMAP backend takes over the mail roles. Gaps in the native-openchangedb ROP paths that Outlook hits are found with a lab ROP trace and fixed one failing test at a time.

**Tech Stack:** C (EMSMDB provider, openchangedb LDB/MySQL backends), MariaDB 11.8, existing C smoke harness (`testsuite/modernization/oc_emsmdb_smoke.c`).

**Spec:** `doc/MODERNIZATION.md` (Roadmap: M2 acceptance "Outlook creates the profile"; M2a lab result of 2026-11-03), `docs/plans/2026-11-03-m2a-directory-connect.md` (scope split), maintainer decision of 2026-11-03: folders Outlook needs but IMAP lacks live in MariaDB/openchangedb; mail folders come from Dovecot from M3 on.

## Decisions

1. **No new mapistore backend in M2c.** "No fallback context" (zero backends, or none offering `MAPISTORE_FALLBACK_ROLE`) means native folders: `openchangedb_create_folder(..., NULL, idx)` and no `mapistore_add_context`/indexing record for them. A configured fallback backend keeps today's behavior.
2. **Special folders are native too while no backend offers their role.** When M3's IMAP backend offers `MAPISTORE_MAIL_ROLE` etc., the existing re-provisioning path (`openchangedb_set_mapistoreURI` on the folder found by name) moves them to the backend; the native folder IDs are kept (MS-OXOSFLD 3.1.4.1 reuse by name).
3. **openchangedb on MariaDB in the lab** (`mapiproxy:openchangedb = mysql://…`), schema from the project's migrations (`openchange_migrate`); its credentials live in a 0600 option file referenced by smb.conf, never in argv or logs. The C tests keep the LDB backend.
4. **ROP trace for the lab:** each ROP's opnum, handle index and return code at debug level 3, no property values or bodies (they can hold mail content).

## Global Constraints

- Debian 13 packages only; no new dependencies.
- No AD, no LDAP server, no Samba daemon.
- Never log passwords, Authorization, cookies, property values or bodies.
- Lab VM only (lab.fitasonline.com.br); never the production mail server.
- Work on branch `m2c` from `m2a`; English commits with the Co-Authored-By trailer; push to the fork after green local checks.

## Review Focus

1. **Second logon / restart:** provisioning must be idempotent — the same folder IDs on every logon, no duplicate folders. Pinned by `test_provision_idempotent` (Task 1).
2. **Another user's mailbox:** logon with another user's EssDN must still fail (existing owner check in `oxcstor.c`). Pinned by `test_logon_other_users_dn` (Task 2).
3. **Backend later added:** a native special folder must be re-pointed, not duplicated, when a backend offers its role. Pinned by `test_provision_backend_takes_over_inbox` (Task 1) with a fake backend returning a `MAPISTORE_MAIL_ROLE` context.
4. **MySQL openchangedb missing tables or credentials:** the daemon must fail Connect cleanly (no crash) and log one line without secrets. Checked in Task 3, step 3.
5. **Unbounded client writes to native folders** (Outlook writes FAI view/rule messages): bounded by the existing 16 MiB request cap; no new limit in M2c — recorded as a known limit in docs (Task 4).

---

### Task 1: Native provisioning without a fallback backend

**Files:**
- Modify: `mapiproxy/servers/default/emsmdb/emsmdbp_provisioning.c` (fallback check near line 408 and the three URI-building branches)
- Test: `testsuite/modernization/oc_emsmdb_smoke.c`

**Interfaces:**
- Produces: `emsmdbp_mailbox_provision(ctx, username)` returns `MAPI_E_SUCCESS` with zero backends; every `EMSMDBP_*` system/special folder index has a folder ID (`openchangedb_get_SystemFolderID`) and native folders report no mapistore URI (`openchangedb_get_mapistoreURI` ≠ success).

- [ ] **Step 1: Write failing tests** (connected alice session from M2a tests; seed openchangedb with the server/org/ou entries `OpenChangeDB.add_server` writes, as LDIF in the test):
  - `test_provision_native_mailbox`: `emsmdbp_mailbox_provision(ctx, "alice@example.invalid") == MAPI_E_SUCCESS`; folder IDs exist for `EMSMDBP_MAILBOX_ROOT`, `EMSMDBP_DEFERRED_ACTION`, `EMSMDBP_VIEWS`, `EMSMDBP_TOP_INFORMATION_STORE`, `EMSMDBP_INBOX`, `EMSMDBP_SENT_ITEMS`, `EMSMDBP_DELETED_ITEMS`, `EMSMDBP_CALENDAR`, `EMSMDBP_CONTACTS`; Inbox has no mapistore URI.
  - `test_provision_idempotent`: a second call returns success and the same nine folder IDs.
  - `test_provision_backend_takes_over_inbox`: register a test backend (via `mapistore_backend_register`) whose `list_contexts` returns a fallback and a `MAPISTORE_MAIL_ROLE` entry; after provisioning again, Inbox keeps its folder ID and its URI is the backend's.
- [ ] **Step 2: Run** `make check-oc-emsmdb` (lab) → FAIL (`MAPI_E_DISK_ERROR` from the missing fallback).
- [ ] **Step 3: Implement**: `fallback_url = NULL` when no fallback entry; every place that builds `"%s0x%"PRIx64"/"` from it passes NULL instead and skips `mapistore_add_context`/`mapistore_indexing_record_add_fmid_for_uri`; `openchangedb_set_mapistoreURI` is skipped when the URI is NULL.
- [ ] **Step 4: Run** `make check-oc-emsmdb check-emsmdb check-mapihttp`, plus `check-oc-emsmdb` with `CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'` → PASS.
- [ ] **Step 5: Commit** `feat(emsmdb): provision a native openchangedb mailbox without a fallback backend`.

### Task 2: RopLogon over the MAPI/HTTP boundary

**Files:**
- Test: `testsuite/modernization/oc_emsmdb_smoke.c`
- Modify (only if the test exposes a defect): `mapiproxy/servers/default/emsmdb/oxcstor.c`

**Interfaces:**
- Consumes: Task 1 provisioning; M2a `oc_emsmdb_connect`.
- Produces: helper `static DATA_BLOB logon_request(TALLOC_CTX *, const char *essdn)` in the test (RopLogon 0xFE, `LogonFlags` private, `OpenFlags` `USE_PER_MDB_REPLID_MAPPING`, like `get_status_request`).

- [ ] **Step 1: Write failing tests**: `test_logon_private_mailbox` — `oc_emsmdb_execute` with alice's RopLogon → `MAPI_E_SUCCESS`, reply ROP `ErrorCode` 0, 13 folder IDs, the Inbox ID among them equals Task 1's; `test_logon_other_users_dn` — alice's session with bob's EssDN → ROP `ErrorCode` `MAPI_E_NO_ACCESS`.
- [ ] **Step 2: Run** `make check-oc-emsmdb` → first on Task 1's base commit with Task 1's provisioning change reverted (Expected: FAIL, ROP `ErrorCode` `MAPI_E_DISK_ERROR`), then on Task 1 (Expected: PASS, or a defect for Step 3). Record which in the ledger.
- [ ] **Step 3: Fix** any defect the test exposes, minimally, in the ROP code.
- [ ] **Step 4: Run** the Task 1 command set → PASS.
- [ ] **Step 5: Commit** `test(emsmdb): cover RopLogon over the MAPI/HTTP C boundary`.

### Task 3: openchangedb on MariaDB in the lab, with a ROP trace

**Files:**
- Modify: `mapiproxy/servers/default/emsmdb/emsmdb_execute.c` (one `OC_DEBUG(3, ...)` per ROP: opnum, handle index, error code)
- Modify: `doc/MAPIHTTP.md` (openchangedb on MariaDB for the lab)

- [ ] **Step 1:** Add the trace line; `make check-oc-emsmdb check-emsmdb` → PASS; commit `feat(emsmdb): trace ROP results at debug level 3`.
- [ ] **Step 2:** Lab: create database `openchange` and user `openchange@localhost` (all privileges on that database only), option file 0600, schema via the project's MySQL setup/migrations; point `mapiproxy:openchangedb` at it; restart; Connect smoke → StatusCode 0.
- [ ] **Step 3:** Break it on purpose (wrong password in the option file): Connect fails with MAPI_E_LOGON_FAILED, daemon stays up, log has one line without the password; restore.
- [ ] **Step 4:** Outlook M365 new profile with log level 3: collect the ROP trace (opnums and error codes only) into the ledger.

### Task 4: Fix the ROP gaps Outlook hits on native folders

**Files:** decided per gap from the Task 3 trace (expected: `emsmdbp_object.c` set_properties on native messages, `oxcmsg.c`, `oxctabl.c`).

- [ ] **Step 1:** For each failing ROP in the trace, in trace order: write a test in `oc_emsmdb_smoke.c` that sends that ROP sequence over `oc_emsmdb_execute` and asserts the Exchange-conformant result; watch it fail; fix minimally; run the Task 1 command set; commit `fix(emsmdb): <ROP> on native openchangedb objects`.
- [ ] **Step 2:** Repeat the Outlook run after each batch of fixes until the trace shows no error on the profile-open path.
- [ ] **Step 3:** Docs: `doc/MODERNIZATION.md` "M2c lab result" (versions, trace summary, known limits incl. Review Focus 5), `doc/CONTINUITY.md`; commit `docs: record the M2c lab run`; push.

**Acceptance (lab):** Outlook M365 opens the new profile without "not responding", shows the folder tree under `teste@lab.fitasonline.com.br` (Inbox, Sent Items, Drafts, Deleted Items, Calendar, Contacts, Tasks), no Connect/Execute/Disconnect loop in the nginx log, no local data file created as default store.
