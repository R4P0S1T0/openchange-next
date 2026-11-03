# M2a: PostfixAdmin directory and successful Connect — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A MAPI/HTTP Connect from a PostfixAdmin mailbox succeeds against the C backend without Samba's SamDB, so Outlook proceeds to Execute (RopLogon).

**Architecture:** MariaDB/PostfixAdmin stays the source of truth. A sync tool writes a plain LDB file (no Samba schema, no LDAP server) with the attributes the existing EMSMDB/NSPI code already queries (`sAMAccountName`, `legacyExchangeDN`, `msExchUserAccountControl`, …). The server opens it with plain `ldb_connect` instead of `samdb_connect`, so every existing `ldb_search` caller works unchanged. `oc_emsmdb_connect` gains the identity check that the DCE/RPC path does with a Samba SID, using the Dovecot canonical user instead.

**Tech Stack:** C (talloc/ldb from Samba as libraries), Python 3.13 with `ldb` (python3-ldb) and `MySQLdb` (python3-mysqldb, already used by `python/openchange/mailbox.py`), Rust 1.85 (mapihttpd), systemd timer.

**Spec:** `doc/MODERNIZATION.md` (Roadmap, M2 row) and `docs/plans/2026-10-30-m1-mapihttp-autodiscover.md` (decisions 4, 5 and 8).

## Scope split of M2

The M2 row ("Outlook creates the profile and the GAL lists the users") needs three independent pieces; each gets its own plan and lab run:

- **M2a (this plan):** directory from PostfixAdmin + successful Connect. Lab result: Connect succeeds and Outlook sends Execute; RopLogon still fails because no mailbox backend exists (`emsmdbp_mailbox_provision` needs `mapistore_list_contexts_for_user`).
- **M2b:** NSPI request types over MAPI/HTTP (Bind, GetSpecialTable, QueryRows, GetProps, ResolveNames, DNToMId, GetMatches, GetMailboxUrl/GetAddressBookUrl) through a C boundary over `emsabp`, reading the same directory LDB.
- **M2c:** minimal mailbox store so RopLogon provisioning succeeds and the profile opens (folders empty until M3).

## Decisions

1. **Directory = generated LDB cache.** Path from smb.conf `mapiproxy:directory_url` (e.g. `tdb:///var/lib/openchange/directory.ldb`). When set, it replaces `dcerpc_mapiproxy:samdb_url`/`samdb_connect`; when unset, legacy Samba behavior is unchanged. Refreshed by `openchange-directory-sync` from a systemd timer every 60 s; staleness up to one minute is documented. The file is written to a temp file in the same directory and renamed, so readers never see a partial file. Each Connect opens its own handle (existing `emsmdbp_init` behavior), so new sessions see the new file.
2. **Fixed DNs.** Default naming context `DC=openchange`; users under `CN=Users,DC=openchange`; configuration `CN=Configuration,DC=openchange`; organization `CN=<org>,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=openchange` (`objectClass: msExchOrganizationContainer`); admin group `CN=<ou>,CN=Administrative Groups,<org DN>` (`objectClass: msExchAdminGroup`, `msExchDefaultAdminGroup: TRUE`). The C side sets the LDB opaques `default_baseDN` and `config_baseDN` to these, since no Samba rootdse module does it.
3. **Identity.** `sAMAccountName` = Dovecot canonical user = PostfixAdmin `mailbox.username` (full lower-case email). `mailNickname` = `<local>-<h8>` where `<local>` is the lower-cased local part with every byte outside `[a-z0-9._-]` replaced by `_`, and `<h8>` is the first 8 hex digits of SHA-256 of the lower-cased email. Stable across domain additions, unique per mailbox. Test vector: `teste@lab.fitasonline.com.br` → computed once in Task 2 and copied into the Rust test of Task 4 (both suites assert the same literal).
4. **LegacyDN** = `/o=<org>/ou=<ou>/cn=Recipients/cn=<mailNickname>`. `--org`/`--ou` must equal the daemon's flags (M7 will unify configuration).
5. **Account state.** `msExchUserAccountControl: 0` when both `mailbox.active` and `domain.active` are 1, else `2`. Removed mailboxes disappear from the file; their existing MAPI/HTTP sessions live until idle expiry (documented limit).
6. **Connect identity (MAPI/HTTP):** exactly one entry with `sAMAccountName` equal to the Dovecot user, account control 0, its `legacyExchangeDN` equal to the client's `user_dn` ignoring ASCII case, and its last `/cn=` equal to `mailNickname`. Anything else → `MAPI_E_LOGON_FAILED`. Delegation stays unsupported. `openchangedb_get_MailboxReplica` is **not** required at Connect: its `conn_info` outputs have no readers and the mailbox is created later by RopLogon provisioning.
7. **displayName** = `mailbox.name` when non-empty after trimming, else the email.

## Global Constraints

- Debian 13 packages only: Rust 1.85, Python 3.13, python3-ldb, python3-mysqldb; no new crates, no new Python packages.
- No AD, no LDAP server, no Samba daemon; Samba only as libraries.
- MariaDB access is read-only (`SELECT` on `postfixadmin.mailbox` and `postfixadmin.domain`); credentials come from a MySQL option file (`read_default_file`), mode 0600, never from argv or logs.
- The directory file is mode 0640, owner root, group `openchange`.
- Never log passwords, Authorization, cookies or bodies. Lab only; never the production server.
- Commits in English with the Co-Authored-By trailer; push to the fork after green local checks (maintainer authorization of 2026-10-30/2026-11-03).

## Review Focus

1. **Case of DNs and addresses.** Outlook may send `user_dn` with different case (`/O=First Organization/...`); LDB compares unknown attributes case-sensitively. Expected: Connect succeeds. Pinned by `@ATTRIBUTES` (`CASE_INSENSITIVE` for `legacyExchangeDN`, `sAMAccountName`, `mail`, `mailNickname`) and test `test_connect_dn_case_insensitive` (Task 3) plus `test_search_is_case_insensitive` (Task 2).
2. **Another user's DN.** An authenticated user presenting a different mailbox's LegacyDN must not get a session. Pinned by `test_connect_other_users_dn` (Task 3).
3. **Sync failure.** MariaDB down or a write error must keep the previous directory file intact and exit non-zero. Pinned by `test_failed_write_keeps_previous_file` (Task 2).
4. **LDB filter metacharacters in emails** (`(`, `)`, `*`, `\` are legal in quoted local parts). Expected: no filter injection, no match on other users. Pinned by `test_connect_filter_metacharacters` (Task 3) using a user `a*b@example.invalid` whose `*` must not match `ab@example.invalid`.
5. **Disabled domain.** Mailbox active but domain inactive must fail Connect. Pinned by `test_inactive_domain_disables_account` (Task 2) and `test_connect_inactive` (Task 3).

---

### Task 1: Open the directory LDB without Samba's SamDB

**Files:**
- Modify: `mapiproxy/servers/default/emsmdb/emsmdbp.c:44-56` (`samdb_init`)
- Test: `testsuite/modernization/oc_emsmdb_smoke.c`, `Makefile` (`$(OC_EMSMDB_TEST)/smb.conf` rule, around line 1847)

**Interfaces:**
- Produces: smb.conf parameter `mapiproxy:directory_url`; `samdb_init` returns a plain LDB handle with opaques `default_baseDN` = `DC=openchange` and `config_baseDN` = `CN=Configuration,DC=openchange` when it is set. Later tasks and M2b (`emsabp`) rely on these exact DNs.

- [ ] **Step 1: Write the failing test** `test_directory_ldb_opens` in `oc_emsmdb_smoke.c`: write a smb.conf with `mapiproxy:directory_url = tdb://<tmp>/directory.ldb`, create that LDB with `ldb_connect` + one `ldb_add` of `CN=alice@example.invalid,CN=Users,DC=openchange` (`objectClass: user`, `sAMAccountName: alice@example.invalid`), call the real `emsmdbp_init` (the test binary keeps `--wrap=emsmdbp_init` for the other tests; add a `__real_emsmdbp_init` path), and assert the returned context is non-NULL, `ldb_get_default_basedn(ctx->samdb_ctx)` linearizes to `DC=openchange`, and `ldb_search(..., "sAMAccountName=alice@example.invalid")` returns 1.
- [ ] **Step 2: Run** `make check-oc-emsmdb` → FAIL (`Connection to "sam.ldb" failed`).
- [ ] **Step 3: Implement** in `samdb_init`: read `lpcfg_parm_string(lp_ctx, NULL, "mapiproxy", "directory_url")`; if set, `ldb_init` + `ldb_connect(url, LDB_FLG_RDONLY)`, then `ldb_set_opaque` the two DNs (allocated on the LDB context); return NULL on any failure. Otherwise keep the current SamDB code path unchanged.
- [ ] **Step 4: Run** `make check-oc-emsmdb` → PASS; existing `test_connect_without_samdb` still passes (it uses `samdb_url`).
- [ ] **Step 5: Commit** `feat(emsmdb): open a plain directory LDB when mapiproxy:directory_url is set`.

### Task 2: `openchange-directory-sync` from PostfixAdmin

**Files:**
- Create: `python/openchange/directory.py`, `setup/openchange-directory-sync`, `python/openchange/tests/test_directory.py`
- Modify: `Makefile` install rules for the new script, `doc/MAPIHTTP.md` (new "Directory" section)

**Interfaces:**
- Produces: `nickname(email: str) -> str`; `legacy_dn(org: str, ou: str, email: str) -> str`; `fetch_mailboxes(conn) -> list[Mailbox]` where `Mailbox = namedtuple("Mailbox", "email name active")` (`active` already combines mailbox and domain); `write_directory(path: str, org: str, ou: str, mailboxes: list[Mailbox]) -> None` (atomic); CLI `openchange-directory-sync --mysql-defaults FILE --org NAME --ou NAME --output PATH`.
- SQL (exact): `SELECT m.username, m.name, (m.active = 1 AND d.active = 1) FROM mailbox m JOIN domain d ON d.domain = m.domain`.

- [ ] **Step 1: Write failing tests** in `test_directory.py` (unittest, no MariaDB; uses a temp dir and `ldb`):
  - `test_nickname_vector`: `nickname("teste@lab.fitasonline.com.br")` equals the literal computed by the implementation once and pasted here (also record it for Task 4); `nickname("A.B+x@Example.invalid")` starts with `a.b_x-`.
  - `test_legacy_dn`: `legacy_dn("First Organization", "Exchange Administrative Group (FYDIBOHF23SPDLT)", "alice@example.invalid") == "/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=" + nickname("alice@example.invalid")`.
  - `test_written_entries`: after `write_directory` with alice (active) and bob (inactive): the user entry has `sAMAccountName`, `mail`, `displayName`, `mailNickname`, `legacyExchangeDN`, `proxyAddresses: SMTP:<email>`, `objectClass: user`, `msExchRecipientTypeDetails: 6`, `msExchRecipientDisplayType: 0`; alice `msExchUserAccountControl` 0, bob 2; the organization and admin-group entries of Decision 2 exist with their objectClasses.
  - `test_display_name_fallback`: name `"  "` → displayName equals the email.
  - `test_search_is_case_insensitive`: search `legacyExchangeDN=<alice DN upper-cased>` returns alice.
  - `test_inactive_domain_disables_account`: `fetch_mailboxes` with a fake cursor returning `("x@d.invalid", "", 0)` yields `active=False`.
  - `test_failed_write_keeps_previous_file`: write once, then call `write_directory` with a mailbox whose email makes `ldb.Message` raise (patch `ldb.Ldb.add` to raise); the original file still opens and still contains alice; no temp file left behind.
- [ ] **Step 2: Run** `python3 -m unittest python.openchange.tests.test_directory -v` (with the repo's usual `PYTHONPATH`) → FAIL (module missing).
- [ ] **Step 3: Implement** `directory.py`: `@ATTRIBUTES` record with `CASE_INSENSITIVE` for `legacyExchangeDN`, `sAMAccountName`, `mail`, `mailNickname`, `cn`; `@INDEXLIST` on `legacyExchangeDN`, `sAMAccountName`, `objectClass`; write to `tempfile.mkstemp(dir=dirname(path))`, `os.fchmod` 0640, chown group `openchange` when it exists, `os.replace` on success, unlink on failure. The CLI connects with `MySQLdb.connect(read_default_file=..., read_default_group="client")` and exits 1 with a one-line message (no credentials) on any error.
- [ ] **Step 4: Run** the unittest command → PASS; `python3 setup/openchange-directory-sync --help` exits 0.
- [ ] **Step 5: Commit** `feat(directory): generate the MAPI directory LDB from PostfixAdmin`.

### Task 3: Successful MAPI/HTTP Connect

**Files:**
- Modify: `mapiproxy/servers/default/emsmdb/oc_emsmdb.c:63-81`, `mapiproxy/servers/default/emsmdb/dcesrv_exchange_emsmdb.c:53-110` (extract the shared part), `mapiproxy/servers/default/emsmdb/dcesrv_exchange_emsmdb.h`
- Create: `mapiproxy/servers/default/emsmdb/emsmdbp_identity.c` (linked into both the RPC module and `liboc_emsmdb`; add to both object lists in `Makefile`)
- Test: `testsuite/modernization/oc_emsmdb_smoke.c`

**Interfaces:**
- Consumes: Task 1 directory handle; Task 2 entry layout (an LDIF fixture in the C test mirrors it — the C test must not depend on Python).
- Produces:
  - `bool emsmdbp_lookup_account(struct emsmdbp_context *ctx, const char *username, const char *user_dn, struct ldb_message **msg)` — Decision 6 checks, no `dcesrv_call_state`.
  - `enum MAPISTATUS emsmdbp_connect_identity(struct emsmdbp_context *ctx, struct ldb_message *msg, const char *user_dn, uint32_t language, TALLOC_CTX *mem_ctx, const char **display_name, const char **dn_prefix)` — the code now in `emsmdb_connect_context` from `nickname = ...` through the reply-string copies (sets `szUserDN`, `szDisplayName`, `szDNPrefix`, `userLanguage`, `username`).
  - `oc_emsmdb_connect` returns `MAPI_E_SUCCESS` with a session whose `ctx` has a random session UUID (`GUID_random()` + `emsmdbp_set_session_uuid`); `display_name`/`dn_prefix` are owned by the session.

- [ ] **Step 1: Write failing tests** (fixture LDIF with alice active, bob active, carol inactive, `a*b` and `ab` users; all LegacyDNs per Decision 4; real `emsmdbp_init`):
  - `test_connect_success`: alice with her DN → `MAPI_E_SUCCESS`, `display_name` = alice's displayName, `dn_prefix` = upper-cased DN up to and including `/CN=`, session non-NULL; `oc_emsmdb_disconnect` frees it.
  - `test_connect_dn_case_insensitive`: alice with her DN upper-cased → success.
  - `test_connect_other_users_dn`: alice with bob's DN → `MAPI_E_LOGON_FAILED`, session NULL.
  - `test_connect_inactive`: carol → `MAPI_E_LOGON_FAILED`.
  - `test_connect_unknown_user`: `nobody@example.invalid` → `MAPI_E_LOGON_FAILED`.
  - `test_connect_filter_metacharacters`: `a*b@example.invalid` with `ab@example.invalid`'s DN → `MAPI_E_LOGON_FAILED`; with its own DN → success.
  - Replace `test_connect_fails_closed` (no longer the contract) by these; keep `test_connect_without_samdb` (missing directory → `MAPI_E_LOGON_FAILED`).
- [ ] **Step 2: Run** `make check-oc-emsmdb` → the new tests FAIL (`MAPI_E_LOGON_FAILED` on success cases).
- [ ] **Step 3: Implement** `emsmdbp_lookup_account` (encode both values with `ldb_binary_encode_string`; search `(sAMAccountName=%s)`; require `count == 1`, control 0, `strcasecmp` on DN); move the shared tail into `emsmdbp_connect_identity` and call it from both `emsmdb_connect_context` (after its existing SID-based verification, unchanged) and `oc_emsmdb_connect`.
- [ ] **Step 4: Run** `make check-oc-emsmdb check-emsmdb check-mapihttp` → PASS (the Rust c-backend integration test must now expect success for its fixture user, or keep using a missing directory; update its fixture accordingly).
- [ ] **Step 5: Commit** `feat(emsmdb): accept MAPI/HTTP Connect for directory mailboxes`.

### Task 4: Autodiscover LegacyDN matches the directory

**Files:**
- Modify: `mapihttpd/src/autodiscover.rs` (LegacyDN construction), `testsuite/modernization/mapihttp/autodiscover-response.xml`

**Interfaces:**
- Consumes: Decision 3 formula and Task 2's test vector literal.
- Produces: `fn nickname(email: &str) -> String` in `autodiscover.rs` (uses the existing `sha2` dependency).

- [ ] **Step 1: Write failing tests** `test_nickname_vector` (same literal as Task 2) and update the Autodiscover response test so `<LegacyDN>` ends in `/cn=Recipients/cn=<nickname(alice@example.invalid)>`.
- [ ] **Step 2: Run** `cargo test --offline --locked` → FAIL.
- [ ] **Step 3: Implement** `nickname` and use it for `<LegacyDN>`.
- [ ] **Step 4: Run** `cargo test --offline --locked`, `cargo clippy --offline --locked --all-targets -- -D warnings`, `cargo fmt --check` → PASS.
- [ ] **Step 5: Commit** `fix(mapihttpd): derive the Autodiscover LegacyDN like the directory`.

### Task 5: Lab run with the C backend

**Files:**
- Modify: `doc/MAPIHTTP.md` (directory sync unit/timer example, `mapiproxy:directory_url`), `doc/MODERNIZATION.md` (new "M2a lab result" section), `doc/CONTINUITY.md`

- [ ] **Step 1:** On the lab VM: install the native build dependencies, `./configure --enable-mapihttp --with-samba=/usr`, `make -j2 all`, `make check-oc-emsmdb check-mapihttp` → PASS; install binary and libraries.
- [ ] **Step 2:** Create a read-only MariaDB user for the sync (`SELECT` on the two tables), option file `/etc/openchange/directory-my.cnf` (0600 root), smb.conf with `mapiproxy:directory_url` and an LDB openchangedb under `/var/lib/openchange`, `openchange-directory-sync.service` + `.timer` (60 s); run once and check entries with `ldbsearch` (no secrets printed).
- [ ] **Step 3:** Switch `openchange-mapihttpd` to the c-backend binary with `--smb-conf`; run the notebook smoke (`curl`): Autodiscover LegacyDN equals the directory entry; Connect returns `X-ResponseCode: 0` with StatusCode 0 and a `MapiContext` cookie.
- [ ] **Step 4:** Outlook M365 new profile: record Connect success, the first Execute, its RopLogon result (expected failure in `emsmdbp_mailbox_provision`, M2c) and the count of 401 responses before each Execute (Task 0 finding 1).
- [ ] **Step 5: Commit** `docs: record the M2a lab run` and push.
