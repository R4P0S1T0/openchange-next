# M6 slice 1 — Contacts in SOGo over CardDAV Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every SOGo address book of the user (contacts, distribution lists, photos) is an Outlook contacts folder, read and write, synced both ways in cached mode, merged field by field with no privileged client and nothing lost.

**Architecture:** A new dlopen()ed mapistore backend `mapistore_dav.so` (namespace `dav://`) in the style of the IMAP backend: a libcurl+expat CardDAV client, a vCard/VLIST line model that preserves unknown lines, a vCard↔MAPI mapping, and a field-fingerprint merge (keyed hashes in MariaDB). The user's Basic password crosses the Rust→C boundary at connect and lives only in process memory. A generic mapistore "poll changes" op, driven every 60 s per session from Rust, turns changes made by other clients into the existing EMSMDB notifications.

**Tech Stack:** C (talloc), libcurl, expat, GnuTLS HMAC (already linked through Samba), MariaDB client (as `indexing_mysql`), Rust 1.85 (mapihttpd), Python 3 (fake CardDAV server for tests).

**Spec:** `docs/superpowers/specs/2026-11-17-m6-contacts-carddav-design.md` (approved 2026-11-17). Read it first; this plan does not repeat its reasoning.

## Global Constraints

- SOGo is the hub; every client is equal. No rule may favour Outlook because it is Outlook.
- Nothing any client wrote is dropped: unmapped vCard/VLIST lines are kept verbatim; a losing value goes to NOTE as `[AAAA-MM-DD conflito] <field>: <value>` (date = merge day, local server date, `YYYY-MM-DD`).
- No contact content stored outside SOGo; only keyed fingerprints (HMAC-SHA-256 truncated to 64 bits) + ETag, table `utf8mb4_bin`.
- Password: never on disk, in logs, in openchangedb/MySQL; zeroed (`explicit_bzero`) when the user's last session ends.
- Standard CardDAV only (RFC 6352, RFC 6578); no SOGo configuration change; no `SOGoTrustProxyAuthentication`. VLIST is handled because it is what SOGo serves, through the same preserve-unknown model.
- `./configure --enable-mapistore-dav`; default build must not need libcurl/expat; enabled without them → `AC_MSG_ERROR`.
- Config (smb.conf, `mapistore` section): `dav_url` (template, `%u` = MAPI username, address-book home, e.g. `https://lab.fitasonline.com.br/SOGo/dav/%u/Contacts/`), `dav_fingerprint_key_file` (32+ random bytes, mode 0600). `dav_url` unset → backend inert.
- Timeouts: connect 5 s, request 15 s. Poll every 60 s per session. 412 merge retries: 3.
- Tests: no network, no real server; `make check-dav-backend` also passes with `CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'`; `make all`, the 17 `check-*` targets in `doc/CONTINUITY.md`, `check-imap-backend`, `cargo test` (with and without `c-backend`), `cargo fmt --check`, Clippy `-D warnings` stay green.
- Never touch production (192.168.0.227). Lab = 192.168.1.215, snapshot/backup before deploys (as in M5: `/root/*.so.<tag>` copies).
- Preserve `.build/worktrees/*`, `.superpowers/sdd/`, `.build/sql-lab-*`, untracked `docs/plans/2026-10-29-openchange-incremental-namedprops.md`. Do not run `git clean -X`.
- Work on branch `m6-contacts` (worktree `.build/worktrees/m6`); small commits `feat(mapistore-dav): …` / `feat(mapihttpd): …`; push and merge to `main` only after asking the maintainer.

## Review Focus

1. **UTF-8, folding and escaping in real vCards** (accents in Portuguese names, `\,` `\;` `\n`, 75-octet folding mid-multibyte) — a round trip must be byte-identical for untouched lines. Test in Task 2.
2. **SOGo down or 401 at logon** — logon and mail must keep working and Contacts folders must not be deleted from Outlook. Tests in Tasks 6 and 9.
3. **Two sessions of the same user** (Outlook + a second Outlook/profile) — one disconnecting must not wipe the password the other still uses. Test in Task 5.
4. **A huge PHOTO (multi-MB) uploaded from Outlook** — capped, not sent as-is, not crashing. Cap = 1 MiB decoded; above it the photo is not written and the rest of the contact is. Test in Task 3.
5. **Invalid sync-token after SOGo restart/cleanup** — full listing fallback, no duplicate MIDs, deletions detected. Test in Task 4/6.

---

## File structure

`mapiproxy/libmapistore/backends/dav/`:

| File | Responsibility |
| --- | --- |
| `dav_backend.h` | shared structs (`DAV_OBJ_*` type tags), declarations |
| `mapistore_dav.c` | `mapistore_init_backend`, settings, op table |
| `dav_vcard.c` | vCard/VLIST line model: parse, serialize, get/set, preserve unknown |
| `dav_map.c` | `enum dav_field` table, vCard ↔ field values ↔ MAPI properties, photos, lists |
| `dav_merge.c` | fingerprints (HMAC) and the 3-way field merge + NOTE lines |
| `dav_fpstore.c` | fingerprint store: MySQL and in-memory |
| `dav_http.c` | libcurl+expat CardDAV client |
| `dav_cred.c` | per-user in-memory credentials, refcounted, zeroed |
| `dav_folder.c` | contexts, folders, tables, ICS (`get_deleted_fmids`), hierarchy writes, poll |
| `dav_message.c` | open/get properties/save/delete of contacts and lists |

Shared: `mapiproxy/libmapistore/mapistore_changes.c` (change numbers, moved from `imap_folder.c:1008`).
Tests: `testsuite/modernization/dav_backend_smoke.c`, `testsuite/modernization/carddav_fake.py`, `testsuite/modernization/fixtures/dav/` (anonymized SOGo responses).

---

### Task 0: Toolchain, build wiring, inert backend

**Files:**
- Modify: `configure.ac` (next to the IMAP block at :800), `Makefile` (next to :774-818), `config.mk.in` if variables are needed
- Create: `mapiproxy/libmapistore/backends/dav/{dav_backend.h,mapistore_dav.c}`, `testsuite/modernization/dav_backend_smoke.c`

**Interfaces:**
- Produces: `enum mapistore_error mapistore_init_backend(void)` registering `name "dav"`, `namespace "dav://"`; `const struct dav_settings *dav_backend_settings(void)` (NULL when `dav_url` unset) with fields `char *url_template; uint8_t *fp_key; size_t fp_key_len;`; make targets `mapistore_dav`, `check-dav-backend`, binary `bin/dav-backend-test`.

- [ ] **Step 1:** Rebuild `/tmp/openchange-build-tools` (method in `doc/MODERNIZATION.md`, toolchain section), adding `libcurl4-openssl-dev` and `libexpat1-dev` via `apt-get download` + `dpkg -x`. Check: `python3 /tmp/openchange-build-tools/run.py pkg-config --modversion libcurl expat` prints two versions.
- [ ] **Step 2: Failing test** `test_inert_when_unconfigured` in `dav_backend_smoke.c`: with no `dav_url`, `backend.list_contexts("u", ictx, mem, &l)` returns `MAPISTORE_SUCCESS` and `l == NULL`; `create_context` returns `MAPISTORE_ERR_NOT_AVAILABLE`.
- [ ] **Step 3:** Run `python3 /tmp/openchange-build-tools/run.py make check-dav-backend` → FAIL (target missing).
- [ ] **Step 4:** Add `--enable-mapistore-dav` (default off; `PKG_CHECK_MODULES` libcurl + expat, `AC_MSG_ERROR` when enabled and missing), Makefile objects/`.so`/install/clean/test targets copied from the IMAP pattern, minimal backend.
- [ ] **Step 5:** `make check-dav-backend` PASS; default `./configure && make -j2 all` still passes without curl in `CFLAGS`.
- [ ] **Step 6:** Commit `build(mapistore-dav): optional dav backend skeleton, inert when unconfigured`.

### Task 1: Shared change numbers

**Files:**
- Create: `mapiproxy/libmapistore/mapistore_changes.c` (+ declarations in `mapistore.h`)
- Modify: `mapiproxy/libmapistore/backends/imap/imap_folder.c:~980-1210` (use the shared code), `Makefile` (libmapistore objects)

**Interfaces:**
- Produces: `enum mapistore_error mapistore_change_number(const char *username, const char *uri, const char *state, mapistore_cn_source source, void *source_ctx, uint64_t *cn, time_t *when)`; `mapistore_change_record_client(username, uri, const struct Binary_r *ck, const struct Binary_r *pcl)` and lookup `mapistore_change_client_keys(username, uri, cn, const struct Binary_r **ck, const struct Binary_r **pcl)`; `typedef enum mapistore_error (*mapistore_cn_source)(void *source_ctx, uint64_t *cn)`. Semantics identical to today's `imap_change_number` and client change-key handling.

- [ ] **Step 1: Failing test** in `testsuite/modernization/emsmdb_backend_smoke.c` or a new `check-mapistore-changes`: same `(user, uri, state)` → same cn; new state → new cn; recorded client ck returned until the state changes, then cleared.
- [ ] **Step 2:** Run → FAIL (symbol missing).
- [ ] **Step 3:** Move the code; `imap_change_number` becomes a thin call (keeps `imap_backend_set_cn_source` for tests).
- [ ] **Step 4:** New test PASS and `make check-imap-backend` PASS unchanged.
- [ ] **Step 5:** Commit `refactor(mapistore): share change numbers between backends`.

### Task 2: vCard/VLIST line model

**Files:** Create `dav_vcard.c`; Test `dav_backend_smoke.c`; fixtures `testsuite/modernization/fixtures/dav/*.vcf`, `*.vlf`

**Interfaces:**
- Produces:
  - `struct dav_card *dav_card_parse(TALLOC_CTX *, const char *text, size_t len)` (NULL on non-vCard/VLIST); `char *dav_card_render(TALLOC_CTX *, const struct dav_card *)` (CRLF, folding at 75 octets on UTF-8 boundaries).
  - `struct dav_line { char *group; char *name; char **params; size_t nparams; char *value; bool touched; char *raw; }` — `raw` = original unfolded text, rendered verbatim unless `touched`.
  - `const char *dav_card_kind(const struct dav_card *)` → `"VCARD"` / `"VLIST"`.
  - `struct dav_line *dav_card_find(const struct dav_card *, const char *name, const char *type_param /* NULL = any */, unsigned index)`; `void dav_card_set(struct dav_card *, const char *name, const char *type_param, unsigned index, const char *value /* NULL = remove */)`; `char *dav_text_unescape(TALLOC_CTX *, const char *)` / `dav_text_escape`.

- [ ] **Step 1:** Capture fixtures from the lab: create in SOGo webmail (account `teste`) one contact with accents, 3 e-mails, 4 phones, 2 addresses, birthday, note with newlines, photo, and one list with 2 contact members + 1 free address; fetch with `curl -u … GET`; anonymize names/addresses; save as `contact_full.vcf`, `list.vlf`. Record the VLIST member line format found (`CARD;UID=…;EMAIL=…;FN=…:` or other) in a comment at the top of `dav_vcard.c`.
- [ ] **Step 2: Failing tests:** `test_vcard_roundtrip_untouched` (parse+render of each fixture is byte-identical modulo line endings normalized to CRLF); `test_vcard_folding_utf8` (a 200-char `NOTE` with `ç`/`ã` is folded without splitting a multibyte sequence; unfold restores it); `test_vcard_escape` (`a\,b\;c\nd` ↔ `a,b;c` + newline + `d`); `test_vcard_set_keeps_unknown` (set `TEL;TYPE=cell` on a card with `X-PHONE-CUSTOM` and `X-ABUID` → both still rendered verbatim); `test_vlist_parse` (members readable, unknown lines kept).
- [ ] **Step 3:** Run → FAIL. **Step 4:** Implement. **Step 5:** PASS (plain and ASan). **Step 6:** Commit `feat(mapistore-dav): vCard and VLIST line model preserving unknown lines`.

### Task 3: Mapping vCard ↔ fields ↔ MAPI

**Files:** Create `dav_map.c`; Test `dav_backend_smoke.c`

**Interfaces:**
- Consumes: Task 2.
- Produces:
  - `enum dav_field` — one value per row of the spec's mapping table: `DAV_F_FN, DAV_F_N_FAMILY, DAV_F_N_GIVEN, DAV_F_N_MIDDLE, DAV_F_N_PREFIX, DAV_F_N_SUFFIX, DAV_F_EMAIL1..3, DAV_F_TEL_WORK, DAV_F_TEL_HOME, DAV_F_TEL_CELL, DAV_F_TEL_FAX, DAV_F_ORG, DAV_F_ORG_UNIT, DAV_F_TITLE, DAV_F_ADR_WORK, DAV_F_ADR_HOME, DAV_F_NOTE, DAV_F_BDAY, DAV_F_URL, DAV_F_PHOTO, DAV_F_LIST_NAME, DAV_F_LIST_MEMBERS, DAV_F_COUNT`.
  - `char *dav_field_get(TALLOC_CTX *, const struct dav_card *, enum dav_field)` (normalized value: unescaped, trimmed; ADR = the 7 components joined by `\n`; PHOTO = decoded bytes as base64 of the bytes, URI photos → NULL; LIST_MEMBERS = sorted member keys joined by `\n`, key = member UID or `mailto:<lowercase email>`); `void dav_field_set(struct dav_card *, enum dav_field, const char *value)`.
  - `enum mapistore_error dav_field_to_props(TALLOC_CTX *, const struct dav_card *, const struct dav_named_tags *, struct mapistore_property_data *out, enum MAPITAGS tag)` and `dav_props_to_fields(TALLOC_CTX *, struct SRow *props, const struct dav_named_tags *, char *values[DAV_F_COUNT], bool present[DAV_F_COUNT])`.
  - `struct dav_named_tags` — mapped IDs for every PidLid used, resolved once per context with `mapistore_namedprops_get_mapped_id` (`mapistore.h:426`).
  - `#define DAV_PHOTO_MAX (1024 * 1024)` decoded bytes.
- Message class: VCARD → `IPM.Contact`, VLIST → `IPM.DistList`. PidLidFileUnder = `"<family>, <given>"`, or FN when N is empty.

- [ ] **Step 1: Failing tests:** `test_map_contact_full` (fixture → each MAPI tag of the spec table has the expected value, including PidLidEmail1EmailAddress/DisplayName/AddressType `SMTP`, PidTagBirthday as FILETIME midnight UTC, photo attachment bytes = PHOTO decoded); `test_map_props_to_fields_roundtrip` (fields → card → fields identical); `test_map_list_members` (a member UID present in the book → wrapped entry ID of that contact's MID; free address → one-off entry; reverse direction produces the same VLIST member lines); `test_photo_cap` (2 MiB photo from Outlook → `DAV_F_PHOTO` not present, other fields present, Review Focus 4).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS. **Step 5:** Commit `feat(mapistore-dav): map vCard and lists to MAPI contacts and distribution lists`.

### Task 4: CardDAV client and fake server

**Files:** Create `dav_http.c`, `testsuite/modernization/carddav_fake.py`; fixtures `fixtures/dav/*.xml` (anonymized PROPFIND/REPORT responses captured from the lab in Step 1)

**Interfaces:**
- Produces:
  - `struct dav_http *dav_http_new(TALLOC_CTX *, const char *base_url, const char *user, const char *password /* borrowed, not copied */)`.
  - `enum mapistore_error dav_list_books(struct dav_http *, TALLOC_CTX *, struct dav_book **books, size_t *n)` with `struct dav_book { char *href; char *segment; char *displayname; char *sync_token; }`.
  - `enum mapistore_error dav_sync(struct dav_http *, TALLOC_CTX *, const char *book_href, const char *token /* NULL = full */, struct dav_change **changes, size_t *n, char **new_token, bool *was_full)` with `struct dav_change { char *href; char *etag /* NULL = removed */; }`; an invalid token (403/409 with `valid-sync-token`) → retries full and sets `*was_full`.
  - `dav_multiget(struct dav_http *, TALLOC_CTX *, const char *book_href, char **hrefs, size_t n, char ***bodies, char ***etags)`, `dav_get(…, const char *href, char **body, char **etag)`.
  - `dav_put(struct dav_http *, const char *href, const char *body, const char *content_type, const char *if_match /* NULL */, bool if_none_match, char **new_etag)`; `dav_delete(…, href, if_match)`; `dav_mkcol_book(…, const char *href, const char *displayname)`; `dav_rename_book(…, href, displayname)`; `dav_delete_book(…, href)`.
  - Status mapping: 2xx OK; 401/403 → `MAPISTORE_ERR_DENIED`; 404 → `MAPISTORE_ERR_NOT_FOUND`; 412 → `MAPISTORE_ERR_CONFLICT` (new, Task 7 adds it to `mapistore_errors.h` — add it here instead if this task lands first); connect/timeout/5xx → `MAPISTORE_ERR_CONN_REFUSED`. Password never in logs (no `CURLOPT_VERBOSE`).
- `carddav_fake.py`: `python3 carddav_fake.py <port-file> <state-dir>` serves Basic auth (`u`/`p`), PROPFIND Depth 1, REPORT sync-collection (tokens = integer counter, `--invalidate-token` endpoint), addressbook-multiget, GET/PUT/DELETE with ETags and `If-Match`/`If-None-Match`, MKCOL/PROPPATCH, plus `POST /_ctl/{edit,delete,fail,slow}` for tests to act as "another client" or a broken server. Responses shaped like the captured SOGo fixtures.

- [ ] **Step 1:** Capture lab responses for PROPFIND `…/Contacts/`, REPORT sync-collection (token -1 and a real one), multiget; anonymize into fixtures.
- [ ] **Step 2: Failing tests:** `test_http_list_books`, `test_http_sync_incremental` (edit via `_ctl` → one change with new etag; delete → etag NULL), `test_http_sync_invalid_token_full` (Review Focus 5), `test_http_put_if_match_412`, `test_http_put_if_none_match_exists`, `test_http_401_denied`, `test_http_timeout_conn_refused` (`_ctl/slow` 20 s → `CONN_REFUSED` within ~15 s).
- [ ] **Step 3:** FAIL. **Step 4:** Implement (expat streaming parser of multistatus; namespaces `DAV:` and `urn:ietf:params:xml:ns:carddav`). **Step 5:** PASS plain and ASan. **Step 6:** Commit `feat(mapistore-dav): CardDAV client`.

### Task 5: Credentials across the boundary

**Files:**
- Modify: `mapiproxy/servers/default/emsmdb/oc_emsmdb.{h,c}`, `mapihttpd/src/{ffi.rs,backend.rs,emsmdb.rs,request.rs}`, `mapiproxy/libmapistore/{mapistore.h,mapistore_backend.c,mapistore_backend_defaults.c,mapistore_interface.c}`
- Create: `dav_cred.c`

**Interfaces:**
- Produces:
  - C boundary: `oc_emsmdb_connect(const char *username, const char *password, const char *user_dn, …)` — password added after username; mirrored in `ffi.rs` in the same commit (header comment rule).
  - mapistore: new optional backend ops `backend.set_credentials(const char *username, const char *password)` and `backend.forget_credentials(const char *username)` (defaults: `MAPISTORE_SUCCESS`, no-op); `mapistore_set_credentials(struct mapistore_context *, const char *username, const char *password)` and `mapistore_forget_credentials(…, username)` call every backend.
  - dav: `dav_cred_get(const char *username)` → borrowed password or NULL; refcount per username (set +1, forget −1, at 0 `explicit_bzero` + free).
  - Rust: `ConnectParams { …, password: Password }`; `Debug` for `ConnectParams` must print `password: "<redacted>"`; `oc_emsmdb_disconnect` calls `mapistore_forget_credentials`.

- [ ] **Step 1: Failing tests:** C `test_cred_refcount` (set twice, forget once → still readable; forget again → NULL, and the buffer is zeroed — observed through a test-only hook `void dav_cred_set_free_hook(void (*hook)(const char *buf, size_t len))` called right before free, asserting every byte is 0); Rust `test_connect_passes_password` (FakeBackend records `ConnectParams`, password equals the Basic one) and `test_connect_params_debug_redacts`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. Order check: `oc_emsmdb_connect` calls `mapistore_set_credentials` before anything that can reach `emsmdbp_mailbox_provision` (RopLogon, `oxcstor.c:85`). **Step 4:** PASS: `check-oc-emsmdb`, `check-mapihttp`, `cargo test` both feature sets, Clippy. **Step 5:** Commit `feat(mapihttpd): pass the verified Basic password to mapistore in memory only`.

### Task 6: Read path — books as folders, contacts, ICS

**Files:** Create `dav_folder.c`, `dav_message.c`, `dav_fpstore.c` (read side of fingerprints is written here; merge in Task 7); Modify `mapistore_dav.c`

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces:
  - `list_contexts`: needs `dav_cred_get(username)`; no credentials or SOGo unreachable/401 → `MAPISTORE_ERR_CONN_REFUSED` (provisioning keeps folders, `emsmdbp_provisioning.c:337`); else `personal` → `dav://contacts/personal/`, `MAPISTORE_CONTACTS_ROLE`, `main_folder=true`; other books → secondary `IPF.Contact` entries `dav://contacts/<segment>/` with their displayname.
  - Per-context state (session memory): sync token, `href → (mid, etag)`; MIDs from indexing on `dav://contacts/<book>/<href segment>`; change numbers via `mapistore_change_number(username, uri, etag, …)`.
  - `get_deleted_fmids`: from `dav_sync` removals, and after a full listing from indexed URIs under the book that are no longer listed.
  - Fingerprint store: `struct dav_fpstore *dav_fpstore_open(TALLOC_CTX *, const char *indexing_url /* mysql://… or NULL */)` (NULL/tdb → in-memory; `shortcut: tdb indexing keeps fingerprints in memory only, which degrades to the "no fingerprint" rule after restart; add a tdb store if anyone runs tdb in production`); `dav_fp_get(store, user, href, uint64_t fp[DAV_F_COUNT], char **etag)`, `dav_fp_put(...)`, `dav_fp_delete(store, user, href)`, `dav_fp_prune(store, user, book_href, char **live_hrefs, size_t n)`. MySQL table `dav_fingerprints(user VARCHAR(320), href VARCHAR(1024), etag VARCHAR(255), fp BLOB, PRIMARY KEY(user, href(255)))` `CHARSET utf8mb4 COLLATE utf8mb4_bin`, created if missing.
  - Fingerprints written after each item is read into Outlook (`dav_fp_put` with the current etag).

- [ ] **Step 1: Failing tests** (against `carddav_fake.py`, through the mapistore API like `imap_backend_smoke.c` does): `test_list_contexts_books` (personal main + 2 secondary), `test_list_contexts_sogo_down_keeps` (`CONN_REFUSED`, Review Focus 2), `test_contents_table_contacts_and_lists` (rows with `PidTagMessageClass` `IPM.Contact`/`IPM.DistList`, display names with accents), `test_open_contact_props_and_photo`, `test_ics_incremental` (edit via `_ctl` → new change number for that MID only; delete → in `get_deleted_fmids`), `test_ics_token_invalid_no_dup_mids` (Review Focus 5), `test_fp_written_on_read`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS plain + ASan; `check-imap-backend` still PASS. **Step 5:** Commit `feat(mapistore-dav): address books as Outlook contacts folders, read and incremental sync`.

### Task 7: Write path — merge, delete, folders

**Files:** Create `dav_merge.c`; Modify `dav_message.c`, `dav_folder.c`, `dav_fpstore.c`, `mapistore_errors.h` (+ `MAPISTORE_ERR_CONFLICT`), `mapistore_interface.c:460` (string) and `:1901` (→ MAPI `ecObjectModified` 0x80040109)

**Interfaces:**
- Produces:
  - `uint64_t dav_fp(const uint8_t *key, size_t key_len, enum dav_field, const char *value /* NULL = absent */)` (HMAC-SHA-256 over `field_id || 0x00 || value`, first 8 bytes big-endian; absent = HMAC of `field_id || 0x01`).
  - `enum mapistore_error dav_merge(TALLOC_CTX *, struct dav_card *server /* modified in place */, const char *outlook[DAV_F_COUNT], const bool outlook_present[DAV_F_COUNT], const uint64_t base[DAV_F_COUNT] /* NULL = no fingerprint */, time_t outlook_time, time_t server_time, const uint8_t *key, size_t key_len, const char *today /* YYYY-MM-DD */)`.
- Merge rule (spec "Conflicts"): per field, `o = fp(outlook) != base`, `s = fp(server) != base`; only `o` → take Outlook; only `s` or neither → keep server; both and values differ → newer of `outlook_time` / `server_time` wins (tie → server, it is already stored), loser appended to NOTE as `[YYYY-MM-DD conflito] <label>: <value>` (labels in Portuguese: `nome`, `e-mail 1`, `celular`, …; PHOTO loser → label only, `foto substituída`, no bytes in NOTE); no base → every differing field is "both". `LIST_MEMBERS` merges as sets: `(server ∪ added_by_outlook) − removed_by_outlook`, where added/removed need the base — without a base members are unioned (nothing removed). `server_time` = `REV` if present, else the time the poll first saw that etag (kept in context state).
- Save (`message.save`): new → render vCard 3.0 / VLIST with fresh UUID `UID`, `PUT <book>/<UID>.vcf` `If-None-Match: *`; existing → `dav_get`, `dav_merge`, `PUT If-Match`; 412 → redo, max 3, then `MAPISTORE_ERR_CONFLICT`; 404 → recreate at a new href with the same UID; then `dav_fp_put` of the merged result. Client change keys recorded with `mapistore_change_record_client`.
- Delete: `DELETE If-Match`; 412 → do not delete, return success to Outlook and mark the MID changed so the next sync brings the item back; `dav_fp_delete` only on real deletion.
- Folders: create under the personal folder → `dav_mkcol_book(<home>/<uuid>/, displayname)`; rename → `dav_rename_book`; delete → `dav_delete_book`; deleting `personal` → `MAPISTORE_ERR_DENIED`.

- [ ] **Step 1: Failing tests:** merge table — `test_merge_only_outlook`, `test_merge_only_server`, `test_merge_both_outlook_newer_note`, `test_merge_both_server_newer_note`, `test_merge_no_base_note`, `test_merge_members_sets`, `test_merge_keeps_unknown_lines`, `test_fp_keyed` (same value, different key → different fp); end-to-end vs fake — `test_save_new_contact_put`, `test_save_concurrent_edit_merged` (`_ctl/edit` phone between Outlook read and save → both changes in the stored vCard), `test_save_412_three_times_conflict`, `test_save_after_remote_delete_recreates`, `test_delete_after_remote_edit_survives`, `test_folder_create_rename_delete`, `test_delete_personal_denied`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS plain + ASan. **Step 5:** Commit `feat(mapistore-dav): write contacts and lists with field merge, no client privileged`.

### Task 8: Changes from other clients reach an open Outlook

**Files:** Modify `mapistore.h`, `mapistore_backend*.c`, `mapistore_interface.c`, `oc_emsmdb.{h,c}`, `emsmdbp_notify.c`, `mapihttpd/src/{ffi.rs,backend.rs,session.rs or a new davpoll.rs}`; `dav_folder.c`

**Interfaces:**
- Produces:
  - Backend op `backend.poll_changes(const char *username, TALLOC_CTX *, struct mapistore_change **list, size_t *n)` with `struct mapistore_change { char *uri; enum { MAPISTORE_CHANGE_CONTENTS, MAPISTORE_CHANGE_FOLDER_ADDED, MAPISTORE_CHANGE_FOLDER_DELETED, MAPISTORE_CHANGE_FOLDER_RENAMED } kind; }`; default: empty list; `mapistore_poll_changes(mstore_ctx, username, mem, &list, &n)` concatenates all backends.
  - dav: `dav_sync` per book + `dav_list_books` diff against the context state.
  - C boundary: `uint32_t oc_emsmdb_poll_changes(oc_emsmdb_session *, uint32_t *pending)`: for each change, `emsmdbp_get_fid_from_uri` then `emsmdbp_notify_folder_changed(ctx, fid, MODIFIED)`; added/deleted books → `emsmdbp_mailbox_provision` + `emsmdbp_notify_hierarchy_changed(ctx, <personal contacts fid>)` (same shape as `emsmdbp_notify_mailbox_changed`, `emsmdbp_notify.c:391`).
  - Rust: `Backend::poll_changes(&self, id: SessionId) -> impl Future<Output = bool>`; one tokio interval task per session, 60 s, started at connect, aborted at disconnect/expiry; serialized with Execute exactly like `folder_changed`; a `true` result wakes the session's NotificationWait like the IMAP watcher does.

- [ ] **Step 1: Failing tests:** C `test_poll_reports_contents_and_books` (fake: edit item + create book → one CONTENTS + one FOLDER_ADDED); Rust `test_poll_interval_calls_backend` (tokio paused time, 2 × 60 s → 2 calls; disconnect → no more), `test_poll_pending_wakes_notification_wait`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS: `check-dav-backend`, `check-oc-emsmdb`, `check-mapihttp`, `cargo test` both, Clippy, `cargo fmt --check`. **Step 5:** Commit `feat(mapihttpd): poll CardDAV changes every 60 s and notify Outlook`.

### Task 9: Lab deployment, acceptance, docs

**Files:** Modify `doc/MAPIHTTP.md` (config `dav_url`, `dav_fingerprint_key_file`, key generation `head -c 32 /dev/urandom > … && chmod 600`), `doc/MODERNIZATION.md` (M6 slice 1 status), `doc/CONTINUITY.md`, CI workflow (install `libcurl4-openssl-dev libexpat1-dev`, run `check-dav-backend` in the enabled job)

- [ ] **Step 1:** Full verification on the branch: `make all` + 17 `check-*` + `check-imap-backend` + `check-dav-backend` (plain and ASan) + Rust suite. All PASS.
- [ ] **Step 2:** Lab: backups of `liboc_emsmdb.so`, `libmapistore.so.*`, existing `mapistore_backends/` (`/root/*.m6-pre`); build with `.build/labcheck.sh`; install; set `dav_url` + key file; restart mapihttpd. Check with `journalctl` that no password appears (`grep -c <password>` = 0).
- [ ] **Step 3:** Acceptance in the TSplus Outlook (cached mode, profile `teste@`), recording results in `doc/MODERNIZATION.md`: spec tests 1, 1b, 2, 3, 4, 5, 6 (stop `sogo` → mail OK, Contacts errors cleanly, folders remain; start again → recovers), 7 (TOTP: enroll lab account `ana` in TOTP via webmail, `curl -u ana:<password> PROPFIND` → record 207 or 401; if 401, document the limitation, ask the maintainer).
- [ ] **Step 4:** Commit docs/CI `docs: M6 slice 1 contacts accepted on the lab`; ask the maintainer before push/merge to `main`.
