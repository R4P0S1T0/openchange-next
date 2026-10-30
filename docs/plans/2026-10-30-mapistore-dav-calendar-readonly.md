# MAPIStore "dav" Backend — Read-only CalDAV Calendar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** First mailbox content backend for mapistore, `dav`, exposing one CalDAV calendar collection as a read-only MAPI calendar folder (open folder, contents table, message properties).

**Architecture:** A dlopen-able `mapistore_dav.so` registers namespace `dav://`. A tiny CalDAV client (PROPFIND / REPORT calendar-query / GET) runs over a pluggable transport function (libcurl in production, fixtures in tests). Each VEVENT is normalized (UTC, DTEND from DURATION) and converted to MAPI properties by reusing libexchange2ical's `ical2exchange_property_*` functions; PidLid canonical tags are translated to the session's mapped named-property IDs. href → MID mapping goes through the existing `struct indexing_context`.

**Tech Stack:** C (talloc), libical (already probed), libcurl, expat (XML; already in the local toolchain), libexchange2ical objects, autoconf/Make, GitHub Actions.

**Spec:** the user's request of 2026-10-30 (milestone "calendar, read-only, CalDAV"), plus `doc/CONTINUITY.md`, `doc/TEST_SERVER_READINESS.md` ("Concrete storage blocker").

## Interface findings (step 1 of the request)

Source: `mapiproxy/libmapistore/mapistore.h:169-245`, `mapistore_backend.c`, `mapistore_backend_defaults.c:346`.

- Loading: `mapistore_backend_load()` dlopens every `.so` in `MAPISTORE_BACKEND_INSTALLDIR` (`$(libdir)/mapistore_backends`, `config.mk.in:51`) and calls `int mapistore_init_backend(void)` (`MAPISTORE_INIT_MODULE`, `mapistore.h:60`). That function fills a `struct mapistore_backend`, calls `mapistore_backend_init_defaults()` first (every op → `MAPISTORE_ERR_NOT_IMPLEMENTED`) and then `mapistore_backend_register()` (which `talloc_memdup`s the struct).
- `backend.init` is called for every registered backend (`mapistore_backend.c:~295`); failure only marks that backend failed.
- **`backend.list_contexts` is called for every backend and any non-success aborts the whole list** (`mapistore_backend.c:323-329`). The dav backend must return `MAPISTORE_SUCCESS` with an empty list when unconfigured.
- `backend.create_context` is selected by exact `namespace` string match (`:361`), then **`context.get_root_folder` is called unconditionally** (`:378`). Both are mandatory.
- Server (emsmdb) paths needed for this milestone and therefore implemented:
  - context: `get_root_folder`, `get_path`
  - folder: `open_message`, `get_child_count`, `open_table`
  - table: `get_available_properties`, `set_columns`, `get_row`, `get_row_count`, `handle_destructor`
  - properties: `get_available_properties`, `get_properties` (same `void *` receives folder or message objects, so objects carry a type tag)
  - message: `get_message_data` (subject + recipients on OpenMessage)
- Everything else stays at the defaults' `MAPISTORE_ERR_NOT_IMPLEMENTED`, including `open_folder` (no subfolders), `table.set_restrictions` / `set_sort_order`, `get_deleted_fmids`, all writes. Consequence recorded, not worked around: Outlook calendar views using restrictions will fail; Outlook is out of scope.
- Named properties: emsmdb passes already-mapped tags (`0x8000+`) to `get_properties` (`oxcprpt.c:1177`). The backend resolves them at context creation with `mapistore_namedprops_get_mapped_id(conn_info->mstore_ctx->nprops_ctx, ...)`.
- Indexing: `struct indexing_context` (`mapistore.h:149`) exposes `get_fmid`, `allocate_fmid`, `add_fmid`, `get_uri` as function pointers, so tests can supply an in-memory fake and production uses the configured tdb/mysql indexer.

No interface blocker was found.

## Design decisions (flag for approval)

1. **Configuration:** `init()` reads `mapistore:dav_calendar_url` from `loadparm_init_global(true)` (same as `pymapistore.c:75`); value is a URL template with `%u` replaced by the MAPI username. Unset → backend inert (empty `list_contexts`, `create_context` → `MAPISTORE_ERR_NOT_AVAILABLE`). No server URL is stored in openchangedb: the context URI is `dav://calendar/`.
2. **Authentication: none in this milestone.** 401 → `MAPISTORE_ERR_DENIED`. Real servers (SOGo) need per-user or trusted-proxy auth; that is a separate decision.
3. **Identity:** MIDs key on `dav://calendar/<last href segment>` via indexing. ETag is kept per item only as version metadata (exposed as nothing yet); it is **not** an identity key because it changes on every edit. sync-token is not used (no ICS sync in scope): `shortcut: full REPORT on each open_table, upgrade with sync-collection when ICS is in scope`.
4. **Fetching:** REPORT asks for `getetag` only; event bodies are fetched with GET lazily and cached on the folder object. `shortcut: N+1 requests per table load, upgrade to calendar-data in REPORT if latency matters`.
5. **XML:** expat (present in `/tmp/openchange-build-tools/root`, `libexpat1-dev` in CI), not libxml2, which is absent locally.
6. **libcurl dev headers are missing locally.** Prerequisite: `apt-get download libcurl4-openssl-dev` and `dpkg -x` into `/tmp/openchange-build-tools/root` (same method as the existing toolchain, `doc/MODERNIZATION.md:834`; no system package installation). Requires network access once.
7. **Reuse:** libexchange2ical's static `ical2exchange_init/get_properties/convert_event` get one public wrapper; `_IcalEvent2Exchange` calls it, so `exchange2ical` behavior is unchanged. Organizer/attendees are not handled there (`ical2exchange.c:215` TODO) and are mapped in dav code instead of changing the tool.

## Global Constraints

- Milestone scope: calendar, read-only, CalDAV. Writes, CardDAV, IMAP → `MAPISTORE_ERR_NOT_IMPLEMENTED`.
- Nothing SOGo-specific in code; SOGo 5.12 is only the eventual target.
- Optional: `--enable-mapistore-dav`; default `./configure && make all` must not need libcurl/expat. Enabled without deps → `AC_MSG_ERROR`.
- No credentials or real server URLs in code, tests or docs (use `https://dav.invalid/...`).
- Tests make no network calls and need no server.
- `make check-mapistore-dav` must also pass with `CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'`.
- Do not change behavior of passing components; finish with `make all` + the 17 `check-*` targets from `doc/CONTINUITY.md`.
- Preserve `.build/worktrees/task1-ldb-reverse`, `.superpowers/sdd/`, `.build/sql-lab-*`, `docs/plans/2026-10-29-openchange-incremental-namedprops.md`.
- Small thematic commits `feat(mapistore-dav): ...`; push only after all checks pass and after telling the user.

## Review Focus

1. **TZID times** (SOGo sends `DTSTART;TZID=...` + VTIMEZONE): FILETIME must be the UTC instant, not the wall clock. Test in Task 2.
2. **Missing DTEND** (DURATION or nothing): `ical2exchange_property_DTSTART_DTEND` returns without setting any time when DTEND is absent; normalization must synthesize DTEND. Test in Task 2.
3. **Multi-day all-day** (`VALUE=DATE`, 3 days): libexchange2ical only flags 1440-minute events; dav sets `PidLidAppointmentSubType=1` whenever DTSTART is a DATE. Test in Task 2.
4. **Unconfigured backend installed next to others** must not break `mapistore_list_contexts` for everyone. Test in Task 1.
5. **Stable MIDs across context re-creation** and an href that disappears between REPORT and GET (404 on GET → row skipped, not whole table failing). Tests in Task 4.

---

### Task 1: Build plumbing, registration and test target

**Files:**
- Modify: `configure.ac` (new `AC_ARG_ENABLE(mapistore-dav)` near line 819; summary block near line 1003), `config.mk.in` (`CURL_CFLAGS/LIBS`, `EXPAT_LIBS`, `MAPISTORE_DAV`), `Makefile` (backend rule under `# mapistore backends`, line ~1012; `check-mapistore-dav` near `check-namedprops`, line ~2119), `.github/workflows/modernization.yml` (new job `mapistore-dav`)
- Create: `mapiproxy/libmapistore/backends/dav/dav_backend.c`, `mapiproxy/libmapistore/backends/dav/dav.h`
- Test: `testsuite/modernization/dav_smoke.c`

**Interfaces:**
- Produces: `int mapistore_init_backend(void)`; `enum mapistore_error dav_config_load(struct loadparm_context *lp_ctx)` (test-visible, non-static, declared in `dav.h`); `struct dav_config { char *calendar_url_template; }` file-static; `enum mapistore_error dav_list_contexts(const char *username, struct indexing_context *, TALLOC_CTX *, struct mapistore_contexts_list **)` producing one entry `{url="dav://calendar/", name="Calendar", role=MAPISTORE_CALENDAR_ROLE, main_folder=true, tag="tag"}` when configured, `*list=NULL` otherwise.

- [ ] **Step 0: Toolchain prerequisite** — extract `libcurl4-openssl-dev` (matching installed `libcurl4t64 8.14.1-2+deb13u7`) into `/tmp/openchange-build-tools/root`; confirm `pkg-config --modversion libcurl expat libical` via that root's pkg-config.
- [ ] **Step 1: Write failing tests** in `dav_smoke.c` (assert style of `namedprops_smoke.c`):
  - `test_register`: `mapistore_init_backend()==0`; `mapistore_backend_registered("dav")==MAPISTORE_SUCCESS`; looked-up backend has `namespace` `"dav://"`.
  - `test_list_contexts_unconfigured`: with no parameter, `list_contexts` returns `MAPISTORE_SUCCESS` and `NULL` list.
  - `test_list_contexts_configured`: `lpcfg_set_cmdline(lp, "mapistore:dav_calendar_url", "https://dav.invalid/%u/cal/")`, `dav_config_load(lp)`; one entry, role `MAPISTORE_CALENDAR_ROLE`, url `"dav://calendar/"`.
  - `test_create_context_unconfigured` → `MAPISTORE_ERR_NOT_AVAILABLE`.
  - `test_write_stub`: `folder.create_message` → `MAPISTORE_ERR_NOT_IMPLEMENTED`.
- [ ] **Step 2:** `make check-mapistore-dav` → fails (missing sources).
- [ ] **Step 3: Implement** configure probe (`PKG_CHECK_MODULES([CURL], [libcurl])`, `PKG_CHECK_MODULES([EXPAT], [expat])`, reuse `$have_libical`; `OC_RULE_ADD(mapistore_dav, MAPISTORE)` only when enabled), Makefile rule building `mapiproxy/libmapistore/backends/mapistore_dav.$(SHLIBEXT)` with install/uninstall/clean into `$(libdir)/mapistore_backends`, and `dav_backend.c` registration with `create_context` returning `NOT_AVAILABLE` when unconfigured. `check-mapistore-dav` without the configure flag prints a skip line and exits 1 with "configure with --enable-mapistore-dav" (not a silent pass).
- [ ] **Step 4:** `./configure <existing flags> --enable-mapistore-dav && make check-mapistore-dav` → PASS; also re-run plain `./configure <existing flags> && make all` → PASS with no curl/expat reference.
- [ ] **Step 5: CI** — add job `mapistore-dav` (copy of native-library setup + `libical-dev libcurl4-openssl-dev libexpat1-dev`), configure with the flag, `make all check-mapistore-dav`, then the sanitizer re-run with `-W testsuite/modernization/dav_smoke.c`. Existing jobs unchanged (they keep proving the default build).
- [ ] **Step 6: Commit** `feat(mapistore-dav): register optional dav backend and build plumbing`.

### Task 2: iCalendar → MAPI mapping

**Files:**
- Modify: `libexchange2ical/ical2exchange.c` (add wrapper, make `_IcalEvent2Exchange` use it), `libexchange2ical/libexchange2ical.h` (declare it)
- Create: `mapiproxy/libmapistore/backends/dav/dav_ical.c`
- Test: `testsuite/modernization/dav_smoke.c`, fixtures in `testsuite/modernization/dav/*.ics`

**Interfaces:**
- Consumes: Task 1 `dav.h`.
- Produces:
  - `enum MAPISTATUS ical2exchange_vevent_props(TALLOC_CTX *mem_ctx, icalcomponent *vevent, struct SPropValue **props, uint32_t *count)` (libexchange2ical; canonical PidLid tags).
  - `struct dav_event { struct SPropValue *props; uint32_t count; struct mapistore_message_recipient *recipients; uint32_t recipients_count; char *subject; }`
  - `enum mapistore_error dav_ical_parse(TALLOC_CTX *, const char *ics, size_t len, struct dav_event **out)` — returns `MAPISTORE_ERR_INVALID_DATA` for malformed/no VEVENT, `MAPISTORE_ERR_NO_MEMORY` on allocation failure. Uses the first master VEVENT (no RECURRENCE-ID); overrides ignored: `shortcut: exceptions dropped, upgrade with exception blobs`.
  - `const struct SPropValue *dav_event_find(const struct dav_event *, uint32_t canonical_tag)`.

- [ ] **Step 1: Failing tests** (fixtures inline or under `testsuite/modernization/dav/`):
  - `test_ical_simple`: SUMMARY "Weekly sync", LOCATION "Room 1", DESCRIPTION "Agenda", DTSTART/DTEND `20261102T130000Z`/`T140000Z` → `PR_SUBJECT_UNICODE`=="Weekly sync", `PidLidLocation`, `PR_BODY_UNICODE`, `PidLidAppointmentStartWhole` FILETIME == NTTIME of 2026-11-02 13:00 UTC, duration 60.
  - `test_ical_tzid`: `DTSTART;TZID=America/Sao_Paulo:20261102T100000` + VTIMEZONE (UTC-3, no DST) → start == 13:00 UTC.
  - `test_ical_duration_only`: DTSTART + `DURATION:PT30M` → end == start + 30 min.
  - `test_ical_allday_single` and `test_ical_allday_multi` (`VALUE=DATE` 20261102→20261105) → `PidLidAppointmentSubType`==1 in both.
  - `test_ical_recurring`: `RRULE:FREQ=WEEKLY;COUNT=4` → `PidLidRecurring` true and `PidLidAppointmentRecur` binary length > 0.
  - `test_ical_organizer_attendees`: ORGANIZER `mailto:org@dav.invalid` CN "Org" → `PR_SENT_REPRESENTING_NAME_UNICODE`=="Org"; two ATTENDEE (REQ-PARTICIPANT, OPT-PARTICIPANT) → `recipients_count`==2, types `MAPI_TO`,`MAPI_CC`.
  - `test_ical_malformed`: `"BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:x"` (truncated) and a VCALENDAR with only VTODO → `MAPISTORE_ERR_INVALID_DATA`.
  - `test_ical_alloc_failure`: loop N=0.. failing the Nth `talloc_*` in dav code (`-Wl,--wrap=` pattern of `check-mysql-utils`) → every result is `SUCCESS` or `NO_MEMORY`, never a crash; ASan clean.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement.** Normalization before calling the wrapper (on a clone): convert DTSTART/DTEND to UTC with the calendar's VTIMEZONE (`icalcomponent_get_timezone` + `icaltime_convert_to_zone`; floating → UTC, `shortcut: floating treated as UTC, upgrade with user's mailbox TZ`); add DTEND from `icalcomponent_get_dtend()` when missing; after conversion set SubType=1 when DTSTART `is_date`. Organizer/attendees mapped here. Link `ical2exchange.o ical2exchange_property.o exchange2ical_utils.o` into the backend and the test.
- [ ] **Step 4:** run → PASS; `make bin/exchange2ical` still links.
- [ ] **Step 5: Commit** `feat(mapistore-dav): map iCalendar events to MAPI appointment properties` (libexchange2ical wrapper may be its own preceding `refactor(exchange2ical): expose vevent property conversion` commit).

### Task 3: CalDAV client over a pluggable transport

**Files:**
- Create: `mapiproxy/libmapistore/backends/dav/dav_caldav.c`
- Test: `testsuite/modernization/dav_smoke.c`, fixtures `testsuite/modernization/dav/*.xml`

**Interfaces:**
- Produces:
  - `struct dav_response { long status; char *body; size_t len; };`
  - `typedef enum mapistore_error (*dav_transport_fn)(void *priv, TALLOC_CTX *, const char *method, const char *url, const char *depth, const char *body, struct dav_response *out);`
  - `enum mapistore_error dav_transport_curl(void *priv, ...)` (libcurl; `CURLOPT_PROTOCOLS_STR "https,http"`, connect/total timeouts 10/30 s, body cap 16 MiB → `INVALID_DATA`).
  - `struct dav_item { char *href; char *etag; };`
  - `enum mapistore_error dav_discover(TALLOC_CTX *, dav_transport_fn, void *priv, const char *url, char **collection_url)` — PROPFIND Depth 0 for `resourcetype`; must contain `C:calendar` (`urn:ietf:params:xml:ns:caldav`) else `NOT_FOUND`.
  - `enum mapistore_error dav_list_events(TALLOC_CTX *, dav_transport_fn, void *priv, const char *collection_url, struct dav_item **items, uint32_t *count)` — REPORT Depth 1, `calendar-query` with `comp-filter VCALENDAR/VEVENT`, prop `getetag`; skips the collection's own href and non-200 propstats.
  - `enum mapistore_error dav_get(TALLOC_CTX *, dav_transport_fn, void *priv, const char *url, char **body, size_t *len)`.
  - Status mapping, used by all three: 401/403 → `DENIED`, 404 → `NOT_FOUND`, 5xx and transport failure → `NOT_AVAILABLE`, other non-2xx → `INVALID_DATA`; PROPFIND/REPORT require 207.

- [ ] **Step 1: Failing tests** using a fixture transport (`struct fixture { long status; const char *body; }` queue, records method/url/depth for assertions):
  - `test_discover_ok` (207 with `<C:calendar/>`) and `test_discover_not_calendar` → `NOT_FOUND`.
  - `test_list_empty`: 207 with only the collection response → `count`==0.
  - `test_list_two`: two events → hrefs `/cal/a.ics`, `/cal/b.ics`, etags `"1"`,`"2"`; request method `REPORT`, depth `"1"`.
  - `test_list_relative_and_absolute_href`: href `https://dav.invalid/cal/a.ics` and `/cal/a.ics` both resolve to `/cal/a.ics`.
  - `test_truncated_xml`: 207 body cut mid-element → `INVALID_DATA`.
  - `test_status_mapping`: 401→`DENIED`, 404→`NOT_FOUND`, 500 and 503→`NOT_AVAILABLE`, 200 for REPORT→`INVALID_DATA`.
  - `test_get_ok` / `test_get_404`.
  - `test_caldav_alloc_failure`: same Nth-failure loop as Task 2.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement** with expat `XML_ParserCreateNS(NULL, ' ')`, matching `DAV: response/href/propstat/status/prop/getetag`; entity declarations rejected (`XML_SetEntityDeclHandler` → stop) to avoid billion-laughs.
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5: Commit** `feat(mapistore-dav): add minimal CalDAV client`.

### Task 4: Read-only calendar context, folder, table and message

**Files:**
- Modify: `mapiproxy/libmapistore/backends/dav/dav_backend.c`
- Create: `mapiproxy/libmapistore/backends/dav/dav_objects.c`
- Test: `testsuite/modernization/dav_smoke.c`

**Interfaces:**
- Consumes: Tasks 2–3 as declared above.
- Produces (all in `dav.h`):
  - `enum dav_object_type { DAV_FOLDER, DAV_MESSAGE, DAV_TABLE };` first member of every object struct.
  - `void dav_set_transport(dav_transport_fn fn, void *priv)` (tests; production default `dav_transport_curl`).
  - Folder object: username, collection URL, root FID, `struct indexing_context *`, cached `dav_item[]` + MIDs + lazily parsed `dav_event *`.
  - Message URI format for indexing: `dav://calendar/<last href segment>` (percent-encoding kept as received).
  - Callbacks wired per "Interface findings": `get_root_folder`, `get_path` (root FID → `"calendar/"`, MID → indexing `get_uri`), `open_message` (`read_write==true` → `DENIED`), `get_child_count` (MESSAGE table → count, FOLDER/FAI → 0), `open_table` (MESSAGE only, else `NOT_IMPLEMENTED`), table `set_columns`/`get_row`/`get_row_count`/`get_available_properties`/`handle_destructor`, properties `get_available_properties`/`get_properties`, `get_message_data`.
  - Named-property translation done once in `create_context`: canonical PidLid tags used by Task 2 → `mapistore_namedprops_get_mapped_id`; unmapped → that column returns `MAPISTORE_ERR_NOT_FOUND`.

- [ ] **Step 1: Failing tests** with a fake in-memory `indexing_context`, a namedprops fixture (as in `namedprops_smoke.c`) and the fixture transport:
  - `test_open_root_and_count`: create_context on `"calendar/"` with fid `0x10001`; PROPFIND+REPORT fixtures for 2 events → `get_child_count(MESSAGE)`==2, `(FOLDER)`==0.
  - `test_table_rows`: `set_columns({PR_MID, PR_SUBJECT_UNICODE, mapped PidLidAppointmentStartWhole})`, `get_row(0)` → MID == the indexing MID for `a.ics`, subject "Weekly sync", start FILETIME as Task 2.
  - `test_stable_mids`: destroy and re-create the context with the same fake indexing → same MIDs for `a.ics`/`b.ics`; a new `c.ics` gets a new MID.
  - `test_get_vanished`: REPORT lists `a.ics`,`b.ics`; GET `b.ics` → 404 → `get_row_count`==1 and `get_row(0)` is `a.ics`.
  - `test_message_props_and_data`: `open_message(mid_a, false)` → `get_properties(PR_SUBJECT_UNICODE, PR_MESSAGE_CLASS_UNICODE)` == "Weekly sync", "IPM.Appointment"; `get_message_data` → `normalized_subject` "Weekly sync", recipients from Task 2.
  - `test_read_only`: `open_message(mid_a, true)` → `DENIED`; `properties.set_properties` and `folder.delete_message` → `NOT_IMPLEMENTED`.
  - `test_server_errors`: REPORT 401 → `create_context`/`open_table` return `DENIED`; 503 → `NOT_AVAILABLE`; no leak under ASan.
  - `test_objects_alloc_failure`: Nth-failure loop over create_context → open_table → get_row.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement.** MIDs: `get_fmid` → if `NOT_FOUND`, `allocate_fmid` + `add_fmid`. Message objects are talloc children of the folder; `handle_destructor` is a no-op returning success.
- [ ] **Step 4:** run → PASS, then the sanitizer run:
  `make -W testsuite/modernization/dav_smoke.c check-mapistore-dav CC='gcc -fsanitize=address,undefined -fno-omit-frame-pointer'` → PASS, then rebuild plain.
- [ ] **Step 5: Commit** `feat(mapistore-dav): expose read-only CalDAV calendar folder`.

### Task 5: Full regression, documentation and continuity

**Files:**
- Modify: `doc/MODERNIZATION.md` (new `## MAPIStore dav calendar backend (2026-10-30)`), `doc/CONTINUITY.md`, `doc/TEST_SERVER_READINESS.md` (storage-blocker row: candidate exists, not qualified), `testsuite/README.md` (commands)

- [ ] **Step 1:** `make all` and all 17 targets: `make check-binary-properties check-property-blobs check-recipient-blobs check-propsdump check-libmapi-modernization check-ndr-modernization check-mapiadmin check-ocpf-lexer check-mapiproxy-registries check-mapiproxy-rpc check-asyncemsmdb check-nspi check-emsmdb check-mpm-pack check-mpm-cache check-namedprops check-mysql-utils` → all pass, plus `check-mapistore-dav` plain and sanitized. Record exact outputs.
- [ ] **Step 2:** Default-build proof: plain configure (no flag) + `make all` + `grep -c curl config.mk` evidence that dav is off.
- [ ] **Step 3:** Docs in existing style: what was done, what was validated (the commands above), and explicitly **not validated**: writes, contacts/CardDAV, mail/IMAP, authentication, Outlook, any real CalDAV/SOGo server, restrictions/sort, recurrence exceptions, sync/ICS, performance.
- [ ] **Step 4: Commit** `docs: record dav calendar backend validation and limits`.
- [ ] **Step 5:** Report to the user and **wait for approval** before `git push origin main`; after push, check the CI run.

---

## Status and roadmap position (added 2026-10-30)

**Deferred until after M1.** No task of this plan has started; no code exists for
it. The maintainer's [project direction](../../doc/MODERNIZATION.md#project-direction-2026-10-30)
places this work in milestone **M6**. The read-only calendar tasks above remain
the first slice of M6 and are not rewritten here.

Outlook can only reach this backend through the MAPI/HTTP service
([M1 plan](2026-10-30-m1-mapihttp-autodiscover.md)) and the PostfixAdmin directory
and provisioning without SamDB (M2): `emsmdbp_init` still requires SamDB
(`mapiproxy/servers/default/emsmdb/emsmdbp.c:44`, `:86`). Until then the backend
is exercised only by `check-mapistore-dav` fixtures.

M6 adds, after the read-only slice:

- Writes: create/modify with `PUT` and `If-Match`/`If-None-Match` on the ETag;
  delete with `DELETE`; conflicts (412) surfaced as a MAPI error rather than
  overwriting.
- Contacts through CardDAV (vCard ↔ MAPI contact properties).
- Free/busy (`mapistore_folder_fetch_freebusy_properties`) from CalDAV
  free-busy data.
- Authentication to the local SOGo. The project direction assumes
  `SOGoTrustProxyAuthentication` with the `x-webobjects-remote-user` header
  ([SOGo FAQ](https://sogo.nu/support/faq/how-to-use-webauth-with-sogo.html)).
  **Unverified for SOGo 5.12 DAV routes.** Open SOGo issue
  [#5987](https://bugs.sogo.nu/view.php?id=5987) (reported on 5.10.0) describes
  credentials not being checked on DAV/ActiveSync when that header is absent and
  proxy trust is enabled; the lab must confirm that only the local service can
  set the header and that SOGo's own DAV/ActiveSync vhost is unaffected.
  This replaces design decision 2 above ("no authentication") for M6.
