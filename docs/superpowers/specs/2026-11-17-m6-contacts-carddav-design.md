# M6 slice 1 — Outlook contacts stored in SOGo over CardDAV (design)

Date: 2026-11-17. Status: draft for maintainer approval.

## Intent

openchange-next lets classic Outlook (2013 SP1+, MAPI/HTTP) work "like Exchange"
on a plain Postfix/Dovecot/SOGo/MariaDB server without AD or LDAP, for the
community. M6 moves Outlook's calendar and contacts into SOGo so the same items
show in Outlook, SOGo webmail and phones (SOGo ActiveSync), with no separate
OpenChange copy — the same principle as Outlook rules stored as Sieve.

This first slice is **contacts, read and write, over CardDAV**. Chosen first
(maintainer, 2026-11-17) because the data model is simpler than calendar and it
proves the whole path calendar will reuse: user credentials into the C core, a
DAV client, incremental sync into Outlook's cached mode, item ↔ MAPI id mapping
and ETag conflicts.

## Goals

- Outlook's default **Contacts** folder is the user's SOGo address book
  `Contacts/personal/`.
- Outlook in **cached mode** (the lab profile) receives the address book through
  ICS and receives later changes made in SOGo webmail or on a phone.
- Create, modify and delete in Outlook reach SOGo; the reverse reaches Outlook.
- Edits on both sides are merged field by field without showing the user an
  error; no value is lost (see Conflicts).
- Authentication with the user's own Basic credentials, held in memory only.

## Non-goals (this slice)

- Calendar/CalDAV, free/busy, meeting requests (later M6 slices).
- Other SOGo address books than `personal`, shared/subscribed address books.
- Distribution lists (Outlook `IPM.DistList`, vCard groups): not offered.
- Contact photos.
- The GAL (already served by NSPI from PostfixAdmin, M2).

## Anti-goals (failure even if it "works")

- **Losing data written by another client.** vCard properties Outlook does not
  map (a phone's custom fields, X- properties, PHOTO) must survive an Outlook
  edit. Writes patch the server's current vCard; they never regenerate it.
- Overwriting a newer server version blindly (no unconditional PUT; merge
  first).
- Contact content stored outside SOGo (only keyed field fingerprints).
- A password on disk, in logs, in openchangedb/MySQL, or in a core dump path we
  control.
- Any SOGo configuration change, `SOGoTrustProxyAuthentication`, or a
  SOGo-specific code path (the backend speaks standard CardDAV, RFC 6352 +
  RFC 6578 sync-collection).
- Breaking mail when SOGo is down: the dav backend failing must not stop logon
  or the IMAP folders.

## Constraints

- C, as a new mapistore backend `mapistore_dav.so` next to `imap`
  (maintainer, 2026-11-17: approach 1). Same object/dispatch style as the IMAP
  backend (`IMAP_OBJ_*` type tag first field, `imap_backend.h`).
- Optional at configure time (`--enable-mapistore-dav`); default build must not
  need libcurl. Enabled without deps → `AC_MSG_ERROR`.
- Dependencies: libcurl (HTTP/TLS), an XML parser already used or available in
  the toolchain (expat, per the 2026-10-30 plan). No vCard library: a small
  RFC 6350 line parser (unfolding, escaping, parameters) that keeps unknown
  lines verbatim.
- Tests: fixtures, no network, no server; ASan/UBSan clean; the existing 17
  `check-*` targets and Rust tests stay green.
- Development and acceptance on the lab VM (192.168.1.215), never production.

## Facts checked (2026-11-17, lab)

- `PROPFIND` with Basic for `teste@lab…` on
  `https://lab…/SOGo/dav/<user>/Contacts/` → 207; collection
  `Contacts/personal/` is an `addressbook` and exposes `sync-token` (`-1` when
  empty).
- `SOGoTOTPEnabled = YES` server-wide; `teste` has no TOTP enrolled. Whether DAV
  accepts the plain password for a TOTP-enrolled account is **still unknown**
  (lab check, below).
- Provisioning binds a folder to a backend through `list_contexts` entries
  (`emsmdbp_provisioning.c:337`): one `main_folder` entry with
  `MAPISTORE_CONTACTS_ROLE` takes the Contacts role. `list_contexts` gets only
  the username.
- The Rust daemon keeps only a credential hash (`session.rs:138`);
  `oc_emsmdb_connect` has no password parameter (`oc_emsmdb.h:32`).
- IMAP change numbers: `imap_change_number(ctx, uri, state)` gives a new CN when
  the per-item state changes (IMAP modseq), in process memory, with Outlook's own
  change keys preserved (`imap_folder.c:1008`). DAV uses the same with state =
  ETag.

## Approaches considered

1. **C backend `dav`, IMAP-backend style** — chosen. Reuses the M3–M5 pattern
   (protocol client inside the backend, fixtures tests), no new boundary
   direction; calendar later reuses libexchange2ical (C). Cost: more new C than
   the "new code in Rust" policy prefers (same exception M3 took).
2. Hybrid: C shell + Rust DAV/vCard via functions exported by the daemon —
   rejected: C→Rust calls are a new pattern, the backend would only work inside
   the daemon, and calendar logic would split across languages.
3. Contacts inside the IMAP backend — rejected: IMAP cannot hold contacts.

## Design

### Credentials

- `oc_emsmdb_connect` gains the user's password (or a separate
  `oc_emsmdb_set_password(session, …)` called right after connect; builder's
  choice, smallest diff). Rust passes it from the Basic header it already
  verified with Dovecot; it is not stored elsewhere in Rust.
- C keeps it in the session's dav context only (talloc, zeroed with
  `memset_s`/`explicit_bzero` in a destructor), never logged. Lifetime = the
  MAPI session.
- A password change in PostfixAdmin: the next Outlook request fails Dovecot auth
  in Rust as today; a 401 from SOGo maps to `MAPISTORE_ERR_DENIED` for that
  operation only.

### Configuration

`mapistore:dav_url` in the existing configuration (same loadparm path the
2026-10-30 plan used), a URL template with `%u` = MAPI username, e.g.
`https://lab.fitasonline.com.br/SOGo/dav/%u/Contacts/personal/`. Unset → backend
inert (`list_contexts` empty, success). CA verification on (system store).

### Folder binding

`list_contexts` returns, without any network call, one entry
`dav://contacts/` with `MAPISTORE_CONTACTS_ROLE`, `main_folder = true`,
`IPF.Contact`. So SOGo being down cannot alter provisioning. Existing native
Contacts folders in openchangedb (lab test data only) are replaced by the
provisioning logic that already exists; no migration of old native contacts.

### Reading and sync

- Item identity: the item's href (last path segment) → MID through the
  configured indexing (`dav://contacts/<segment>`). ETag is version, not
  identity.
- Change numbers: `imap_change_number`'s logic with state = ETag. Builder moves
  it to a shared helper used by both backends rather than copying it.
- Listing: `REPORT sync-collection` with the stored sync-token; a full listing
  when there is no token or SOGo rejects it (`valid-sync-token` precondition).
  `get_deleted_fmids` answers from the hrefs reported as removed (and, after a
  full listing, from indexed hrefs that are gone), like the IMAP backend does
  for expunged UIDs. Fetch vCards in bulk with `addressbook-multiget`.
- Sync token, href list and ETags live in session memory; a new session starts
  from a full listing (correct, just slower).
- **SOGo-side changes while Outlook is open:** a per-session poll every 60 s with
  `sync-collection`; any change raises the same contents-table notification the
  IMAP watcher raises, so Outlook runs its incremental sync. Polling stops with
  the session. (My call; webmail/phone edits reach Outlook within ~1 min.)

### vCard ↔ MAPI mapping (minimum set)

| vCard | MAPI |
| --- | --- |
| FN, N (family, given, middle, prefix, suffix) | PidTagDisplayName, PidTagSurname, PidTagGivenName, PidTagMiddleName, PidTagDisplayNamePrefix, PidTagGeneration; PidLidFileUnder from N |
| EMAIL ×3 (first three, in order) | PidLidEmail1/2/3 EmailAddress + DisplayName + AddressType `SMTP` |
| TEL;TYPE=work / home / cell / fax | PidTagBusinessTelephoneNumber, PidTagHomeTelephoneNumber, PidTagMobileTelephoneNumber, PidTagBusinessFaxNumber |
| ORG, TITLE | PidTagCompanyName + PidTagDepartmentName, PidTagTitle |
| ADR;TYPE=work / home | PidLidWorkAddress* , PidTagHome* address fields |
| NOTE | PidTagBody |
| BDAY | PidTagBirthday |
| URL | PidTagBusinessHomePage |
| UID | kept, never changed; generated (UUID) on create |

Everything else in the vCard is preserved untouched on write. Named properties
resolve through `mapistore_namedprops_get_mapped_id` at context creation.
vCard 3.0 (what SOGo stores) is written back as 3.0.

### Writing

- Create (Outlook new contact, cached upload or online SaveChanges): render a
  vCard 3.0, `PUT` to `<collection>/<uuid>.vcf` with `If-None-Match: *`.
- Modify: GET-free when the cached vCard + ETag are fresh, else GET; patch the
  mapped properties into the parsed vCard, `PUT` with `If-Match: <etag>`.
- Delete: `DELETE` with `If-Match`. If the item changed in SOGo since Outlook
  saw it, the delete still wins (my call: deleting is an explicit user act);
  412 → re-GET, re-DELETE with the new ETag.
- Outlook's own change keys/PCL preserved exactly as the IMAP backend does so a
  write does not bounce back as a new change.

### Conflicts: field-level merge, no error shown (maintainer, 2026-11-17)

Goal: the user never sees a sync conflict. Approaches weighed with the
maintainer: (A) SOGo wins + Outlook conflict item; (B) Outlook wins + copy in
SOGo; (C) field merge with a full base vCard in MariaDB (rejected: a second
copy of contact data); (C2) field merge with per-field fingerprints —
**chosen**; fingerprints inside the vCard as X- property (rejected: SOGo
ActiveSync/phones may drop it); online-only Contacts (rejected: breaks cached
mode).

- **Fingerprint store:** for each item, the hash of every mapped field (the
  vCard ↔ MAPI table above, normalized value) as last agreed by Outlook and
  SOGo, plus the ETag it belongs to. Stored in MariaDB next to the indexing
  data (new table, `utf8mb4_bin`, keyed by user + item href). Hash = keyed
  hash (e.g. HMAC-SHA-256 truncated to 64 bits, per-installation key) so a
  short field (a 4-digit extension) cannot be brute-forced from the table. No
  contact content is stored outside SOGo.
- Fingerprints are written whenever Outlook and SOGo agree on a version:
  after each successful read into Outlook and after each successful PUT.
- **On Outlook modify:** GET the current vCard. For each mapped field:
  - Outlook value ≠ fingerprint → Outlook changed it;
  - SOGo value ≠ fingerprint → SOGo side changed it;
  - only one side changed → take that side; neither → keep;
  - **both changed to different values → Outlook wins** (last writer), and the
    SOGo value is appended to the contact's NOTE as one line
    `[openchange-next AAAA-MM-DD] <field>: <old value>` so nothing is lost
    (my call over server-log-only: the user can see and recover it; the
    maintainer may switch it to log-only).
  PUT the merged vCard with `If-Match`; on 412 (changed again meanwhile) redo
  the merge, at most 3 times, then fall back to the MAPI conflict result.
  Outlook then receives the merged item on the next sync.
- No fingerprint for an item (first sync after install, store lost): SOGo's
  current version is taken as the base, i.e. Outlook's differing fields win —
  the same rule as "both changed".
- Unmapped vCard properties are never compared or touched (anti-goal 1).
- Fingerprint rows are deleted with the item; a full listing prunes rows of
  hrefs that no longer exist.

### Failure behavior

- SOGo unreachable or 5xx: folder operations return
  `MAPISTORE_ERR_CONN_REFUSED`/`NOT_AVAILABLE`; the rest of the mailbox works;
  logon never fails because of dav.
- Timeouts: connect 5 s, request 15 s (libcurl), my call.

## Tests

- Fixture-driven unit tests (`make check-mapistore-dav`): vCard parse/serialize
  round trip with unknown properties preserved, folding/escaping/UTF-8; mapping
  both directions; sync-collection and multiget XML parsing (SOGo-shaped
  fixtures, anonymized); token invalid → full listing; deletes →
  `get_deleted_fmids`; merge table (one side / both sides / neither / no
  fingerprint / repeated 412); NOTE line on both-changed; fingerprints pruned
  on delete; inert when unconfigured; password zeroed.
- Lab acceptance with the Outlook on the TSplus (.167), cached mode:
  1. existing SOGo contacts appear in Outlook;
  2. Outlook create/edit/delete → visible in SOGo webmail;
  3. webmail create/edit/delete → in Outlook within ~1 min without restart;
  4. phone-added field (custom X- or extra TEL) survives an Outlook edit;
  5. Outlook offline: change the e-mail in Outlook and the phone in webmail on
     the same contact → both kept, no conflict shown; change the same field on
     both sides → Outlook's value wins and webmail's value is in the NOTE;
  6. SOGo stopped → mail still works, Contacts errors cleanly;
  7. TOTP: enroll a lab account in TOTP and check DAV with the plain password;
     record the result (if refused, document it as a known limitation for this
     slice; no workaround without the maintainer).

## Left to the builder

- Password parameter vs. setter on the C boundary; struct layout; file split.
- Exact MAPI conflict codes per path; exact named-property list beyond the
  table if Outlook's contact form needs more (e.g. PidLidEmail1OriginalEntryId).
- XML parser choice if expat is unavailable in the toolchain (rebuild
  `/tmp/openchange-build-tools` first; it was lost on reboot).
