# M6 slice 1 — Outlook contacts stored in SOGo over CardDAV (design)

Date: 2026-11-17. Status: approved by the maintainer (2026-11-17).

## Intent

openchange-next lets classic Outlook (2013 SP1+, MAPI/HTTP) work "like Exchange"
on a plain Postfix/Dovecot/SOGo/MariaDB server without AD or LDAP, for the
community. M6 moves Outlook's calendar and contacts into SOGo so the same items
show in Outlook, SOGo webmail and phones (SOGo ActiveSync), with no separate
OpenChange copy — the same principle as Outlook rules stored as Sieve.

**The essence (maintainer, 2026-11-17):** the same data, the same everywhere,
nothing lost — Outlook at the factory, the phone on the road, webmail from the
other side of the world. **SOGo is the hub and every client is equal; Outlook
is one more client, never the privileged one.** Every rule below is judged
against that: no client wins because it is Outlook, nothing a client can show
is hidden from Outlook, and nothing any client wrote is dropped.

This first slice is **contacts, read and write, over CardDAV**. Chosen first
(maintainer, 2026-11-17) because the data model is simpler than calendar and it
proves the whole path calendar will reuse: user credentials into the C core, a
DAV client, incremental sync into Outlook's cached mode, item ↔ MAPI id mapping
and merge without loss.

## Goals

- **Every SOGo address book of the user is an Outlook contacts folder**:
  `personal` is Outlook's default Contacts folder; each other address book is a
  contacts subfolder under it. Address books created, renamed or deleted in
  Outlook are created, renamed or deleted in SOGo, and the reverse.
- Contacts **and distribution lists** (SOGo lists ↔ Outlook `IPM.DistList`),
  **with photos**.
- Outlook in **cached mode** (the lab profile) receives everything through ICS
  and receives later changes made in SOGo webmail or on a phone.
- Create, modify and delete in Outlook reach SOGo; the reverse reaches Outlook.
- Edits on several clients are merged field by field without showing the user
  an error; no value is lost, and no client is privileged (see Conflicts).
- Authentication with the user's own Basic credentials, held in memory only.

## Non-goals (this slice)

- Calendar/CalDAV, free/busy, meeting requests (next M6 slices, same design
  principles).
- Address books other users shared with this user (SOGo ACL/subscriptions).
- The GAL (already served by NSPI from PostfixAdmin, M2).
- Publishing MAPI/HTTP on the internet so Outlook works outside the factory:
  needed for the essence, but it is deployment (M7: nginx/HAProxy exposure,
  hardening). Phone and webmail already work from anywhere.

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
2026-10-30 plan used), a URL template with `%u` = MAPI username, pointing at the user's address-book home, e.g.
`https://lab.fitasonline.com.br/SOGo/dav/%u/Contacts/`. Unset → backend
inert (`list_contexts` empty, success). CA verification on (system store).

### Folder binding

- `list_contexts` lists the user's address books (PROPFIND Depth 1 on
  `…/Contacts/`, keep `addressbook` collections): `personal` →
  `dav://contacts/personal/` with `MAPISTORE_CONTACTS_ROLE`,
  `main_folder = true`; every other book → a secondary `IPF.Contact` entry
  `dav://contacts/<book>/` under it. `list_contexts` only gets the username, so
  the credentials are kept per user in process memory from connect until the
  user's last session ends (zeroed then), and provisioning runs after connect
  has stored them (builder: verify the order in `emsmdbp_init`).
- **SOGo down during provisioning:** return `MAPISTORE_ERR_CONN_REFUSED`, as the
  IMAP backend does, so provisioning keeps the existing folders instead of
  deleting them (`emsmdbp_provisioning.c:337`).
- Folder hierarchy changes: Outlook creating a contacts folder under Contacts →
  `MKCOL` (extended, `addressbook` resourcetype) with the display name; rename
  → `PROPPATCH displayname`; delete → `DELETE` of the collection. Address books
  created/renamed/deleted in SOGo reach Outlook through the hierarchy
  notification the IMAP watcher already uses, detected by the poll below.
  Deleting `personal` is refused (SOGo refuses it too).
- Existing native Contacts folders in openchangedb (lab test data only) are
  replaced by the existing provisioning logic; no migration of old native
  contacts.

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
- **Changes from other clients while Outlook is open:** a per-session poll
  every 60 s: `sync-collection` on each address book plus a Depth 1 PROPFIND
  of `…/Contacts/` for added/renamed/removed books; any change raises the
  contents-table or hierarchy notification the IMAP watcher raises, so Outlook
  runs its incremental sync. Polling stops with the session. (My call: SOGo has
  no push for DAV clients; webmail/phone edits reach Outlook within ~1 min.)

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
| PHOTO (inline base64, JPEG/PNG) | contact picture attachment (`ContactPicture.jpg`, PidTagAttachmentContactPhoto, PidLidHasPicture) |
| UID | kept, never changed; generated (UUID) on create |

**Photos:** both directions; one fingerprint for the whole picture. A PHOTO by
URI (not inline) is preserved but not shown in Outlook. Size cap for what
Outlook uploads: builder's call, documented (SOGo/phones choke on huge
PHOTOs).

**Distribution lists:** SOGo stores a list as a `text/x-vlist` resource
(`BEGIN:VLIST` with one `CARD` line per member: member UID reference, `EMAIL`,
`FN`), not as a standard vCard 4 `KIND:group` — **builder verifies the exact
format on the lab** by creating a list in webmail and fetching it. Mapping:
VLIST `FN`/`NICKNAME`/`DESCRIPTION` ↔ PidLidDistributionListName / PidTagBody;
members ↔ PidLidDistributionListMembers + OneOffMembers (+ Checksum): a member
referencing a contact in the same address book becomes a wrapped entry ID of
that contact; a member with only name+email becomes a one-off entry. Unknown
VLIST lines are preserved like vCard ones. Member list is merged as a set
(added on one side + removed on the other both apply).

Everything else in the vCard is preserved untouched on write. Named properties
resolve through `mapistore_namedprops_get_mapped_id` at context creation.
vCard 3.0 (what SOGo stores) is written back as 3.0.

### Writing

- Create (Outlook new contact, cached upload or online SaveChanges): render a
  vCard 3.0, `PUT` to `<collection>/<uuid>.vcf` with `If-None-Match: *`.
- Modify: GET-free when the cached vCard + ETag are fresh, else GET; patch the
  mapped properties into the parsed vCard, `PUT` with `If-Match: <etag>`.
- Delete: `DELETE` with `If-Match`. **If the item changed on another client
  since Outlook saw it (412), it is not deleted**: the delete is dropped and the
  newer version comes back to Outlook on the next sync (nothing lost wins over
  delete; maintainer, 2026-11-17). Symmetric case: Outlook modifies an item that
  another client deleted (404) → the Outlook edit recreates it (PUT
  `If-None-Match: *` at a new href with the same UID), for the same reason.
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
  - **both changed to different values → the most recent edit wins, whichever
    client made it** (maintainer, 2026-11-17: no privileged client). Outlook's
    edit time is its PidTagLastModificationTime; the other side's is the vCard
    `REV` when present, else the time the poll first saw that ETag. The losing
    value is appended to the contact's NOTE as one neutral line
    `[AAAA-MM-DD conflito] <field>: <value>` so nothing is lost and every client
    shows it (no product name in user data).
  PUT the merged vCard with `If-Match`; on 412 (changed again meanwhile) redo
  the merge, at most 3 times, then fall back to the MAPI conflict result.
  Outlook then receives the merged item on the next sync.
- No fingerprint for an item (first sync after install, store lost): every
  differing field is treated as "both changed" — most recent wins, the other
  value goes to the NOTE.
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
  1. existing SOGo contacts, lists, photos and every address book appear in
     Outlook; a book created in webmail appears as a subfolder, and one created
     in Outlook appears in webmail;
  1b. a list created in webmail is usable in Outlook (send to it) and a list
     created in Outlook shows its members in webmail and on the phone;
  2. Outlook create/edit/delete → visible in SOGo webmail;
  3. webmail create/edit/delete → in Outlook within ~1 min without restart;
  4. phone-added field (custom X- or extra TEL) survives an Outlook edit;
  5. Outlook offline: change the e-mail in Outlook and the phone in webmail on
     the same contact → both kept, no conflict shown; change the same field on
     both sides → the later edit wins (try it both ways round) and the other
     value is in the NOTE; delete in Outlook offline + edit in webmail → the
     contact survives;
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
