# M5: Outlook sees mailbox changes without a restart (design)

Date: 2026-11-13. Status: draft for approval.

## Intent

Outlook in cached mode (MAPI/HTTP, OST) must pick up everything that changes in the IMAP
mailbox while it is open, as an IMAP client would: new mail, read/unread, flags, moves,
deletions, folders created/renamed/deleted, whatever made them (SOGo, a phone, Sieve rules,
another Outlook). Today those changes show only after Outlook restarts. Calendar and
contacts are M6.

Goals: a change in a mail folder reaches Outlook in seconds; no client configuration;
one IMAP connection per online user at most.
Non-goals: NewMail desktop alerts with the message preview (nice to have, below); public
folders; push to clients other than Outlook over MAPI/HTTP.
Anti-goals: anything that makes Outlook resync whole folders on every tick, or that loses
or duplicates mail in the OST.

## What the lab established (2026-11-13)

Spike plus a reference capture against gromox (grommunio's MAPI server, run in an isolated
container only to observe; nothing of it is used or copied):

- Cached-mode Outlook registers only two subscriptions: NewMail + CriticalError on the
  whole store, and ObjectModified on one FAI message. A NewMail notification alone (any
  variant) does not make it synchronize, and neither does scheduled Send/Receive.
- At logon it opens a **deep hierarchy table** (RopGetHierarchyTable, TableFlags 0x84 =
  Depth | SuppressesNotifications) on the mailbox root, sets 11 columns (FolderId,
  DisplayName, Subfolders, ParentFolderId, 0x36E0 XViewInfo, DeletedCountTotal,
  **LocalCommitTimeMax**, FolderFlags, HierRev, ContentCount, ContentUnread), reads it and
  **keeps it open**.
- When mail arrives, gromox sends RopNotify **TableModified (0x0100), TABLE_ROW_MODIFIED**
  on that table handle with the folder's new row (plus a NewMail 0x8002 on the store
  subscription). About 30 s later (Outlook's cached-mode download timer) Outlook runs ICS
  on that folder.
- Our server answered LocalCommitTimeMax with NOT_FOUND, so Outlook had nothing to
  compare. With LocalCommitTimeMax answered by the IMAP backend and the same ROW_MODIFIED
  sent by hand, Outlook ran RopSyncConfigure and showed the new message without a restart.

The transport already works: NotificationWait answering EventPending=1 makes Outlook send
an Execute, and RopNotify blocks appended to any Execute response reach it.

## Approaches (chosen: C)

- A. IMAP NOTIFY, translating each IMAP event into precise MAPI object notifications.
  Fast, but the translation (MID of every message event) is the bug-prone part, and
  Outlook does not need it: it only needs to know which folder changed.
- B. Periodic LIST-STATUS per user, folder-level "changed". Simple, up to N seconds late.
- **C (chosen by the user): NOTIFY as a folder-level trigger, LIST-STATUS as the fallback
  when the NOTIFY connection is down.** ICS (M3/M4) computes the actual differences.

## Design

### 1. Folder change detection (Rust, mapihttpd)

A watcher per user that has at least one live EMSMDB session, started on the first
Connect and stopped with the last Disconnect/expiry:

- One IMAP connection to Dovecot on loopback, authenticated as `<user>*<master>` with the
  master user and password the C backend already uses (read from the same smb.conf
  options), plain on loopback as today.
- `NOTIFY SET STATUS (personal (MessageNew MessageExpunge FlagChange MailboxName))`
  (RFC 5465; STATUS makes Dovecot report changes of mailboxes that are not selected);
  every untagged event names a mailbox (STATUS/LIST responses carry it) and becomes
  "mailbox X changed" or "mailbox list changed". Events for the same mailbox within 1 s
  are coalesced.
- If NOTIFY fails or the connection drops: reconnect with backoff; while down, poll
  `LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN UIDNEXT HIGHESTMODSEQ))` every 60 s and
  diff against the last snapshot. The poll also runs once after every reconnect, so events
  missed while down are not lost.

### 2. Folder state includes HIGHESTMODSEQ (C, IMAP backend)

The folder "state" that drives the change number and the change time is today
`uidvalidity:messages:unseen:uidnext`, so a flag-only change (\Flagged from SOGo) does not
move it. `imap_status` adds HIGHESTMODSEQ (CONDSTORE) to STATUS and to the state string.
PidTagLocalCommitTimeMax is answered with the time of the folder's last state change (same
source as PidTagLastModificationTime; done in the spike branch). PR_CONTENT_UNREAD comes
from the backend instead of the old hard-coded 0 (done in the spike branch).

### 3. Notification build (C, emsmdb)

New FFI call on the existing C worker, serialized with Execute:
`oc_emsmdb_folder_changed(session, mailbox_name, kind)` where kind is modified, added or
deleted. For the session:

- Track the open deep hierarchy tables (GetHierarchyTable with TableFlags_Depth, without
  TableFlags_NoNotifications), forgotten when the table handle is released.
- Resolve the mailbox name to the FID Outlook knows: the openchangedb system folder whose
  MAPIStoreURI points at that mailbox (Inbox, Sent, Deleted Items, ...), else the
  mapistore indexing FID of the URI.
- For each tracked table whose subtree contains the folder: modified -> ROW_MODIFIED with
  the folder's row in the table's columns (same code path QueryRows uses) and
  InsertAfterFID = its previous sibling or 0; added -> ROW_ADDED; deleted ->
  ROW_DELETED with the FID.
- Queue the RopNotify blobs on the session (in process; the memcached "deliver" path is
  not used for this) and return whether anything is pending.

The next Execute response of that session appends the queued blobs (the existing code
already appends notifications; the size limit is respected, leftovers stay queued for the
next Execute).

### 4. Wake-up (Rust)

When `folder_changed` reports pending notifications, the session's NotificationWait (if
any) returns at once with EventPending=1; if none is waiting, the next NotificationWait
returns immediately. The 300 s wait stays the upper bound.

### 5. Nice to have (same milestone if cheap)

NewMail 0x8002 on the store subscription when the Inbox UIDNEXT grows, with the new
message's MID (indexing it like M3 listing does), so Outlook can show its new-mail alert.

## Constraints

- Lab Outlook runs on a shared terminal server (TS-167, ~40 real users): acceptance only
  acts inside our own session.
- Dovecot is 2.4 with NOTIFY, IDLE, CONDSTORE/QRESYNC, LIST-STATUS (checked).
- One C worker thread serves every session: folder_changed must be quick (no IMAP round
  trips per tracked table beyond one folder property read).

## Acceptance (lab, Outlook classic, cached mode)

Without restarting Outlook, within about a minute (download timer included):
new mail by SMTP; mail filed by a Sieve rule into another folder; read/unread and flag
changed in SOGo; message moved and deleted in SOGo; folder created, renamed and deleted in
SOGo. Then the same with the NOTIFY connection killed (fallback poll).

## Left to the builder

Exact Rust structure of the watcher, backoff values, coalescing window, how the session
maps to its user for the watcher, test fixtures (Dovecot fixture already used by the IMAP
backend suite).

## Cleanup after M5

Remove the gromox reference container, its nginx routing, the test site and CA, the
`ref@` account from the Outlook profiles on TS-167, and the spike code.
