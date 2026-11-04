# M4: IMAP writes and sending from Outlook — design

Date: 2026-11-04. Status: approved in conversation; reviewed 2026-11-04 (lab facts below).
Roadmap: `doc/MODERNIZATION.md` M4 ("Writes: send through submission 587,
move, delete, flags"). Builds on the M3 read-only IMAP mapistore backend
(libetpan, Dovecot master user `openchange` on loopback).

## Goal

What a person does in Outlook reaches Dovecot and Postfix, so webmail and
IMAP clients see the same mailbox: move, copy, delete, read state, flags,
drafts, folder create/rename/delete, and sending mail.

Success: in the lab, with classic Outlook for Microsoft 365 in cached mode,
each action is visible in webmail; a sent message arrives with a valid DKIM
signature and a copy sits in Sent; Postfix refuses a From that is not the
user's (and Outlook shows the error).

## Maintainer decisions (2026-11-04)

- Sending: option 1, all in C inside the existing process, with libetpan
  (SMTP client and MIME writer). Rejected: a queue to the Rust daemon (two
  processes, no synchronous error), `/usr/sbin/sendmail` (bypasses the
  submission policy, so a user could send as another).
- Permanent delete (Shift+Delete, emptying Deleted Items) expunges in IMAP,
  as webmail does.
- Folder create/rename/delete are in scope.
- Outbox is an IMAP mailbox (durable, one MIME path shared with Drafts).

## Out of scope

Send-as/delegates, rules and auto-replies, meeting requests (M6), real-time
notifications and restart-stable change numbers (M5), the M3 review items
deferred to M5 (I2, I3, I6).

## Architecture

No new service. The IMAP backend gains three files; emsmdb routes the
operations it refuses today to the backend.

1. `imap_write.c` — IMAP mutations over the session's master-user
   connection: `UID MOVE`/`UID COPY` (RFC 6851, UIDPLUS COPYUID for the new
   UIDs), `UID STORE` of `\Seen`/`\Flagged`/`\Deleted`, `UID EXPUNGE` of
   exactly the UIDs Outlook deleted (never a bare `EXPUNGE`, which would
   also remove messages webmail flagged), `APPEND` (APPENDUID), `CREATE` +
   `SUBSCRIBE`, `RENAME`, `DELETE`. The fmid index changes only after the
   server confirmed.
2. `imap_compose.c` — an in-memory MAPI message (properties, recipients,
   attachments) built while Outlook writes it, and its RFC 5322/MIME
   rendering with libetpan: text and/or HTML body, attachments (base64),
   UTF-8 with RFC 2047 encoded-words in headers, Date, Message-ID,
   In-Reply-To/References when Outlook gives them. Bcc recipients are
   envelope-only.
3. `imap_submit.c` — submission to `mapistore:smtp_host` (default
   127.0.0.1) port `mapistore:smtp_port` (587) with STARTTLS, AUTH PLAIN as
   `<user>*openchange` with the master password, MAIL FROM the user's
   primary address, RCPT for To/Cc/Bcc. Postfix keeps deciding:
   `reject_sender_login_mismatch`, rspamd DKIM, limits.

Indexing gains `update_uri_prefix(ctx, username, old_prefix, new_prefix)`
(MySQL and TDB backends), because a folder rename changes the URI of every
folder and message under it; without it those mids turn into ghosts.

## Operations

| Outlook | Backend | IMAP |
|---|---|---|
| Move/copy messages (RopMoveCopyMessages, ICS ImportMessageMove) | `move_copy_messages` | `UID MOVE`/`UID COPY`; target mids bound to the COPYUID URIs |
| Delete (move to Deleted Items) | as move | `UID MOVE` to Trash |
| Shift+Delete, empty Deleted Items (RopDeleteMessages, ICS ImportDeletes, hard or soft) | `delete_message` | `UID STORE +FLAGS (\Deleted)`, `UID EXPUNGE <uid>` |
| Read/unread (RopSetReadFlags, ICS ImportReadStateChanges) | `set_read_flag` | `\Seen` |
| Follow-up flag (PidTagFlagStatus 2 / cleared) | `set_properties` + `save` | `\Flagged` |
| Reply / forward (PidTagLastVerbExecuted 102-103 / 104) | `set_properties` + `save` | `\Answered` / `$Forwarded` |
| Other property edits on received mail | `save` | ignored (logged at level 5), success |
| New or edited draft (Drafts) | `create_message`/`open_message`, `set_properties`, `modify_recipients`, attachments, `save` | `APPEND` new version; then `\Deleted` + `UID EXPUNGE` the old; the mid is re-pointed to the new URI |
| Send (RopSubmitMessage on a message in Outbox) | `submit` | `APPEND` to `Outbox` (on save), SMTP, then `UID MOVE` Outbox→Sent, or expunge when PidTagDeleteAfterSubmit |
| Create folder | `create_folder` | `CREATE`, `SUBSCRIBE` |
| Rename / move folder | `set_properties` (PidTagDisplayName), `move_folder` | `RENAME`; `update_uri_prefix` |
| Delete folder | `delete` | `DELETE`, only when empty of messages and subfolders (Outlook deletes children first); default folders refused |

Which messages are re-rendered: only those with MSGFLAG_UNSENT (drafts and
messages waiting in Outbox), wherever they sit. Any other message is
received mail: `save` writes its flags and nothing else, so received mail
is never rewritten.

Cross-store moves (an IMAP message to an openchangedb-only folder, or back)
are refused with MAPI_E_NO_SUPPORT; the message stays where it was.

Outbox: an IMAP mailbox named `Outbox`, created on first logon and left
unsubscribed; provisioned like the other default folders (M3 takeover). It
holds a message only between upload and send. IMAP clients that honour
subscriptions hide it; SOGo in the lab does not set
`SOGoMailShowSubscribedFoldersOnly` and may list it. Accepted: changing
that setting would change webmail for everyone, and a visible Outbox shows
a message that did not leave.

Sent copy: the backend files the exact bytes it sent with `UID MOVE`
Outbox→Sent (the `\Sent` SPECIAL-USE mailbox), or expunges them when
PidTagDeleteAfterSubmit is set. emsmdb's
`oxomsg_mapistore_handle_message_relocation` would create and re-compose a
second message; after a successful submit the message no longer reports
PidTagTargetEntryId/PidTagSentMailSvrEID, so it does nothing.

Change numbers: after a write the folder state string changes, so the next
sync echoes the change back to Outlook (it already has it; harmless). M5
replaces this.

## Errors

- Every IMAP write checks the tagged response; on NO/BAD/timeout the
  backend returns an error, the index is untouched, and emsmdb reports the
  error to Outlook (as the M3 delete fix does).
- SMTP: a refused MAIL FROM/RCPT/DATA aborts the send, the message stays in
  Outbox, RopSubmitMessage returns the error; Outlook shows "could not
  send". No partial sends. A message over the server's EHLO SIZE is
  refused before DATA.
- Remote delivery failures are Postfix's bounces into the Inbox, as for any
  client.
- `UID EXPUNGE` needs UIDPLUS; without it the backend refuses permanent
  deletes rather than run a bare `EXPUNGE`.

## Security

- Logs never carry addresses, subjects, bodies or the master password
  (same rule as M3).
- Non-loopback SMTP requires STARTTLS with certificate verification; on
  loopback, STARTTLS without hostname verification (the certificate names
  the public host).
- The SMTP identity is always the session's own user; From/Sender are not
  trusted for authorization, Postfix's login map is.
- Received mail is never rewritten: only flags change on it.

## Testing

- Backend unit tests against Dovecot's `imap` binary in PREAUTH mode (the
  M3 harness): each operation's IMAP effect and index effect; delete of one
  UID leaves another `\Deleted` message alone; rename keeps mids under the
  folder; refused writes leave the index alone.
- MIME rendering tests: round trip through the M3 parser (subject with
  accents, HTML + text, attachment bytes, Bcc absent from headers).
- Submission tests against a scripted fake SMTP server on a socketpair
  (EHLO/STARTTLS skipped in the fake, AUTH, MAIL, RCPT, DATA, refusals,
  SIZE), and one lab test against the real Postfix 587.
- Lab acceptance with Outlook: each row of the operations table seen in
  webmail; send to a lab account and to an external-looking address (SMTP
  egress is blocked, so delivery is checked in the Postfix queue/log
  without addresses); DKIM-Signature present; spoofed From refused.
## Lab facts (checked 2026-11-04)

- Submission 587 (STARTTLS mandatory) accepts AUTH as `<user>*openchange`
  with the master password; MAIL FROM the user's own address: RCPT 250;
  MAIL FROM another lab account: RCPT 553 (`reject_sender_login_mismatch`
  applies to the target user). EHLO offers SIZE, 8BITMIME, SMTPUTF8,
  PIPELINING.
- Dovecot offers MOVE, UIDPLUS, SPECIAL-USE, LIST-EXTENDED, CONDSTORE and
  QRESYNC (the last two are for M5).
