# Stage B — Outlook server rules as a Sieve script (design)

Status: proposal, 2026-11-13. Follows milestone M4 (merged a012ae9b).

## Intent

Outlook rules that the user marks as server rules (Rules and Alerts, applied on the Inbox) must run when mail is delivered, even with Outlook closed. They should behave as they do on Exchange. Today `RopModifyRules` accepts the rules and drops them, and `RopGetRulesTable` returns an empty table (`mapiproxy/servers/default/emsmdb/oxorule.c`). Outlook therefore shows every server rule as disabled with "cannot be uploaded to Microsoft Exchange".

Dovecot already runs Sieve at delivery (LMTP, Pigeonhole 2.4), and SOGo writes its own filters there. The rules are translated into a Sieve script of their own, named `outlook`, which runs next to SOGo's script.

## Goals

- `RopModifyRules` on the Inbox stores the rules and installs the Sieve that matches them. This covers add, modify, remove and the Replace flag.
- `RopGetRulesTable` on the Inbox returns the stored rules, so Outlook shows them as enabled and can edit them.
- A rule that cannot be translated is still stored. It comes back with `ST_ERROR` set in `PidTagRuleState` and produces no Sieve, so the user can see that it does not run on the server.
- Nothing about rules needs a database migration or new production state beyond one Dovecot setting.

## Non-goals

- Two-way sync with SOGo filters, because SOGo rewrites its own script on every save.
- Rules on folders other than the Inbox. They keep today's behaviour: accepted and dropped. Exchange only runs delivery rules on the Inbox.
- Client-only rules (`OP_DEFER_ACTION`, "on this computer only"). Outlook runs those itself. They are stored and returned like any other rule, with no Sieve emitted.
- Out-of-office (OOF) rules and auto-reply templates (`OP_REPLY` / `OP_OOF_REPLY`). These are stored with `ST_ERROR`.
- Notifications (M5).

## Anti-goals (failures even if it "works")

- A rule silently disappears: it is accepted but neither runs nor shows an error.
- Touching or deactivating SOGo's script, or making `outlook` the active script.
- A Sieve that fails to compile ends up installed (ManageSieve `PUTSCRIPT` validates it, and an error must reach Outlook).
- The master password crosses the network in clear text, or Sieve text is built without escaping the user's strings (header and Sieve injection).

## Constraints (from the code and the lab)

- The IDL already decodes `ModifyRules_req` (`RuleData` with `ROW_ADD`/`ROW_MODIFY`/`ROW_REMOVE`, `ModifyRulesFlag_Replace`), `PT_SRESTRICT` and `PT_ACTIONS` (`RuleAction`/`ActionBlock`). No new parser is needed.
- The IMAP backend already reaches Dovecot with the master user `openchange`. It also has a host/port/tunnel pattern for submission (`imap_settings`, `imap_tunnel_spawn`, `imap_smtp_send`), with loopback-only plus STARTTLS, and a tunnel used only in tests.
- In the lab, Dovecot 2.4.1 has `protocols = imap lmtp sieve`, ManageSieve on 4190, `ssl = required`, a personal storage at `~/sieve` and an active link `~/.dovecot.sieve`. `/usr/lib/dovecot/managesieve` with `USER=<mailbox>` runs a PREAUTH session on stdio (verified 2026-11-13). `sievec` and `sieve-test` are installed.
- The CI fixture installs only `dovecot-imapd`. It needs `dovecot-managesieved` and `dovecot-sieve`.
- The production server (.227) has the same Dovecot layout as the lab (the lab is a replica). This is not verified, and the deploy step must check it.

## Approaches considered

- **A — The Sieve script is the only store (chosen).** Each rule's MAPI properties are kept inside the `outlook` script, as one comment line per rule holding the base64 of the NDR-encoded property array, followed by the Sieve generated from it. `GetRulesTable` reads the script back with `GETSCRIPT` and decodes the comment lines. `ModifyRules` reads, applies the changes, regenerates and runs `PUTSCRIPT`. This keeps one source of truth, needs no migration and no new production state, and if the script is deleted the rules disappear consistently. The cost is one ManageSieve round trip per `GetRulesTable` (Outlook calls it rarely).
- **B — A new openchangedb table, with the script generated from it.** Reads are faster, but there are two stores that can diverge, production needs migration 3, and the LDB backend needs a matching change. Rejected for maintenance cost.
- **C — Keep the rules in the Inbox FAI `IPM.RuleOrganizer` message (already stored since M4).** That blob is Outlook's private format, undocumented in parts, and it does not carry `PidTagRuleId`. Rejected.

The user picked A on 2026-11-13 ("o ideal para manter a ideia inicial e o que facilite manutenção").

## Design

### Dovecot

- One extra script per user, in the personal storage but not active:
  ```
  sieve_script outlook {
    type = before
    driver = file
    path = ~/sieve/outlook.sieve
  }
  ```
  `type = before` runs the Outlook rules before SOGo's active script, and after the global `spam-para-junk` script, which is defined earlier. A user with no `outlook.sieve` must deliver normally. The lab check is task 1 of the plan.
- The server writes the script through ManageSieve as the master user (`<user>*openchange`): `PUTSCRIPT "outlook"`, never `SETACTIVE`. SOGo only manages its own `sogo` script, so neither side touches the other.

### Connection

- A new file in the IMAP backend, `imap_sieve.c`, holds a minimal ManageSieve client (RFC 5804): greeting/capabilities, STARTTLS, `AUTHENTICATE "PLAIN"`, `GETSCRIPT`, `PUTSCRIPT` (literal `{n+}`), `DELETESCRIPT`, `LOGOUT`. It is built on libetpan's `mailstream`, as the SMTP client is.
- Settings go in `imap_settings`: `mapistore:sieve_host` (default 127.0.0.1, loopback only), `mapistore:sieve_port` (default 4190) and `mapistore:sieve_tunnel` (tests: PREAUTH on stdio, no TLS). The rules use the same master password file.
- `GETSCRIPT` on a missing script counts as an empty rule list. `PUTSCRIPT` with no rules left becomes `DELETESCRIPT`.

### Path from the ROPs to the backend

- New mapistore folder operations (in `mapistore.h`, the backend ops table, and `mapistore_folder_*` wrappers), wired the way `submit` was wired in M4:
  - `get_rules(folder, mem_ctx, &rules, &count)`: rows as `SRow`/property arrays.
  - `modify_rules(folder, flags, RuleData *, count)`: returns a MAPI error code.
- `oxorule.c`:
  - `GetRulesTable`: if the folder is a mapistore folder and the backend implements `get_rules`, the rows are loaded into the table object. The rules table then serves `SetColumns`/`QueryRows` from those rows, with `denominator = count`. For any other folder, the stub stays as it is.
  - `ModifyRules`: same dispatch. The backend's error code goes to `mapi_repl->error_code`.
  - Before calling the backend, `OP_MOVE`/`OP_COPY` target folder EntryIDs are resolved to mapistore URIs in emsmdb, which knows how to turn an EntryID into a FID and then a URI. The backend turns a URI into an IMAP mailbox name with the M3/M4 helpers.
- In the IMAP backend, only the Inbox context implements the rules. Other IMAP folders return `MAPISTORE_ERR_NOT_IMPLEMENTED`, and emsmdb falls back to the stub.

### Storage format inside `outlook.sieve`

```
# openchange-rules v1 -- generated by OpenChange; edits are overwritten
require ["fileinto","imap4flags","copy","mailbox"];
# rule 1 <base64 NDR of the rule's property array, one line>
if allof (address :contains "from" "chefe@exemplo"), header :contains "subject" "Relatório") {
  fileinto :create "INBOX/Chefe";
  stop;
}
# rule 2 <...>
# (rule 2: not translatable, ST_ERROR)
```

- Each `# rule <id>` line keeps every property Outlook sent: `PidTagRuleId`, `Sequence`, `State`, `UserFlags`, `Condition`, `Actions`, `Provider`, `Name`, `Level` and `ProviderData`. `GetRulesTable` returns them exactly as written.
- On `ROW_ADD` the server assigns `PidTagRuleId` as the highest existing id plus 1, and Outlook reads it back.
- Rules are emitted in `PidTagRuleSequence` order. Rules whose state lacks `ST_ENABLED` are stored, with no Sieve emitted.
- `ST_ERROR` is computed when the script is generated and is never trusted from the client: it is set when translation fails and cleared when translation succeeds.
- Lines that do not start with the v1 header or `# rule` are ignored when the script is read. Hand edits are lost on the next save, as the header says.

### Translation (MAPI rule → Sieve)

Supported conditions (`PidTagRuleCondition`). Anything else makes the rule `ST_ERROR`:

| MAPI | Sieve |
|------|-------|
| `RES_AND` / `RES_OR` / `RES_NOT` | `allof` / `anyof` / `not` |
| `RES_CONTENT` on `PidTagSubject`, with FL_SUBSTRING / FL_FULLSTRING, and FL_IGNORECASE or exact case | `header :contains`/`:is` (`:comparator "i;octet"` when exact) `"subject"` |
| `RES_CONTENT` on `PidTagSenderEmailAddress` / `PidTagSentRepresentingEmailAddress` / `PidTagSenderName` | `address`/`header :contains "from"` |
| `RES_CONTENT` on `PidTagBody` | `body :text :contains` (requires `body`) |
| `RES_CONTENT` on `PidTagDisplayTo` / `PidTagDisplayCc` | `address :contains "to"` / `"cc"` |
| `RES_SUB` on recipients with `PidTagSmtpAddress`/`PidTagEmailAddress` (how Outlook encodes "from people") | `address :contains ["to","cc"]`, or `"from"` for the sender sub-object |
| `RES_PROPERTY` on `PidTagImportance` (=, ≠) | `header :is "importance"` / `"x-priority"` (high = `1`, `2`; low = `4`, `5`) |
| `RES_EXIST` / no condition (`rt` absent) | `true` |

Supported actions (`PidTagRuleActions`). Anything else makes the rule `ST_ERROR`:

| MAPI | Sieve |
|------|-------|
| `OP_MOVE` to a folder in this mailbox | `fileinto :create "<mailbox>"` |
| `OP_COPY` | `fileinto :copy :create "<mailbox>"` |
| `OP_MOVE` to Deleted Items / `OP_DELETE` | `fileinto "<Trash mailbox>"` for both (call: "permanently delete" also goes to the Trash, so a wrong rule never loses mail) |
| `OP_MARK_AS_READ` | `addflag "\\Seen"` |
| `OP_TAG` on `PidTagFlagStatus` = 2 | `addflag "\\Flagged"` |
| `OP_FORWARD` / `OP_REDIRECT` (SMTP or one-off recipients, no flags or `FWD_PRESERVE_SENDER`) | `redirect :copy "<addr>"` |
| `ST_EXIT_LEVEL` in the state | `stop;` at the end of the block |
| `OP_DEFER_ACTION` (client-only) | nothing (stored, not `ST_ERROR`) |

- A move to a folder in another store, or a forward to an EX/GAL EntryID that cannot be resolved to SMTP, makes the rule `ST_ERROR`.
- The `require` line lists only the extensions that are actually used.
- Strings are escaped per RFC 5228 (`\` and `"`), and any string containing CR, LF or NUL is rejected. Mailbox names are UTF-8 (`mailbox` extension), converted from the backend's modified UTF-7 names.
- Forwarding goes through the Dovecot/Postfix redirect path, under the same sender checks as Postfix.

### Errors

| Failure | Reply to `RopModifyRules` |
|---------|---------------------------|
| ManageSieve unreachable or login failed | `MAPI_E_CALL_FAILED`, logged at level 1 |
| `PUTSCRIPT` refused (compile error or quota) | `MAPI_E_CALL_FAILED`, logged with the server's text at level 1. Nothing changes on the server. |
| Rule not translatable | Success: the rule is stored with `ST_ERROR` (Outlook shows the error state) |
| Malformed `RuleData` (`ROW_MODIFY`/`ROW_REMOVE` of an unknown id) | `MAPI_E_NOT_FOUND`, with no partial write: the whole request applies or nothing does |

Two Outlook sessions editing at the same time get last-writer-wins, as on Exchange.

### Testing

- Unit (libcheck, in the IMAP backend suite):
  - MAPI rule → Sieve text, for each row of the two tables;
  - escaping and injection cases;
  - round trip of the encode/decode of the comment lines;
  - the `ST_ERROR` cases.
- The generated scripts are compiled with `sievec` when it is installed, and skipped otherwise.
- Fixture: the Dovecot test fixture gains a `managesieve` tunnel. The tests cover `GETSCRIPT` on an empty store, then `PUTSCRIPT`, then `GETSCRIPT`, then `DELETESCRIPT`, and a refused script. `sieve-test` checks that a sample message lands in the right mailbox.
- CI: `dovecot-managesieved` and `dovecot-sieve` added to `.github/workflows/modernization.yml`.
- Lab acceptance with Outlook (PC .162, test account):
  - create "from ana → folder X" and "subject contains Y → mark read + stop";
  - send mail from ana and check that it lands right with Outlook closed;
  - edit and delete the rules;
  - create a rule with an unsupported action and check that Outlook shows it in error;
  - check that SOGo's filters keep working and that SOGo still sees only its own script (webmail, through the browser).

## Left to the builder

- The exact NDR helper used to serialize a property array, from those that already exist in libmapi/ndr.
- Where the table rows live on the emsmdb table object (follow how other non-mapistore tables are served).
- The exact Outlook restriction shapes, to be read from the lab log at level 5 during acceptance. The condition table covers the documented shapes; anything Outlook sends outside it falls into `ST_ERROR` rather than failing.
