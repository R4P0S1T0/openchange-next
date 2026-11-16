# openchange-next

Outlook for Windows connecting "as Exchange" to an ordinary open-source mail
server — no Microsoft Exchange, no Active Directory, no LDAP.

openchange-next is a modernized fork of [OpenChange](https://github.com/openchange/openchange).
It adds a MAPI/HTTP service in front of the OpenChange core and stores
everything in the stack you already run on one server:

| Piece | Role |
| --- | --- |
| Postfix | Sending (submission on 587) |
| Dovecot | Mail storage over IMAP, and login (Outlook's Basic credentials are checked against Dovecot) |
| SOGo | Calendar and contacts over CalDAV/CardDAV (M6); webmail and phones (ActiveSync) stay on SOGo |
| MariaDB + PostfixAdmin | Address book (the GAL) and the OpenChange store state |
| nginx | TLS, `/mapi/` and Autodiscover in front of the service |

## What it is and is not

- **Clients:** Outlook 2013 SP1 and later on Windows (2013, 2016, 2019, 2021,
  2024 and classic Microsoft 365 Outlook), online and cached (OST) mode.
- **Protocol:** MAPI over HTTP only. RPC/TCP and RPC over HTTP are not supported.
- **Not covered:** Outlook 2010, the "new Outlook" for Windows (it does not use
  MAPI), Outlook for Mac, public folders, mobile devices (use SOGo ActiveSync).
- **Not** a full Exchange replacement: the aim is that Outlook works against your
  existing mail server.

## Status

| Milestone | What | State |
| --- | --- | --- |
| M1 | MAPI/HTTP service (Rust), Autodiscover, login through Dovecot | Done |
| M2 | Directory from PostfixAdmin, profile creation, address book | Done |
| M3 | Read mail from IMAP | Done |
| M4 | Send, move, delete, flags; Outlook rules stored as Sieve | Done |
| M5 | Cached mode: initial sync and live changes without restarting Outlook | Done |
| M6 | Calendar and contacts stored in SOGo, free/busy, meeting requests | Next |
| M7 | Debian package, single configuration file, installation guide | Planned |

Details, acceptance results and decisions are in
[doc/MODERNIZATION.md](doc/MODERNIZATION.md#roadmap). Until M7 there is no
installation guide; the server is tested on a lab copy of a production mail server.

## How it fits together

- `mapihttpd/` — Rust service: MAPI/HTTP endpoints, Autodiscover, sessions,
  login through Dovecot, address book (NSPI) from MariaDB, IMAP change watching.
- C core, called by the service through a narrow interface:
  `libmapi/` (protocol encoding), `mapiproxy/servers/default/emsmdb` (the mailbox
  provider), `mapiproxy/libmapistore` (store backends, including the IMAP one in
  `backends/imap`), `mapiproxy/libmapiproxy` (openchangedb on MariaDB).
- Samba is used only as a library (NDR, talloc); no Samba daemon runs.

## Build and test

Debian 13. Dependencies are listed in
[.github/workflows/modernization.yml](.github/workflows/modernization.yml); the
build also needs Samba 4.22.10's `pidl` on `PATH` (the workflow shows how).

```sh
./autogen.sh && ./configure --with-samba=/usr
make -j"$(nproc)" all
make check-emsmdb check-oc-emsmdb check-mapihttp check-imap-backend   # and the other check-* targets in the workflow
python3 -m unittest discover -s python/openchange/tests
python3 -m unittest discover -s testsuite/modernization
cargo test --offline --locked
```

Rust dependencies are vendored in `vendor/` so the service builds offline with
Debian's Rust.

## Documentation

- [doc/MODERNIZATION.md](doc/MODERNIZATION.md) — direction, roadmap, results per milestone.
- [doc/CONTINUITY.md](doc/CONTINUITY.md) — current hand-off notes.
- [docs/plans](docs/plans) and [docs/superpowers](docs/superpowers) — design and plan for each milestone.
- [README.smbconf.md](README.smbconf.md) — configuration options of the C core.

## Legacy code

Components of the original OpenChange that the new direction does not use (PHP,
Qt and C++ bindings, the RPC/TCP-only modules, old packaging) were
removed in November 2026. They remain available at the git tag `legacy-2026-11`.

## Licence

GNU General Public License v3 or later — see [COPYING](COPYING). Protocol IDL
files carry their own notice in [IDL_LICENSE.txt](IDL_LICENSE.txt).
