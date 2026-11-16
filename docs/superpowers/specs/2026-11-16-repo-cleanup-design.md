# Repository cleanup before M6 (design)

Date: 2026-11-16. Status: approved by the maintainer.

## Intent

Before M6 starts, make the repository look like what the project is now: a MAPI/HTTP
server for Outlook next to Postfix, Dovecot, SOGo and MariaDB/PostfixAdmin. A newcomer
from the community should see only what runs, and a README that says so. Doing it now
avoids conflicts with the M6 changes to `Makefile` and `configure.ac`.

Goals: remove code that is dead and outside the new architecture; rewrite `README.md`.
Non-goals: moving directories, changing the build system, refactoring or porting code
(deferred by the maintainer). Anti-goals: anything that changes the behaviour of the
daemon, the C core or the tests that pass today.

## Approaches

- **A. Delete with a tag first (chosen).** Tag the current state, delete dead
  directories, drop their references from the build and CI, verify, rewrite the README.
  The repository becomes small; the old code stays one `git checkout` away.
- B. Move everything into `legacy/`: no build work, but the clutter stays in the tree.
- C. README and local cleanup only: does not remove anything.

## Decisions

1. Tag `legacy-2026-11` on `main` before any deletion; push the tag.
2. Work on branch `cleanup`; `main` changes only by merge after verification.
3. Step 1 (not in the build): `php/`, `packaging/`, `.travis.yml`,
   `mapiproxy/services/`, plus the new `README.md`.
4. Step 2 (wired into the build): `qt/`, `libmapi++/`,
   `pyopenchange/`, `testprogs/`, `mapiproxy/servers/default/rfr`,
   `mapiproxy/servers/default/asyncemsmdb`, with their `Makefile`, `configure.ac`,
   CI, script and doc references.
5. Kept for now: `utils/`, `libmapiadmin/`, `vendor/` (offline Rust build, needed for
   the M7 Debian package), `libexchange2ical/` (the M6 calendar plan reuses its
   iCalendar to MAPI conversion; kept by ruling during execution).
6. Merge gate: `make all`, the `check-*` targets, the Python and Rust tests pass, and
   the lab daemon built from `cleanup` serves the TSplus Outlook as before
   (opens, synchronizes, no new errors in the journal).
7. The README describes: what the project is and is not, the target stack and clients,
   status per milestone (M1–M5 done, M6 next), how to build and test, where the docs
   are, licence. The 2008 goals text goes away.

## Accepted behaviour change

The Samba-hosted `dcesrv_mapiproxy` (RPC/TCP, unsupported) no longer has an RFR
server module: in its server mode, RfrGetNewDSA/RfrGetFQDNFromLegacyDN are no longer
answered and it no longer tries to load the module. Proxy mode is unchanged. The
MAPI/HTTP service never used it.

## Left to the builder

Exact `Makefile`/`configure.ac` edits; which doc paragraphs referencing removed code to
update or drop; README wording.
