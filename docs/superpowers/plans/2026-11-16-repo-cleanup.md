# Repository cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove dead legacy code from the repository and rewrite `README.md`, without changing what builds and runs today.

**Architecture:** Tag the current `main`, work on branch `cleanup`, delete in two steps (outside the build, then wired into the build), verify against a baseline taken on a fresh lab build tree, merge only after the lab Outlook still works.

**Tech Stack:** autotools `configure.ac` + hand-written `Makefile`, GitHub Actions (`.github/workflows/modernization.yml`), Rust `mapihttpd`, lab 192.168.1.215 (Samba 4.22.10 source at `/srv/build/samba-4.22.10`).

**Spec:** `docs/superpowers/specs/2026-11-16-repo-cleanup-design.md`

## Global Constraints

- Tag `legacy-2026-11` on `main` before any deletion; push the tag.
- Work on branch `cleanup`; `main` changes only by merge after verification.
- Delete only: `php/`, `packaging/`, `.travis.yml`, `mapiproxy/services/`, `qt/`, `libmapi++/`, `pyopenchange/`, `testprogs/`, `mapiproxy/servers/default/rfr`, `mapiproxy/servers/default/asyncemsmdb`, plus files that exist only to build or test them.
- Keep: `utils/`, `libmapiadmin/`, `vendor/`, `libexchange2ical/` (M6 reuses it).
- No change to code that the daemon, the C core or the remaining tests use. No directory moves, no build-system change.
- Merge gate: `make all`, every remaining `check-*` target in the CI workflow, the Python and Rust tests, and the lab daemon built from `cleanup` serving the TSplus Outlook as before.

## Review Focus

- A Makefile rule or `all` dependency still naming a deleted file: `make all` on a **fresh** tree fails (an incremental tree hides it because old `.o`/`.so` remain). Every verification runs in a fresh clone.
- `configure.ac` options or `AC_CONFIG_FILES` entries for deleted parts (`--enable-pymapi`, Qt, libmapi++ `.pc`): `./autogen.sh && ./configure` must finish with no missing-file error.
- `make install`/`uninstall` and `script/check_install.py` expecting removed files (`libmapipp.so`, `libmapi++.pc`, `exchange_ds_rfr.so`, `dcesrv_asyncemsmdb.so`): the CI install job must still pass.
- Docs and scripts linking deleted paths (`packaging`, `asyncemsmdb`, `rfr`, `pyopenchange`, `php`, `qt`): `git grep` for each removed path returns only history/changelog mentions.
- The lab `make install` from the new tree leaves stale old files in `/usr/local` (e.g. `dcesrv_asyncemsmdb.so`): harmless, but the daemon must not load them; check `openchange-mapihttpd` starts and Outlook syncs.

---

### Task 0: Tag, branch and baseline

**Files:** none changed.

- [ ] **Step 1:** Push `main` (commits `f3584a8a`, `40dbcecf` and this plan), then `git tag -a legacy-2026-11 -m "Last state before the 2026-11 cleanup" main && git push origin legacy-2026-11`.
- [ ] **Step 2:** `git worktree add .build/worktrees/cleanup -b cleanup main`.
- [ ] **Step 3:** Baseline on the lab in a fresh tree: `git archive main | ssh renanmorano@192.168.1.215 'rm -rf /srv/build/baseline && mkdir -p /srv/build/baseline && tar -xf - -C /srv/build/baseline'`, then in it with `PATH=/srv/build/samba-4.22.10/pidl:$PATH PERL5LIB=/srv/build/samba-4.22.10/pidl/lib`: `./autogen.sh && ./configure --with-samba=/usr && make -j2 all`, every `make check-*` target listed in `.github/workflows/modernization.yml`, `python3 -m unittest discover -s python/openchange/tests`, `python3 -m unittest discover -s testsuite/modernization`, and in `mapihttpd/` `cargo test --offline --locked`. Save pass/fail per command to `/srv/build/baseline.txt`.
Expected: the list of what passes today. Later tasks must pass the same list minus the targets they delete (`check-asyncemsmdb`).

### Task 1: Step 1 deletions and new README

**Files:**
- Delete: `php/`, `packaging/`, `.travis.yml`, `mapiproxy/services/`
- Modify: any file found by `git grep -nE "packaging/|php/|\.travis|mapiproxy/services"` outside `CHANGES.md` (expected: the `Makefile` line for services, a few files under `script/`, `doc/`, `docs/`)
- Rewrite: `README.md`

- [ ] **Step 1:** `git rm -r php packaging .travis.yml mapiproxy/services` in the `cleanup` worktree.
- [ ] **Step 2:** Fix every reference from the grep above: drop the line or reword it to say the component was removed (link `legacy-2026-11` when a reader may want the old code).
- [ ] **Step 3:** Rewrite `README.md` with these sections, in plain English, short: what the project is (Outlook 2013 SP1+ over MAPI/HTTP against a single server with Postfix, Dovecot, SOGo, MariaDB/PostfixAdmin and nginx; no Active Directory, no LDAP); what it is not (not a full Exchange replacement, no RPC/TCP, no mobile — phones stay on SOGo ActiveSync, no "new Outlook"); status table M1–M7 with M1–M5 done and M6 next, linking `doc/MODERNIZATION.md#roadmap`; architecture in three lines (Rust `mapihttpd` front end, C core: libmapi NDR, emsmdb provider, libmapistore with the IMAP backend, openchangedb on MariaDB); build and test (the configure/make/check and cargo commands from Task 0); docs map (`doc/MODERNIZATION.md`, `doc/CONTINUITY.md`, `docs/plans`, `docs/superpowers`); legacy code (tag `legacy-2026-11`); licence (GPLv3+, `COPYING`). Remove the 2008 goals text. Keep `README.smbconf.md` and link it.
- [ ] **Step 4:** Fresh-tree check on the lab as in Task 0 Step 3, from `git archive cleanup` into `/srv/build/cleanup`: configure, `make -j2 all`, all baseline commands.
Expected: identical results to the baseline.
- [ ] **Step 5:** Commit: `chore: remove PHP bindings, old packaging, Travis and mapiproxy services; rewrite README`.

### Task 2: Remove client-side legacy libraries and programs

**Files:**
- Delete: `qt/`, `libexchange2ical/`, `libmapi++/`, `pyopenchange/`, `testprogs/`, `libmapi++.pc.in`, and any other file that exists only for them (find with `git grep -lE "libmapi\+\+|libmapipp|exchange2ical|pyopenchange|testprogs|qt/"`).
- Modify: `Makefile` (rules, `all`/`install`/`uninstall`/`clean`/`distclean` lists, pkg-config lists), `configure.ac` (options and `AC_CONFIG_FILES` for these parts), `script/check_install.py` if it lists their files, docs that reference them.

- [ ] **Step 1:** `git rm -r` the directories and files above.
- [ ] **Step 2:** Remove their rules and every list entry from `Makefile`; remove their options, checks and output files from `configure.ac`. Nothing else in these files changes.
- [ ] **Step 3:** `git grep` for each removed name returns only `CHANGES.md` and history notes in `doc/`.
- [ ] **Step 4:** Fresh-tree check on the lab (`/srv/build/cleanup` recreated from `git archive cleanup`), plus `make install DESTDIR=/tmp/oc-stage && python3 script/check_install.py /tmp/oc-stage && make uninstall DESTDIR=/tmp/oc-stage`.
Expected: same results as the baseline; install check passes.
- [ ] **Step 5:** Commit: `chore: remove Qt, exchange2ical, libmapi++, pyopenchange and testprogs`.

### Task 3: Remove the RPC/TCP-only server modules

**Files:**
- Delete: `mapiproxy/servers/default/rfr/`, `mapiproxy/servers/default/asyncemsmdb/`, `asyncemsmdb.idl`, `testsuite/modernization/asyncemsmdb_smoke.c`, the `bin/asyncemsmdb` source and anything else only they use (find with `git grep -lE "asyncemsmdb|exchange_ds_rfr|dcesrv_mapiproxy_rfr"`; `mapiproxy/dcesrv_mapiproxy_rfr.c` belongs to the RPC proxy — delete it only if nothing else in the `Makefile` links it).
- Modify: `Makefile` (`exchange_ds_rfr`, `dcesrv_asyncemsmdb`, `check-asyncemsmdb` rules and list entries), `.github/workflows/modernization.yml` (the `check-asyncemsmdb` steps and the ctypes load lines at lines ~92, ~101, ~107–109 for these `.so`), `script/check_install.py`, docs.

- [ ] **Step 1:** `git rm` the files above.
- [ ] **Step 2:** Remove their rules, list entries and CI steps. The ctypes line that loads several `exchange_*.so` keeps the remaining names.
- [ ] **Step 3:** `git grep -nE "asyncemsmdb|exchange_ds_rfr"` returns only history notes.
- [ ] **Step 4:** Fresh-tree check on the lab plus the install check from Task 2.
Expected: baseline minus `check-asyncemsmdb`.
- [ ] **Step 5:** Commit: `chore: remove the RPC/TCP referral and async EMSMDB modules`.

### Task 4: Lab acceptance, merge and push

- [ ] **Step 1:** On the lab, as root: back up `/etc/openchange`, `/var/lib/openchange`, `/usr/local/lib/liboc_emsmdb.so`, `/usr/local/sbin/openchange-mapihttpd` to `/root/backup-pre-cleanup-<date>`; then from `/srv/build/cleanup`: `make install`, `install -m0644 mapiproxy/servers/liboc_emsmdb.so /usr/local/lib/`, build `mapihttpd` with `cargo build --release --offline --locked --features c-backend` and `install -m0755` it as `/usr/local/sbin/openchange-mapihttpd`, `ldconfig`, `systemctl restart openchange-mapihttpd`.
- [ ] **Step 2:** In the TSplus session, restart Outlook for `teste@lab.fitasonline.com.br`; send one mail to itself, create and delete a folder. In the journal since the restart: no new `error 0x8` other than the known `OpenFolder NOT_FOUND`, no crash.
Expected: Outlook opens, syncs, mail and folder changes appear as before.
- [ ] **Step 3:** If Step 2 fails, restore the backup and stop. Otherwise `git merge --no-ff cleanup` into `main` with message `merge: repository cleanup before M6`, push `main` and `cleanup`.
- [ ] **Step 4:** Update `doc/CONTINUITY.md` header to the current state (M5 done, cleanup done, M6 next) and commit on `main`.
