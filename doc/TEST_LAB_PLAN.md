# First server lab plan

Decision on 2026-10-29: a server is useful now for inventory and an isolated
source build/staged install. Starting OpenChange services, provisioning AD and
trying mailbox/Outlook workflows still require the
[first-deployment acceptance criteria](TEST_SERVER_READINESS.md). The 40% marker
remains a planning estimate, not a substitute for those criteria.

## Phases and evidence

| Phase | Work | Completion evidence | Current decision |
| --- | --- | --- | --- |
| 0. Inventory | Record OS, architecture, RAM/disk, existing services, network access and whether the machine is disposable | Host inventory and an agreed lab scope; no configuration changes | Can begin now |
| 1. Build on the target OS | Build from the reviewed sources; run native/Python checks, install under DESTDIR, run the install checker and uninstall | Build/test logs, exact dependency versions, install manifest and zero remaining staged files | Can begin after host details; this does not install system services |
| 2. Complete the deployment design | Select a mailbox storage backend, verify its ABI and supported operations; finish dependency/input review; specify AD, SQL/cache endpoints and teardown | A concrete reviewed configuration and backend build/tests, with first-deployment criteria satisfied | Blocked by mailbox storage and remaining review |
| 3. Start a disposable server | Use a dedicated VM and test domain, provision AD and storage, start services and check local RPC/authentication | Provision/startup/health logs and a demonstrated reset to the initial VM state | Not yet ready |
| 4. Exercise clients | Test mailbox logon, folders, messages, attachment/calendar operations and notifications; then a recorded Outlook version | A feature/result matrix with failures captured and account isolation checked | Depends on phase 3 |

No real accounts or an existing production domain are needed in phases 0–1.
For phases 2–3, preserve a VM reset point before AD/schema changes. Leave the
optional cache plugin disabled in the first configuration until its unresolved
identity/integrity review is complete.

## Concrete storage blocker

This checkout implements the MAPIStore backend loader and API. Its
[`backends/` directory](../mapiproxy/libmapistore/backends/) contains named-property
and indexing adapters; these are metadata/index services, not a mailbox content
backend. The former fsocpf build registration is commented out in
[`configure.ac`](../configure.ac), and there is no production implementation of
`mapistore_init_backend()` in the checked-in sources. The existing backend
registration tests use synthetic backends.

The reported target SOGo 5.12 installation has no OpenChange mailbox plugin;
this plan does not treat it as an available backend.

A successful `make all` or module load therefore does not provide a usable
mailbox store. Before functional deployment, identify a concrete backend source
and version, establish that it builds against the current interface, and test
its folder/message/attachment operations and ownership checks. No external
backend has been selected or qualified by this plan.

## Client transport blocker

The recovered native RPC/TCP entry points do not establish compatibility with
current Outlook. The historical RPC-over-HTTP service remains unported and a
MAPI/HTTP service has not been implemented here. A mailbox backend alone will
not complete that client path. Outlook's precise edition, version and build
must be part of the acceptance matrix.

The client work needs an implemented and tested HTTP transport, authentication,
session lifecycle, Autodiscover responses and wire-level client checks.
Microsoft documents [MAPI/HTTP and Outlook connectivity](https://learn.microsoft.com/en-us/troubleshoot/outlook/connectivity/outlook-not-connect-exchange-use-mapi-over-http)
and [Autodiscover](https://learn.microsoft.com/en-us/exchange/architecture/client-access/autodiscover).
This is a separate implementation/integration milestone after selecting the
mailbox storage path, not a feature established by the current test suite.

## Host information needed

Record whether the target is a dedicated/recreatable VM or a shared server,
its OS/version, architecture, RAM, free disk and private-network access. For a
Debian host, the following inventory commands are read-only:

```sh
cat /etc/os-release
uname -m
free -h
df -h /
command -v samba samba-tool testparm
# Missing packages are expected before preparing a new lab.
dpkg-query -W -f='${binary:Package}\t${Version}\n' samba samba-dev python3-samba libmariadb3
```

Do not include passwords, private keys or full application configuration in the
inventory. Host access/installation details will be chosen once its role is
known; no SSH destination or credentials are assumed here.

## Target build evidence

Follow [the staged-install procedure](TEST_INSTALL.md) on the selected OS.
Preserve the source commit plus any working changes, compiler/configure output,
OS package versions, focused test logs, `install.json` and uninstall results.
For build prerequisites only, `python3 script/doctor.py --json` supplies an
additional inventory; it does not inspect live service health or approve a
security baseline.

The local extracted toolchain and its installed-files archive are investigation
artifacts. Rebuild on the target OS rather than copying binaries linked against
that temporary toolchain. If the distribution's Samba package differs from the
locally tested one, repeat compatibility checks, including private Samba ABI
users, before proceeding to phase 3.

## Dependency review checkpoint

The Samba review was refreshed on 2026-10-29. The Debian tracker lists Trixie's
`2:4.22.11+dfsg-0+deb13u1` and security package
`2:4.22.10+dfsg-0+deb13u2`; package revisions matter in addition to the upstream
version. [DSA-6401-1](https://security-tracker.debian.org/tracker/DSA-6401-1)
records the latter as the Trixie fix for its listed July vulnerabilities.
This establishes the scope of that advisory, not a complete stack approval.

[CVE-2026-15779](https://security-tracker.debian.org/tracker/CVE-2026-15779)
remains open for Trixie and concerns `pam_winbind` home-directory creation.
Assess that component against the actual host configuration; do not enable
`pam_winbind`/`mkhomedir` as part of the initial OpenChange lab design.
The newer [CVE-2026-109411](https://security-tracker.debian.org/tracker/CVE-2026-109411)
is recorded as not affecting Trixie because the vulnerable code is absent.

Check the actual installed/candidate packages and applicable advisories again
when preparing the host, including SQL, cache and other dependencies. Neither
an upstream version string nor a successful build certifies a patched server.
