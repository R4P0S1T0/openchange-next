#!/usr/bin/env python3
"""Read-only inventory of prerequisites for the OpenChange build.

This checks discovery, not ABI compatibility or successful compilation.
Only the Python standard library is needed to run it.
"""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parent.parent
TOOLS = (
    "make", "cc", "c++", "autoconf", "autoheader", "aclocal",
    "pkg-config", "perl", "pidl", "flex", "bison", "mysql_config",
    "python3", "python3-config",
)
MODULES = (
    "nanomsg >= 0.5", "libmemcached >= 1.0.18", "talloc", "dcerpc", "ndr",
    "samba-hostconfig", "samba-util", "tevent", "samba-credentials",
    "tdb", "ldb", "dcerpc_server", "samdb", "check",
)


def run(command):
    """Run a discovery command without a shell; return diagnostic failures."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=10, check=False
        )
        return result.returncode, (result.stdout or result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return 1, str(error)


def samba_version(pkg_config):
    # samba-hostconfig.pc describes the library API (often 0.0.1), not the
    # Samba distribution release. Use the installed version header instead.
    code, includedir = run([pkg_config, "--variable=includedir", "samba-hostconfig"])
    if code != 0 or not includedir:
        return None
    try:
        header = (Path(includedir) / "samba/version.h").read_text()
    except OSError:
        return None
    match = re.search(r'^#define\s+SAMBA_VERSION_OFFICIAL_STRING\s+"([^"]+)"',
                      header, re.MULTILINE)
    return match.group(1) if match else None


def inspect(root=ROOT):
    checks = []
    for tool in TOOLS:
        path = shutil.which(tool)
        checks.append({"name": tool, "status": "ok" if path else "missing",
                       "detail": path or "not on PATH"})

    python = shutil.which("python3")
    if python:
        code, version = run([python, "-c", 'import sys; print("%d.%d" % sys.version_info[:2])'])
        parsed = re.fullmatch(r"(\d+)\.(\d+)", version)
        supported = code == 0 and parsed and tuple(map(int, parsed.groups())) >= (3, 11)
        checks.append({
            "name": "Python runtime",
            "status": "ok" if supported else "incompatible",
            "detail": "Python {} detected; Python 3.11+ required".format(version),
        })

    pkg_config = shutil.which("pkg-config")
    for module in MODULES:
        if pkg_config:
            code, detail = run([pkg_config, "--print-errors", "--exists", module])
            if code != 0 and module == "nanomsg >= 0.5":
                code, detail = run([pkg_config, "--print-errors", "--exists", "libnanomsg >= 0.5"])
            status = "ok" if code == 0 else "missing"
        else:
            status, detail = "unchecked", "pkg-config is unavailable"
        checks.append({"name": module, "status": status, "detail": detail})

    expected = re.search(
        r"^SAMBA4_RELEASE=(.+)$",
        (root / "script/samba4_ver.sh").read_text(), re.MULTILINE,
    ).group(1).strip()
    if pkg_config:
        version = samba_version(pkg_config)
        checks.append({
            "name": "Samba baseline",
            "status": "ok" if version == expected else "unverified",
            "detail": "installed {}; repository baseline {}".format(version or "unknown", expected),
        })
    return {
        "scope": "build prerequisite inventory; not a build or ABI check",
        "samba_baseline": expected,
        "checks": checks,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable inventory")
    parser.add_argument("--strict", action="store_true", help="fail on missing or unverified prerequisites")
    args = parser.parse_args(argv)
    report = inspect()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(report["scope"])
        print("Repository Samba baseline: " + report["samba_baseline"])
        for check in report["checks"]:
            print("[{status}] {name}: {detail}".format(**check))
        print("Also required: header/link checks in ./configure and runtime integration tests.")
    return int(args.strict and any(c["status"] != "ok" for c in report["checks"]))


if __name__ == "__main__":
    raise SystemExit(main())
